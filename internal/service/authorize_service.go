// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// authorize_service.go — AuthorizeService use-case.
//
// Pipeline (per request):
//
//  1. Resolve permission → FGA relation (`<domain>.<resource>.<verb>` →
//     `<resource>_<verb>` per kacho-corelib/authz convention).
//  2. Build Conditions context (`current_time` from server clock; merges
//     user-provided `context` from the RPC body).
//  3. FGA `Check` with Conditional tuples in pinned `AuthorizationModelID`.
//     Allowed=false → return deny ("no path").
//  4. Allow.
//
// Clean Architecture: domain.* + port-ifaces only. Adapter wiring lives in
// cmd/kacho-iam/main.go.
//
// The OPA guardrail overlay step (`data.kacho.iam.guardrails.deny`) was removed.
// FGA is the sole policy gate; the OPA sidecar and bundle wiring are gone.
//
// Latency budget: ≤30ms p95 — FGA Check ≤10ms, 20ms margin for
// principal-extraction + transport.
//
// Cluster-admin short-circuit cost: the per-object FGA resolve runs FIRST and
// the cluster-admin super-gate (cluster:…#system_admin) is the FALLBACK on a DENY.
// So the common ALLOW path is ONE FGA round-trip (no redundant cluster-admin Check);
// only a DENIED request pays a SECOND round-trip to test cluster-admin authority.
// BatchCheck memoizes the cluster-admin verdict per-subject so a same-subject batch
// resolves it at most once. Correctness/fail-closed unchanged — cluster-admin is
// still allowed on everything, resolved second.
package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// serverAuthoritativeCondKeys are CEL condition-context attributes that describe
// the authenticated principal or the connection. They MUST be server-derived —
// never taken from a client-supplied request body. AuthorizeService is reachable
// on the PUBLIC listener and the inner caller-authority gate allows a self-query,
// so a tenant could otherwise set these in `req.Context` and forge satisfaction
// of a security condition (mfa_fresh / source_ip_in_range / non_expired /
// device_compliant) it does not actually hold (CWE-807 / security.md "no
// reliance on untrusted inputs in a security decision").
var serverAuthoritativeCondKeys = []string{
	"current_time",       // server clock (always forced below)
	"acr_value",          // authentication assurance level (overlaid from trusted ctx)
	"amr_claims",         // authentication methods
	"mfa_at",             // last MFA timestamp
	"client_ip",          // connection source address
	"source_ip",          // connection source address (alias)
	"valid_until",        // grant expiry
	"device_attestation", // device posture
}

// buildCondContext assembles the CEL condition-context passed to OpenFGA. It
// starts from the client-supplied req.Context but STRIPS every
// server-authoritative attribute (a client cannot forge principal/connection
// facts) and then overlays only values the server actually trusts: the server
// clock as current_time, and the FD-4-trusted acr from the request ctx (the same
// trusted acr the ACR-floor interceptor enforces). Attributes the server cannot
// yet derive from a trusted source (amr_claims / mfa_at / client_ip /
// device_attestation) are left ABSENT so the dependent condition fails CLOSED
// rather than being satisfiable by a forged value. Genuinely request-scoped,
// non-security attributes pass through unchanged.
func buildCondContext(ctx context.Context, reqContext map[string]any, now time.Time) map[string]any {
	condCtx := make(map[string]any, len(reqContext)+1)
	for k, v := range reqContext {
		condCtx[k] = v
	}
	for _, k := range serverAuthoritativeCondKeys {
		delete(condCtx, k)
	}
	condCtx["current_time"] = now.Unix()
	if acr, trusted := grpcsrv.TrustedACRFromContext(ctx); trusted && acr != "" {
		condCtx["acr_value"] = acr
	}
	return condCtx
}

// Authorizer — port-iface narrowed to AuthorizeService needs.
type Authorizer interface {
	CheckWithContext(ctx context.Context, subject, relation, object string, condCtx map[string]any) (bool, error)
	ListObjects(ctx context.Context, subject, relation, objectType string, condCtx map[string]any, maxResults int) ([]string, error)
	ListSubjects(ctx context.Context, objectType, objectID, relation string, pageSize int, pageToken string) ([]string, string, error)
	Expand(ctx context.Context, objectType, objectID, relation string) (*authztypes.ExpandTree, error)
	// ReadTuples — filtered read; used by Check to enrich deny_reasons with
	// the subject's existing relations on the object (so the user can see
	// "you have `viewer` but need `editor`" instead of opaque "no path").
	// Nil-zero filters are wildcard.
	ReadTuples(ctx context.Context, subjectFilter, relationFilter, objectFilter string, pageSize int, pageToken string) ([]authztypes.ConditionalTuple, string, error)
}

// StructuralFactResolver — port over the structural facts iam can PROVE from its
// own committed rows: the parent pointers the super-access cascade derives over,
// and the account's owner. Implemented by internal/authzcascade.
//
// It exists because those tuples otherwise reach OpenFGA only through the
// at-least-once outbox, which makes the cascade delivery-dependent — the one thing
// the recorded decision chose a cascade in order NOT to be. See the package doc of
// internal/authzcascade.
type StructuralFactResolver interface {
	// Derivable reports whether this object type can be spoken about at all,
	// without touching the database — so a Check on an object iam does not own
	// costs no read.
	Derivable(objectType string) bool
	// StructuralFacts returns the facts for one object. (nil, nil) means "nothing
	// is claimed" (unknown type or absent row); a non-nil error means the row could
	// not be read, which is an outage and NOT a denial.
	StructuralFacts(ctx context.Context, objectType, objectID string) ([]authztypes.TupleKey, error)
}

// AuthorizeService — use-case.
type AuthorizeService struct {
	relations Authorizer
	modelID   string // pinned authorization_model_id
	// clusterAdmin — flat cluster-admin super-gate (explicit RBAC model). When
	// wired, Check/CheckRelation short-circuit to ALLOW for a subject holding
	// cluster:cluster_kacho_root#system_admin BEFORE the per-object FGA resolve.
	// Optional / nil-safe: an unwired checker never short-circuits (the
	// ordinary FGA path is the sole decision — backward-compatible).
	clusterAdmin authzguard.RelationChecker
	// structural — request-time source of the cascade's structural facts. Wired in
	// production; nil in unit tests that do not exercise the cascade.
	structural StructuralFactResolver
	// shadow — теневое сравнение формы E с движком. nil — сравнение выключено, и
	// каждый вопрос ведёт себя ровно как прежде: ни один исход сравнения не меняет
	// ответа вызывающему (см. shadow_port.go).
	shadow ShadowComparator
}

// AuthorizeServiceConfig — DI config.
type AuthorizeServiceConfig struct {
	Relations Authorizer
	ModelID   string
	// ClusterAdminChecker — flat cluster-admin short-circuit port. nil → no
	// short-circuit (ordinary FGA path only).
	ClusterAdminChecker authzguard.RelationChecker
	// StructuralFacts — request-time resolver for the cascade's structural facts.
	// nil → the cascade resolves only over tuples the queue has already delivered.
	StructuralFacts StructuralFactResolver
	// Shadow — теневое сравнение формы E с движком (XC-12). nil → сравнения нет, и
	// каждый вопрос отвечается ровно как прежде.
	Shadow ShadowComparator
}

// NewAuthorizeService — builder.
func NewAuthorizeService(cfg AuthorizeServiceConfig) *AuthorizeService {
	return &AuthorizeService{
		relations:    cfg.Relations,
		modelID:      cfg.ModelID,
		clusterAdmin: cfg.ClusterAdminChecker,
		structural:   cfg.StructuralFacts,
		shadow:       cfg.Shadow,
	}
}

// CheckRequest — input for `Check`.
type CheckRequest struct {
	Subject  string // "user:usr_xxx" / "service_account:sva_xxx" / "group:grp_xxx#member"
	Resource ResourceRef
	Action   string // "<domain>.<resource>.<verb>"
	// RequiredRelation — when non-empty, overrides verb-derived relation.
	// api-gateway middleware populates this from the catalog's
	// `required_relation` annotation so admin-only RPCs (e.g.
	// `vpc.address_pools.list` with `required_relation=system_admin`) gate
	// on the explicit relation instead of the auto-derived `viewer` which
	// would slip through `cluster.viewer = user:*`.
	RequiredRelation string
	Context          map[string]any // optional CEL-context
}

// ResourceRef — typed resource ref.
type ResourceRef struct {
	Type string
	ID   string
}

// CheckResult — output.
type CheckResult struct {
	Allowed              bool
	DenyReasons          []string
	AuthorizationModelID string
	CheckedAt            time.Time
}

// batchCheckParallelism bounds how many items of ONE BatchCheck pass are resolved
// against the relation store at the same time.
//
// # Why a bound is needed at all, and why it is not "as many as the batch"
//
// BatchCheck is the door every sibling service's List filter walks through:
// vpc/compute/nlb/storage each read a page from their own database, cut it into
// slices of at most 100 ids (the published cap enforced below) and hand each slice
// to this method.
//
// The predicate is per-object, so there is one store QUESTION per item. The number
// of store ROUND-TRIPS is a different quantity and is NOT inherent: the store
// answers one relation about many objects in a single request (cap
// MaxBatchChecksPerRequest), and authzfilter already uses that to turn a
// contract-sized page into tens of requests instead of a thousand. A sibling's
// slice is uniform by construction — same subject, resource type, action and
// relation, only the id varies — so a 100-item slice is answerable here in a
// couple of round-trips rather than a hundred. That it still costs a hundred is an
// OPEN REMAINDER, not physics; whoever closes it starts from
// authzcascade.Client.BatchCheckWithContext, which already carries the cascade.
// This bound does not close that remainder and is not meant to: the bound is about
// WAITING, the remainder is about round-trips.
//
// What the bound is about is that the caller's deadline is per REQUEST: a sibling gives
// one slice one second (their authzfilter.DefaultConfig().Timeout). Resolving the
// slice one item after another makes its wall time 100 × the store's answer time,
// so a store answering in 10ms consumes that entire budget and anything slower
// fails the caller's whole POSITIVE List closed with UNAVAILABLE. Each sibling
// already bounds ITS fan-out over slices for exactly this reason; that bound
// cannot see inside this hop, which is where the waiting actually was.
//
// 8 rather than "one goroutine per item": in-flight questions multiply against the
// store's own internal concurrency and against concurrent Lists from other
// callers, so an unbounded burst trades one caller's latency for everyone's. At 8
// a full 100-item slice is 13 waves instead of 100, which is the difference between
// "fits in the caller's budget with room" and "is the caller's budget".
//
// The numeral 8 is also authzfilter.BatchParallelism, and the two are NOT the same
// quantity — do not "unify" them on the strength of the digit. There, 8 bounds
// in-flight PARTITIONS, each already carrying MaxBatchChecksPerRequest questions,
// which its own godoc counts as hundreds of questions the store may be resolving
// at once. Here, 8 bounds in-flight single questions. Same numeral, units apart by
// the batch cap; an earlier revision of this comment claimed the two "bound the
// same pressure", which was wrong by that factor.
//
// Locked, with both directions, by TestBatchCheck_ResolvesItsItemsConcurrently and
// TestBatchCheck_ConcurrencyIsBounded.
const batchCheckParallelism = 8

// clusterAdminMemo memoizes the cluster-admin short-circuit verdict for a single
// subject across a Check/BatchCheck pass, so a batch from one subject (or a single
// request) issues the cluster:…#system_admin FGA Check AT MOST ONCE. The
// cluster-admin relation is subject-scoped (one cluster:cluster_kacho_root#
// system_admin tuple), so the verdict is identical for every object in the pass —
// caching it is correct and preserves fail-closed (the Check is still performed,
// just deduped).
//
// The single-flight is not decoration. A BatchCheck pass resolves its items
// concurrently (batchCheckParallelism), so this memo is read and written from
// several goroutines at once; and the resolution itself must be inside the guard,
// not merely the field writes. Guarding only the fields would let every worker that
// arrives before the first one finishes miss the memo and ask again — the batch
// would be race-free and would still issue one super-gate question per item, which
// is the very cost this type exists to remove.
//
// The guard is PER SUBJECT, and that is the whole point of the map. An earlier
// revision held one mutex across the resolution and claimed serialising "costs
// nothing that matters: at most one question per subject". The first half was
// false whenever the second half's premise did not hold: on a slice whose items
// name different subjects — a shape this method explicitly supports — the single
// lock was held across a network call for every item in turn, so the pool was
// defeated entirely and the pass ran at parallelism one. Keyed per subject, the
// claim is now true as written: same-subject workers wait for the one question
// that is being asked on their behalf, different subjects never wait for each
// other, and the per-object checks are never serialised.
type clusterAdminMemo struct {
	mu sync.Mutex
	by map[string]*clusterAdminVerdict
}

// clusterAdminVerdict — the single-flight slot for ONE subject.
type clusterAdminVerdict struct {
	once    sync.Once
	allowed bool
}

// isClusterAdmin returns the (memoized) cluster-admin verdict for subject. The
// first call for a subject performs the flat super-gate Check; concurrent and
// subsequent calls for the SAME subject reuse it. Different subjects resolve
// independently and in parallel.
func (s *AuthorizeService) isClusterAdmin(ctx context.Context, m *clusterAdminMemo, subject string) bool {
	if m == nil {
		return authzguard.SubjectIsClusterAdmin(ctx, s.clusterAdmin, subject)
	}
	m.mu.Lock()
	if m.by == nil {
		m.by = make(map[string]*clusterAdminVerdict, 1)
	}
	slot := m.by[subject]
	if slot == nil {
		slot = &clusterAdminVerdict{}
		m.by[subject] = slot
	}
	m.mu.Unlock()

	// Only the map lookup is under the shared lock; the question itself is under
	// this subject's own slot, so subjects do not block one another.
	slot.once.Do(func() {
		slot.allowed = authzguard.SubjectIsClusterAdmin(ctx, s.clusterAdmin, subject)
	})
	return slot.allowed
}

// Check — single-tuple authorization check (with Conditions + OPA overlay).
func (s *AuthorizeService) Check(ctx context.Context, req CheckRequest) (*CheckResult, error) {
	return s.check(ctx, req, nil)
}

// check is the Check implementation parameterized by an optional cluster-admin
// memo (shared across a BatchCheck pass; nil for a standalone Check).
//
// Возвраты именованы ради ОДНОГО свойства: теневой вопрос сводится на КАЖДОМ
// пути, а путей отсюда много (короткое замыкание администратора облака,
// структурный запасной путь, отказ). Сведение, приписанное к одному из них, снова
// оставило бы часть решений без сравнения — и именно ту часть, где решение
// принято дёшево. Заодно это покрывает и `BatchCheck`: он отвечает каждый свой
// пункт этой же функцией.
func (s *AuthorizeService) check(ctx context.Context, req CheckRequest, caMemo *clusterAdminMemo) (result *CheckResult, err error) {
	now := time.Now().UTC().Truncate(time.Second)
	result = &CheckResult{
		AuthorizationModelID: s.modelID,
		CheckedAt:            now,
	}

	// Input validation.
	if req.Subject == "" {
		return result, fmt.Errorf("Illegal argument subject: required")
	}
	if req.Resource.Type == "" || req.Resource.ID == "" {
		return result, fmt.Errorf("Illegal argument resource: required")
	}
	if req.Action == "" {
		return result, fmt.Errorf("Illegal argument action: required")
	}
	// Explicit relation override. When the api-gateway
	// passes `required_relation` from the catalog, we honor it verbatim
	// instead of deriving from action verb — the catalog is the single
	// source of truth for what FGA relation gates each RPC. Verb-derived
	// fallback only applies when override is empty (legacy peer-service
	// callers still work).
	relation := strings.TrimSpace(req.RequiredRelation)
	if relation == "" {
		relation = resolveActionToRelation(req.Action)
	}
	if relation == "" {
		// Cluster-admin fallback: even an unresolvable relation is allowed for a
		// cluster-admin (the flat super-gate is authority on everything). Checked on
		// the deny path only — the common allow case never pays this round-trip.
		// Отношения нет — вопроса форме E тоже нет: спросить её «наугад» значило бы
		// получить честное «нет» о том, чего не спрашивали. Но решение принято, и оно
		// обязано попасть в знаменатель.
		s.shadowUnaskable("действие не разрешается в отношение", req.Resource.Type, "")
		if s.isClusterAdmin(ctx, caMemo, req.Subject) {
			result.Allowed = true
			return result, nil
		}
		result.DenyReasons = []string{fmt.Sprintf("action %q does not resolve to a known relation", req.Action)}
		return result, nil
	}
	// Cluster is a singleton (`cluster_kacho_root` — см. domain/cluster.go::
	// ClusterSingletonID). Per-RPC catalog entries для reference data
	// (compute.Region/Zone, etc.) задают
	// scope_extractor: {object_type: cluster, from_request_field: '*'} →
	// api-gateway / compute internal authz middleware шлют Resource.ID == "*".
	// Substitute на singleton id перед общим wildcard-reject (ниже), чтобы
	// FGA-cascade `define viewer: [user, user:*]` на cluster действительно
	// работал. (api-gateway тоже substitute'ит локально — этот fix покрывает
	// прямые service→IAM caller'ы compute/vpc.)
	if req.Resource.Type == "cluster" && req.Resource.ID == "*" {
		req.Resource.ID = domain.ClusterSingletonID
	}
	// A wildcard resource id ("*") reaches us from the api-gateway authz
	// middleware when an RPC's scope id could not be extracted from the
	// request (List/Search RPCs with no scope param). OpenFGA rejects a
	// typed-wildcard object on Check (`the 'object' field cannot reference a
	// typed wildcard`) — passing it through would surface as an Unavailable
	// error and fail-closed to a misleading 503. A non-scopable resource has
	// no resolvable authorization path, so we deny cleanly (-> gRPC
	// PermissionDenied 403) instead of erroring.
	if req.Resource.ID == "*" {
		// Объекта нет — вопроса форме E нет; решение всё равно названо (знаменатель).
		s.shadowUnaskable("область запроса не названа", req.Resource.Type, relation)
		// Cluster-admin fallback: an unscopable resource has no per-object path,
		// but a cluster-admin is authority on everything. Deny path only.
		if s.isClusterAdmin(ctx, caMemo, req.Subject) {
			result.Allowed = true
			return result, nil
		}
		result.DenyReasons = []string{"no path: unscoped resource"}
		return result, nil
	}
	object := fmt.Sprintf("%s:%s", req.Resource.Type, req.Resource.ID)

	// Build the CEL condition-context: principal/connection attributes are
	// server-derived (forged client values stripped); see buildCondContext.
	condCtx := buildCondContext(ctx, req.Context, now)

	// Теневой вопрос уходит ЗДЕСЬ — до любого обращения к движку и до любого
	// короткого замыкания ниже. Сведение отложено на выход: вердикт окончателен
	// только там, а сравнивать половину ответа значило бы записывать расхождение
	// между стадиями одного решения, а не между формами.
	settleShadow := s.askShadow(ctx, req.Subject, req.Resource.Type, req.Resource.ID, relation, condCtx)
	defer func() { settleShadow(result.Allowed, err == nil) }()

	// FGA Check.
	if s.relations == nil {
		return result, fmt.Errorf("%w: authz unavailable", iamerr.ErrUnavailable)
	}
	allowed, err := s.relations.CheckWithContext(ctx, req.Subject, relation, object, condCtx)
	if err != nil {
		return result, fmt.Errorf("%w: authz unavailable: %w", iamerr.ErrUnavailable, err)
	}
	if allowed {
		result.Allowed = true
		return result, nil
	}
	// Per-object resolve DENIED. Cluster-admin fallback: the flat super-gate
	// (cluster:…#system_admin) is the first second-chance — a cluster-admin holds
	// authority on everything even without a per-object tuple. The common
	// allow case above already returned, so only a denied request pays this extra
	// round-trip; fail-closed preserved (a non-cluster-admin stays denied).
	if s.isClusterAdmin(ctx, caMemo, req.Subject) {
		result.Allowed = true
		return result, nil
	}
	// Structural fallback: the cascade's parent pointers read from iam's committed
	// rows instead of from whatever the outbox has delivered. This is what makes the
	// account administrator and the account owner resolve at request time, as the
	// cloud administrator already did above.
	structuralAllowed, serr := s.structuralFallback(ctx, req.Subject, relation, object, condCtx)
	if serr != nil {
		return result, fmt.Errorf("%w: authz unavailable: %w", iamerr.ErrUnavailable, serr)
	}
	if structuralAllowed {
		result.Allowed = true
		return result, nil
	}
	result.DenyReasons = []string{s.formatDenyReason(ctx, req.Subject, relation, object, req.Action)}
	return result, nil
}

// formatDenyReason composes a human-readable deny reason for a Check that
// returned false. It best-effort reads the subject's existing direct
// relations on the same object via FGA ReadTuples and embeds them so the
// caller can see what they DO have vs what they NEEDED. Falls back to a
// minimal "no path" message when ReadTuples fails or returns nothing —
// the deny decision itself is never affected by a ReadTuples failure
// (we already know it's a deny; this is just diagnostics).
//
// Example outputs:
//
//	subject user:usr_abc lacks relation 'editor' on vpc_network:vpcn_xyz
//	  (action 'vpc.networks.update'); current direct relations: [viewer]
//	subject user:usr_def lacks relation 'admin' on cluster:cluster_kacho_root
//	  (action 'iam.cluster.grantAdmin'); no direct relations granted
//
// The format is intentionally one-line + structured-enough for log
// pattern matching; UI surfaces it verbatim under a "Why was I denied?"
// disclosure. (deny_reasons remains repeated string for wire-format
// compat — we use the first slot.)
func (s *AuthorizeService) formatDenyReason(ctx context.Context, subject, relation, object, action string) string {
	relations := s.readSubjectRelations(ctx, subject, object)
	tail := "no direct relations granted"
	if len(relations) > 0 {
		tail = fmt.Sprintf("current direct relations: [%s]", strings.Join(relations, ", "))
	}
	actionPart := ""
	if action != "" {
		actionPart = fmt.Sprintf(" (action %q)", action)
	}
	return fmt.Sprintf("subject %s lacks relation %q on %s%s; %s",
		subject, relation, object, actionPart, tail)
}

// readSubjectRelations best-effort enumerates the (subject, *, object)
// direct tuples and returns the set of relation names (deduplicated,
// stable order). Returns nil on any error — the caller treats nil as
// "no direct relations granted".
//
// Bounded by a small page size (16) because the diagnostic only needs
// a hint, not a full audit; an oversized list would be noise.
func (s *AuthorizeService) readSubjectRelations(ctx context.Context, subject, object string) []string {
	if s.relations == nil || subject == "" || object == "" {
		return nil
	}
	tuples, _, err := s.relations.ReadTuples(ctx, subject, "", object, 16, "")
	if err != nil || len(tuples) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tuples))
	out := make([]string, 0, len(tuples))
	for _, t := range tuples {
		if t.Relation == "" {
			continue
		}
		if _, ok := seen[t.Relation]; ok {
			continue
		}
		seen[t.Relation] = struct{}{}
		out = append(out, t.Relation)
	}
	return out
}

// CheckRelationRequest — input for `CheckRelation` — the FGA-native variant
// of `Check` used by the server-side per-RPC authz gate
// (`InternalIAMService.Check`).
//
// Unlike CheckRequest, the caller supplies an already-resolved FGA
// `Relation` (`viewer`/`editor`/`admin`/…) and an FGA `Object` string
// (`<type>:<id>`) — the gateway/service-side permission-map has already done
// the action→relation resolution.
type CheckRelationRequest struct {
	Subject  string // "user:usr_xxx" / "service_account:sva_xxx" / "group:grp_xxx#member"
	Relation string // pre-resolved FGA relation
	Object   string // FGA object string "<type>:<id>"
	// HigherConsistency forces a strong read-after-write (OpenFGA
	// HIGHER_CONSISTENCY, cache/replica-lag bypass) for THIS check. Set ONLY by the
	// owner-tuple confirm-gate (read-after-OWN-write), which must observe a tuple
	// just written to the same store; the hot per-RPC enforcement gate leaves it
	// false and keeps OpenFGA's default MINIMIZE_LATENCY read.
	HigherConsistency bool
}

// consistentAuthorizer — OPTIONAL capability of the Authorizer: a CheckWithContext
// that forces OpenFGA HIGHER_CONSISTENCY. Implemented by *clients.OpenFGAHTTPClient.
// CheckRelation type-asserts to it only when HigherConsistency is requested, so a
// test stub that implements only CheckWithContext still works (falls back to the
// default read).
type consistentAuthorizer interface {
	CheckWithContextConsistent(ctx context.Context, subject, relation, object string, condCtx map[string]any) (bool, error)
}

// contextualAuthorizer — OPTIONAL capability of the Authorizer: a Check that also
// carries request-scoped tuples. Implemented by *clients.OpenFGAHTTPClient; a test
// stub that implements only CheckWithContext keeps working and simply never gets a
// structural fallback (which is why StructuralFallbackReachable exists — a
// production wiring that lost the capability must be a failure, not a silence).
type contextualAuthorizer interface {
	CheckWithContextualTuples(ctx context.Context, subject, relation, object string,
		condCtx map[string]any, contextual []authztypes.TupleKey) (bool, error)
}

// StructuralFallbackReachable reports whether the structural fallback can run at
// all: a resolver is wired AND the Authorizer can carry contextual tuples. The
// boot guard reads it, so "the cascade silently went back to being queue-dependent"
// cannot be a runtime surprise. Exported because the composition root is where a
// missing wiring must become a refusal to start.
func (s *AuthorizeService) StructuralFallbackReachable() bool {
	if s.structural == nil || s.relations == nil {
		return false
	}
	_, ok := s.relations.(contextualAuthorizer)
	return ok
}

// splitFGAObject splits "<type>:<id>" on the FIRST colon. Object ids may
// themselves contain colons (registry_repository:<reg>/<repo>:<tag>), so the
// remainder is the id verbatim.
func splitFGAObject(object string) (objectType, objectID string, ok bool) {
	i := strings.Index(object, ":")
	if i <= 0 || i == len(object)-1 {
		return "", "", false
	}
	return object[:i], object[i+1:], true
}

// structuralFallback re-resolves a DENIED check with the structural facts iam can
// prove from its OWN committed rows, supplied as request-scoped contextual tuples.
//
// It is the reason the super-access cascade holds while the outbox has delivered
// nothing: the pointers the cascade derives over are projections of committed
// columns, so they are knowable at request time and need not be waited for.
//
// Placement is the deny path, after the cluster-admin super-gate, for the same
// reason that gate sits there: the common ALLOW never pays for it, and a caller who
// was already allowed cannot have their answer changed by it. A contextual tuple
// can only ADD a path, so this can turn a deny into an allow and never the reverse
// — which is why supplying only TRUE facts about the row is the whole safety
// argument, and why authzcascade/cascade_coverage_test.go pins which relations the
// model reads those facts through.
//
// Returns (allowed, err). A non-nil err means the structural fact could not be
// read; the caller must surface that as an outage rather than as a denial, because
// the fact is part of the decision and an unread fact is an unknown answer, not a
// negative one.
//
// A caller asking for HIGHER_CONSISTENCY does NOT get it here: this Check uses the
// default read. The only effect is a possible false DENY (the store's own replica has
// not caught up with a tuple written moments ago), which is the safe direction and is
// what the fallback exists to make rare in the first place. The structural fact itself
// is read from the primary, so the part this package is responsible for is not subject
// to that lag.
func (s *AuthorizeService) structuralFallback(
	ctx context.Context, subject, relation, object string, condCtx map[string]any,
) (bool, error) {
	if s.structural == nil {
		return false, nil
	}
	objectType, objectID, ok := splitFGAObject(object)
	if !ok || !s.structural.Derivable(objectType) {
		return false, nil // no read for an object iam does not own
	}
	ca, ok := s.relations.(contextualAuthorizer)
	if !ok {
		return false, nil
	}
	facts, err := s.structural.StructuralFacts(ctx, objectType, objectID)
	if err != nil {
		return false, err
	}
	if len(facts) == 0 {
		return false, nil
	}
	return ca.CheckWithContextualTuples(ctx, subject, relation, object, condCtx, facts)
}

// CheckRelation — relation-native authorization check (FGA Check + OPA
// overlay). Used by the cluster-internal per-RPC authz gate
// (`InternalIAMService.Check`). Reuses the same FGA + OPA pipeline as
// `Check`, but skips the action→relation resolution step because the caller
// already supplies the resolved relation.
func (s *AuthorizeService) CheckRelation(ctx context.Context, req CheckRelationRequest) (result *CheckResult, err error) {
	now := time.Now().UTC().Truncate(time.Second)
	result = &CheckResult{
		AuthorizationModelID: s.modelID,
		CheckedAt:            now,
	}

	if req.Subject == "" {
		return result, fmt.Errorf("Illegal argument subject: required")
	}
	if req.Relation == "" {
		return result, fmt.Errorf("Illegal argument relation: required")
	}
	if req.Object == "" {
		return result, fmt.Errorf("Illegal argument object: required")
	}

	// Server forces current_time into the conditions context.
	condCtx := map[string]any{"current_time": now.Unix()}

	// Теневой вопрос — до движка и до всех замыканий ниже (см. check). Форма
	// объекта, которую разобрать не удалось, форме E НЕ отдаётся: она честно
	// ответила бы «нет» о несуществующем объекте, и сравнение записало бы
	// расхождение, которого нет, — но решение всё равно называется, иначе оно
	// выпадает из знаменателя молча.
	if objType, objID, ok := splitFGAObject(req.Object); ok {
		settleShadow := s.askShadow(ctx, req.Subject, objType, objID, req.Relation, condCtx)
		defer func() { settleShadow(result.Allowed, err == nil) }()
	} else {
		s.shadowUnaskable("объект вопроса не разобран", "", req.Relation)
	}

	if s.relations == nil {
		return result, fmt.Errorf("%w: authz unavailable", iamerr.ErrUnavailable)
	}
	allowed, err := s.checkRelationWire(ctx, req, condCtx)
	if err != nil {
		return result, fmt.Errorf("%w: authz unavailable: %w", iamerr.ErrUnavailable, err)
	}
	if allowed {
		result.Allowed = true
		return result, nil
	}
	// Per-object resolve DENIED. Cluster-admin fallback: the internal
	// per-RPC authz gate (InternalIAMService.Check) honors the same flat super-gate
	// as the public Check — a cluster-admin keeps access through the internal path
	// after the cascade is contracted. Checked AFTER the per-object resolve so the
	// common allow case costs a single round-trip; nil-safe.
	if authzguard.SubjectIsClusterAdmin(ctx, s.clusterAdmin, req.Subject) {
		result.Allowed = true
		return result, nil
	}
	// Structural fallback — same reason and same ordering as in check(): the
	// cascade's parent pointers come from iam's committed rows, so levels below the
	// cloud administrator stop depending on the outbox having delivered them. This
	// is the path the api-gateway per-RPC gate takes.
	structuralAllowed, serr := s.structuralFallback(ctx, req.Subject, req.Relation, req.Object, condCtx)
	if serr != nil {
		return result, fmt.Errorf("%w: authz unavailable: %w", iamerr.ErrUnavailable, serr)
	}
	if structuralAllowed {
		result.Allowed = true
		return result, nil
	}
	// CheckRelation is the gateway/internal path — same rich-deny format as the
	// public Check (no `action` available here, so the action segment is omitted).
	result.DenyReasons = []string{s.formatDenyReason(ctx, req.Subject, req.Relation, req.Object, "")}
	return result, nil
}

// checkRelationWire issues the underlying FGA Check for CheckRelation, routing to
// the HIGHER_CONSISTENCY variant when the caller requested a strong read-after-write
// (owner-tuple confirm-gate). When the Authorizer does not implement the optional
// consistentAuthorizer (a test stub), it falls back to the default read — correct,
// just not consistency-forced.
func (s *AuthorizeService) checkRelationWire(ctx context.Context, req CheckRelationRequest, condCtx map[string]any) (bool, error) {
	if req.HigherConsistency {
		if cc, ok := s.relations.(consistentAuthorizer); ok {
			return cc.CheckWithContextConsistent(ctx, req.Subject, req.Relation, req.Object, condCtx)
		}
	}
	return s.relations.CheckWithContext(ctx, req.Subject, req.Relation, req.Object, condCtx)
}

// BatchCheck — fan-out over a bounded worker pool, results in request-order.
//
// # Why the items do not wait on each other
//
// This is the door every sibling service's List filter walks through: vpc, compute,
// nlb and storage each read a page from their OWN database, cut it into slices of at
// most 100 ids (the cap enforced below) and hand each slice here. The predicate is
// per-object, so one store question per item is inherent and is NOT what changed.
//
// What changed is that the items are no longer a queue. The caller's deadline is per
// REQUEST — a sibling gives one slice one second — while a sequential pass costs
// items × the store's answer time, so an optimistic 5ms store already spent half that
// budget and a 10ms one spent all of it. The result was not a slow page but a failed
// one: the caller's whole POSITIVE List returning UNAVAILABLE, on the path that
// exists to make Lists correct. Each sibling already bounds its fan-out over slices
// for exactly this reason; that bound stops at this hop, and the waiting was inside
// it. Measured, with both counts, in TestBatchCheck_ResolvesItsItemsConcurrently.
//
// # What must not change, and is asserted
//
//   - REQUEST ORDER. Results are written to their own index, never appended: a
//     batched answer that is right but shuffled filters a page by another row's
//     verdict, and no caller can detect it.
//   - FAIL-CLOSED, WHOLE-BATCH, on ErrUnavailable — a transient backend outage is not
//     a per-item deny (it would leak the raw transport error onto a user-facing
//     surface AND turn an outage into a permanent 403). The first such error wins and
//     cancels the rest; per-item validation failures still degrade to a deny reason
//     without failing the batch.
//   - The cluster-admin super-gate stays deduped to one question per subject; the memo
//     is single-flight for that reason (see clusterAdminMemo).
func (s *AuthorizeService) BatchCheck(ctx context.Context, reqs []CheckRequest) ([]*CheckResult, error) {
	if len(reqs) > 100 {
		return nil, fmt.Errorf("Illegal argument checks: batch size %d > 100", len(reqs))
	}
	out := make([]*CheckResult, len(reqs))
	if len(reqs) == 0 {
		return out, nil
	}
	// Share ONE cluster-admin memo across the batch: a same-subject batch (the
	// common shape) resolves the cluster:…#system_admin Check at most once on the
	// deny path instead of once per item. The memo re-resolves when the subject
	// changes, so a mixed-subject batch stays correct.
	caMemo := &clusterAdminMemo{}

	// The first unavailable-class error aborts the pass; cancelling stops the
	// workers that have not asked yet rather than paying for answers already known
	// to be discarded.
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	workers := batchCheckParallelism
	if len(reqs) < workers {
		workers = len(reqs)
	}

	type item struct {
		idx int
		req CheckRequest
	}
	queue := make(chan item)

	var (
		mu      sync.Mutex
		firstEr error
		wg      sync.WaitGroup
	)
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for it := range queue {
				res, err := s.check(cctx, it.req, caMemo)
				if err != nil {
					// An FGA-backend-unavailable failure is NOT a per-item deny:
					// mirror the standalone Check sibling and fail the WHOLE batch
					// with the ErrUnavailable sentinel (handler → retryable gRPC
					// Unavailable with a fixed redacted message). Collapsing it into
					// a deny_reason would leak the raw OpenFGA transport error
					// (endpoint host:port + store id) onto a user-facing surface AND
					// mis-signal a transient outage as a permanent 403
					// (security.md hardening-invariant #1).
					if errors.Is(err, iamerr.ErrUnavailable) {
						mu.Lock()
						if firstEr == nil {
							firstEr = err
							cancel()
						}
						mu.Unlock()
						return
					}
					// Genuine per-item validation failure (e.g. "Illegal argument …",
					// deterministic + leak-free) surfaces as allowed=false +
					// deny=[err]; the whole batch does NOT fail.
					out[it.idx] = &CheckResult{
						Allowed:     false,
						DenyReasons: []string{err.Error()},
						CheckedAt:   time.Now().UTC().Truncate(time.Second),
					}
					continue
				}
				// Written to its OWN index, so workers touch disjoint slots and the
				// answer keeps the caller's order without a lock.
				out[it.idx] = res
			}
		}()
	}
feed:
	for i, r := range reqs {
		select {
		case queue <- item{idx: i, req: r}:
		case <-cctx.Done():
			break feed // a worker already failed the batch closed; stop feeding
		}
	}
	close(queue)
	wg.Wait()

	if firstEr != nil {
		return nil, firstEr
	}
	// cancel() is called only after firstEr is set, so a done cctx with no recorded
	// error means the CALLER's context expired mid-batch. Report it rather than
	// handing back a partially-filled slice whose unresolved slots are nil.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ListObjectsRequest — input for ListObjects.
type ListObjectsRequest struct {
	Subject      string
	ResourceType string
	Action       string
	// MaxResults — CLIENT-side trim of the (already server-capped) response. It
	// can only NARROW the result; a larger value never widens it. 0 → 1000.
	MaxResults int
	// PageToken — carried from the proto request only so a non-empty value can be
	// REJECTED: OpenFGA's ListObjects has no continuation token, so a page cannot
	// be honoured and quietly ignoring the token would return the wrong one.
	PageToken string
	Context   map[string]any
}

// ListObjectsResult — output.
type ListObjectsResult struct {
	ResourceIDs []string
	// NextPageToken — ALWAYS empty. It mirrors the proto response field, which is
	// a dead skeleton: ListObjects cannot paginate (see the RPC doc). Kept so the
	// wire contract has a named, documented counterpart rather than a silently
	// unset field, and locked by TestListObjects_PageToken_Rejected.
	NextPageToken string
	// Truncated — true when the answer is a CUT PREFIX, either because OpenFGA hit
	// its own server-side ceiling or because MaxResults trimmed it. A caller that
	// ignores this will mistake a prefix for the complete set.
	Truncated bool
}

// fgaListObjectsServerCap — OpenFGA's OWN server-side ceiling on a ListObjects
// response (`OPENFGA_LIST_OBJECTS_MAX_RESULTS`; default 1000, and unset — hence
// default — on the deployed stand). It is applied by the SERVER and there is NO
// continuation token, so a response of exactly this size is indistinguishable
// from "there were more": we must report it as truncated.
//
// Do NOT "fix" a truncated answer by raising this. It is an external, finite
// bound; the cure for a visibility question is to ask it PER-OBJECT instead of
// by enumeration (see internal/authzfilter, and the iam read use-cases which no
// longer call this RPC at all).
const fgaListObjectsServerCap = 1000

// ListObjects — "which objects of resource_type can subject act on?".
// Requires a configured OpenFGA client; on an unprovisioned store id the client
// fails CLOSED (ErrNotConfigured → UNAVAILABLE) — the composition root does not
// refuse to start, see clients.ErrNotConfigured (#654).
//
// # Bounded and NOT paginated — read this before relying on the result
//
// The answer is a BOUNDED PREFIX, never a guaranteed-complete set:
//
//   - OpenFGA caps the response server-side at fgaListObjectsServerCap objects
//     of the type IN THE STORE (cluster-wide, not per-tenant) and offers no
//     continuation token. `max_results` is a CLIENT-side trim applied on top, so
//     it can only NARROW the answer — asking for more can never widen it.
//   - `Truncated` reports either bound (server cap hit, or client trim applied).
//     A caller that ignores `Truncated` will silently mistake a cut prefix for
//     the complete set.
//   - There is no pagination and there cannot be one: `NextPageToken` is always
//     empty and a non-empty `page_token` is REJECTED rather than ignored
//     (silently ignoring it would return a wrong page dressed as a right one).
//
// Consequently this RPC MUST NOT be used as a visibility oracle — neither
// "enumerate then match" for a read-by-id, nor "enumerate then narrow the SQL"
// for a List. Both silently lose a tenant's own resources once the store holds
// more objects of the type than the cap. Ask a per-object Check/BatchCheck for
// the ids on the page instead (that is what iam's own read use-cases and
// kacho-vpc's authzfilter now do). The RPC remains for genuine enumeration use
// (admin tooling / discovery) where a bounded prefix plus a truncation flag is
// an acceptable answer.
//
// For a list/get-class action on a verb-bearing type the visibility set is the
// UNION of the principal's `viewer`-set and `v_list`-set on the type:
//
//	visible = ListObjects(subject, "viewer", <type>) ∪ ListObjects(subject, "v_list", <type>)
//
// The `viewer` branch surfaces objects the principal resolves the viewer tier on
// (broader access); the `v_list` branch surfaces objects granted ONLY a names/labels
// selector (an object-only `<type>:<id> # v_list @ subj` tuple with NO viewer cascade
// — see-in-selector-without-content). Centralizing the union HERE means a
// consumer (vpc/compute/nlb) issues ONE ListObjects call with ONE action and gets
// both sets; the consumers do not each re-implement the union. This mirrors the
// account/project use-case List union, generalized to all verb-bearing leaf types.
//
// A non-verb-bearing type (e.g. `cluster`, which defines no v_* relations) uses the
// single resolved relation only — a v_list ListObjects on it would 400 on a
// dangling relation.
func (s *AuthorizeService) ListObjects(ctx context.Context, req ListObjectsRequest) (res *ListObjectsResult, err error) {
	if s.relations == nil {
		return nil, fmt.Errorf("%w: authz unavailable", iamerr.ErrUnavailable)
	}
	relation := resolveActionToRelation(req.Action)
	if relation == "" {
		return nil, fmt.Errorf("Illegal argument action %q", req.Action)
	}
	// OpenFGA's ListObjects has no continuation token, so a page_token can never
	// be honoured. Rejecting it is the honest contract: accepting-and-ignoring
	// would hand the caller page 1 while they believe they hold page 2.
	if req.PageToken != "" {
		return nil, fmt.Errorf("Illegal argument page_token: ListObjects does not paginate")
	}
	now := time.Now().UTC().Truncate(time.Second)
	// Same server-authoritative sanitisation as Check: forged principal/connection
	// attributes are stripped, current_time / trusted acr are server-derived.
	condCtx := buildCondContext(ctx, req.Context, now)
	// maxR is a CLIENT-side trim: it can only narrow the (already server-capped)
	// response, never widen it. The 10000 ceiling therefore bounds our own work,
	// not OpenFGA's.
	maxR := req.MaxResults
	if maxR <= 0 {
		maxR = 1000
	}
	if maxR > 10000 {
		maxR = 10000
	}

	// viewer ∪ v_list for a read-class action on a verb-bearing type. The
	// extra v_list query runs ONLY when the resolved relation is the read tier AND
	// the type carries v_* relations; otherwise a single ListObjects (back-compat).
	relations := []string{relation}
	if relation == relationViewer && authzmap.TypeHasVerbRelations(req.ResourceType) {
		relations = []string{relationViewer, relationVList}
	}

	// Форма E спрашивается тем же НАБОРОМ отношений и до движка: спросить её об
	// одном из объединяемых отношений значило бы сравнить два разных вопроса.
	// Сведение отложено: сверяются множества, а множество известно только целиком.
	settleShadow := s.askShadowObjects(ctx, req.Subject, req.ResourceType, relations)
	defer func() {
		if err != nil || res == nil {
			settleShadow(nil, false, false)
			return
		}
		settleShadow(res.ResourceIDs, !res.Truncated, true)
	}()

	seen := make(map[string]struct{})
	ids := make([]string, 0, maxR)
	// serverCapped — at least one relation's response came back at OpenFGA's own
	// ceiling, i.e. the server cut it. This is the ONLY signal available (there is
	// no continuation token and no server-side "more" flag), and it must be checked
	// PER RELATION: the union of two capped responses can hold up to 2×cap ids, so
	// a check on the merged length would miss it.
	serverCapped := false
	for _, rel := range relations {
		got, err := s.relations.ListObjects(ctx, req.Subject, rel, req.ResourceType, condCtx, maxR)
		if err != nil {
			// Fail-closed on EITHER relation — never a partial list (no leak, no
			// silent narrowing).
			return nil, fmt.Errorf("authz listObjects: %w", err)
		}
		if len(got) >= fgaListObjectsServerCap {
			serverCapped = true
		}
		for _, id := range got {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	// Truncated must reflect BOTH bounds. `len(ids) >= maxR` alone (the previous
	// formula) was silently FALSE for every server-capped answer whenever the
	// caller asked for more than the server cap — e.g. max_results=5000 over a
	// 1000-capped response reported "complete". That is exactly how a tenant's own
	// objects vanished without any signal.
	truncated := serverCapped || len(ids) >= maxR
	return &ListObjectsResult{
		ResourceIDs: ids,
		Truncated:   truncated,
	}, nil
}

// ListSubjectsRequest — input.
type ListSubjectsRequest struct {
	ResourceType      string
	ResourceID        string
	Action            string
	PageSize          int
	PageToken         string
	SubjectTypeFilter string
}

// ListSubjectsResult — output.
type ListSubjectsResult struct {
	Subjects      []string
	NextPageToken string
}

// ListSubjects — inverse of ListObjects.
func (s *AuthorizeService) ListSubjects(ctx context.Context, req ListSubjectsRequest) (_ *ListSubjectsResult, err error) {
	if s.relations == nil {
		return nil, fmt.Errorf("%w: authz unavailable", iamerr.ErrUnavailable)
	}
	if req.PageSize > 1000 {
		return nil, fmt.Errorf("Illegal argument page_size %d > 1000", req.PageSize)
	}
	relation := resolveActionToRelation(req.Action)
	if relation == "" {
		return nil, fmt.Errorf("Illegal argument action %q", req.Action)
	}
	// Форма E спрашивается до движка. Сверяется НЕОТФИЛЬТРОВАННЫЙ ответ: сужение по
	// типу субъекта — свойство запроса, а не модели, и сравнивать отфильтрованное с
	// полным значило бы объявить расхождением сам фильтр.
	//
	// Сведение отложено, а не приписано к путям: путь, добавленный завтра между
	// вопросом и сведением, иначе оставил бы теневой вызов висеть со своим сроком —
	// и это свойство построения, а не внимательности автора.
	var (
		engineSubjects []string
		engineComplete bool
		engineAnswered bool
	)
	settleShadow := s.askShadowSubjects(ctx, req.ResourceType, req.ResourceID, relation)
	defer func() { settleShadow(engineSubjects, engineComplete, engineAnswered) }()

	subs, next, err := s.relations.ListSubjects(ctx, req.ResourceType, req.ResourceID, relation, req.PageSize, req.PageToken)
	if err != nil {
		return nil, fmt.Errorf("authz listSubjects: %w", err)
	}
	// Страница с продолжением — не всё множество: сверять её с полным ответом формы
	// значило бы записать расхождением границу страницы.
	engineSubjects, engineComplete, engineAnswered = subs, next == "" && req.PageToken == "", true
	if req.SubjectTypeFilter != "" {
		filtered := subs[:0]
		prefix := req.SubjectTypeFilter + ":"
		for _, s := range subs {
			if strings.HasPrefix(s, prefix) {
				filtered = append(filtered, s)
			}
		}
		subs = filtered
	}
	return &ListSubjectsResult{Subjects: subs, NextPageToken: next}, nil
}

// ExpandRequest — input.
type ExpandRequest struct {
	ResourceType string
	ResourceID   string
	Relation     string
	MaxDepth     int
}

// ExpandResult — output.
type ExpandResult struct {
	Resource             ResourceRef
	Relation             string
	Tree                 *authztypes.ExpandTree
	AuthorizationModelID string
}

// ExpandRelations — Zanzibar userset tree.
func (s *AuthorizeService) ExpandRelations(ctx context.Context, req ExpandRequest) (_ *ExpandResult, err error) {
	if s.relations == nil {
		return nil, fmt.Errorf("%w: authz unavailable", iamerr.ErrUnavailable)
	}
	// Форма E спрашивается до движка; сверяются субъекты, названные основаниями, —
	// единственное, что обе формы называют одинаково (см. shadow_port.go). Сведение
	// отложено по той же причине, что в ListSubjects.
	var (
		engineSubjects []string
		engineComplete bool
		engineAnswered bool
	)
	settleShadow := s.askShadowSources(ctx, req.ResourceType, req.ResourceID, req.Relation)
	defer func() { settleShadow(engineSubjects, engineComplete, engineAnswered) }()

	tree, err := s.relations.Expand(ctx, req.ResourceType, req.ResourceID, req.Relation)
	if err != nil {
		return nil, fmt.Errorf("authz expand: %w", err)
	}
	depth := req.MaxDepth
	if depth <= 0 {
		depth = 16
	}
	if depth > 32 {
		depth = 32
	}
	truncateTree(tree, depth)
	// Читается ПОСЛЕ обрезки по глубине: вызывающий получает обрезанное дерево, и
	// сверять надо то, что он получил, а не то, что пришло с провода.
	engineSubjects, engineComplete = expandTreeSubjects(tree)
	engineAnswered = true
	return &ExpandResult{
		Resource:             ResourceRef{Type: req.ResourceType, ID: req.ResourceID},
		Relation:             req.Relation,
		Tree:                 tree,
		AuthorizationModelID: s.modelID,
	}, nil
}

// truncateTree — depth-limit the expand tree.
func truncateTree(t *authztypes.ExpandTree, depth int) {
	if t == nil || depth <= 0 {
		return
	}
	if depth == 1 {
		// Mark all subtrees as truncated.
		for i := range t.Computed {
			if t.Computed[i].Subtree != nil {
				t.Computed[i].Subtree.Truncated = true
				t.Computed[i].Subtree.Computed = nil
				t.Computed[i].Subtree.TupleToUserset = nil
			}
		}
		for i := range t.TupleToUserset {
			if t.TupleToUserset[i].Subtree != nil {
				t.TupleToUserset[i].Subtree.Truncated = true
				t.TupleToUserset[i].Subtree.Computed = nil
				t.TupleToUserset[i].Subtree.TupleToUserset = nil
			}
		}
		return
	}
	for i := range t.Computed {
		truncateTree(t.Computed[i].Subtree, depth-1)
	}
	for i := range t.TupleToUserset {
		truncateTree(t.TupleToUserset[i].Subtree, depth-1)
	}
}

// FGA relation literals shared by the ListObjects union: the read tier and
// the per-verb list relation. The verb-bearing union queries both.
const (
	relationViewer = "viewer"
	relationVList  = "v_list"
)

// resolveActionToRelation — `<domain>.<resource>.<verb>` → FGA relation.
// Convention from kacho-corelib/authz: relation is `<resource>_<verb>` for
// verbs in {get,list,update,delete,create} mapped to {viewer,viewer,editor,
// admin,editor}. For domain-specific actions we fall back to the verb
// directly (`compute.instances.ssh` → `ssh`).
func resolveActionToRelation(action string) string {
	parts := strings.Split(action, ".")
	if len(parts) < 2 {
		return ""
	}
	// Lower-case the verb: action strings carry the RPC method name with its
	// first letter lowered but inner camelCase preserved (Get→get,
	// ListByScope→listByScope, AddCidrBlocks→addCidrBlocks). The case
	// labels below are all lower-case, so without this fold a multi-word verb
	// like "listByScope" would miss every case and fall through to the
	// unknown→deny branch — which regressed legitimate non-CRUD reads/mutations
	// (e.g. AccessBindingService.ListByScope → 403). Folding here keeps the
	// fail-closed posture for genuinely-unknown verbs while correctly mapping
	// the known multi-word ones.
	verb := strings.ToLower(parts[len(parts)-1])
	switch verb {
	case "get", "list":
		return "viewer"
	case "create", "update":
		return "editor"
	case "delete":
		return "admin"
	// Action verbs that are semantically editor-level mutations but are not
	// the canonical CRUD verbs. Mapping them to a real model relation avoids
	// an FGA 400 (unknown relation) on the Check.
	case "invite", "move", "start", "stop", "restart",
		"addmember", "removemember", "addmembers", "removemembers",
		"attachdisk", "detachdisk", "attachnetworkinterface",
		"detachnetworkinterface", "attachfilesystem", "detachfilesystem",
		"addlistener", "removelistener",
		"attachtargetgroup", "detachtargetgroup", "enablezones",
		"disablezones", "addtargets", "removetargets",
		"updaterule",
		"updaterules", "addcidrblocks", "removecidrblocks",
		// SAKey credential-mutation verbs — issuing/revoking a Service Account
		// OAuth key (SAKeyService.Issue/Revoke). Catalog gates these at editor;
		// the verb-fallback must agree so an action-only (no required_relation)
		// Check doesn't unknown→deny them (regressed SAKeyService.Issue → 403).
		"issue", "revoke":
		return "editor"
	case "listaccessbindings", "listoperations", "gettargetstates",
		"getserialportoutput", "getlatestbyfamily", "getbyvalue",
		"listbysubnet", "listsubnets", "listsecuritygroups",
		"listroutetables", "listmembers", "listsnapshotschedules",
		"listusedaddresses", "listbyscope", "listbysubject", "batchcheck",
		"check", "expandrelations", "listsubjects", "evaluate":
		return "viewer"
	}
	// Domain-specific known model relations pass through verbatim
	// (e.g. compute.instances.ssh → ssh, compute.instances.console → console).
	switch verb {
	case "ssh", "console", "admin", "editor", "viewer":
		return verb
	}
	// Unknown verb — fail-closed. Defaulting to "viewer" is over-permissive: a
	// read-only subject already holds `viewer`, so a typo'd or unrecognised
	// MUTATING verb would be wrongly ALLOWED. Returning "" signals the caller
	// to deny explicitly (Check: empty relation → deny; ListObjects/ListSubjects:
	// empty relation → InvalidArgument). New verbs must be added to a mapping
	// above before they can authorize.
	return ""
}
