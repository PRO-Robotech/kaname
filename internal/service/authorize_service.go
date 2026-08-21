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
//  3. Вердикт реляционной формы по плану, скомпилированному из модели прав.
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

// buildCondContext assembles the condition-context the verdict is evaluated
// against. It starts from the client-supplied req.Context but STRIPS every
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
// Authorizer — ИСТОЧНИК ВЕРДИКТА для края.
//
// Поверхность сузилась вместе со снятием внешнего движка отношений, и сузилась
// по существу, а не по вкусу: из неё ушло всё, что было вопросом к ЧУЖОМУ
// хранилищу — перечисление объектов без продолжения, чтение и запись кортежей,
// сведения о хранилище. Осталось то, что спрашивают у РЕШЕНИЯ.
//
// Реализация — `internal/authzcascade.Client` поверх реляционной формы.
type Authorizer interface {
	// CheckWithContext — вердикт об объекте с условным контекстом запроса.
	CheckWithContext(ctx context.Context, subject, relation, object string, condCtx map[string]any) (bool, error)
	// ListSubjects — кто держит отношение на объекте, страницей С КУРСОРОМ.
	ListSubjects(ctx context.Context, objectType, objectID, relation string, pageSize int, pageToken string) ([]string, string, error)
	// Sources — кого называют основания права на объекте (разбор «почему»).
	Sources(ctx context.Context, objectType, objectID, relation string) ([]string, error)
	// DirectRelations — какие отношения субъект уже держит НА ЭТОМ объекте.
	//
	// Читатель один — текст отказа («не хватает `editor`; сейчас есть [`viewer`]»).
	// Прежде на это отвечало чтение кортежей у движка; читатель и единица те же,
	// источник — своя таблица.
	DirectRelations(ctx context.Context, subject, objectType, objectID string, limit int) ([]string, error)
}

type AuthorizeService struct {
	relations Authorizer
	// clusterAdmin — flat cluster-admin super-gate (explicit RBAC model). When
	// wired, Check/CheckRelation short-circuit to ALLOW for a subject holding
	// cluster:cluster_kacho_root#system_admin BEFORE the per-object FGA resolve.
	// Optional / nil-safe: an unwired checker never short-circuits (the
	// ordinary FGA path is the sole decision — backward-compatible).
	clusterAdmin authzguard.RelationChecker
}

// AuthorizeServiceConfig — вход сборщика.
type AuthorizeServiceConfig struct {
	Relations Authorizer
	// ClusterAdminChecker — плоский надзор администратора облака.
	//
	// Спрашивает о ДРУГОМ объекте, чем тот, о котором идёт вопрос:
	// `cluster:<синглтон>#system_admin`. Именно поэтому три верхних уровня
	// супер-доступа сделаны каскадом, а не материализацией: человек, обязанный
	// всё починить, не должен зависеть от состояния доставки.
	//
	// Со снятия внешнего движка на этот вопрос отвечает ТА ЖЕ форма, что и на
	// вопрос об объекте, — обе стороны спрашивают одно значение, поэтому «два
	// действующих источника ответа» перестало быть возможным by construction.
	ClusterAdminChecker authzguard.RelationChecker
}

// NewAuthorizeService — builder.
func NewAuthorizeService(cfg AuthorizeServiceConfig) *AuthorizeService {
	return &AuthorizeService{
		relations:    cfg.Relations,
		clusterAdmin: cfg.ClusterAdminChecker,
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
	Allowed     bool
	DenyReasons []string
	CheckedAt   time.Time
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
	result = &CheckResult{CheckedAt: now}

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
	// request (List/Search RPCs with no scope param). A typed wildcard is not an
	// object: there is no row to ask about, so there is no question to put. The
	// external engine refused it outright and the refusal surfaced as a misleading
	// 503; a refusal is not what the caller needs to hear either way. A non-scopable
	// resource has no resolvable authorization path, so we deny cleanly (-> gRPC
	// PermissionDenied 403) instead of erroring.
	if req.Resource.ID == "*" {
		// Объекта нет — вопроса форме E нет; решение всё равно названо (знаменатель).
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

	allowed, err := s.verdict(ctx, req.Subject, caMemo, relation, object, condCtx)
	if err != nil {
		return result, err
	}
	result.Allowed = allowed
	if !allowed {
		result.DenyReasons = []string{s.formatDenyReason(ctx, req.Subject, relation, object, req.Action)}
	}
	return result, nil
}

// verdict — ОКОНЧАТЕЛЬНЫЙ вердикт края.
//
// Слагаемых ДВА, и было три. Ушёл структурный запасной путь: он пересдавал
// отказанный вопрос второй раз, приложив к нему закоммиченные строки iam как
// кортежи, действующие только на этот запрос, — потому что внешний движок знал
// только то, что доехало до него очередью. Форма читает эти строки ПЕРВЫМ же
// вопросом и поднимается по цепи областей до вершины сама, поэтому дополнять её
// тем же самым нечем.
//
// Оставшееся второе слагаемое — плоский надзор администратора облака. Он спрашивает
// о ДРУГОМ объекте (`cluster:<синглтон>#system_admin`) и потому не является ни
// запасным путём, ни послаблением. Платит за него только отказ: общий разрешающий
// случай возвращается выше и лишнего вопроса не делает.
func (s *AuthorizeService) verdict(
	ctx context.Context, subject string, caMemo *clusterAdminMemo,
	relation, object string, condCtx map[string]any,
) (bool, error) {
	if s.relations == nil {
		return false, fmt.Errorf("%w: authz unavailable", iamerr.ErrUnavailable)
	}
	allowed, err := s.relations.CheckWithContext(ctx, subject, relation, object, condCtx)
	if err != nil {
		return false, fmt.Errorf("%w: authz unavailable: %w", iamerr.ErrUnavailable, err)
	}
	if allowed {
		return true, nil
	}
	return s.isClusterAdmin(ctx, caMemo, subject), nil
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
	objectType, objectID, ok := splitFGAObject(object)
	if !ok {
		return nil
	}
	relations, err := s.relations.DirectRelations(ctx, subject, objectType, objectID, 16)
	if err != nil {
		// Диагностика не вправе испортить ответ: отказ уже принят, и хвост текста
		// просто не появится — ровно как не появлялся, когда не отвечало чужое
		// хранилище кортежей.
		return nil
	}
	return relations
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
	// HigherConsistency — вызывающий требует чтения, которое НЕ отстаёт от его
	// собственной только что закоммиченной записи.
	//
	// ТРЕБОВАНИЕ ВЫПОЛНЯЕТСЯ ВСЕГДА, И ЭТО НЕ «ПОЛЕ, НА КОТОРОЕ НЕ СМОТРЯТ».
	// Просьба адресовалась ЧУЖОМУ хранилищу, у которого была своя копия и свои
	// кэши чтения: без неё оно отвечало со своей отстающей стороны. Реляционная
	// форма читает ведущую базу службы, поэтому read-after-write у неё держится
	// by construction — гарантия, которую поле просит, дана безусловно, а не
	// проигнорирована.
	//
	// Поле остаётся на контракте намеренно: оно называет ТРЕБОВАНИЕ вызывающего,
	// а не способ его исполнения. Появится путь чтения с реплики (§7 приёмки R7-3
	// держит его вне границ) — требование снова станет различающим, и различать
	// его будет тот, кто этот путь заведёт.
	HigherConsistency bool
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

// CheckRelation — relation-native authorization check (FGA Check + OPA
// overlay). Used by the cluster-internal per-RPC authz gate
// (`InternalIAMService.Check`). Reuses the same FGA + OPA pipeline as
// `Check`, but skips the action→relation resolution step because the caller
// already supplies the resolved relation.
func (s *AuthorizeService) CheckRelation(ctx context.Context, req CheckRelationRequest) (result *CheckResult, err error) {
	now := time.Now().UTC().Truncate(time.Second)
	result = &CheckResult{CheckedAt: now}

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

	allowed, err := s.verdictForRelation(ctx, req, condCtx)
	if err != nil {
		return result, err
	}
	result.Allowed = allowed
	if !allowed {
		// CheckRelation is the gateway/internal path — same rich-deny format as the
		// public Check (no `action` available here, so the action segment is omitted).
		result.DenyReasons = []string{s.formatDenyReason(ctx, req.Subject, req.Relation, req.Object, "")}
	}
	return result, nil
}

// verdictForRelation — ОКОНЧАТЕЛЬНЫЙ вердикт ВНУТРЕННЕЙ двери.
//
// Та же пара слагаемых, что у публичной, и по тем же причинам (см. verdict).
// Дверь эта — та, через которую идёт КАЖДЫЙ запрос платформы: интерсептор каждой
// службы спрашивает `InternalIAMService.Check`, а он делегирует сюда, не в
// публичный `Check`.
func (s *AuthorizeService) verdictForRelation(
	ctx context.Context, req CheckRelationRequest, condCtx map[string]any,
) (bool, error) {
	if s.relations == nil {
		return false, fmt.Errorf("%w: authz unavailable", iamerr.ErrUnavailable)
	}
	// Просьбы «ответь не с реплики» здесь больше нет, и это не потеря свойства.
	// Она адресовалась чужому хранилищу, у которого своя копия отставала; форма
	// читает ведущую базу службы, поэтому read-after-write у неё выполняется by
	// construction. Поле запроса остаётся ИМЕНЕМ требования вызывающего.
	allowed, err := s.relations.CheckWithContext(ctx, req.Subject, req.Relation, req.Object, condCtx)
	if err != nil {
		return false, fmt.Errorf("%w: authz unavailable: %w", iamerr.ErrUnavailable, err)
	}
	if allowed {
		return true, nil
	}
	return authzguard.SubjectIsClusterAdmin(ctx, s.clusterAdmin, req.Subject), nil
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
					// a deny_reason would leak the raw resolver error onto a
					// user-facing surface AND
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

// ПЕРЕЧИСЛЕНИЯ ОБЪЕКТОВ ЗДЕСЬ БОЛЬШЕ НЕТ — снято с контракта (решение Р1, R7-3).
//
// Оно отвечало ОГРАНИЧЕННЫМ ПРЕФИКСОМ без продолжения: потолок ставила чужая
// сторона, признак усечения отдавался честно, а получить остаток было нельзя
// НИКАК. Значит объекты сверх потолка оставались недостижимы при живых правах —
// ровно то, что `security.md` §«Фильтрация» запрещает формулой «страница →
// проверка страницы, НИКОГДА перечисли вселенную → отфильтруй».
//
// Заменителя не введено намеренно. «Что мне видно» получают постраничным `List`
// ресурсной службы, который сужает СТРАНИЦУ пообъектной проверкой (`pkg/listnarrow`).

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
	subs, next, err := s.relations.ListSubjects(ctx, req.ResourceType, req.ResourceID, relation, req.PageSize, req.PageToken)
	if err != nil {
		return nil, fmt.Errorf("authz listSubjects: %w", err)
	}
	// Страница с продолжением — не всё множество: сверять её с полным ответом формы
	// значило бы записать расхождением границу страницы.
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
}

// ExpandResult — output.
type ExpandResult struct {
	Resource ResourceRef
	Relation string
	Tree     *authztypes.ExpandTree
}

// ExpandRelations — ИЗ ЧЕГО складывается право на объекте.
//
// Отвечает реляционная форма: основания права разворачиваются в набор субъектов,
// которые это право в итоге получают. Ответ ОДНОУРОВНЕВЫЙ, и это свойство
// источника, а не упрощение переходника: основание — плоская запись (факт ·
// выдача · членство), и глубины у него не бывает.
//
// Графовые рёбра сняты с контракта вместе с движком, который их производил
// (решение S6): поле, которое не заполняется никогда, обещает возможность,
// которой нет.
func (s *AuthorizeService) ExpandRelations(ctx context.Context, req ExpandRequest) (*ExpandResult, error) {
	if s.relations == nil {
		return nil, fmt.Errorf("%w: authz unavailable", iamerr.ErrUnavailable)
	}
	subjects, err := s.relations.Sources(ctx, req.ResourceType, req.ResourceID, req.Relation)
	if err != nil {
		return nil, fmt.Errorf("authz expand: %w", err)
	}
	return &ExpandResult{
		Resource: ResourceRef{Type: req.ResourceType, ID: req.ResourceID},
		Relation: req.Relation,
		Tree:     &authztypes.ExpandTree{Leaves: subjects},
	}, nil
}

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
