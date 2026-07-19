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
}

// AuthorizeServiceConfig — DI config.
type AuthorizeServiceConfig struct {
	Relations Authorizer
	ModelID   string
	// ClusterAdminChecker — flat cluster-admin short-circuit port. nil → no
	// short-circuit (ordinary FGA path only).
	ClusterAdminChecker authzguard.RelationChecker
}

// NewAuthorizeService — builder.
func NewAuthorizeService(cfg AuthorizeServiceConfig) *AuthorizeService {
	return &AuthorizeService{
		relations:    cfg.Relations,
		modelID:      cfg.ModelID,
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
	Allowed              bool
	DenyReasons          []string
	AuthorizationModelID string
	CheckedAt            time.Time
}

// clusterAdminMemo memoizes the cluster-admin short-circuit verdict for a single
// subject across a Check/BatchCheck pass, so a batch from one subject (or a single
// request) issues the cluster:…#system_admin FGA Check AT MOST ONCE. The
// cluster-admin relation is subject-scoped (one cluster:cluster_kacho_root#
// system_admin tuple), so the verdict is identical for every object in the pass —
// caching it is correct and preserves fail-closed (the Check is still performed,
// just deduped).
type clusterAdminMemo struct {
	subject string
	done    bool
	allowed bool
}

// isClusterAdmin returns the (memoized) cluster-admin verdict for subject. The
// first call performs the flat super-gate Check; subsequent calls for the SAME
// subject reuse it. A different subject re-resolves (and overwrites the memo).
func (s *AuthorizeService) isClusterAdmin(ctx context.Context, m *clusterAdminMemo, subject string) bool {
	if m != nil && m.done && m.subject == subject {
		return m.allowed
	}
	allowed := authzguard.SubjectIsClusterAdmin(ctx, s.clusterAdmin, subject)
	if m != nil {
		m.subject, m.done, m.allowed = subject, true, allowed
	}
	return allowed
}

// Check — single-tuple authorization check (with Conditions + OPA overlay).
func (s *AuthorizeService) Check(ctx context.Context, req CheckRequest) (*CheckResult, error) {
	return s.check(ctx, req, nil)
}

// check is the Check implementation parameterized by an optional cluster-admin
// memo (shared across a BatchCheck pass; nil for a standalone Check).
func (s *AuthorizeService) check(ctx context.Context, req CheckRequest, caMemo *clusterAdminMemo) (*CheckResult, error) {
	now := time.Now().UTC().Truncate(time.Second)
	result := &CheckResult{
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
	// (cluster:…#system_admin) is the SOLE second-chance — a cluster-admin holds
	// authority on everything even without a per-object tuple. The common
	// allow case above already returned, so only a denied request pays this extra
	// round-trip; fail-closed preserved (a non-cluster-admin stays denied).
	if s.isClusterAdmin(ctx, caMemo, req.Subject) {
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

// CheckRelation — relation-native authorization check (FGA Check + OPA
// overlay). Used by the cluster-internal per-RPC authz gate
// (`InternalIAMService.Check`). Reuses the same FGA + OPA pipeline as
// `Check`, but skips the action→relation resolution step because the caller
// already supplies the resolved relation.
func (s *AuthorizeService) CheckRelation(ctx context.Context, req CheckRelationRequest) (*CheckResult, error) {
	now := time.Now().UTC().Truncate(time.Second)
	result := &CheckResult{
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

// BatchCheck — fan-out, results in request-order.
func (s *AuthorizeService) BatchCheck(ctx context.Context, reqs []CheckRequest) ([]*CheckResult, error) {
	if len(reqs) > 100 {
		return nil, fmt.Errorf("Illegal argument checks: batch size %d > 100", len(reqs))
	}
	// Share ONE cluster-admin memo across the batch: a same-subject batch (the
	// common shape) resolves the cluster:…#system_admin Check at most once on the
	// deny path instead of once per item. The memo re-resolves when the subject
	// changes, so a mixed-subject batch stays correct.
	caMemo := &clusterAdminMemo{}
	out := make([]*CheckResult, len(reqs))
	for i, r := range reqs {
		res, err := s.check(ctx, r, caMemo)
		if err != nil {
			// An FGA-backend-unavailable failure is NOT a per-item deny: mirror
			// the standalone Check sibling and fail the WHOLE batch with the
			// ErrUnavailable sentinel (handler → retryable gRPC Unavailable with a
			// fixed redacted message). Collapsing it into a deny_reason would leak
			// the raw OpenFGA transport error (endpoint host:port + store id) onto
			// a user-facing surface AND mis-signal a transient outage as a
			// permanent 403 (security.md hardening-invariant #1).
			if errors.Is(err, iamerr.ErrUnavailable) {
				return nil, err
			}
			// Genuine per-item validation failure (e.g. "Illegal argument …",
			// deterministic + leak-free) surfaces as allowed=false + deny=[err];
			// the whole batch does NOT fail.
			out[i] = &CheckResult{
				Allowed:     false,
				DenyReasons: []string{err.Error()},
				CheckedAt:   time.Now().UTC().Truncate(time.Second),
			}
			continue
		}
		out[i] = res
	}
	return out, nil
}

// ListObjectsRequest — input for ListObjects.
type ListObjectsRequest struct {
	Subject      string
	ResourceType string
	Action       string
	MaxResults   int
	PageToken    string
	Context      map[string]any
}

// ListObjectsResult — output.
type ListObjectsResult struct {
	ResourceIDs   []string
	NextPageToken string
	Truncated     bool
}

// ListObjects — "which objects of resource_type can subject act on?".
// Requires a configured OpenFGA client (composition root fails fast otherwise).
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
func (s *AuthorizeService) ListObjects(ctx context.Context, req ListObjectsRequest) (*ListObjectsResult, error) {
	if s.relations == nil {
		return nil, fmt.Errorf("%w: authz unavailable", iamerr.ErrUnavailable)
	}
	relation := resolveActionToRelation(req.Action)
	if relation == "" {
		return nil, fmt.Errorf("Illegal argument action %q", req.Action)
	}
	now := time.Now().UTC().Truncate(time.Second)
	// Same server-authoritative sanitisation as Check: forged principal/connection
	// attributes are stripped, current_time / trusted acr are server-derived.
	condCtx := buildCondContext(ctx, req.Context, now)
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

	seen := make(map[string]struct{})
	ids := make([]string, 0, maxR)
	for _, rel := range relations {
		got, err := s.relations.ListObjects(ctx, req.Subject, rel, req.ResourceType, condCtx, maxR)
		if err != nil {
			// Fail-closed on EITHER relation — never a partial list (no leak, no
			// silent narrowing).
			return nil, fmt.Errorf("authz listObjects: %w", err)
		}
		for _, id := range got {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	truncated := len(ids) >= maxR
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
func (s *AuthorizeService) ListSubjects(ctx context.Context, req ListSubjectsRequest) (*ListSubjectsResult, error) {
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
func (s *AuthorizeService) ExpandRelations(ctx context.Context, req ExpandRequest) (*ExpandResult, error) {
	if s.relations == nil {
		return nil, fmt.Errorf("%w: authz unavailable", iamerr.ErrUnavailable)
	}
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
	case "invite", "move", "relocate", "start", "stop", "restart",
		"addmember", "removemember", "addmembers", "removemembers",
		"attachdisk", "detachdisk", "attachnetworkinterface",
		"detachnetworkinterface", "attachfilesystem", "detachfilesystem",
		"updatemetadata", "updatenetworkinterface", "addonetoonenat",
		"removeonetoonenat", "addlistener", "removelistener",
		"attachtargetgroup", "detachtargetgroup", "enablezones",
		"disablezones", "addtargets", "removetargets",
		"setaccessbindings", "updateaccessbindings", "updaterule",
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
