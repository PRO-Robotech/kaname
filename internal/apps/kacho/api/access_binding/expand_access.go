// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// expand_access.go — ExpandAccessUseCase. Sync read "who can perform <relation> on <object>": resolves the
// FGA userset into CONCRETE principals (USER / SERVICE_ACCOUNT), closing the
// effective-principal audit gap — a binding on a GROUP subject (or a rules-model
// scope_grant grant) otherwise only shows "group G" / nothing, not its members.
//
// Mechanism — OpenFGA `ListUsers` (graph-traversing). Earlier this use-case did a
// flat filtered-Read of (object, relation) plus a hand-rolled group#member walk.
// A flat Read sees ONLY literal tuples on the EXACT (object, relation) node — it
// does NOT traverse the authorization graph, so every rules-model grant that
// reaches the queried relation through INDIRECTION resolved to EMPTY:
//   - computed-userset cascade (admin⇒editor⇒viewer): a `compute.instance.*` role
//     emits `account#admin@subject`; ExpandAccess(account, viewer) saw nothing.
//   - scope_grant indirection (`g_admin_<type> from <anchor>`): the subject sits
//     on the `scope_grant:…` object, never on the queried object's relation.
//   - group#member usersets (incl. nested groups).
// `ListUsers` natively traverses all three and returns the concrete grantees with
// groups already expanded (the FGA server bounds the walk — no client-side
// cycle-guard / depth / paging needed). We restrict `user_filters` to the
// concrete principal types so usersets/wildcards never appear in the result.

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// maxExpandResults — default + hard cap on the concrete-principal fan-out.
// A query exceeding it returns truncated=true.
const (
	defaultExpandResults = 1000
	maxExpandResults     = 10000
)

// expandUserTypes — the closed set of concrete principal types ExpandAccess
// resolves (FGA `user_filters`). A GROUP is never a concrete principal — it is
// expanded by FGA into its (user / service_account) members, so it is NOT a
// filter type. Keeping the filter to these two means ListUsers returns only
// `object`-form entries (no userset / wildcard leaves to drop).
var expandUserTypes = []string{"user", "service_account"}

// PrincipalLister — narrow port: resolve the CONCRETE principals (FGA-prefixed
// "user:…" / "service_account:…") that hold object+relation, traversing the full
// authorization graph (computed usersets + scope_grant indirection + group
// memberships). Implemented by the OpenFGA client's ListUsers.
type PrincipalLister interface {
	ListUsers(ctx context.Context, objectType, objectID, relation string, userTypes []string) ([]string, error)
}

// Principal — a concrete grantee resolved by ExpandAccess (USER or
// SERVICE_ACCOUNT; never a GROUP).
type Principal struct {
	Type domain.SubjectType
	ID   domain.SubjectID
}

type ExpandAccessUseCase struct {
	lister PrincipalLister
	// repo + relations back the per-object grant-authority gate. When wired,
	// Execute requires the caller to hold
	// grant-authority/admin on the target object's scope BEFORE the principals are
	// resolved — the SAME requireGrantAuthority predicate ListByScope/ListByRole
	// enforce (read==enforce: a caller may expand "who can do X" only on objects
	// they are themselves authorized to administer). repo is nil-safe: for leaf FGA
	// objects (compute.instance, …) authority resolves purely through the FGA admin
	// path, so only relations is strictly required.
	repo      Repo
	relations clients.RelationStore
	logger    *slog.Logger
}

func NewExpandAccessUseCase(l PrincipalLister) *ExpandAccessUseCase {
	return &ExpandAccessUseCase{lister: l}
}

// WithGrantAuthority wires the per-object authority gate. repo resolves the
// owner-path for hierarchy scopes (account/project); relations resolves the
// delegated-admin FGA path for every scope. Mirrors the WithRelationStore wiring
// on Create/Delete/ListByScope. Logger is used for failure diagnostics.
func (u *ExpandAccessUseCase) WithGrantAuthority(repo Repo, relations clients.RelationStore, logger *slog.Logger) *ExpandAccessUseCase {
	u.repo = repo
	u.relations = relations
	u.logger = logger
	return u
}

// Execute resolves <relation> on <objectType>:<objectID> into concrete
// principals. maxResults<=0 → default (1000); capped at 10000. Returns
// truncated=true when the resolved set exceeded maxResults.
func (u *ExpandAccessUseCase) Execute(ctx context.Context, objectType, objectID, relation string, maxResults int) ([]Principal, bool, error) {
	// Anti-anonymous floor — a precondition for, not a substitute for, the
	// per-object authority gate below.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, false, err
	}
	if objectType == "" {
		return nil, false, status.Error(codes.InvalidArgument, "Illegal argument object_type (must be non-empty)")
	}
	if objectID == "" {
		return nil, false, status.Error(codes.InvalidArgument, "Illegal argument object_id (must be non-empty)")
	}
	if relation == "" {
		return nil, false, status.Error(codes.InvalidArgument, "Illegal argument relation (must be non-empty)")
	}
	// Validate `relation` against the closed known-relation set BEFORE any FGA
	// probe. An arbitrary string would otherwise be forwarded verbatim into the FGA
	// query, letting a caller probe the model's internal relation graph. Unknown →
	// INVALID_ARGUMENT.
	if !authzmap.IsExpandableRelation(relation) {
		return nil, false, status.Errorf(codes.InvalidArgument, "Illegal argument relation %q", relation)
	}

	// Per-object authority gate (read==enforce). The caller may expand "who
	// can do <relation> on <object>" ONLY if they hold grant-authority/admin on the
	// object's scope — the SAME predicate ListByScope/ListByRole enforce. This
	// runs BEFORE the principal resolution, so an unauthorized caller never observes
	// the effective principals (no authz-topology / membership leak). Not wired
	// (degraded mode / older unit fixtures) ⇒ skip the gate; production always wires it.
	if u.repo != nil || u.relations != nil {
		if err := requireGrantAuthority(ctx, u.repo, u.relations, objectType, objectID); err != nil {
			return nil, false, err
		}
	}
	limit := maxResults
	if limit <= 0 {
		limit = defaultExpandResults
	}
	if limit > maxExpandResults {
		limit = maxExpandResults
	}

	// Resolve concrete principals via the graph-traversing ListUsers (groups,
	// computed usersets and scope_grant indirection all expanded server-side). One
	// ask for limit+1 lets us detect truncation without a second round-trip.
	principals, err := u.lister.ListUsers(ctx, objectType, objectID, relation, expandUserTypes)
	if err != nil {
		if u.logger != nil {
			u.logger.WarnContext(ctx, "ExpandAccess ListUsers failed",
				slog.String("object_type", objectType), slog.String("object_id", objectID),
				slog.String("relation", relation), slog.Any("error", err))
		}
		// Fail-closed: never leak the FGA/transport error text; no partial result.
		return nil, false, status.Error(codes.Internal, "failed to expand access")
	}

	seen := make(map[Principal]struct{}, len(principals))
	out := make([]Principal, 0, len(principals))
	truncated := false
	for _, s := range principals {
		p, ok := parseFGAPrincipal(s)
		if !ok {
			continue // unparseable / non-principal (group userset / wildcard)
		}
		if _, dup := seen[p]; dup {
			continue // granted directly AND via a group → counted once
		}
		seen[p] = struct{}{}
		if len(out) >= limit {
			truncated = true
			break
		}
		out = append(out, p)
	}
	return out, truncated, nil
}

// parseFGAPrincipal parses an FGA user string into a concrete Principal. Returns
// ok=false for a GROUP userset ("group:grp_x#member") or any non-user/SA form —
// those are not concrete principals (FGA already expanded groups to members).
func parseFGAPrincipal(s string) (Principal, bool) {
	typ, id, found := strings.Cut(s, ":")
	if !found || id == "" {
		return Principal{}, false
	}
	// Drop any FGA relation sigil (e.g. "group:grp_x#member") — only a bare
	// user/service_account id is a concrete principal.
	if i := strings.IndexByte(id, '#'); i >= 0 {
		return Principal{}, false
	}
	switch typ {
	case "user":
		return Principal{Type: domain.SubjectTypeUser, ID: domain.SubjectID(id)}, true
	case "service_account":
		return Principal{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(id)}, true
	default:
		return Principal{}, false
	}
}
