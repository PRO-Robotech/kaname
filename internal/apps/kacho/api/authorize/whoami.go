// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// whoami.go — WhoAmIUseCase: aggregate caller identity + permission
// snapshot for `AuthorizeService.WhoAmI` (GET /iam/v1/me).
//
// Pipeline (per request, no caching — each call hits FGA twice + Postgres
// once per account row; cheap enough for UI bootstrap):
//
//  1. Resolve principal from auth context (operations.PrincipalFromContext).
//     Anonymous / system-bootstrap → Unauthenticated.
//  2. (user only) Read user row from Postgres for email + display_name.
//  3. FGA Check `system_admin@cluster:cluster_kacho_root`.
//  4. FGA Check `viewer@cluster:cluster_kacho_root`.
//  5. Reader.Users().ListAccountsForUser → set of account ids.
//  6. For each account: Reader.Accounts().Get + AccessBindings().ListBySubject
//     (filtered to account-scope) → coarse role tags.
//
// Designed for UI bootstrap and CLI permission previews — the data is
// coarse (cluster flags + per-account role tags) and intentionally NOT a
// per-RPC authority. Per-RPC gating remains at the api-gateway authz
// middleware.
package authorize

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// WhoAmICheckerForAuthz — minimal FGA port-iface for WhoAmI's two cluster
// Check calls (system_admin, viewer). Narrower than the full
// service.Authorizer so unit tests can mock just two methods.
type WhoAmICheckerForAuthz interface {
	CheckWithContext(ctx context.Context, subject, relation, object string, condCtx map[string]any) (bool, error)
}

// WhoAmIUseCase — aggregate identity + permission snapshot.
type WhoAmIUseCase struct {
	repo      kachorepo.Repository
	relations WhoAmICheckerForAuthz // nil → cluster_admin / cluster_viewer always false
}

// NewWhoAmIUseCase — builder.
func NewWhoAmIUseCase(r kachorepo.Repository, relations WhoAmICheckerForAuthz) *WhoAmIUseCase {
	return &WhoAmIUseCase{repo: r, relations: relations}
}

// WhoAmIAccountMembership — per-account membership snapshot returned by
// WhoAmI; coarse role tags derived from ACTIVE AccessBindings on the
// account object. Mirrors iamv1.AccountMembership (handler layer marshals).
type WhoAmIAccountMembership struct {
	AccountID   domain.AccountID
	AccountName string
	Roles       []string // coarse: owner | admin | editor | viewer
}

// WhoAmIResult — output.
type WhoAmIResult struct {
	Subject       string // "user:<id>" / "service_account:<id>"
	UserID        domain.UserID
	Email         string
	DisplayName   string
	SystemAdmin   bool
	ClusterViewer bool
	Accounts      []WhoAmIAccountMembership
	CheckedAt     time.Time
}

// Execute — see package doc.
func (u *WhoAmIUseCase) Execute(ctx context.Context) (*WhoAmIResult, error) {
	if u.repo == nil {
		return nil, status.Error(codes.Unavailable, "iam repo not wired")
	}
	if authzguard.IsAnonymous(ctx) {
		// Anonymous → Unauthenticated (NOT PermissionDenied). The catalog
		// marks WhoAmI as <exempt>, so the gateway passes anonymous
		// through; the handler is the authoritative gate.
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}
	p := operations.PrincipalFromContext(ctx)
	now := time.Now().UTC().Truncate(time.Second)
	res := &WhoAmIResult{
		Subject:   fmt.Sprintf("%s:%s", p.Type, p.ID),
		CheckedAt: now,
	}

	// 1) Per-principal identity columns (only meaningful for "user").
	switch p.Type {
	case "user":
		res.UserID = domain.UserID(p.ID)
		if err := u.fillUserIdentity(ctx, res); err != nil {
			return nil, err
		}
	case "service_account":
		// SA-display-name lookup is out of scope of WhoAmI for now —
		// the principal display name (forwarded by the api-gateway)
		// is good enough; UI distinguishes SA by the `subject` prefix.
		res.DisplayName = p.DisplayName
	default:
		// system / bootstrap was filtered above; any other type
		// (group / future) is conservatively treated as identity-only.
		res.DisplayName = p.DisplayName
	}

	// 2) Cluster-wide permission flags via two FGA Checks.
	if u.relations != nil {
		object := "cluster:" + domain.ClusterSingletonID
		// Errors here MUST NOT fail the whole WhoAmI — fall back to
		// false (least privilege) so the UI bootstrap still renders.
		// A logging side-effect could be added; deferred to ops-time.
		if allowed, err := u.relations.CheckWithContext(ctx, res.Subject, "system_admin", object, nil); err == nil {
			res.SystemAdmin = allowed
		}
		if allowed, err := u.relations.CheckWithContext(ctx, res.Subject, "viewer", object, nil); err == nil {
			res.ClusterViewer = allowed
		}
	}

	// 3) Per-account membership snapshot (user principals only — SA can be
	// added once SA-account membership is modelled; until then SAs see
	// an empty list and rely on per-RPC authz).
	if p.Type == "user" {
		accts, err := u.collectAccounts(ctx, domain.UserID(p.ID))
		if err != nil {
			return nil, err
		}
		res.Accounts = accts
	}
	return res, nil
}

// fillUserIdentity reads the user's email + display_name. The user row may
// be missing during a brief window after first-login (PENDING → ACTIVE
// race); WhoAmI must still return the principal identity from the auth
// context, with empty email/display_name. ErrNotFound is therefore
// tolerated, never propagated as Internal.
func (u *WhoAmIUseCase) fillUserIdentity(ctx context.Context, res *WhoAmIResult) error {
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	user, err := rd.Users().Get(ctx, res.UserID)
	if err != nil {
		// Best-effort: a missing row is acceptable (auth-context
		// still identifies the principal); transport errors propagate.
		if mapped := shared.MapRepoErr(err); status.Code(mapped) == codes.NotFound {
			return nil
		}
		return shared.MapRepoErr(err)
	}
	res.Email = string(user.Email)
	res.DisplayName = string(user.DisplayName)
	return nil
}

// collectAccounts enumerates account-memberships for the user and labels
// each with coarse role tags. Always returns a non-nil slice (possibly
// length-0).
func (u *WhoAmIUseCase) collectAccounts(ctx context.Context, userID domain.UserID) ([]WhoAmIAccountMembership, error) {
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	accountIDs, err := rd.Users().ListAccountsForUser(ctx, userID)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	if len(accountIDs) == 0 {
		return []WhoAmIAccountMembership{}, nil
	}

	// Read the subject's bindings ONCE; bucket by account id. Cheaper
	// than per-account ListByScope calls when the user has many
	// accounts (e.g. multi-tenant admin).
	bindings, _, err := rd.AccessBindings().ListBySubject(
		ctx,
		domain.SubjectType("user"),
		domain.SubjectID(userID),
		repoab.PageFilter{PageSize: 1000},
	)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	rolesByAccount := make(map[domain.AccountID]map[string]struct{}, len(accountIDs))
	for _, b := range bindings {
		if b.Status != domain.AccessBindingStatusActive {
			continue
		}
		if string(b.ResourceType) != "account" {
			continue
		}
		bucket, ok := rolesByAccount[domain.AccountID(b.ResourceID)]
		if !ok {
			bucket = make(map[string]struct{})
			rolesByAccount[domain.AccountID(b.ResourceID)] = bucket
		}
		bucket[classifyRoleID(b.RoleID)] = struct{}{}
	}

	out := make([]WhoAmIAccountMembership, 0, len(accountIDs))
	for _, aid := range accountIDs {
		acc, err := rd.Accounts().Get(ctx, aid)
		if err != nil {
			// Skip accounts that disappeared mid-query; dangling-ref
			// graceful per the cross-service ref convention, applied
			// here within-service for missing rows that may be an
			// in-flight DELETE.
			if status.Code(shared.MapRepoErr(err)) == codes.NotFound {
				continue
			}
			return nil, shared.MapRepoErr(err)
		}
		mem := WhoAmIAccountMembership{
			AccountID:   acc.ID,
			AccountName: string(acc.Name),
		}
		// owner-implicit: caller is accounts.owner_user_id → tag "owner"
		// even when there is no explicit AccessBinding row.
		if string(acc.OwnerUserID) == string(userID) {
			if rolesByAccount[aid] == nil {
				rolesByAccount[aid] = make(map[string]struct{})
			}
			rolesByAccount[aid]["owner"] = struct{}{}
		}
		if bucket := rolesByAccount[aid]; len(bucket) > 0 {
			tags := make([]string, 0, len(bucket))
			for t := range bucket {
				tags = append(tags, t)
			}
			sort.Strings(tags)
			mem.Roles = tags
		}
		out = append(out, mem)
	}
	// Stable order so UI lists don't shuffle between calls.
	sort.Slice(out, func(i, j int) bool {
		return string(out[i].AccountID) < string(out[j].AccountID)
	})
	return out, nil
}

// classifyRoleID maps a role id to a coarse role tag (admin / editor /
// viewer). Mirrors UserService.Invite::resolveRoleRelation: looks at the
// trailing segment of the role id, falls back to `viewer` (least
// privilege) for anything unrecognised. Avoids a per-binding Roles().Get
// round-trip — the role id is the source of truth for the UI tag.
func classifyRoleID(roleID domain.RoleID) string {
	v := strings.ToLower(string(roleID))
	if i := strings.LastIndexByte(v, '.'); i >= 0 {
		v = v[i+1:]
	}
	switch v {
	case "admin":
		return "admin"
	case "edit", "editor":
		return "editor"
	case "view", "viewer":
		return "viewer"
	case "owner":
		return "owner"
	}
	return "viewer"
}
