// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// get.go — GetAccessBindingUseCase. Sync read.

import (
	"context"
	"log/slog"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

type GetAccessBindingUseCase struct {
	repo      Repo
	relations clients.RelationStore
	// queries — FGA ListObjects-порт для D-6 label-grant Get-видимости (v_get/v_list
	// на iam_access_binding). nil → только self/granted-floor (back-compat).
	queries clients.RelationQueries
	logger  *slog.Logger
}

func NewGetAccessBindingUseCase(r Repo) *GetAccessBindingUseCase {
	return &GetAccessBindingUseCase{repo: r}
}

// WithRelationStore wires the FGA client so the resource-scope grant-authority check
// (requireGrantAuthority) can resolve delegated admins — notably cluster-scope
// bindings, whose authority is `system_admin@cluster` in FGA (no DB owner).
func (u *GetAccessBindingUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *GetAccessBindingUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

// WithRelationQueries wires the FGA ListObjects port so a label-selector grant
// (viewer ∪ v_list on iam_access_binding) lets its grantee Get the labeled binding —
// the D-6 additive path, consistent with the gateway already Checking v_get on AB.Get.
// nil → self/granted-floor only.
func (u *GetAccessBindingUseCase) WithRelationQueries(q clients.RelationQueries) *GetAccessBindingUseCase {
	u.queries = q
	return u
}

func (u *GetAccessBindingUseCase) Execute(ctx context.Context, id domain.AccessBindingID) (domain.AccessBinding, error) {
	if err := shared.ValidateResourceID(string(id), domain.PrefixAccessBinding, "access binding"); err != nil {
		return domain.AccessBinding{}, err
	}
	// Anti-anonymous guard (catalog entry is <exempt>).
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return domain.AccessBinding{}, err
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return domain.AccessBinding{}, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.AccessBindings().Get(ctx, id)
	if err != nil {
		// When an AB does not exist we return PermissionDenied, not
		// NotFound. This prevents existence-leakage (garbage-id probe cannot
		// distinguish "doesn't exist" from "exists but you lack access").
		// The authz-deny test `garbage-perresource` relies on 403 for all
		// subjects including authenticated non-owners.
		return domain.AccessBinding{}, authzguard.PermissionDenied()
	}
	// RBAC rules-model 2026: AccessBinding no longer carries
	// a resource-scoped target dimension (the "what object" decision lives on
	// role.rules now), so there is no per-binding target/selector to project here.
	// Load the multi-subject set on the
	// SAME reader-tx (before the scope-filter may release it) so the response fills
	// BOTH subjects[] (full set) AND the legacy single (= subjects[0]). Zero child
	// rows ⇒ a legacy binding; the projection falls back to the one-element legacy
	// single (toPb domainSubjectsToProto).
	subs, serr := rd.AccessBindings().ListSubjects(ctx, id)
	if serr != nil {
		return domain.AccessBinding{}, shared.MapRepoErr(serr)
	}
	got.Subjects = subs
	// Scope-filter: AB visible только если principal является:
	//   - subject (granted to self), OR
	//   - holder of grant-authority on the binding's scope (resource owner OR
	//     delegated FGA admin). requireGrantAuthority uniformly covers
	//     account / project (DB owner + FGA admin) AND cluster (FGA
	//     `system_admin@cluster` — no DB owner). Bug B follow-on: the previous
	//     ad-hoc account/project-only owner switch denied cluster-scope
	//     bindings to the bootstrap cluster-admin (newman get-cluster-binding).
	if authzguard.IsSelf(ctx, string(got.SubjectID)) {
		return got, nil
	}
	// Release the read-TX before the authority check — requireGrantAuthority
	// opens its own Reader; holding two concurrently on the same fake/real
	// pool is unnecessary.
	_ = rd.Rollback(ctx)
	if err := requireGrantAuthority(ctx, u.repo, u.relations, string(got.ResourceType), got.ResourceID); err == nil {
		return got, nil
	}
	// D-6 additive path: a label-selector grant materializes viewer/v_list on the
	// binding-object itself (iam_access_binding:<id>). Its grantee may Get the labeled
	// binding even without scope grant-authority — consistent with the gateway's v_get
	// Check on AB.Get. Fail-closed: FGA error → UNAVAILABLE. Resolver unwired → deny.
	visible, ok, verr := vlistVisibleBindingIDs(ctx, u.queries)
	if verr != nil {
		return domain.AccessBinding{}, verr
	}
	if ok && visible[string(got.ID)] {
		return got, nil
	}
	return domain.AccessBinding{}, authzguard.PermissionDenied()
}
