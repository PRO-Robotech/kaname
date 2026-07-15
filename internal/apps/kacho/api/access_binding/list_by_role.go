// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// list_by_role.go — ListByRoleUseCase for the RBAC rules-model 2026.
//
// Audit read "who holds role R": returns the AccessBindings carrying a given
// role, each filled with the dual subjects[]/legacy projection. Sync read
// (not an Operation).
//
// Authorisation: authenticated floor + per-row scope-filter — a binding row is
// returned only if the caller holds grant-authority on that binding's scope
// (owner of the owning Account/Project OR FGA admin on the scope object), the
// same predicate as Create/Delete/ListByScope. A caller therefore sees only
// the bindings-of-the-role they would be allowed to read individually; no
// existence-leak of bindings on scopes they cannot administer.

import (
	"context"
	"log/slog"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

type ListByRoleUseCase struct {
	repo      Repo
	relations clients.RelationStore
	logger    *slog.Logger
}

func NewListByRoleUseCase(r Repo) *ListByRoleUseCase {
	return &ListByRoleUseCase{repo: r}
}

// WithRelationStore wires the FGA client for the per-row delegated-admin scope
// filter. When unset (unit tests / degraded mode) only owner-based access passes.
func (u *ListByRoleUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *ListByRoleUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

func (u *ListByRoleUseCase) Execute(ctx context.Context, roleID string, f repoab.ListByRoleFilter) ([]domain.AccessBinding, string, error) {
	if err := shared.ValidateResourceID(roleID, domain.PrefixRole, "role"); err != nil {
		return nil, "", err
	}
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, "", err
	}

	// Read + fill the dual subjects[]/legacy projection via the shared read
	// skeleton; the reader-tx is released before the per-row authority filter
	// (requireGrantAuthority opens its own reader).
	out, next, err := readBindingsWithSubjects(ctx, u.repo, func(rd Reader) ([]domain.AccessBinding, string, error) {
		return rd.AccessBindings().ListByRole(ctx, domain.RoleID(roleID), f)
	})
	if err != nil {
		return nil, "", err
	}

	// Per-row scope-filter: keep only the bindings whose scope the caller may
	// administer (grant-authority holder / admin). requireGrantAuthority opens its
	// own reader, so the list reader is released first. Self-grants (the caller is
	// the subject) are also visible.
	filtered := out[:0:0]
	for _, b := range out {
		if authzguard.IsSelf(ctx, string(b.SubjectID)) {
			filtered = append(filtered, b)
			continue
		}
		if err := requireGrantAuthority(ctx, u.repo, u.relations, string(b.ResourceType), b.ResourceID); err == nil {
			filtered = append(filtered, b)
		}
	}
	// NB: the next_page_token reflects the pre-filter page boundary (the repo
	// keyset cursor). A page may return fewer rows than page_size after the
	// scope-filter; the client paginates until next_page_token is empty (parity
	// with the per-object filtered List RPCs).
	return filtered, next, nil
}
