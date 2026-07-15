// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

// list.go — ListUsersUseCase. Единая модель видимости (паритет с
// account/serviceAccount/role List): результат фильтруется через UNION
// FGA-отношений
//
//	visible(iam_user) = ListObjects(subj,"viewer","iam_user")
//	                  ∪ ListObjects(subj,"v_list","iam_user")
//
//   - ветка `viewer` — user'ы, на которые принципал держит viewer-tier
//     (account-admin/owner резолвит viewer на каждого user'а своего аккаунта через
//     account-tier cascade; self-tuple iam_user:<U>#subject@user:<U> резолвится в
//     viewer-ветку — self-floor);
//   - ветка `v_list` — user'ы, выданные ТОЛЬКО `iam.user.{get,list}` через
//     names/labels-селектор (object-only `iam_user:<id> # v_list @ subj`, БЕЗ
//     viewer-каскада — see-in-selector-without-content).
//
// Устраняет прежнюю membership-over-show модель (любой член аккаунта видел ВСЕХ
// user'ов аккаунта без per-object грантов, T3.3 D-5). Инварианты сохранены:
//   - anonymous → empty ДО любого FGA-вызова (fail-closed, не Unavailable);
//   - system bootstrap → unfiltered (admin tooling, internal-only listener);
//   - FGA-ошибка на любой relation → Unavailable (никогда partial/owner-only);
//   - cluster-admin/operator/owner покрыты той же веткой `viewer` (tier-cascade).

import (
	"context"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
)

type ListUsersUseCase struct {
	repo Repo
	// relationQueries — FGA ListObjects-порт, резолвящий visible-set принципала на
	// iam_user. При nil use-case fail-closed (никогда unfiltered).
	relationQueries clients.RelationQueries
}

func NewListUsersUseCase(r Repo) *ListUsersUseCase {
	return &ListUsersUseCase{repo: r}
}

// WithRelationStore wires the FGA ListObjects client (паритет с account/SA/role List).
func (uc *ListUsersUseCase) WithRelationStore(relations clients.RelationQueries) *ListUsersUseCase {
	uc.relationQueries = relations
	return uc
}

func (uc *ListUsersUseCase) Execute(ctx context.Context, f user.ListFilter) ([]domain.User, string, error) {
	// Anonymous → empty (default-deny) ДО любого FGA-вызова.
	if authzguard.IsAnonymous(ctx) {
		return nil, "", nil
	}
	principal := operations.PrincipalFromContext(ctx)

	// System bootstrap → unfiltered (admin tooling, internal-only).
	if principal.Type == domain.PrincipalTypeSystem && principal.ID == domain.PrincipalIDBootstrap {
		return uc.list(ctx, f)
	}

	out, next, err := uc.list(ctx, f)
	if err != nil {
		return nil, "", err
	}
	visible, err := uc.visibleUserIDs(ctx, principal)
	if err != nil {
		return nil, "", err
	}
	// Self-floor: юзер всегда видит собственную запись, независимо от
	// FGA-материализации (паритет с GetUser.IsSelf). Защищает от отсутствующего/
	// протухшего subject self-tuple, из-за которого юзер без self-grant не видел бы
	// даже себя в списке пользователей своего аккаунта.
	if principal.Type == domain.PrincipalTypeUser && principal.ID != "" {
		visible[principal.ID] = true
	}
	filtered := out[:0]
	for _, u := range out {
		if visible[string(u.ID)] {
			filtered = append(filtered, u)
		}
	}
	return filtered, next, nil
}

// visibleUserIDs — UNION FGA viewer ∪ v_list на iam_user. Fail-closed: nil-порт
// или FGA-ошибка на любой relation → Unavailable.
func (uc *ListUsersUseCase) visibleUserIDs(ctx context.Context, principal operations.Principal) (map[string]bool, error) {
	if uc.relationQueries == nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	subject := userPrincipalSubject(principal)
	if subject == "" {
		return map[string]bool{}, nil
	}
	visible := map[string]bool{}
	for _, relation := range []string{"viewer", "v_list"} {
		ids, err := uc.relationQueries.ListObjects(ctx, subject, relation, "iam_user", nil, 0)
		if err != nil {
			return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
		}
		for _, id := range ids {
			visible[id] = true
		}
	}
	return visible, nil
}

func (uc *ListUsersUseCase) list(ctx context.Context, f user.ListFilter) ([]domain.User, string, error) {
	rd, err := uc.repo.Reader(ctx)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	out, next, err := rd.Users().List(ctx, f)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	return out, next, nil
}

// userPrincipalSubject builds the FGA subject string: `user:<id>` / `service_account:<id>`.
func userPrincipalSubject(p operations.Principal) string {
	switch p.Type {
	case "user":
		return "user:" + p.ID
	case "service_account":
		return "service_account:" + p.ID
	default:
		return ""
	}
}
