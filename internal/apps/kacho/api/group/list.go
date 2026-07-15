// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package group

// list.go — ListGroupsUseCase. Единая модель видимости (паритет с
// account/project/service_account/role List): результат фильтруется через UNION
// FGA-отношений
//
//	visible(iam_group) = ListObjects(subj,"viewer","iam_group")
//	                   ∪ ListObjects(subj,"v_list","iam_group")
//
//   - ветка viewer — группы, на которые принципал держит viewer-tier (account-admin
//     резолвит viewer на каждую группу своего аккаунта через account-tier cascade);
//   - ветка v_list — группы, выданные ТОЛЬКО `iam.group.{get,list}` через
//     names/labels-селектор (object-only `iam_group:<id> # v_list @ subj`, БЕЗ
//     viewer-каскада — see-in-selector-without-content).
//
// Устраняет прежний over-show (любой держатель `account:<id>#v_list` видел ВСЕ
// группы аккаунта без per-object грантов; account-tier НЕ каскадит в iam_group
// viewer/v_list — DIRECT-only). Инварианты сохранены:
//   - anonymous → empty ДО любого FGA-вызова (fail-closed, не Unavailable);
//     не-forwarded principal (включая system/bootstrap fallback) — тоже anonymous;
//   - FGA-ошибка на любой relation → Unavailable (никогда partial/owner-only).

import (
	"context"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	repogroup "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
)

type ListGroupsUseCase struct {
	repo Repo
	// relationQueries — FGA ListObjects-порт, резолвящий visible-set принципала на
	// iam_group. При nil use-case fail-closed (никогда unfiltered).
	relationQueries clients.RelationQueries
}

func NewListGroupsUseCase(r Repo) *ListGroupsUseCase {
	return &ListGroupsUseCase{repo: r}
}

// WithRelationStore wires the FGA ListObjects client (паритет с
// account/project/service_account/role List).
func (u *ListGroupsUseCase) WithRelationStore(relations clients.RelationQueries) *ListGroupsUseCase {
	u.relationQueries = relations
	return u
}

func (u *ListGroupsUseCase) Execute(ctx context.Context, f repogroup.ListFilter) ([]domain.Group, string, error) {
	// Anonymous → empty (default-deny) ДО любого FGA-вызова. authzguard.IsAnonymous
	// относит сюда и не-forwarded principal (api-gateway не передал заголовки →
	// system/bootstrap fallback) — fail-closed, без unfiltered-обхода.
	if authzguard.IsAnonymous(ctx) {
		return nil, "", nil
	}
	principal := operations.PrincipalFromContext(ctx)

	out, next, err := u.list(ctx, f)
	if err != nil {
		return nil, "", err
	}
	visible, err := u.visibleGroupIDs(ctx, principal)
	if err != nil {
		return nil, "", err
	}
	filtered := out[:0]
	for _, g := range out {
		if visible[string(g.ID)] {
			filtered = append(filtered, g)
		}
	}
	return filtered, next, nil
}

// visibleGroupIDs — UNION FGA viewer ∪ v_list на iam_group. Fail-closed: nil-порт
// или FGA-ошибка на любой relation → Unavailable.
func (u *ListGroupsUseCase) visibleGroupIDs(ctx context.Context, principal operations.Principal) (map[string]bool, error) {
	if u.relationQueries == nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	subject := principalSubject(principal)
	if subject == "" {
		return map[string]bool{}, nil
	}
	visible := map[string]bool{}
	for _, relation := range []string{"viewer", "v_list"} {
		ids, err := u.relationQueries.ListObjects(ctx, subject, relation, "iam_group", nil, 0)
		if err != nil {
			return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
		}
		for _, id := range ids {
			visible[id] = true
		}
	}
	return visible, nil
}

func (u *ListGroupsUseCase) list(ctx context.Context, f repogroup.ListFilter) ([]domain.Group, string, error) {
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	out, next, err := rd.Groups().List(ctx, f)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	return out, next, nil
}

// principalSubject builds the FGA subject string: `user:<id>` / `service_account:<id>`.
// Любой другой тип → "" (нерезолвимый subject → deny).
func principalSubject(p operations.Principal) string {
	switch p.Type {
	case "user":
		return "user:" + p.ID
	case "service_account":
		return "service_account:" + p.ID
	default:
		return ""
	}
}
