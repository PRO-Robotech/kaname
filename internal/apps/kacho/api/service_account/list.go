// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service_account

// list.go — ListServiceAccountsUseCase. Единая модель видимости (паритет с
// account/project/role List): результат фильтруется через UNION FGA-отношений
//
//	visible(iam_service_account) = ListObjects(subj,"viewer","iam_service_account")
//	                             ∪ ListObjects(subj,"v_list","iam_service_account")
//
//   - ветка `viewer` — SA, на которые принципал держит viewer-tier (account-admin
//     резолвит viewer на каждый SA своего аккаунта через account-tier cascade;
//     viewer подразумевает доступ к содержимому);
//   - ветка `v_list` — SA, выданные ТОЛЬКО `iam.serviceAccount.{get,list}` через
//     names/labels-селектор (object-only `iam_service_account:<id> # v_list @ subj`,
//     БЕЗ viewer-каскада — see-in-selector-without-content).
//
// Устраняет прежнюю membership-over-show модель (любой член аккаунта видел ВСЕ SA
// аккаунта без per-object грантов). Инварианты сохранены:
//   - anonymous → empty ДО любого FGA-вызова (fail-closed, не Unavailable);
//   - system bootstrap → unfiltered (admin tooling, internal-only listener);
//   - FGA-ошибка на любой relation → Unavailable (никогда partial/owner-only);
//   - cluster-admin/operator покрыты той же веткой `viewer` (system_viewer floor).

import (
	"context"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	reposa "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
)

type ListServiceAccountsUseCase struct {
	repo Repo
	// relationQueries — FGA ListObjects-порт, резолвящий visible-set принципала на
	// iam_service_account. При nil use-case fail-closed (никогда unfiltered).
	relationQueries clients.RelationQueries
}

func NewListServiceAccountsUseCase(r Repo) *ListServiceAccountsUseCase {
	return &ListServiceAccountsUseCase{repo: r}
}

// WithRelationStore wires the FGA ListObjects client (паритет с account/role List).
func (u *ListServiceAccountsUseCase) WithRelationStore(relations clients.RelationQueries) *ListServiceAccountsUseCase {
	u.relationQueries = relations
	return u
}

func (u *ListServiceAccountsUseCase) Execute(ctx context.Context, f reposa.ListFilter) ([]domain.ServiceAccount, string, error) {
	// Anonymous → empty (default-deny) ДО любого FGA-вызова.
	if authzguard.IsAnonymous(ctx) {
		return nil, "", nil
	}
	principal := operations.PrincipalFromContext(ctx)

	// System bootstrap → unfiltered (admin tooling, internal-only).
	if principal.Type == domain.PrincipalTypeSystem && principal.ID == domain.PrincipalIDBootstrap {
		return u.list(ctx, f)
	}

	out, next, err := u.list(ctx, f)
	if err != nil {
		return nil, "", err
	}
	visible, err := u.visibleServiceAccountIDs(ctx, principal)
	if err != nil {
		return nil, "", err
	}
	filtered := out[:0]
	for _, sa := range out {
		if visible[string(sa.ID)] {
			filtered = append(filtered, sa)
		}
	}
	return filtered, next, nil
}

// visibleServiceAccountIDs — UNION FGA viewer ∪ v_list на iam_service_account.
// Fail-closed: nil-порт или FGA-ошибка на любой relation → Unavailable.
func (u *ListServiceAccountsUseCase) visibleServiceAccountIDs(ctx context.Context, principal operations.Principal) (map[string]bool, error) {
	if u.relationQueries == nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	subject := principalSubject(principal)
	if subject == "" {
		return map[string]bool{}, nil
	}
	visible := map[string]bool{}
	for _, relation := range []string{"viewer", "v_list"} {
		ids, err := u.relationQueries.ListObjects(ctx, subject, relation, "iam_service_account", nil, 0)
		if err != nil {
			return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
		}
		for _, id := range ids {
			visible[id] = true
		}
	}
	return visible, nil
}

func (u *ListServiceAccountsUseCase) list(ctx context.Context, f reposa.ListFilter) ([]domain.ServiceAccount, string, error) {
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	out, next, err := rd.ServiceAccounts().List(ctx, f)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	return out, next, nil
}

// principalSubject builds the FGA subject string: `user:<id>` / `service_account:<id>`.
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
