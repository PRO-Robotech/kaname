// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

// list.go — ListUsersUseCase. Единая модель видимости (паритет с
// account/serviceAccount/role List): результат фильтруется через UNION
// FGA-отношений
//
//	visible(id) = Check(subj,"viewer","iam_user:"+id)
//	            ∨ Check(subj,"v_list","iam_user:"+id)
//
// спрашиваемых для user'ов СТРАНИЦЫ (страница читается курсором из своей БД
// ПЕРВОЙ). Прежняя форма — «перечислить всё видимое и пересечь» — молча резалась
// server-side пределом OpenFGA ListObjects (см. internal/authzfilter).
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
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzfilter"
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
	// Формат пагинации — ПЕРВЫМ стейтментом, до решения о том, кто спрашивает.
	//
	// Ниже стоит замыкание по личности: анонимный (в том числе непроброшенный)
	// вызывающий получает пустую страницу и до репозитория не доходит. Пока
	// формат курсора проверял только репозиторий, один и тот же мусорный
	// page_token получал разный ответ в зависимости от того, опознан ли
	// вызывающий, — то есть проверка ввода зависела от прав. Репозиторий
	// остаётся авторитетным на служимом пути.
	if err := shared.ValidatePagination(f.PageToken, f.PageSize); err != nil {
		return nil, "", err
	}
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
	visible, err := uc.visibleUserIDs(ctx, principal, userIDsOf(out))
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

// visibleUserIDs — отношение ЧТЕНИЯ на iam_user (предикат страницы берётся у
// authzfilter.RelationsFor), спрашиваемое ПРЯМО по каждому объекту СТРАНИЦЫ:
// строка попадает в страницу ровно тогда, когда вызывающий вправе прочитать её
// одиночным Get.
//
// Здесь менялись ДВЕ независимые вещи, обе уже применены. Форма: прежний
// ListObjects («перечисли всех видимых user'ов») молча резался server-side
// пределом OpenFGA (1000 объектов типа в сторе, без continuation-token), из-за
// чего собственная запись тенанта выпадала из выдачи навсегда. Предикат: здесь
// стоял союз `viewer ∪ v_list` — снят, потому что ярусные и глагольные
// отношения развязаны намеренно и союз расходился с гейтом чтения в обе
// стороны. См. package-doc internal/authzfilter.
//
// Fail-closed: nil-порт или FGA-ошибка на любом объекте → Unavailable.
func (uc *ListUsersUseCase) visibleUserIDs(ctx context.Context, principal operations.Principal, ids []string) (map[string]bool, error) {
	if uc.relationQueries == nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	subject := userPrincipalSubject(principal)
	if subject == "" {
		return map[string]bool{}, nil
	}
	visible, err := authzfilter.VisibleSet(ctx, uc.relationQueries, subject, "iam_user", ids)
	if err != nil {
		return nil, shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	return visible, nil
}

// userIDsOf проецирует страницу user'ов в голые id.
func userIDsOf(rows []domain.User) []string {
	out := make([]string, 0, len(rows))
	for _, u := range rows {
		out = append(out, string(u.ID))
	}
	return out
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
