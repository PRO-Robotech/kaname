// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grant_delegation

// authority.go — право выдавать на аккаунте для глаголов службы делегирований
// (Р1 приёмки делегированных выдач, PRO-Robotech/kaname#986).

import (
	"context"
	stderrors "errors"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// accountGrantObjectType — тип области права выдавать в модели: аккаунт.
const accountGrantObjectType = "account"

// requireAccountGrantAuthority — право выдавать на аккаунте ТРЕМЯ путями §0.1
// приёмки, теми же, что у выдачи на области аккаунта: администратор облака
// (Путь 0), владелец аккаунта (Путь 1), отношение `admin` на объекте аккаунта
// (Путь 2). Делегированного пути здесь нет по построению: делегат делегирований
// не заводит, перечнем не читает и не отзывает (GD-21, GD-44 c, GD-61 d).
//
// Три исхода у каждого вопроса к модели: «да», «нет» и «спросить не удалось» —
// последнее `UNAVAILABLE` `authz backend unavailable`, а не отказ. Несуществующий
// аккаунт — отказ в праве, побайтово как у вызывающего без права (скрытие
// существования).
func requireAccountGrantAuthority(ctx context.Context, repo Repo, relations clients.RelationStore, accountID domain.AccountID) error {
	return requireAccountGrantAuthorityWithOwner(ctx, relations, accountID, func(ctx context.Context) (domain.UserID, error) {
		return accountOwner(ctx, repo, accountID)
	})
}

// requireAccountGrantAuthorityWithOwner сохраняет те же три пути для обычного
// чтения и Writer. Владелец читается лениво: администратор облака, как прежде,
// не занимает соединение для этого вопроса.
func requireAccountGrantAuthorityWithOwner(ctx context.Context, checker authzguard.RelationChecker, accountID domain.AccountID, ownerOf func(context.Context) (domain.UserID, error)) error {
	admin, err := authzguard.IsClusterAdminE(ctx, checker)
	if err != nil {
		return authzguard.AuthzBackendUnavailable()
	}
	if admin {
		return nil
	}
	owner, err := ownerOf(ctx)
	if err != nil {
		return err
	}
	return authzguard.RequireScopeRelation(ctx, checker, accountGrantObjectType, string(accountID), string(owner), "admin")
}

// accountOwner — владелец аккаунта; нет аккаунта — отказ в праве.
func accountOwner(ctx context.Context, repo Repo, accountID domain.AccountID) (domain.UserID, error) {
	rd, err := repo.Reader(ctx)
	if err != nil {
		return "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	return accountOwnerFromReader(ctx, rd, accountID)
}

// accountOwnerFromReader не открывает и не завершает транзакцию вызывающего.
func accountOwnerFromReader(ctx context.Context, rd Reader, accountID domain.AccountID) (domain.UserID, error) {
	acct, err := rd.Accounts().Get(ctx, accountID)
	if err != nil {
		if stderrors.Is(err, iamerr.ErrNotFound) {
			return "", authzguard.PermissionDenied()
		}
		return "", shared.MapRepoErr(err)
	}
	return acct.OwnerUserID, nil
}
