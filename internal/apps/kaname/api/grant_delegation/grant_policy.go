// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grant_delegation

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// delegationGrantPolicy связывает декларации с обязательными проверками
// права выдавать на аккаунте. Update проверяет также сохранённого автора;
// установка дополнительно требует полномочий администратора облака.
var delegationGrantPolicy = struct {
	account      func(context.Context, Repo, clients.RelationStore, domain.AccountID) error
	transaction  func(context.Context, authzguard.RelationChecker, domain.AccountID, func(context.Context) (domain.UserID, error)) error
	update       func(context.Context, domain.GrantDelegation, func(context.Context) error) error
	installation func(installationTransaction, context.Context, *authzmodel.Plans) error
}{
	account:      requireAccountGrantAuthority,
	transaction:  requireAccountGrantAuthorityWithOwner,
	update:       requireUpdateAuthority,
	installation: installationTransaction.RequireInstallationAuthority,
}

// GrantDeclarations описывает публичные RPC по исполняемым путям.
// Legacy Create проверяет право до запуска операции, configured Create —
// дополнительно в транзакции записи. Это существующее различие во времени
// проверки; декларация не обещает транзакционный повтор в legacy-режиме.
// Отзыв доверенности также проверяет право выдавать на аккаунте до операции.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{
			// Create добавляет держателя права выдавать с заданными осями;
			// ExecuteInstallation проходит тот же account и затем installation.
			FullMethod: iamv1.GrantDelegationService_Create_FullMethodName,
			Effect:     grantpolicy.ChangesHoldersAndTier,
			RequiresCheck: delegationGrantPolicy.account != nil &&
				delegationGrantPolicy.transaction != nil && delegationGrantPolicy.installation != nil,
		},
		{
			// Update сохраняет делегата и расширяет только оси разрешённой
			// выдачи. Право вызывающего и автора проверяется до операции
			// и под замком текущей строки в обоих режимах writer.
			FullMethod: iamv1.GrantDelegationService_Update_FullMethodName,
			Effect:     grantpolicy.ChangesTier,
			RequiresCheck: delegationGrantPolicy.account != nil &&
				delegationGrantPolicy.transaction != nil && delegationGrantPolicy.update != nil,
		},
		{
			// Execute (get.go) вызывает loadDelegation через Reader, затем
			// проверяет делегата или право выдавать; ToProto меняет лишь ответ.
			FullMethod: iamv1.GrantDelegationService_Get_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// Execute (list.go) проверяет право выдавать и читает страницу
			// Reader.AccessBindings().GrantDelegations().List без записи.
			FullMethod: iamv1.GrantDelegationService_List_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// Отзыв прекращает право делегата и снимает выданные им привязки.
			// Полный режим повторяет проверку полномочий при записи.
			FullMethod: iamv1.GrantDelegationService_Revoke_FullMethodName,
			Effect:     grantpolicy.ChangesHoldersAndTier,
			Direction:  grantpolicy.WithdrawsAccess,
			RequiresCheck: delegationGrantPolicy.account != nil &&
				delegationGrantPolicy.transaction != nil,
		},
	}
}
