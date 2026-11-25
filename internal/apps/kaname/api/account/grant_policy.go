// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations описывает эффект операций аккаунта и действующие проверки.
// Проверка доступа к самому аккаунту не подтверждает право на всю выдачу,
// которая получилась бы после пересчёта селекторов.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{
			// GetAccountUseCase.Execute (get.go) читает Reader.Accounts().Get;
			// AllowsVGet только проверяет видимость.
			FullMethod: iamv1.AccountService_Get_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListAccountsUseCase.Execute (list.go) читает кандидатов через Reader
			// и отбирает видимые строки без записи прав.
			FullMethod: iamv1.AccountService_List_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// Handler.ListOperations (handler.go) вызывает
			// shared.ListOperationsUseCase.Execute (operations.ListForCaller).
			FullMethod: iamv1.AccountService_ListOperations_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListAllOperationsUseCase.Execute (list_all_operations.go) проверяет
			// право аудита и читает opsRepo.List в пределах аккаунта.
			FullMethod: iamv1.AccountService_ListAllOperations_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// Создание записывает владельца и его привязку. Право администратора
			// кластера требуется для заданного извне ID, а не для каждого создания.
			FullMethod: iamv1.AccountService_Create_FullMethodName,
			Effect:     grantpolicy.ChangesHoldersAndTier,
		},
		{
			// Метки аккаунта могут расширять или сужать применимость
			// селекторов самого объекта и вложенных правил. Проверка
			// v_update разрешает мутацию объекта, а итоговый эффект выдачи
			// требует отдельного подтверждения.
			FullMethod: iamv1.AccountService_Update_FullMethodName,
			Effect:     grantpolicy.ChangesHoldersAndTier,
			Direction:  grantpolicy.ExpandsOrMixesAccess,
		},
		{
			// Удаление отзывает привязки области через RevokeBindingsInScope.
			FullMethod:          iamv1.AccountService_Delete_FullMethodName,
			Effect:              grantpolicy.ChangesHoldersAndTier,
			Direction:           grantpolicy.WithdrawsAccess,
			WithdrawalAuthority: grantpolicy.TargetAccountDeletionWithdrawal,
		},
	}
}
