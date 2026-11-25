// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service_account

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations описывает чтение и эффекты жизненного цикла учётки.
// Проверка права вызвать метод в prepared writer не заменяет проверку права
// выдавать доступ; в legacy-путях отдельной обязательной проверки также нет.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{
			// GetServiceAccountUseCase.Execute (get.go) читает
			// Reader.ServiceAccounts().Get и проверяет AllowsVGet.
			FullMethod: iamv1.ServiceAccountService_Get_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListServiceAccountsUseCase.Execute (list.go) читает область
			// видимости и Reader.ServiceAccounts().List; VisibleSet сужает ответ.
			FullMethod: iamv1.ServiceAccountService_List_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// Handler.ListOperations (handler.go) вызывает
			// shared.ListOperationsUseCase.Execute (operations.ListForCaller).
			FullMethod: iamv1.ServiceAccountService_ListOperations_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// doCreate (create.go) записывает создателя и событие реконсайла:
			// совпавшие привязки материализуют держателей и ярусы доступа
			// к новой учётке. Структурная связь account сама права не выдаёт.
			FullMethod:    iamv1.ServiceAccountService_Create_FullMethodName,
			Effect:        grantpolicy.ChangesHoldersAndTier,
			RequiresCheck: false,
		},
		{
			// doUpdate (update.go) при изменении меток запускает реконсайл:
			// селектор может добавить или снять держателей и их ярусы.
			// Не меняющие доступ имя и описание не покрывают весь RPC.
			FullMethod:    iamv1.ServiceAccountService_Update_FullMethodName,
			Effect:        grantpolicy.ChangesHoldersAndTier,
			RequiresCheck: false,
		},
		{
			// doDelete (delete.go) удаляет объект и со-коммитит событие
			// удаления: реконсайл снимает его материализованный доступ.
			// SAC-12: prepared writer повторяет v_delete именно на удаляемой
			// учётке. Ссылки, которые защищают её от удаления, сохраняются.
			FullMethod:          iamv1.ServiceAccountService_Delete_FullMethodName,
			Effect:              grantpolicy.ChangesHoldersAndTier,
			Direction:           grantpolicy.WithdrawsAccess,
			WithdrawalAuthority: grantpolicy.TargetServiceAccountDeletionWithdrawal,
		},
		{
			// SetEnabled(false) закрывает аутентификацию и действительность
			// installation-источника fga_writer: его проверка в
			// pg/resource_installation_sources.go требует sa.enabled.
			// Назначенный ярус не меняется; держатель перестаёт действовать.
			// SAC-12/16 сохраняют отключение по v_update на учётке запроса.
			// prepared writer повторяет эту проверку перед записью состояния.
			FullMethod:          iamv1.ServiceAccountService_Disable_FullMethodName,
			Effect:              grantpolicy.ChangesHolders,
			Direction:           grantpolicy.WithdrawsAccess,
			RequiresCheck:       false,
			WithdrawalAuthority: grantpolicy.TargetServiceAccountDisableWithdrawal,
		},
		{
			// SetEnabled(true) вновь допускает аутентификацию и может
			// восстановить держателя installation-источника fga_writer
			// при сохранённых привязке и назначении; ярус не переписывается.
			FullMethod:    iamv1.ServiceAccountService_Enable_FullMethodName,
			Effect:        grantpolicy.ChangesHolders,
			Direction:     grantpolicy.ExpandsOrMixesAccess,
			RequiresCheck: false,
		},
	}
}
