// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package interactiveclient

import (
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Обработчики всех трёх мутаций вызывают этот гейт перед сценарием записи.
var requireMutationAuthority = authzguard.RequireClusterAdmin

// GrantDeclarations описывает чтение и изменение допуска OAuth-клиента.
// Создание, доставка и отзыв удостоверений меняют возможных держателей
// действующего доступа, но не назначенные роли и ярусы их прав.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{
			// GetUseCase.Execute вызывает только clientRepo.Get;
			// InteractiveClientRepo.Get читает строку клиента.
			FullMethod: iamv1.InternalInteractiveClientService_Get_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListUseCase.Execute проверяет пагинацию и фильтр, затем
			// читает страницу через clientRepo.List без изменения допуска.
			FullMethod: iamv1.InternalInteractiveClientService_List_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// CreateUseCase.Execute получает секрет и проверочное значение
			// у OwnInteractiveClientProvider.Register и вставляет ACTIVE-клиента.
			// CeremonyVaults.LookupClient допускает эту регистрацию к выдаче
			// удостоверений. Полномочие system_admin на кластере покрывает
			// все регистрации клиентов этой службы.
			FullMethod:    iamv1.InternalInteractiveClientService_Create_FullMethodName,
			Effect:        grantpolicy.ChangesHolders,
			Direction:     grantpolicy.ExpandsOrMixesAccess,
			RequiresCheck: requireMutationAuthority != nil,
		},
		{
			// UpdateUseCase.Execute может менять redirect_uris:
			// CeremonyVaults.LookupClient читает их, а AuthorizeUseCase.Trust
			// проверяет допустимый адрес доставки кода. Это меняет получателя
			// удостоверения; audiences, grant_types и способ неизменяемы.
			// Обработчик требует system_admin на кластере.
			FullMethod:    iamv1.InternalInteractiveClientService_Update_FullMethodName,
			Effect:        grantpolicy.ChangesHolders,
			Direction:     grantpolicy.ExpandsOrMixesAccess,
			RequiresCheck: requireMutationAuthority != nil,
		},
		{
			// DeleteUseCase.Execute удаляет строку через clientRepo.Delete:
			// token_families_client_fk каскадно снимает семейства, их коды
			// и refresh-токены. Deregister также снимает проверочное значение
			// секрета. Обработчик требует system_admin на кластере.
			FullMethod:    iamv1.InternalInteractiveClientService_Delete_FullMethodName,
			Effect:        grantpolicy.ChangesHolders,
			Direction:     grantpolicy.WithdrawsAccess,
			RequiresCheck: requireMutationAuthority != nil,
		},
	}
}
