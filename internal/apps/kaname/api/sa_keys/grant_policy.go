// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package sa_keys

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations описывает доступ через удостоверения служебной учётки.
// Проверки состояния учётки, уровня вызывающего и владения ключом не заменяют
// отдельную обязательную проверку права выдавать изменяемый доступ.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{
			// IssueSAKeyUseCase сохраняет хэш секрета, открытый ключ либо
			// доверенных издателей через commitMapping. Соответствующий
			// предъявитель может действовать от имени учётки; её назначения
			// и ярусы этот путь не меняет. Сам токен выдаёт другой endpoint.
			FullMethod:    iamv1.SAKeyService_Issue_FullMethodName,
			Effect:        grantpolicy.ChangesHolders,
			RequiresCheck: false,
		},
		{
			// ListSAKeysUseCase.Execute вызывает только repo.List;
			// преобразование ответа не выпускает новый ключ или секрет.
			FullMethod: iamv1.SAKeyService_List_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// RevokeSAKeyUseCase.doRevoke удаляет принадлежащую учётке
			// запись ключа через DeleteOwnedByID: этот способ предъявления
			// больше не допускается. Назначенный учётке ярус сохраняется.
			FullMethod:          iamv1.SAKeyService_Revoke_FullMethodName,
			Effect:              grantpolicy.ChangesHolders,
			Direction:           grantpolicy.WithdrawsAccess,
			WithdrawalAuthority: grantpolicy.TargetServiceAccountKeyWithdrawal,
		},
	}
}
