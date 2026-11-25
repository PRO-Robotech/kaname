// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user_tokens

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations описывает эффекты личных удостоверений по исполняемым
// путям. Право распоряжаться удостоверениями и проверка состояния владельца
// не являются отдельной обязательной проверкой права выдавать доступ.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{
			// IssueUserTokenUseCase через commitMapping сохраняет открытый
			// ключ либо хэш секрета и возвращает материал предъявителю.
			// Это новый способ действовать от имени человека, не изменение
			// его назначенных ярусов; ключевую пару обменивает токен-эндпоинт.
			FullMethod:    iamv1.UserTokenService_Issue_FullMethodName,
			Effect:        grantpolicy.ChangesHolders,
			RequiresCheck: false,
		},
		{
			// ListUserTokensUseCase.Execute вызывает только repo.List;
			// преобразование записей в ответ нового удостоверения не выдаёт.
			FullMethod: iamv1.UserTokenService_List_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// RevokeUserTokenUseCase.doRevoke удаляет принадлежащее человеку
			// удостоверение через DeleteOwnedByID. Этот носитель перестаёт
			// допускать предъявителя, но назначения и ярусы не меняются.
			FullMethod:          iamv1.UserTokenService_Revoke_FullMethodName,
			Effect:              grantpolicy.ChangesHolders,
			Direction:           grantpolicy.WithdrawsAccess,
			WithdrawalAuthority: grantpolicy.TargetUserCredentialWithdrawal,
		},
	}
}
