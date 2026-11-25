// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_revocations

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations описывает эффекты внутренних RPC отзыва сессий.
// Допуск внутреннего модуля к RPC не доказывает отдельное право выдачи.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{
			// RevokeUseCase.Execute пишет отзыв по jti и/или отсечку
			// человека через RevokeTx/RevokeAllUserTokensTx. Оба срока
			// отзыва монотонны. Допуск внутреннего вызывающего ещё
			// требуется подтвердить отдельным правилом каталога.
			FullMethod:    iamv1.InternalSessionRevocationsService_Revoke_FullMethodName,
			Effect:        grantpolicy.ChangesHolders,
			Direction:     grantpolicy.WithdrawsAccess,
			RequiresCheck: false,
		},
		{
			// Handler.IsRevoked только читает запись отзыва и состояние
			// семейства через tokenrevocation.FamilyRevoked.
			FullMethod: iamv1.InternalSessionRevocationsService_IsRevoked_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// Handler.ListByUser после проверки session_reader читает
			// страницу записей; проверка и перечисление не меняют доступ.
			FullMethod: iamv1.InternalSessionRevocationsService_ListByUser_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// Handler.SessionCutoffOf вызывает только RevokedBefore;
			// прочитанный момент сам новую отсечку не устанавливает.
			FullMethod: iamv1.InternalSessionRevocationsService_SessionCutoffOf_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
	}
}
