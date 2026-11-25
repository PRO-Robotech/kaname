// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations различает испытание, проверку предъявления и изменение
// способов действовать от имени человека. Проверки свежести, принадлежности
// и последнего способа входа не являются отдельной проверкой права выдачи.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{
			// BeginRegistrationUseCase.Execute сохраняет рукоятку церемонии
			// и испытание; ключа, сессии и нового допуска ещё не создаёт.
			FullMethod: iamv1.AccessKeyService_BeginRegistration_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// FinishRegistrationUseCase.commit сохраняет пригодный для входа
			// ключ: его обладатель получает способ действовать от имени
			// человека. Назначенные человеку ярусы при этом не меняются.
			FullMethod:    iamv1.AccessKeyService_FinishRegistration_FullMethodName,
			Effect:        grantpolicy.ChangesHolders,
			RequiresCheck: false,
		},
		{
			// ListUseCase.Execute вызывает только Store.KeysOf;
			// производственный pg.AccessKeyRepo.KeysOf читает user_access_keys.
			FullMethod: iamv1.AccessKeyService_List_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// RevokeUseCase.commit удаляет ключ, завершает прочие сессии
			// и пишет отсечку: носители перестают допускать держателя.
			// Сохранённые назначения прав и их ярусы не переписываются.
			FullMethod:          iamv1.AccessKeyService_Revoke_FullMethodName,
			Effect:              grantpolicy.ChangesHolders,
			Direction:           grantpolicy.WithdrawsAccess,
			WithdrawalAuthority: grantpolicy.TargetUserCredentialWithdrawal,
		},
		{
			// BeginAssertionUseCase.Execute читает ключи вызывающего
			// и сохраняет испытание, не меняя его доступ или сессию.
			FullMethod: iamv1.AccessKeyService_BeginAssertion_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// FinishAssertionUseCase.Execute потребляет испытание и через
			// pg.advanceSignCountTx меняет sign_count/last_used_at ключа.
			// RPC возвращает флаги, но не выдаёт удостоверение и не меняет
			// human_sessions.last_presented_at или уровень сессии.
			FullMethod: iamv1.AccessKeyService_FinishAssertion_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
	}
}
