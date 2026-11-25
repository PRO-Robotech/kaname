// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations описывает подтверждённые пути UserService и InternalUserService.
// Get читает запись с проверкой видимости, List отбирает видимых кандидатов,
// ListOperations читает журнал операций. Проверка права вызвать метод и
// координация писателя личности не являются отдельной проверкой права выдавать.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{FullMethod: iamv1.UserService_Get_FullMethodName, Effect: grantpolicy.UnchangedAccess},
		{FullMethod: iamv1.UserService_List_FullMethodName, Effect: grantpolicy.UnchangedAccess},
		{FullMethod: iamv1.UserService_ListOperations_FullMethodName, Effect: grantpolicy.UnchangedAccess},
		{
			// InternalHandler.Get вызывает тот же GetUserUseCase.Execute (get.go).
			FullMethod: iamv1.InternalUserService_Get_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// Приглашение создаёт членство и может создать выдачу на проект.
			// RequireBinding применяется только в ветви выдачи роли на проект.
			FullMethod: iamv1.UserService_Invite_FullMethodName,
			Effect:     grantpolicy.ChangesHoldersAndTier,
		},
		{
			// doUpdate (update.go) меняет метки и запускает реконсайл iam.user:
			// селекторы могут добавить или снять держателей и их ярусы доступа.
			FullMethod:    iamv1.UserService_Update_FullMethodName,
			Effect:        grantpolicy.ChangesHoldersAndTier,
			RequiresCheck: false,
		},
		{
			// doDelete (delete.go) отсекает удостоверения, снимает личность,
			// её самокортеж и указатели членств; событие удаления отзывает
			// материализованный привязками доступ к объекту iam.user.
			FullMethod:          iamv1.UserService_Delete_FullMethodName,
			Effect:              grantpolicy.ChangesHoldersAndTier,
			Direction:           grantpolicy.WithdrawsAccess,
			WithdrawalAuthority: grantpolicy.TargetUserIdentityWithdrawal,
		},
		{
			// doRemove (remove_from_account.go) снимает членство и указатель
			// iam_user#account, через который наследовался доступ к личности.
			// RemoveMembership также обесценивает последнее pending-приглашение.
			FullMethod:          iamv1.UserService_RemoveFromAccount_FullMethodName,
			Effect:              grantpolicy.ChangesHoldersAndTier,
			Direction:           grantpolicy.WithdrawsAccess,
			WithdrawalAuthority: grantpolicy.TargetAccountMembershipWithdrawal,
		},
		{
			// doSetInviteStatus (set_blocked.go) запрещает вход личности
			// и отсекает ранее выданное. Назначенные ярусы не переписываются.
			FullMethod:          iamv1.UserService_Block_FullMethodName,
			Effect:              grantpolicy.ChangesHolders,
			Direction:           grantpolicy.WithdrawsAccess,
			WithdrawalAuthority: grantpolicy.TargetUserBlockWithdrawal,
		},
		{
			// doSetInviteStatus (set_blocked.go) возвращает возможность входа
			// при сохранённых членствах и выдачах; старую отсечку не снимает.
			FullMethod:    iamv1.UserService_Unblock_FullMethodName,
			Effect:        grantpolicy.ChangesHolders,
			Direction:     grantpolicy.ExpandsOrMixesAccess,
			RequiresCheck: false,
		},
		{
			// doReset (reset_second_factor.go) снимает второй фактор и запасные
			// коды, отсекает выданные удостоверения и восстанавливает путь
			// регистрации второго фактора по паролю (Ф12-30).
			FullMethod:    iamv1.UserService_ResetSecondFactor_FullMethodName,
			Effect:        grantpolicy.ChangesHolders,
			Direction:     grantpolicy.ExpandsOrMixesAccess,
			RequiresCheck: false,
		},
		{
			// doReset (reset_access_keys.go) снимает испытания регистрации
			// и ключи, отсекает выданные удостоверения; ярусы выдач не меняет.
			FullMethod:          iamv1.UserService_ResetAccessKeys_FullMethodName,
			Effect:              grantpolicy.ChangesHolders,
			Direction:           grantpolicy.WithdrawsAccess,
			WithdrawalAuthority: grantpolicy.TargetUserAccessKeysWithdrawal,
		},
		{
			// doResend (resend_invite.go) вызывает только EmitInviteMail:
			// pg/tx.go пишет окно частоты и почтовое намерение; членство,
			// срок приглашения и выдачи доступа остаются прежними.
			FullMethod: iamv1.UserService_ResendInvite_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
	}
}
