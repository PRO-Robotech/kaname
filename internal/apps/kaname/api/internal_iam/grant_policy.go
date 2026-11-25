// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// requireForceLogoutAuthority связывает декларацию с входной проверкой
// system_admin, которую вызывает ForceLogout до обработки запроса.
var requireForceLogoutAuthority = (*Handler).requireSystemAdmin

// GrantDeclarations описывает эффекты внутренних RPC по исполняемым путям.
// Проверенная личность модуля и fga_writer допускают запись ресурса, но сами
// по себе не доказывают отдельное полномочие выдавать изменяемый доступ.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{
			// LookupSubjectUseCase.Execute читает пользователя или служебную
			// учётку через Reader и проверяет возможность аутентификации.
			FullMethod: iamv1.InternalIAMService_LookupSubject_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// Handler.Check вызывает AuthorizeService.CheckRelation:
			// вычисленный вердикт не меняет держателей или ярусы доступа.
			FullMethod: iamv1.InternalIAMService_Check_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ForceLogout снимает действующие сессии и ставит отсечку
			// отзыва удостоверений субъекта. Назначения и ярусы IAM сохраняются.
			// Полномочие system_admin на кластере покрывает весь эффект.
			FullMethod:    iamv1.InternalIAMService_ForceLogout_FullMethodName,
			Effect:        grantpolicy.ChangesHolders,
			Direction:     grantpolicy.WithdrawsAccess,
			RequiresCheck: requireForceLogoutAuthority != nil,
		},
		{
			// SubjectChangeService.PollSubjectChanges читает окно журнала;
			// клиентский курсор не подтверждает и не снимает выдачи.
			FullMethod: iamv1.InternalIAMService_PollSubjectChanges_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// RegisterResourceUseCase.Register публикует объект либо меняет
			// зеркало и отношения с материализацией совпавших привязок.
			// Метки и иерархия могут менять держателей и ярусы доступа.
			// Проверки владельца типа и fga_writer не заменяют проверку
			// права выдачи во всех режимах регистратора.
			FullMethod:    iamv1.InternalIAMService_RegisterResource_FullMethodName,
			Effect:        grantpolicy.ChangesHoldersAndTier,
			RequiresCheck: false,
		},
		{
			// CloseChildParent закрывает приём новых потомков текущей регистрации.
			// Подписанная программа пишет закрытие инкарнации и аудит. Существующие
			// держатели, ярусы и отношения с уже зарегистрированными потомками сохраняются.
			FullMethod: iamv1.InternalIAMService_CloseChildParent_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// Unregister снимает публикацию либо источники зарегистрированного
			// объекта. После обработки снятия регистрации общий реконсайл
			// может материализовать ранее выданный доступ для сохранившегося объекта.
			// Допуск fga_writer покрывает снятие своих источников. Для полного
			// эффекта RPC отдельное доказательство ещё отсутствует.
			FullMethod:    iamv1.InternalIAMService_UnregisterResource_FullMethodName,
			Effect:        grantpolicy.ChangesHoldersAndTier,
			Direction:     grantpolicy.ExpandsOrMixesAccess,
			RequiresCheck: false,
		},
		{
			// ResolveBasic читает удостоверение и состояние владельца.
			// TouchLastUsed меняет только last_used_at для наблюдаемости,
			// не продлевая и не выдавая удостоверение или доступ.
			FullMethod: iamv1.InternalIAMService_ResolveBasicCredential_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// GetRoleCompiledUseCase.Execute читает сохранённую проекцию
			// Permissions через Reader.Roles().Get, не пересобирая выдачи.
			FullMethod: iamv1.InternalIAMService_GetRoleCompiled_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// BasicCredentialRepo.CheckBasicLive читает удостоверение,
			// отсечку и допуск владельца, возвращая только вердикт живости.
			FullMethod: iamv1.InternalIAMService_CheckBasicCredentialLive_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
	}
}
