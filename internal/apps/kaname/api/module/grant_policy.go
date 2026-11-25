// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package module

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// moduleApplyGrantPolicy задаёт входную проверку администратора для обоих
// путей применения. Публичная публикация также сверяет выдачу под замком.
var moduleApplyGrantPolicy = struct {
	require func(context.Context, adminChecker) error
}{require: requireClusterSystemAdmin}

// GrantDeclarations описывает эффекты внутреннего каталога. Plan только
// оценивает последствия, а Get и List читают текущее состояние. Apply меняет
// действующие проекции прав вместе со строками каталога.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{FullMethod: iamv1.CatalogPublicationService_PlanPublication_FullMethodName, Effect: grantpolicy.UnchangedAccess},
		{
			// Публикация пересчитывает каталог и проекции ролей. В транзакции
			// повторно проверяются system_admin и срок его исходной выдачи.
			FullMethod: iamv1.CatalogPublicationService_ApplyPublication_FullMethodName,
			Effect:     grantpolicy.ChangesHoldersAndTier, Direction: grantpolicy.ExpandsOrMixesAccess,
			RequiresCheck: moduleApplyGrantPolicy.require != nil,
		},
		{FullMethod: iamv1.InternalModuleService_Plan_FullMethodName, Effect: grantpolicy.UnchangedAccess},
		{FullMethod: iamv1.InternalModuleService_Get_FullMethodName, Effect: grantpolicy.UnchangedAccess},
		{FullMethod: iamv1.InternalModuleService_List_FullMethodName, Effect: grantpolicy.UnchangedAccess},
		{
			// ApplyUseCase.Execute (apply.go) вызывает VerbApplier.Apply;
			// modulecatalog.Applier.apply также создаёт и оживляет строки
			// каталога, меняет признаки глаголов. Переселение проекций в сироты
			// и вырезание снятых типов не делают Apply чистым отзывом.
			FullMethod: iamv1.InternalModuleService_Apply_FullMethodName,
			Effect:     grantpolicy.ChangesHoldersAndTier,
			Direction:  grantpolicy.ExpandsOrMixesAccess,
			// system_admin на кластере — действующее административное
			// полномочие на весь эффект. Подтверждение плана, ACR и потолки
			// последствий этой проверки не заменяют.
			RequiresCheck: moduleApplyGrantPolicy.require != nil,
		},
	}
}
