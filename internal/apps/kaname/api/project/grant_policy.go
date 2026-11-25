// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package project

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations описывает эффект операций проекта и действующие проверки.
// Проверка доступа к проекту не подтверждает право на всю выдачу,
// которая получилась бы после пересчёта селекторов.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{
			// GetProjectUseCase.Execute (get.go) читает Reader.Projects().Get;
			// AllowsVGet только проверяет видимость.
			FullMethod: iamv1.ProjectService_Get_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListProjectsUseCase.Execute (list.go) читает кандидатов через Reader
			// и отбирает видимые строки без записи прав.
			FullMethod: iamv1.ProjectService_List_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// Handler.ListOperations (handler.go) вызывает
			// shared.ListOperationsUseCase.Execute (operations.ListForCaller).
			FullMethod: iamv1.ProjectService_ListOperations_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// После создания материализуются действующие привязки на новый
			// проект. Проверка создания ресурса не проверяет полученные выдачи.
			FullMethod: iamv1.ProjectService_Create_FullMethodName,
			Effect:     grantpolicy.ChangesHoldersAndTier,
		},
		{
			// Метки проекта могут расширять и сужать применимость
			// селекторов проекта и зависящих от него контейнерных правил.
			// При допуске по v_update итоговый эффект выдачи ещё не доказан.
			FullMethod: iamv1.ProjectService_Update_FullMethodName,
			Effect:     grantpolicy.ChangesHoldersAndTier,
			Direction:  grantpolicy.ExpandsOrMixesAccess,
		},
		{
			// Удаление отзывает привязки проекта через RevokeBindingsInScope.
			FullMethod:          iamv1.ProjectService_Delete_FullMethodName,
			Effect:              grantpolicy.ChangesHoldersAndTier,
			Direction:           grantpolicy.WithdrawsAccess,
			WithdrawalAuthority: grantpolicy.TargetProjectDeletionWithdrawal,
		},
	}
}
