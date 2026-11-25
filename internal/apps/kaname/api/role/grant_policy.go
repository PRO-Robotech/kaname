// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// roleGrantPolicy связывает декларации с исполняемыми проверками. Проверка
// метода отделена от проверки предлагаемого содержимого роли: право править
// метаданные само по себе не доказывает право менять доступ через метки.
var roleGrantPolicy = struct {
	create      grantpolicy.CatalogDeclaration
	update      grantpolicy.CatalogDeclaration
	content     func(context.Context, kaname.SemanticAuthorityWriter, domain.Subject, domain.Role, bool) error
	method      func(context.Context, kaname.SemanticAuthorityWriter, domain.Subject, domain.Role, bool) error
	legacyRules func(*UpdateRoleUseCase, context.Context, domain.RoleID) error
}{
	create: grantpolicy.CatalogDeclaration{
		FullMethod: iamv1.RoleService_Create_FullMethodName,
		Effect:     grantpolicy.ChangesHoldersAndTier,
		// content проверяет правила в configured-пути, но не весь RPC.
		RequiresCheck: false,
	},
	update: grantpolicy.CatalogDeclaration{
		FullMethod: iamv1.RoleService_Update_FullMethodName,
		Effect:     grantpolicy.ChangesHoldersAndTier,
		// Правила проходят content либо legacyRules; имя и описание не
		// меняют доступ. Метки же могут сменить держателей и ярус доступа
		// к роли, проходя лишь method в configured-пути.
		RequiresCheck: false,
	},
	content:     grantpolicy.RequireRole,
	method:      grantpolicy.RequireRoleMethod,
	legacyRules: (*UpdateRoleUseCase).requireRulesGrantAuthority,
}

// GrantDeclarations описывает весь RPC, включая варианты, которые текущие
// проверки не покрывают. Наличие content не делает весь Create/Update
// проверенным: у legacy Create нет обязательной проверки содержимого, а
// собственные метки роли меняют доступ к ней независимо от её правил.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{
			// GetRoleUseCase.Execute (get.go) читает роль; attachIntegrity
			// (integrity.go) читает проекции и заполняет только ответ.
			FullMethod: iamv1.RoleService_Get_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListRolesUseCase.Execute (list.go) читает и фильтрует роли;
			// attachIntegrity (integrity.go) заполняет ответ по читающим портам.
			FullMethod: iamv1.RoleService_List_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// Handler.ListOperations (handler.go) вызывает
			// shared.ListOperationsUseCase.Execute (operations.ListForCaller).
			FullMethod: iamv1.RoleService_ListOperations_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		roleGrantPolicy.create,
		roleGrantPolicy.update,
		{
			// ESC §2 п.4: удаление роли сужает доступ по праву v_delete на ней.
			FullMethod:          iamv1.RoleService_Delete_FullMethodName,
			Effect:              grantpolicy.ChangesHoldersAndTier,
			Direction:           grantpolicy.WithdrawsAccess,
			WithdrawalAuthority: grantpolicy.TargetRoleDeletionWithdrawal,
		},
	}
}
