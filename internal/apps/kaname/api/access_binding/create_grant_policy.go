// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// createGrantPolicy связывает объявление эффекта с проверками, которые
// действительно используются при приёме и записи выдачи.
var createGrantPolicy = struct {
	legacy        func(*CreateAccessBindingUseCase, context.Context, string, string) error
	full          func(context.Context, kaname.SemanticAuthorityWriter, domain.Subject, granteffect.Binding) error
	fullDelegated func(context.Context, kaname.SemanticAuthorityWriter, domain.Subject, domain.AccessBinding, domain.Role) error
}{
	legacy:        (*CreateAccessBindingUseCase).requireGrantAuthority,
	full:          grantpolicy.RequireBinding,
	fullDelegated: requireDelegatedBindingDecision,
}

// CreateGrantDeclaration сообщает эффект публичной операции и наличие
// проверок. Делегированный legacy-путь остаётся прямым вызовом внутри Execute,
// под действующей проверкой списка вызывающих.
func CreateGrantDeclaration() grantpolicy.CatalogDeclaration {
	return grantpolicy.CatalogDeclaration{
		FullMethod: iamv1.AccessBindingService_Create_FullMethodName,
		Effect:     grantpolicy.ChangesHoldersAndTier,
		RequiresCheck: createGrantPolicy.legacy != nil &&
			createGrantPolicy.full != nil && createGrantPolicy.fullDelegated != nil,
	}
}

// GrantDeclarations включает эффекты публичных операций. Проверка права
// менять метаданные или снимать свою делегированную выдачу не подтверждает
// обязательную проверку права выдавать для всего эффекта операции.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		CreateGrantDeclaration(),
		{
			// UpdateAccessBindingUseCase.writeBindingMetadata (update.go)
			// меняет метки объекта и ставит событие пересчёта; doUpdate также
			// запускает ReconcileObjectForward. Селекторы других выдач могут
			// сменить держателей и ярус доступа к этой привязке. Проверки
			// requireGrantAuthority и RequireScopeAdministration относятся
			// к области привязки, а не к новой выдаче через её метки.
			FullMethod:    iamv1.AccessBindingService_Update_FullMethodName,
			Effect:        grantpolicy.ChangesHoldersAndTier,
			RequiresCheck: false,
		},
		{
			// DeleteAccessBindingUseCase.deleteOnce (delete.go) и
			// withdrawStaged (staged_withdrawal.go) удаляют привязку и её
			// выдачу. removalAuthority допускает removalByDelegate без
			// проверки текущего права делегирующего выдавать (GD-31).
			// Это сужение доступа, а не неизменность держателей или яруса.
			FullMethod:          iamv1.AccessBindingService_Delete_FullMethodName,
			Effect:              grantpolicy.ChangesHoldersAndTier,
			Direction:           grantpolicy.WithdrawsAccess,
			WithdrawalAuthority: grantpolicy.ActiveDelegationBindingWithdrawal,
			RequiresCheck:       false,
		},
		{
			// RevokeAccessBindingUseCase.doRevoke (revoke.go) и
			// withdrawStaged снимают сохранённый набор выданных отношений.
			// Как у Delete, делегированный отзыв проверяет принадлежность
			// действующему делегированию, но не право выдавать заново.
			FullMethod:          iamv1.AccessBindingService_Revoke_FullMethodName,
			Effect:              grantpolicy.ChangesHoldersAndTier,
			Direction:           grantpolicy.WithdrawsAccess,
			WithdrawalAuthority: grantpolicy.ActiveDelegationBindingWithdrawal,
			RequiresCheck:       false,
		},
		{
			// GetAccessBindingUseCase.Execute (get.go) читает binding,
			// subjects и materialized_at; проверки видимости ничего не выдают.
			FullMethod: iamv1.AccessBindingService_Get_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListUseCase.Execute (list.go) читает видимую страницу и соседей;
			// projectSubjectsBatch/projectMaterializedAtBatch меняют только ответ.
			FullMethod: iamv1.AccessBindingService_List_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListByScopeUseCase.Execute (list_by_scope.go) читает через
			// readBindingsWithSubjects и фильтрует страницу по видимости.
			FullMethod: iamv1.AccessBindingService_ListByScope_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListBySubjectUseCase.Execute (list_by_subject.go) проверяет
			// subjectReadAuthority и читает через readBindingsWithSubjects.
			FullMethod: iamv1.AccessBindingService_ListBySubject_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListByAccountUseCase.Execute (list_by_account.go) читает через
			// readBindingsWithSubjects; право админа лишь выбирает видимые строки.
			FullMethod: iamv1.AccessBindingService_ListByAccount_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListByRoleUseCase.Execute (list_by_role.go) читает через
			// readBindingsWithSubjects и проверяет полномочия на области строк.
			FullMethod: iamv1.AccessBindingService_ListByRole_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListSubjectPrivilegesUseCase.Execute (list_subject_privileges.go)
			// вызывает Reader.AccessBindings().ListSubjectPrivileges и фильтр видимости.
			FullMethod: iamv1.AccessBindingService_ListSubjectPrivileges_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListAssignableRolesUseCase.Execute (list_assignable_roles.go)
			// читает Reader.Roles().ListAssignable после проверки полномочий.
			FullMethod: iamv1.AccessBindingService_ListAssignableRoles_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ExpandAccessUseCase.Execute (expand_access.go) проверяет полномочия,
			// вызывает PrincipalLister.ListUsers и собирает ответ без записи выдач.
			FullMethod: iamv1.AccessBindingService_ExpandAccess_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// Handler.ListOperations (handler.go) делегирует чтение
			// shared.ListOperationsUseCase.Execute (operations.ListForCaller).
			FullMethod: iamv1.AccessBindingService_ListOperations_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
	}
}
