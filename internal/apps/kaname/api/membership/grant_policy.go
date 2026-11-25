// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations описывает все публичные операции членства по их
// исполняемым путям. Создание использует общий поток user.InviteUserUseCase;
// декларация не меняет его политику приглашения и выдачи роли.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{
			// Handler.Create вызывает Creator.CreateMembership, провязанный
			// к user.InviteUserUseCase.CreateMembership. Его run добавляет
			// членство через UsersW.InsertPending и может создать выдачу роли
			// на проект через AccessBindingsW.Insert и InsertSubjects.
			// Проверка canInviteUsers допускает приглашение по праву на аккаунт.
			// RequireBinding в pg.InviteDecisions.once проверяет только выдачу
			// на проект в активной фазе; обязательной проверки выдачи для
			// полного RPC, включая создание без проекта, она не образует.
			FullMethod:    iamv1.MembershipService_Create_FullMethodName,
			Effect:        grantpolicy.ChangesHoldersAndTier,
			RequiresCheck: false,
		},
		{
			// GetMembershipUseCase.Execute (get.go) читает Reader.Get
			// с аккаунтом и идентификатором членства в условии отбора.
			FullMethod: iamv1.MembershipService_Get_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListMembershipsUseCase.Execute (list.go) читает Reader.List
			// в названном аккаунте; проверка формы и чтение не меняют доступ.
			FullMethod: iamv1.MembershipService_List_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListMyMembershipsUseCase.Execute (list_mine.go) читает
			// Reader.ListMine для личности из контекста без записи членства.
			FullMethod: iamv1.MembershipService_ListMine_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
	}
}
