// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// addMemberGrantPolicy связывает эффект добавления участника с обязательными
// проверками: до операции в legacy-режиме и до записи в полной политике.
var addMemberGrantPolicy = struct {
	legacy func(*AddMemberUseCase, context.Context, domain.GroupID) error
	full   func(context.Context, kaname.SemanticAuthorityWriter, domain.Subject, domain.GroupMember) error
}{
	legacy: (*AddMemberUseCase).requireMembersGrantAuthority,
	full:   grantpolicy.RequireGroupAddition,
}

// GrantDeclarations описывает эффект операций группы и их действующие
// проверки. Удаление по контракту ESC-24 сужает доступ по праву изменения
// группы, поэтому отдельной проверки права выдавать у него нет.
// При создании и обновлении пересчитывается доступ к группе как к объекту.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{
			// GetGroupUseCase.Execute (get.go) читает Reader.Groups().Get;
			// AllowsVGet только проверяет видимость.
			FullMethod: iamv1.GroupService_Get_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListGroupsUseCase.Execute (list.go) читает Reader.Groups().List
			// и фильтрует страницу через authzfilter.VisibleSet.
			FullMethod: iamv1.GroupService_List_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// ListMembersUseCase.Execute (list_members.go) проверяет AllowsVerb
			// и читает Reader.Groups().ListMembers, не меняя членство.
			FullMethod: iamv1.GroupService_ListMembers_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			// Handler.ListOperations (handler.go) вызывает
			// shared.ListOperationsUseCase.Execute (operations.ListForCaller).
			FullMethod: iamv1.GroupService_ListOperations_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
		{
			FullMethod:    iamv1.GroupService_AddMember_FullMethodName,
			Effect:        grantpolicy.ChangesHolders,
			RequiresCheck: addMemberGrantPolicy.legacy != nil && addMemberGrantPolicy.full != nil,
		},
		{
			FullMethod:          iamv1.GroupService_RemoveMember_FullMethodName,
			Effect:              grantpolicy.ChangesHolders,
			Direction:           grantpolicy.WithdrawsAccess,
			WithdrawalAuthority: grantpolicy.TargetGroupMembershipWithdrawal,
		},
		{
			// ESC §2 п.4: удаление группы сужает доступ по праву v_delete на ней.
			FullMethod:          iamv1.GroupService_Delete_FullMethodName,
			Effect:              grantpolicy.ChangesHoldersAndTier,
			Direction:           grantpolicy.WithdrawsAccess,
			WithdrawalAuthority: grantpolicy.TargetGroupDeletionWithdrawal,
		},
		{
			// На новую группу материализуются совпавшие привязки.
			FullMethod: iamv1.GroupService_Create_FullMethodName,
			Effect:     grantpolicy.ChangesHoldersAndTier,
		},
		{
			// Изменение меток меняет совпадения селекторов для самой группы.
			FullMethod: iamv1.GroupService_Update_FullMethodName,
			Effect:     grantpolicy.ChangesHoldersAndTier,
		},
	}
}
