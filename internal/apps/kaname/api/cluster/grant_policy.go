// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// clusterAdminGrantPolicy связывает оба изменения держателей с обязательным
// правом system_admin на синглтоне кластера. Эта проверка вызывается обоими
// сценариями до создания операции, независимо от способа открытия транзакции.
// Публичные близнецы используют те же сценарии и эти же декларации.
var clusterAdminGrantPolicy = struct {
	grant   grantpolicy.CatalogDeclaration
	revoke  grantpolicy.CatalogDeclaration
	require func(context.Context, adminChecker) error
}{
	grant: grantpolicy.CatalogDeclaration{
		FullMethod: iamv1.InternalClusterService_GrantAdmin_FullMethodName,
		Effect:     grantpolicy.ChangesHolders,
	},
	revoke: grantpolicy.CatalogDeclaration{
		FullMethod: iamv1.InternalClusterService_RevokeAdmin_FullMethodName,
		Effect:     grantpolicy.ChangesHolders,
	},
	require: requireClusterSystemAdmin,
}

// GrantDeclarations описывает действующие пути внутреннего близнеца.
// GrantAdmin создаёт либо восстанавливает держателя фиксированного system_admin,
// RevokeAdmin снимает его; состав ярусов этого права запросом не меняется.
// Оба сценария обязательно проверяют полномочия администратора на входе;
// configured AdminDecisionRunner повторяет проверку в транзакции записи,
// а fallback через Begin сохраняет только входную проверку. RequiresCheck
// не обещает транзакционный повтор во всех режимах. Действующий контракт
// проверки RevokeAdmin здесь зафиксирован без изменения правил отзыва.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	grant, revoke := clusterAdminGrantPolicy.grant, clusterAdminGrantPolicy.revoke
	grant.RequiresCheck = clusterAdminGrantPolicy.require != nil
	revoke.RequiresCheck = grant.RequiresCheck
	return []grantpolicy.CatalogDeclaration{
		// Get и ListAdmins только читают clusterReader.Get и grantReader.ListActive.
		{FullMethod: iamv1.InternalClusterService_Get_FullMethodName, Effect: grantpolicy.UnchangedAccess},
		{FullMethod: iamv1.InternalClusterService_ListAdmins_FullMethodName, Effect: grantpolicy.UnchangedAccess},
		grant,
		revoke,
	}
}
