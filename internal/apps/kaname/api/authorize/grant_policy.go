// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authorize

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations описывает действующие пути: вопросы о праве, чтение его
// оснований и снимка личности не меняют держателей доступа и его ярусы.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{FullMethod: iamv1.AuthorizeService_Check_FullMethodName, Effect: grantpolicy.UnchangedAccess},
		{FullMethod: iamv1.AuthorizeService_BatchCheck_FullMethodName, Effect: grantpolicy.UnchangedAccess},
		{FullMethod: iamv1.AuthorizeService_ListSubjects_FullMethodName, Effect: grantpolicy.UnchangedAccess},
		{FullMethod: iamv1.AuthorizeService_ExpandRelations_FullMethodName, Effect: grantpolicy.UnchangedAccess},
		{FullMethod: iamv1.AuthorizeService_WhoAmI_FullMethodName, Effect: grantpolicy.UnchangedAccess},
	}
}
