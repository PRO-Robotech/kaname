// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package permission_catalog

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations описывает проекцию живого каталожного факта: после
// RequireAuthenticated сценарий читает Source.Facts и собирает ответ,
// не меняя держателей доступа и его ярусы.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{FullMethod: iamv1.PermissionCatalogService_ListPermissionCatalog_FullMethodName, Effect: grantpolicy.UnchangedAccess},
	}
}
