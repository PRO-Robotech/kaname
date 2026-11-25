// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_operations

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations описывает чтение административной ленты операций:
// проверка права и выдача списка не меняют держателей доступа и его ярусы.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{FullMethod: iamv1.InternalOperationsService_ListIamOperations_FullMethodName, Effect: grantpolicy.UnchangedAccess},
	}
}
