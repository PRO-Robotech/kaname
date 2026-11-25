// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package identityquota

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations описывает чтение квот личности вызывающего.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{
			// Handler.List читает IdentityOfUser и States. Производственный
			// pg.IdentityQuotaRepo дополняет ответ величинами посадки только
			// в памяти: квоты, их потребление и доступ здесь не изменяются.
			FullMethod: iamv1.IdentityQuotaService_List_FullMethodName,
			Effect:     grantpolicy.UnchangedAccess,
		},
	}
}
