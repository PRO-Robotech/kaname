// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_metadata

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations описывает обработчики внешнего зеркала. Get выполняет
// ReadAuthorizedMirrorMetadata в одном снимке. Для Update устанавливается
// только писатель, прошедший проверку ABI. Без него обработчик отказывает.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{
		{FullMethod: iamv1.ResourceMetadataService_Get_FullMethodName, Effect: grantpolicy.UnchangedAccess},
		{
			// writeMirrorMetadata всегда проходит finalizeMetadataAuthorization:
			// checkMirrorGrantIdentity требует удержанный снимок, затем v_update
			// и RequireMetadataGrant подтверждают целевое действие и прирост прав.
			FullMethod: iamv1.ResourceMetadataService_Update_FullMethodName,
			Effect:     grantpolicy.ChangesHoldersAndTier, Direction: grantpolicy.ExpandsOrMixesAccess,
			RequiresCheck: true,
		},
	}
}
