// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package child_registration

import (
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations учитывает материализацию доступа к зарегистрированному
// потомку. Право регистрации на родителе проверяется повторно перед записью.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	return []grantpolicy.CatalogDeclaration{{
		FullMethod: iamv1.ChildRegistrationService_Register_FullMethodName,
		Effect:     grantpolicy.ChangesHoldersAndTier, Direction: grantpolicy.ExpandsOrMixesAccess,
		// Проверка действия родителя не доказывает весь прирост по селекторам.
		RequiresCheck: false,
	}}
}
