// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstrap_token

import (
	"slices"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// GrantDeclarations описывает выдачу удостоверения фиксированной bootstrap-учётки.
func GrantDeclarations() []grantpolicy.CatalogDeclaration {
	method := iamv1.InternalBootstrapTokenService_MintBootstrapToken_FullMethodName
	return []grantpolicy.CatalogDeclaration{{
		// Handler.MintBootstrapToken вызывает MintUseCase.Execute (mint.go):
		// provision создаёт только запись ключа через pg.BootstrapStore,
		// а bootstraptokenwire.localMint.MintToken подписывает access-токен.
		// Предъявитель получает возможность действовать за эту учётку;
		// назначенный ей ярус операция не переписывает.
		// Первый токен фиксированной учётки выдаётся по полномочию,
		// назначенному проверенным SPIFFE SAN для этого метода. CallerPolicy
		// применяет этот список в каждом режиме, пустой список закрывает выпуск.
		// Декларация зависит от набора методов, который строит сам CallerPolicy.
		FullMethod:    method,
		Effect:        grantpolicy.ChangesHolders,
		RequiresCheck: slices.Contains(authzguard.SANRestrictedInternalRPCs(), method),
	}}
}
