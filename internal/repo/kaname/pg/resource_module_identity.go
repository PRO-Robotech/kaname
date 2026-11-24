// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Service и CatalogModule имеют разный смысл даже у одной проверенной личности:
// assignment/SA используют имя службы, каталог — имя владельца манифеста.
// Например, nlb и loadbalancer нельзя взаимозаменять при выводе SA.
type resourceModuleIdentity struct {
	serviceName   string
	catalogModule string
	actor         string
}

func resourceIdentityFromGate(ctx context.Context, gate *authzguard.RelationWriteGate) (resourceModuleIdentity, error) {
	if err := ctx.Err(); err != nil {
		return resourceModuleIdentity{}, err
	}
	if gate == nil {
		return resourceModuleIdentity{}, kaname.ErrSourceUnconfirmed
	}
	serviceName, err := gate.Authorize(ctx)
	if err != nil {
		return resourceModuleIdentity{}, err
	}
	catalogModule, err := gate.AuthorizeCatalogModule(ctx)
	if err != nil {
		return resourceModuleIdentity{}, err
	}
	if !nativeQuestionToken(serviceName) || !nativeQuestionToken(catalogModule) {
		return resourceModuleIdentity{}, kaname.ErrSourceUnconfirmed
	}
	return resourceModuleIdentity{serviceName: serviceName, catalogModule: catalogModule, actor: authzguard.ServiceAccountIDForService(serviceName)}, nil
}

func (id resourceModuleIdentity) valid() bool {
	return nativeQuestionToken(id.serviceName) && nativeQuestionToken(id.catalogModule) && id.actor == authzguard.ServiceAccountIDForService(id.serviceName)
}
