// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/stretchr/testify/require"
)

func TestResourceModuleIdentitySeparatesServiceFromCatalogOwner(t *testing.T) {
	roster, err := moduleidentity.Parse([]string{"modules/kacho-nlb=module-writer"})
	require.NoError(t, err)
	gate := authzguard.NewRelationWriteGate(nil).WithModuleRoster(roster)
	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kaname.test"), "spiffe://kaname.test/ns/modules/sa/kacho-nlb", true)
	identity, err := resourceIdentityFromGate(ctx, gate)
	require.NoError(t, err)
	require.True(t, identity.valid())
	require.Equal(t, "nlb", identity.serviceName)
	require.Equal(t, "loadbalancer", identity.catalogModule)
	require.Equal(t, authzguard.ServiceAccountIDForService("nlb"), identity.actor)
	require.NotEqual(t, authzguard.ServiceAccountIDForService("loadbalancer"), identity.actor)
	identity.serviceName = identity.catalogModule
	require.False(t, identity.valid(), "имя владельца каталога не заменяет личность module SA")
}

func TestResourceModuleIdentityRejectsUnverifiedAndUndeclaredService(t *testing.T) {
	roster, err := moduleidentity.Parse([]string{"modules/kacho-vpc=module-writer"})
	require.NoError(t, err)
	gate := authzguard.NewRelationWriteGate(nil).WithModuleRoster(roster)
	for _, san := range []string{"spiffe://kaname.test/ns/foreign/sa/kacho-vpc", "spiffe://kaname.test/ns/modules/sa/kacho-nlb"} {
		ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kaname.test"), san, true)
		identity, err := resourceIdentityFromGate(ctx, gate)
		require.Error(t, err)
		require.False(t, identity.valid())
	}
	identity, err := resourceIdentityFromGate(context.Background(), gate)
	require.Error(t, err)
	require.False(t, identity.valid())
}
