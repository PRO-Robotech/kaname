// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"fmt"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func TestResourceFootprintOldNewGateDoesNotAdoptForeignCarrierAuthority(t *testing.T) {
	footprint := newResourceFootprint()
	require.NoError(t, footprint.addRegistrationScopes([]domain.ContainerScope{{Registered: true, AccountID: "old-account"}}))
	require.NoError(t, footprint.addRegistrationScopes([]domain.ContainerScope{{Registered: true, AccountID: "new-account"}}))
	require.NoError(t, footprint.addCarrier("binding", "foreign-carrier", []domain.AccountID{"foreign-account"}))
	require.NoError(t, footprint.addObject(domain.ResourceRef{Type: "vpc.network", ID: "network"}))
	sealed, err := footprint.local()
	require.NoError(t, err)
	require.Equal(t, []domain.AccountID{"new-account", "old-account"}, sealed.registration)
	require.Equal(t, []domain.AccountID{"foreign-account", "new-account", "old-account"}, sealed.plan.Accounts)
	require.Equal(t, kaname.AuthorityFenceAccounts, sealed.plan.Mode)
	require.NotContains(t, sealed.owners, kaname.AuthorityOwnerRef{Kind: "service_account", ID: "module-home"})
	// Сохранённый план не разделяет изменяемые slices/map с дальнейшим collector.
	require.NoError(t, footprint.addMutationAccount("later-account"))
	require.NotContains(t, sealed.plan.Accounts, domain.AccountID("later-account"))
}

func TestResourceFootprintDoesNotInferAuthorityFromMutationDependencies(t *testing.T) {
	footprint := newResourceFootprint()
	require.NoError(t, footprint.addCarrier("role", "role", []domain.AccountID{"carrier-account"}))
	require.NoError(t, footprint.addObject(domain.ResourceRef{Type: "vpc.network", ID: "network"}))
	sealed, err := footprint.local()
	require.NoError(t, err)
	require.Empty(t, sealed.registration, "object materialization не выдумывает registration gate")
	require.Equal(t, []domain.AccountID{"carrier-account"}, sealed.plan.Accounts)
}

func TestResourceFootprintUnknownAndOverboundDoNotBecomeGlobal(t *testing.T) {
	footprint := newResourceFootprint()
	require.ErrorIs(t, footprint.addRegistrationScopes([]domain.ContainerScope{{AccountID: "claimed-account"}}), kaname.ErrSourceUnconfirmed)
	require.ErrorIs(t, footprint.addCarrier("service_account", "module", []domain.AccountID{"actor-home"}), kaname.ErrSourceUnconfirmed)
	require.NoError(t, footprint.addObject(domain.ResourceRef{Type: "vpc.network", ID: "network"}))
	for i := 0; i <= kaname.MaxAuthorityFenceAccounts; i++ {
		require.NoError(t, footprint.addMutationAccount(domain.AccountID(fmt.Sprintf("account-%04d", i))))
	}
	_, err := footprint.local()
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

func TestResourceFootprintGlobalCarrierPreservesSeparateRegistrationAuthority(t *testing.T) {
	footprint := newResourceFootprint()
	require.NoError(t, footprint.addRegistrationScopes([]domain.ContainerScope{{Registered: true, AccountID: "registered-account"}}))
	require.NoError(t, footprint.addObject(domain.ResourceRef{Type: "vpc.network", ID: "network"}))
	require.NoError(t, footprint.addGlobalCarrier("role", "system-role"))
	_, err := footprint.local()
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	classified, err := footprint.classified()
	require.NoError(t, err)
	require.Equal(t, kaname.AuthorityFenceGlobal, classified.plan.Mode)
	require.Empty(t, classified.plan.Accounts)
	require.Equal(t, []domain.AccountID{"registered-account"}, classified.registration)
	require.Contains(t, classified.owners, kaname.AuthorityOwnerRef{Kind: "role", ID: "system-role"})
	require.ErrorIs(t, footprint.addGlobalCarrier("service_account", "shared-module"), kaname.ErrSourceUnconfirmed)
}
