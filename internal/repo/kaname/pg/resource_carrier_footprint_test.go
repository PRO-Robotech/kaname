// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func TestResourceCarrierFootprintSharedRecipientDoesNotJoinAccountLanes(t *testing.T) {
	for _, account := range []string{"account-a", "account-b"} {
		t.Run(account, func(t *testing.T) {
			p := parentCaptureFixture(t)
			parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceAccount, typ: "account", id: account}, map[string]any{"id": account})
			f := newResourceFootprint()
			require.NoError(t, f.addObject(domain.ResourceRef{Type: "vpc.network", ID: account + "-object"}))
			b := domain.AccessBinding{ID: domain.AccessBindingID(account + "-binding"), Scope: domain.ScopeAccount, ResourceType: "account", ResourceID: account, RoleID: "same-module-role", SubjectType: domain.SubjectTypeServiceAccount, SubjectID: "same-module-sa"}
			require.NoError(t, p.addBindingFootprint(context.Background(), f, b))
			plan, err := f.classified()
			require.NoError(t, err)
			require.Equal(t, kaname.AuthorityFenceAccounts, plan.plan.Mode)
			require.Equal(t, []domain.AccountID{domain.AccountID(account)}, plan.plan.Accounts)
			require.Empty(t, plan.registration)
			require.NotContains(t, plan.owners, kaname.AuthorityOwnerRef{Kind: "role", ID: "same-module-role"})
			require.NotContains(t, plan.owners, kaname.AuthorityOwnerRef{Kind: "service_account", ID: "same-module-sa"})
		})
	}
}

func TestResourceCarrierFootprintProjectUsesCapturedCurrentAccount(t *testing.T) {
	p := parentCaptureFixture(t)
	parentCaptureProject(t, p, "project", "current-account")
	parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceAccount, typ: "account", id: "current-account"}, map[string]any{"id": "current-account"})
	f := newResourceFootprint()
	require.NoError(t, f.addObject(domain.ResourceRef{Type: "vpc.network", ID: "object"}))
	require.NoError(t, p.addBindingFootprint(context.Background(), f, domain.AccessBinding{ID: "binding", Scope: domain.ScopeProject, ResourceType: "project", ResourceID: "project"}))
	plan, err := f.classified()
	require.NoError(t, err)
	require.Equal(t, []domain.AccountID{"current-account"}, plan.plan.Accounts)
	require.Empty(t, plan.registration)
	require.Contains(t, plan.owners, kaname.AuthorityOwnerRef{Kind: "project", ID: "project"})
	// Прежний аккаунт роли не подменяет ownership после переноса проекта.
	require.ErrorIs(t, p.addRoleMutationFootprint(context.Background(), f, domain.Role{ID: "role", ProjectID: "project", AccountID: "old-account"}), kaname.ErrSourceUnconfirmed)
}

func TestResourceCarrierFootprintUnknownDoesNotEscalateToGlobal(t *testing.T) {
	p := parentCaptureFixture(t)
	f := newResourceFootprint()
	require.ErrorIs(t, p.addBindingFootprint(context.Background(), f, domain.AccessBinding{ID: "binding", Scope: domain.ScopeAccount, ResourceType: "project", ResourceID: "unknown"}), kaname.ErrSourceUnconfirmed)
	require.False(t, f.global)
	require.Empty(t, f.mutation)
	parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceAccount, typ: "account", id: "gone"})
	require.ErrorIs(t, p.addBindingFootprint(context.Background(), f, domain.AccessBinding{ID: "binding", Scope: domain.ScopeAccount, ResourceType: "account", ResourceID: "gone"}), kaname.ErrSourceUnconfirmed)
	require.False(t, f.global)
	require.NoError(t, p.addRoleMutationFootprint(context.Background(), f, domain.Role{ID: "system-role", IsSystem: true, ClusterID: "cluster"}))
	require.True(t, f.global)
}
