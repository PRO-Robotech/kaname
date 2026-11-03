// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Generalized RID08 public/primary census: accepted axes come from exact parsed
// delivery, never from persisted GD. I resolves independently even for noGD.
func rid12PublicCensus(t *testing.T, f *installationNativeWorld, wantedAccounts []string, declarations map[string]*manifest.Manifest, noGD bool) rid08PublicProof {
	t.Helper()
	f.renewOperator(t, f.given.ctx)
	proof := rid08PublicProof{Accounts: rid08PrimaryAccounts(t, f), ServiceAccounts: map[string]string{}, Delegations: map[string]string{}, Created: map[string]time.Time{}}
	sas := map[string]*iamv1.ServiceAccount{}
	token := ""
	tokens := map[string]bool{}
	for {
		require.False(t, tokens[token])
		tokens[token] = true
		proof.SAPages++
		q := url.Values{"accountId": {f.baseline.SystemID}, "pageSize": {"2"}, "pageToken": {token}}
		var page iamv1.ListServiceAccountsResponse
		f.publicRead(t, "/iam/v1/serviceAccounts?"+q.Encode(), &page)
		for _, item := range page.ServiceAccounts {
			require.NotNil(t, item)
			require.NotContains(t, sas, item.Id)
			var got iamv1.ServiceAccount
			f.publicRead(t, "/iam/v1/serviceAccounts/"+url.PathEscape(item.Id), &got)
			require.True(t, proto.Equal(item, &got))
			var account, name string
			var created time.Time
			require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT account_id,name,created_at FROM kaname.service_accounts WHERE id=$1`, got.Id).Scan(&account, &name, &created))
			require.Equal(t, f.baseline.SystemID, account)
			require.Equal(t, account, got.AccountId)
			require.Equal(t, name, got.Name)
			requireNativePublicCreatedAt(t, created, got.CreatedAt)
			sas[got.Id] = proto.Clone(&got).(*iamv1.ServiceAccount)
			proof.ServiceAccounts[got.Id] = rid08CanonicalMessage(t, &got)
		}
		token = page.NextPageToken
		if token == "" {
			break
		}
	}
	var count int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.service_accounts WHERE account_id=$1`, f.baseline.SystemID).Scan(&count))
	require.Len(t, sas, count)
	require.Len(t, sas, len(f.baseline.ServiceAccounts)+3)
	require.GreaterOrEqual(t, proof.SAPages, 3)
	for module, m := range declarations {
		require.Len(t, m.Seed.ServiceAccounts, 1)
		name := m.Seed.ServiceAccounts[0].Name
		require.Equal(t, "system", m.Seed.ServiceAccounts[0].Account)
		found := ""
		for id, sa := range sas {
			if sa.Name != name {
				continue
			}
			require.Empty(t, found)
			found = id
			require.Equal(t, f.baseline.SystemID, sa.AccountId)
			require.NotEqual(t, f.creator.ID, id)
			for _, account := range wantedAccounts {
				require.NotEqual(t, account, id)
			}
			require.NotEqual(t, f.baseline.SystemID, id)
			require.NotContains(t, f.baseline.ServiceAccounts, id)
			require.Equal(t, "svc-"+module, sa.Name)
			requireNativeAuthority(t, f.given, "service_account", id, 0)
		}
		require.NotEmpty(t, found, "I independently resolved by ordinary SYS SA List/Get and primary name/account before reading GD")
	}
	wanted := map[string]bool{}
	for _, id := range wantedAccounts {
		wanted[id] = true
	}
	require.False(t, wanted[f.baseline.SystemID])
	for _, a := range proof.Accounts {
		token = ""
		tokens = map[string]bool{}
		modules := map[string]bool{}
		for {
			require.False(t, tokens[token])
			tokens[token] = true
			proof.GDPages++
			q := url.Values{"accountId": {a.ID}, "pageSize": {"2"}, "pageToken": {token}}
			var page iamv1.ListGrantDelegationsResponse
			f.publicRead(t, "/iam/v1/grantDelegations?"+q.Encode(), &page)
			for _, item := range page.GrantDelegations {
				require.NotNil(t, item)
				require.True(t, wanted[a.ID], "no GD outside the frozen requested membership")
				require.NotContains(t, proof.Delegations, item.Id)
				var got iamv1.GrantDelegation
				f.publicRead(t, "/iam/v1/grantDelegations/"+url.PathEscape(item.Id), &got)
				require.True(t, proto.Equal(item, &got))
				require.False(t, noGD)
				require.Contains(t, declarations, got.Module)
				declaration := declarations[got.Module].Seed.GrantDelegations[0]
				require.False(t, modules[got.Module])
				modules[got.Module] = true
				require.Equal(t, a.ID, got.AccountId)
				require.Equal(t, iamv1.GrantDelegation_ACTIVE, got.Status)
				require.NotNil(t, got.Delegate)
				require.Equal(t, iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT, got.Delegate.Type)
				require.Contains(t, sas, got.Delegate.Id)
				require.Equal(t, "svc-"+got.Module, sas[got.Delegate.Id].Name)
				require.NotEqual(t, f.creator.ID, got.Delegate.Id)
				require.NotNil(t, got.DelegatedBy)
				require.Equal(t, "service_account", got.DelegatedBy.Type)
				require.Equal(t, f.creator.ID, got.DelegatedBy.Id)
				require.Nil(t, got.RevokedAt)
				require.Nil(t, got.RevokedBy)
				var account, delegate, kind, creator, module, status string
				expectedRoles := []string{}
				for _, name := range declaration.RoleIDs {
					var role string
					require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT id FROM kaname.roles WHERE name=$1 AND owner_module=$2 AND cluster_id=$3 AND live`, name, got.Module, domain.ClusterSingletonID).Scan(&role))
					expectedRoles = append(expectedRoles, role)
				}
				var roles, targets, subjects []string
				var created time.Time
				require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT account_id,delegate_id,delegated_by_type,delegated_by_id,module,status,role_ids,target_types,subject_types,created_at FROM kaname.grant_delegations WHERE id=$1`, got.Id).Scan(&account, &delegate, &kind, &creator, &module, &status, &roles, &targets, &subjects, &created))

				require.Equal(t, account, got.AccountId)
				require.Equal(t, delegate, got.Delegate.Id)
				require.Equal(t, kind, got.DelegatedBy.Type)
				require.Equal(t, creator, got.DelegatedBy.Id)
				require.Equal(t, module, got.Module)
				require.Equal(t, "ACTIVE", status)
				require.ElementsMatch(t, expectedRoles, roles)
				require.Equal(t, roles, got.RoleIds)
				require.ElementsMatch(t, declaration.TargetTypes, targets)
				require.Equal(t, targets, got.TargetTypes)
				expectedSubjects := []iamv1.SubjectType{}
				expectedStored := []string{}
				for _, name := range declaration.SubjectTypes {
					value, ok := iamv1.SubjectType_value[name]
					require.True(t, ok)
					expectedSubjects = append(expectedSubjects, iamv1.SubjectType(value))
					expectedStored = append(expectedStored, strings.ToLower(strings.TrimPrefix(name, "SUBJECT_TYPE_")))
				}
				require.ElementsMatch(t, expectedStored, subjects)
				require.ElementsMatch(t, expectedSubjects, got.SubjectTypes)
				requireNativePublicCreatedAt(t, created, got.CreatedAt)
				proof.Created[got.Id] = created
				proof.Delegations[got.Id] = rid08CanonicalMessage(t, &got)
			}
			token = page.NextPageToken
			if token == "" {
				break
			}
		}
		if wanted[a.ID] && !noGD {
			require.Len(t, modules, len(declarations))
		} else {
			require.Empty(t, modules)
		}
	}
	want := len(declarations) * len(wantedAccounts)
	if noGD {
		want = 0
	}
	require.Len(t, proof.Delegations, want)
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.grant_delegations`).Scan(&count))
	require.Len(t, proof.Delegations, count)
	return proof
}
