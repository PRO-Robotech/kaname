// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type rid08AccountRow struct {
	ID, Name, Owner string
	Created         time.Time
}
type rid08PublicProof struct {
	Accounts                     []rid08AccountRow
	ServiceAccounts, Delegations map[string]string
	Created                      map[string]time.Time
	SAPages, GDPages             int
}

func rid08PrimaryAccounts(t *testing.T, f *installationNativeWorld) []rid08AccountRow {
	t.Helper()
	rows, err := f.given.pool.Query(f.given.ctx, `SELECT id,name,owner_user_id,created_at FROM kaname.accounts ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	result := []rid08AccountRow{}
	for rows.Next() {
		var a rid08AccountRow
		require.NoError(t, rows.Scan(&a.ID, &a.Name, &a.Owner, &a.Created))
		result = append(result, a)
	}
	require.NoError(t, rows.Err())
	return result
}
func rid08PrimaryGD(t *testing.T, f *installationNativeWorld) string {
	t.Helper()
	var raw string
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(g) ORDER BY id),'[]'::jsonb)::text FROM kaname.grant_delegations g`).Scan(&raw))
	return raw
}
func rid08CanonicalMessage(t *testing.T, p proto.Message) string {
	t.Helper()
	raw, err := protojson.Marshal(p)
	require.NoError(t, err)
	var value any
	require.NoError(t, json.Unmarshal(raw, &value))
	raw, err = json.Marshal(value)
	require.NoError(t, err)
	return string(raw)
}
func rid08GDOperations(t *testing.T, f *installationNativeWorld) []string {
	t.Helper()
	metadata, err := anypb.New(&iamv1.CreateGrantDelegationMetadata{})
	require.NoError(t, err)
	rows, err := f.given.pool.Query(f.given.ctx, `SELECT id FROM kaname.operations WHERE metadata_type=$1 ORDER BY id`, metadata.TypeUrl)
	require.NoError(t, err)
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	require.NoError(t, rows.Err())
	return ids
}
func rid08NewOperations(t *testing.T, f *installationNativeWorld, before []string, want int) {
	t.Helper()
	old := map[string]bool{}
	for _, id := range before {
		old[id] = true
	}
	after := rid08GDOperations(t, f)
	count := 0
	seenPairs := map[string]bool{}
	for _, id := range after {
		if old[id] {
			continue
		}
		count++
		op, err := operations.NewRepo(f.given.pool, "kaname").Get(f.given.ctx, id)
		require.NoError(t, err)
		require.NotNil(t, op.Response)
		var gd iamv1.GrantDelegation
		require.NoError(t, op.Response.UnmarshalTo(&gd))
		require.False(t, seenPairs[gd.Id])
		seenPairs[gd.Id] = true
		requireNativeInstallationOperation(t, f.given.ctx, f.given.pool, id, gd.AccountId, f.creator.ID, gd.Id)
		var got iamv1.GrantDelegation
		f.publicRead(t, "/iam/v1/grantDelegations/"+gd.Id, &got)
		require.True(t, proto.Equal(&gd, &got))
	}
	require.Equal(t, want, count)
	require.Len(t, after, len(before)+want)
}

// O сначала обнаруживает каждую публичную страницу. Первичные запросы затем независимо проверяют
// полный состав, точные ID, оси, создателей и публичные канонические временные метки.
func rid08PublicCensus(t *testing.T, f *installationNativeWorld, wantedAccounts []string) rid08PublicProof {
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
				require.Contains(t, []string{"ridfirst", "ridsecond"}, got.Module)
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
				var account, delegate, kind, creator, module, status, role string
				var roles, targets, subjects []string
				var created time.Time
				require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT account_id,delegate_id,delegated_by_type,delegated_by_id,module,status,role_ids,target_types,subject_types,created_at FROM kaname.grant_delegations WHERE id=$1`, got.Id).Scan(&account, &delegate, &kind, &creator, &module, &status, &roles, &targets, &subjects, &created))
				require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT id FROM kaname.roles WHERE name=$1 AND owner_module=$2 AND cluster_id=$3 AND live`, got.Module+".reader", got.Module, domain.ClusterSingletonID).Scan(&role))
				require.Equal(t, account, got.AccountId)
				require.Equal(t, delegate, got.Delegate.Id)
				require.Equal(t, kind, got.DelegatedBy.Type)
				require.Equal(t, creator, got.DelegatedBy.Id)
				require.Equal(t, module, got.Module)
				require.Equal(t, "ACTIVE", status)
				require.Equal(t, []string{role}, roles)
				require.Equal(t, roles, got.RoleIds)
				require.Equal(t, []string{got.Module + ".objects"}, targets)
				require.Equal(t, targets, got.TargetTypes)
				require.Equal(t, []string{"service_account"}, subjects)
				require.Equal(t, []iamv1.SubjectType{iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT}, got.SubjectTypes)
				requireNativePublicCreatedAt(t, created, got.CreatedAt)
				proof.Created[got.Id] = created
				proof.Delegations[got.Id] = rid08CanonicalMessage(t, &got)
			}
			token = page.NextPageToken
			if token == "" {
				break
			}
		}
		if wanted[a.ID] {
			require.Len(t, modules, 2)
		} else {
			require.Empty(t, modules)
		}
	}
	require.Len(t, proof.Delegations, 2*len(wantedAccounts))
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.grant_delegations`).Scan(&count))
	require.Len(t, proof.Delegations, count)
	return proof
}
func rid08NonSystemIDs(t *testing.T, rows []rid08AccountRow, system string) []string {
	t.Helper()
	ids := []string{}
	sys := 0
	for _, a := range rows {
		if a.ID == system {
			sys++
			require.Equal(t, "system", a.Name)
		} else {
			ids = append(ids, a.ID)
		}
	}
	require.Equal(t, 1, sys)
	sort.Strings(ids)
	return ids
}
