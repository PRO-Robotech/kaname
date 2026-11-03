// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type nativePublicReceipt struct {
	ServiceAccounts map[string]string
	Delegations     map[string]string
}

func (f *installationNativeWorld) publicRead(t *testing.T, path string, out proto.Message) {
	t.Helper()
	var raw json.RawMessage
	code, err := f.wire.JSON(f.given.ctx, http.MethodGet, path, f.operator.Bearer(), nil, &raw)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code, "ordinary independent O read")
	require.NoError(t, protojson.Unmarshal(raw, out))
}

// F6/P6: discover every page through O's public credential, Get each discovered
// resource, then compare exact identities/axes/dates to read-only persistence.
// SQL never supplies the public List result and cannot substitute for it.
func (f *installationNativeWorld) requirePublicDeliveredPairs(t *testing.T, modules ...string) nativePublicReceipt {
	t.Helper()
	f.renewOperator(t, f.given.ctx) // fresh real code exchange + normal /me verification
	receipt := nativePublicReceipt{ServiceAccounts: map[string]string{}, Delegations: map[string]string{}}
	accounts := map[string]*iamv1.ServiceAccount{}
	tokens := map[string]bool{}
	token := ""
	for {
		require.False(t, tokens[token], "SA pagination token repeated")
		tokens[token] = true
		q := url.Values{"accountId": {f.baseline.SystemID}, "pageSize": {"2"}, "pageToken": {token}}
		var page iamv1.ListServiceAccountsResponse
		f.publicRead(t, "/iam/v1/serviceAccounts?"+q.Encode(), &page)
		require.LessOrEqual(t, len(page.ServiceAccounts), 2)
		for _, item := range page.ServiceAccounts {
			require.NotNil(t, item)
			require.NotEmpty(t, item.Id)
			require.NotContains(t, accounts, item.Id)
			var got iamv1.ServiceAccount
			f.publicRead(t, "/iam/v1/serviceAccounts/"+url.PathEscape(item.Id), &got)
			require.True(t, proto.Equal(item, &got), "SA List/Get must agree")
			require.Equal(t, f.baseline.SystemID, got.AccountId)
			var account, name string
			var created time.Time
			require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT account_id,name,created_at FROM kaname.service_accounts WHERE id=$1`, got.Id).Scan(&account, &name, &created))
			require.Equal(t, account, got.AccountId)
			require.Equal(t, name, got.Name)
			require.NotNil(t, got.CreatedAt)
			require.True(t, created.Equal(got.CreatedAt.AsTime()))
			encoded, err := json.Marshal([]any{got.Id, got.AccountId, got.Name, got.CreatedAt.AsTime()})
			require.NoError(t, err)
			receipt.ServiceAccounts[got.Id] = string(encoded)
			accounts[got.Id] = proto.Clone(&got).(*iamv1.ServiceAccount)
		}
		token = page.NextPageToken
		if token == "" {
			break
		}
	}
	require.Len(t, accounts, len(f.baseline.ServiceAccounts)+1+len(modules))
	require.Contains(t, accounts, f.creator.ID)
	var saCount int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.service_accounts WHERE account_id=$1`, f.baseline.SystemID).Scan(&saCount))
	require.Len(t, accounts, saCount, "public census equals complete SYS persistence census")
	expectedModules := map[string]bool{}
	for _, module := range modules {
		expectedModules[module] = false
	}
	tokens = map[string]bool{}
	token = ""
	for {
		require.False(t, tokens[token], "GD pagination token repeated")
		tokens[token] = true
		q := url.Values{"accountId": {f.tenantID}, "pageSize": {"2"}, "pageToken": {token}}
		var page iamv1.ListGrantDelegationsResponse
		f.publicRead(t, "/iam/v1/grantDelegations?"+q.Encode(), &page)
		require.LessOrEqual(t, len(page.GrantDelegations), 2)
		for _, item := range page.GrantDelegations {
			require.NotNil(t, item)
			require.NotEmpty(t, item.Id)
			require.NotContains(t, receipt.Delegations, item.Id)
			var got iamv1.GrantDelegation
			f.publicRead(t, "/iam/v1/grantDelegations/"+url.PathEscape(item.Id), &got)
			require.True(t, proto.Equal(item, &got), "GD List/Get must agree")
			require.Contains(t, expectedModules, got.Module)
			require.False(t, expectedModules[got.Module])
			expectedModules[got.Module] = true
			require.Equal(t, f.tenantID, got.AccountId)
			require.Equal(t, iamv1.GrantDelegation_ACTIVE, got.Status)
			require.NotNil(t, got.Delegate)
			require.Equal(t, iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT, got.Delegate.Type)
			require.Contains(t, accounts, got.Delegate.Id)
			require.Equal(t, "svc-"+got.Module, accounts[got.Delegate.Id].Name)
			require.NotEqual(t, f.creator.ID, got.Delegate.Id)
			require.NotEqual(t, f.tenantID, got.Delegate.Id)
			require.NotEqual(t, f.tenantID, f.creator.ID)
			require.NotNil(t, got.DelegatedBy)
			require.Equal(t, "service_account", got.DelegatedBy.Type)
			require.Equal(t, f.creator.ID, got.DelegatedBy.Id)
			require.Equal(t, []iamv1.SubjectType{iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT}, got.SubjectTypes)
			require.Equal(t, []string{got.Module + ".objects"}, got.TargetTypes)
			require.Nil(t, got.RevokedAt)
			require.Nil(t, got.RevokedBy)
			var account, delegate, creatorType, creator, module, status string
			var roles, targets, subjects []string
			var created time.Time
			require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT account_id,delegate_id,delegated_by_type,delegated_by_id,module,status,role_ids,target_types,subject_types,created_at FROM kaname.grant_delegations WHERE id=$1`, got.Id).Scan(&account, &delegate, &creatorType, &creator, &module, &status, &roles, &targets, &subjects, &created))
			require.Equal(t, account, got.AccountId)
			require.Equal(t, delegate, got.Delegate.Id)
			require.Equal(t, creatorType, got.DelegatedBy.Type)
			require.Equal(t, creator, got.DelegatedBy.Id)
			require.Equal(t, module, got.Module)
			require.Equal(t, "ACTIVE", status)
			require.Equal(t, roles, got.RoleIds)
			require.Equal(t, targets, got.TargetTypes)
			require.Equal(t, []string{"service_account"}, subjects)
			require.Len(t, got.RoleIds, 1)
			require.NotNil(t, got.CreatedAt)
			require.True(t, created.Equal(got.CreatedAt.AsTime()))
			encoded, err := protojson.Marshal(&got)
			require.NoError(t, err)
			var canonical any
			require.NoError(t, json.Unmarshal(encoded, &canonical))
			encoded, err = json.Marshal(canonical)
			require.NoError(t, err)
			receipt.Delegations[got.Id] = string(encoded)
		}
		token = page.NextPageToken
		if token == "" {
			break
		}
	}
	require.Len(t, receipt.Delegations, len(modules))
	for module, seen := range expectedModules {
		require.True(t, seen, "missing public module %s", module)
	}
	var gdCount int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.grant_delegations WHERE account_id=$1`, f.tenantID).Scan(&gdCount))
	require.Len(t, receipt.Delegations, gdCount, "public census includes every ACTIVE/REVOKED history row")
	f.publicReadSequence++
	encoded, err := json.Marshal(receipt)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(f.session.Root, fmt.Sprintf("public-delivery-census-%03d.json", f.publicReadSequence)), encoded, 0600))
	return receipt
}
