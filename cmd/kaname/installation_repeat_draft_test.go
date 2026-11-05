// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"net/url"
	"testing"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// Разворачиваем каждую НЕТРИВИАЛЬНУЮ ось, а не только порядок файлов манифеста.
// Разворот единственного элемента не может установить идемпотентность порядка множества.
func reverseNativeDelegationAxes(t *testing.T, raw []byte) []byte {
	t.Helper()
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &doc))
	seed, ok := doc["seed"].(map[string]any)
	require.True(t, ok)
	declarations, ok := seed["grantDelegations"].([]any)
	require.True(t, ok)
	require.Len(t, declarations, 1)
	entry, ok := declarations[0].(map[string]any)
	require.True(t, ok)
	for _, axis := range []string{"roleIds", "targetTypes", "subjectTypes"} {
		values, ok := entry[axis].([]any)
		require.True(t, ok)
		require.GreaterOrEqual(t, len(values), 2)
		for i, j := 0, len(values)-1; i < j; i, j = i+1, j-1 {
			values[i], values[j] = values[j], values[i]
		}
	}
	changed, err := yaml.Marshal(doc)
	require.NoError(t, err)
	return changed
}

// И S1, и S2 выполняют настоящий полный serve, штатную подготовку учётных записей,
// полную публичную перепись и второй настоящий запуск с переставленными всеми тремя осями.
func ridNativeSequentialAxisRepeat(t *testing.T) {
	for _, mode := range []string{"S1", "S2"} {
		t.Run(mode, func(t *testing.T) { ridNativeSequentialAxisRepeatMode(t, mode) })
	}
}
func ridNativeSequentialAxisRepeatMode(t *testing.T, mode string) {
	f := newInstallationNativeWorld(t)
	accounts := []string{f.tenantID}
	if mode == "S2" {
		accounts = f.createRID02Accounts(t)
	}
	full, err := installruntime.BoundaryDelivery(2, 2)
	require.NoError(t, err)
	in := installruntime.DeliveryInput{Manifests: installruntime.RIDDeliveryFixture{First: full}, CredentialFile: f.creator.CredentialFile, TenantAccountID: &f.tenantID}
	if mode == "S2" {
		in.TenantAccountID = nil
	}
	requireNativeOK(t, f.apply(t, in), len(accounts))
	var roles, targets, subjects int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT cardinality(role_ids),cardinality(target_types),cardinality(subject_types)
 FROM kaname.grant_delegations WHERE account_id=$1 AND module='ridbounds'`, f.tenantID).Scan(&roles, &targets, &subjects))
	require.Equal(t, 2, roles)
	require.Equal(t, 2, targets)
	require.Equal(t, 4, subjects)
	before := f.stableReceipt(t)
	publicBefore := f.rid02PublicBoundsCensus(t, accounts)
	newmanBefore := rid02NewmanPhase(t, f, mode, "BEFORE-REORDER", accounts, nil)
	in.Manifests.First = reverseNativeDelegationAxes(t, full)
	requireNativeOK(t, f.apply(t, in), len(accounts))
	require.Equal(t, before, f.stableReceipt(t), "reorder-only restart preserves IDs dates creators axes and provisioned credentials")
	require.Equal(t, publicBefore, f.rid02PublicBoundsCensus(t, accounts))
	f.requireSameCredential(t)
	rid02NewmanPhase(t, f, mode, "AFTER-REORDER", accounts, newmanBefore)
}

func (f *installationNativeWorld) rid02PublicBoundsCensus(t *testing.T, accounts []string) nativePublicReceipt {
	t.Helper()
	f.renewOperator(t, f.given.ctx)
	out := nativePublicReceipt{ServiceAccounts: map[string]string{}, Delegations: map[string]string{}}
	canonical := func(message proto.Message) string {
		raw, err := protojson.Marshal(message)
		require.NoError(t, err)
		var value any
		require.NoError(t, json.Unmarshal(raw, &value))
		raw, err = json.Marshal(value)
		require.NoError(t, err)
		return string(raw)
	}
	token := ""
	seen := map[string]bool{}
	for {
		require.False(t, seen[token])
		seen[token] = true
		q := url.Values{"accountId": {f.baseline.SystemID}, "pageSize": {"2"}, "pageToken": {token}}
		var page iamv1.ListServiceAccountsResponse
		f.publicRead(t, "/iam/v1/serviceAccounts?"+q.Encode(), &page)
		for _, item := range page.ServiceAccounts {
			require.NotNil(t, item)
			require.NotContains(t, out.ServiceAccounts, item.Id)
			var got iamv1.ServiceAccount
			f.publicRead(t, "/iam/v1/serviceAccounts/"+url.PathEscape(item.Id), &got)
			require.True(t, proto.Equal(item, &got))
			require.Equal(t, f.baseline.SystemID, got.AccountId)
			out.ServiceAccounts[got.Id] = canonical(&got)
		}
		token = page.NextPageToken
		if token == "" {
			break
		}
	}
	require.Len(t, out.ServiceAccounts, len(f.baseline.ServiceAccounts)+2)
	for _, account := range accounts {
		token = ""
		seen = map[string]bool{}
		count := 0
		for {
			require.False(t, seen[token])
			seen[token] = true
			q := url.Values{"accountId": {account}, "pageSize": {"2"}, "pageToken": {token}}
			var page iamv1.ListGrantDelegationsResponse
			f.publicRead(t, "/iam/v1/grantDelegations?"+q.Encode(), &page)
			for _, item := range page.GrantDelegations {
				require.NotNil(t, item)
				require.NotContains(t, out.Delegations, item.Id)
				var got iamv1.GrantDelegation
				f.publicRead(t, "/iam/v1/grantDelegations/"+url.PathEscape(item.Id), &got)
				require.True(t, proto.Equal(item, &got))
				require.Equal(t, account, got.AccountId)
				require.Equal(t, iamv1.GrantDelegation_ACTIVE, got.Status)
				require.NotNil(t, got.DelegatedBy)
				require.Equal(t, f.creator.ID, got.DelegatedBy.Id)
				require.Equal(t, "service_account", got.DelegatedBy.Type)
				require.NotNil(t, got.Delegate)
				require.Contains(t, out.ServiceAccounts, got.Delegate.Id)
				require.Len(t, got.RoleIds, 2)
				require.Equal(t, []string{"ridbounds.objects00", "ridbounds.objects01"}, got.TargetTypes)
				require.Len(t, got.SubjectTypes, 4)
				out.Delegations[got.Id] = canonical(&got)
				count++
			}
			token = page.NextPageToken
			if token == "" {
				break
			}
		}
		require.Equal(t, 1, count)
	}
	return out
}
