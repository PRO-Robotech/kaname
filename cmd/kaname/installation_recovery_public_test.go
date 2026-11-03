// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// Reopen actual production listeners with the already-staged manifest (no GD
// apply). Public O independently discovers exactly the recovered durable rows;
// this startup cannot manufacture missing delegations to make recovery green.
func rid02PublicRecoveredCensus(t *testing.T, f *installationNativeWorld, records []rid02CrashRecord) {
	t.Helper()
	before := f.stableReceipt(t)
	f.apply(t, installruntime.DeliveryInput{Manifests: nativeWithoutDelegations(t, installruntime.NewRIDDeliveryFixture()), CredentialFile: f.creator.CredentialFile})
	require.Equal(t, before, f.stableReceipt(t), "public-read restart cannot change recovered identities or rows")
	f.renewOperator(t, f.given.ctx)
	expected := map[string]map[string]rid02CrashRecord{}
	for _, r := range records {
		if expected[r.Input.Input.AccountID] == nil {
			expected[r.Input.Input.AccountID] = map[string]rid02CrashRecord{}
		}
		if r.Committed {
			expected[r.Input.Input.AccountID][r.Proposed] = r
		}
	}
	publicIDs := map[string][]string{}
	for account, want := range expected {
		seen := map[string]bool{}
		tokens := map[string]bool{}
		token := ""
		for {
			require.False(t, tokens[token])
			tokens[token] = true
			q := url.Values{"accountId": {account}, "pageSize": {"2"}, "pageToken": {token}}
			var page iamv1.ListGrantDelegationsResponse
			f.publicRead(t, "/iam/v1/grantDelegations?"+q.Encode(), &page)
			for _, item := range page.GrantDelegations {
				require.NotNil(t, item)
				require.Contains(t, want, item.Id)
				require.False(t, seen[item.Id])
				seen[item.Id] = true
				var got iamv1.GrantDelegation
				f.publicRead(t, "/iam/v1/grantDelegations/"+url.PathEscape(item.Id), &got)
				require.True(t, proto.Equal(item, &got))
				r := want[item.Id]
				op, err := operations.NewRepo(f.given.pool, "kaname").Get(f.given.ctx, r.Operation)
				require.NoError(t, err)
				var response iamv1.GrantDelegation
				require.NoError(t, op.Response.UnmarshalTo(&response))
				require.True(t, proto.Equal(&response, &got))
				require.Equal(t, f.creator.ID, got.DelegatedBy.Id)
				require.Equal(t, "service_account", got.DelegatedBy.Type)
				require.Equal(t, r.Input.Input.DelegateID, got.Delegate.Id)
				var created time.Time
				require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT created_at FROM kaname.grant_delegations WHERE id=$1`, got.Id).Scan(&created))
				requireNativePublicCreatedAt(t, created, got.CreatedAt)
				publicIDs[account] = append(publicIDs[account], got.Id)
			}
			token = page.NextPageToken
			if token == "" {
				break
			}
		}
		require.Len(t, seen, len(want), "complete public recovery census")
	}
	raw, err := json.Marshal(publicIDs)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(f.session.Root, "public-recovered-census.json"), raw, 0600))
	f.requireSameCredential(t)
}
