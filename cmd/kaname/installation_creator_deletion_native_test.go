// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func (w *ridLifecycleWorld) revokeCreatorKeys(t *testing.T) {
	t.Helper()
	f := w.f
	// More than one real key prevents a one-key shortcut from proving "all".
	f.ridKey(t, f.creator.ID, f.creator.AccountID, "creator-spare")
	keys := f.ridList(t, "/iam/v1/serviceAccounts/"+f.creator.ID+"/keys", "keys", nil)
	require.GreaterOrEqual(t, len(keys), 2)
	seen := map[string]bool{}
	for _, raw := range keys {
		var key iamv1.ServiceAccountOAuthClient
		require.NoError(t, protojson.Unmarshal(raw, &key))
		require.NotEmpty(t, key.Id)
		require.False(t, seen[key.Id])
		seen[key.Id] = true
		f.ridOperation(t, "DELETE", "/iam/v1/serviceAccounts/"+f.creator.ID+"/keys/"+key.Id, f.operator.Bearer(), nil, 0)
	}
	require.True(t, seen[f.creator.KeyID])
	require.Empty(t, f.ridList(t, "/iam/v1/serviceAccounts/"+f.creator.ID+"/keys", "keys", nil))
	var n int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.service_account_oauth_clients WHERE sva_id=$1`, f.creator.ID).Scan(&n))
	require.Zero(t, n)
}
func (w *ridLifecycleWorld) creatorReferenceCensus(t *testing.T, allowedActiveDelegate string) {
	t.Helper()
	f := w.f
	// Full public GD history in every fixture account, independently Get each.
	active := []string{}
	for _, account := range w.accounts {
		for _, gd := range w.delegations(t, account) {
			if gd.Delegate.Id == f.creator.ID && gd.Status == iamv1.GrantDelegation_ACTIVE {
				active = append(active, gd.Id)
			}
		}
	}
	if allowedActiveDelegate == "" {
		require.Empty(t, active)
	} else {
		require.Equal(t, []string{allowedActiveDelegate}, active)
	}
	bindings := f.ridList(t, "/iam/v1/accessBindings", "accessBindings", url.Values{"filter": {fmt.Sprintf("subject=%q", f.creator.ID)}, "includeRevoked": {"true"}})
	for _, raw := range bindings {
		var binding iamv1.AccessBinding
		require.NoError(t, protojson.Unmarshal(raw, &binding))
		require.NotEqual(t, iamv1.AccessBinding_ACTIVE, binding.Status)
	}
	accounts := append([]string{f.baseline.SystemID}, w.accounts...)
	for _, account := range accounts {
		for _, raw := range f.ridList(t, "/iam/v1/groups", "groups", url.Values{"accountId": {account}}) {
			var group iamv1.Group
			require.NoError(t, protojson.Unmarshal(raw, &group))
			for _, memberRaw := range f.ridList(t, "/iam/v1/groups/"+group.Id+":listMembers", "members", nil) {
				var member iamv1.GroupMember
				require.NoError(t, protojson.Unmarshal(memberRaw, &member))
				require.False(t, member.MemberType == "service_account" && member.MemberId == f.creator.ID, "creator has an actual group reference")
			}
		}
	}
	// Read-only observer catches an omitted public reference; it cannot create,
	// remove or authorize the references being audited.
	var members, grants, delegates int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT
 (SELECT count(*) FROM kaname.group_members WHERE member_type='service_account' AND member_id=$1),
 (SELECT count(DISTINCT b.id) FROM kaname.access_bindings b LEFT JOIN kaname.access_binding_subjects s ON s.binding_id=b.id WHERE b.revoked_at IS NULL AND ((b.subject_type='service_account' AND b.subject_id=$1) OR (s.subject_type='service_account' AND s.subject_id=$1))),
 (SELECT count(*) FROM kaname.grant_delegations WHERE active_delegate_id=$1)`, f.creator.ID).Scan(&members, &grants, &delegates))
	require.Zero(t, members)
	require.Zero(t, grants)
	require.Equal(t, len(active), delegates)
	requireNativeAuthority(t, f.given, "service_account", f.creator.ID, 0)
}
func (w *ridLifecycleWorld) deleteCreator(t *testing.T) {
	w.deleteCreatorObserved(t, nil)
}
func (w *ridLifecycleWorld) deleteCreatorObserved(t *testing.T, public *rid05PublicContext) {
	t.Helper()
	w.revokeCreatorKeys(t)
	w.creatorReferenceCensus(t, "")
	public.keysClean(t, w)
	public.beforeNativeDelete(t, w)
	before := w.snapshot(t)
	w.f.ridOperation(t, "DELETE", "/iam/v1/serviceAccounts/"+w.f.creator.ID, w.f.operator.Bearer(), nil, 0)
	code, raw := w.f.ridRequest(t, "GET", "/iam/v1/serviceAccounts/"+w.f.creator.ID, w.f.operator.Bearer(), nil)
	require.Equal(t, 404, code)
	var refusal struct{ Code int }
	require.NoError(t, json.Unmarshal(raw, &refusal))
	require.Equal(t, 5, refusal.Code)
	require.Equal(t, before, w.snapshot(t), "creator deletion preserves historical delegatedBy and existing bindings")
	var n int
	require.NoError(t, w.f.given.pool.QueryRow(w.f.given.ctx, `SELECT count(*) FROM kaname.service_accounts WHERE id=$1`, w.f.creator.ID).Scan(&n))
	require.Zero(t, n)
	public.nativeDeleted(t, w)
	public.deleted(t, w)
}
func (w *ridLifecycleWorld) oldCredentialRefused(t *testing.T) {
	w.oldCredentialRefusedObserved(t, nil)
}
func (w *ridLifecycleWorld) oldCredentialRefusedObserved(t *testing.T, public *rid05PublicContext) {
	t.Helper()
	code, oauth, assertion, err := w.f.wire.StandingKeyRefusal(w.f.given.ctx, w.f.creator, "https://kaname.local", "https://kaname.local")
	w.f.secrets = append(w.f.secrets, assertion)
	require.NoError(t, err)
	require.Equal(t, 401, code)
	require.Equal(t, "invalid_client", oauth)
	public.beforeRefusedApply(t, w)
	w.refusedApplyObserved(t, installationResult{Stage: "authentication", Code: "UNAUTHENTICATED"}, func() { public.refusalBeforeRestore(t, w) })
	public.afterRefusedApply(t, w)
}
func rid05DeletedWorld(t *testing.T, w *ridLifecycleWorld) (*iamv1.AccessBinding, map[string]any) {
	return rid05DeletedWorldObserved(t, w, nil)
}
func rid05DeletedWorldObserved(t *testing.T, w *ridLifecycleWorld, public *rid05PublicContext) (*iamv1.AccessBinding, map[string]any) {
	t.Helper()
	g, body := rid04Retire(t, w)
	public.prepare(t, w, g, body)
	w.deleteCreatorObserved(t, public)
	w.issuerToken = w.f.ridToken(t, w.issuer)
	w.denied(t, "/iam/v1/accessBindings", w.issuerToken, body)
	w.unchangedActive(t, g)
	return g, body
}
func rid05NewSameName(t *testing.T, w *ridLifecycleWorld) string {
	t.Helper()
	id := w.f.ridSA(t, w.f.creator.AccountID, "rid-native-standing-creator")
	require.NotEqual(t, w.f.creator.ID, id)
	var got iamv1.ServiceAccount
	w.f.publicRead(t, "/iam/v1/serviceAccounts/"+id, &got)
	require.Equal(t, "rid-native-standing-creator", got.Name)
	require.Equal(t, w.f.creator.AccountID, got.AccountId)
	w.f.ridAuthorityMaterialized(t, id, false)
	requireNativeAuthority(t, w.f.given, "service_account", id, 0)
	return id
}
func ridNativeCreatorDelete(t *testing.T) {
	rid03BothModes(t, false, func(t *testing.T, w *ridLifecycleWorld) {
		public := rid05PublicConsumer(t, w, "deleted")
		rid05DeletedWorldObserved(t, w, public)
		w.oldCredentialRefusedObserved(t, public)
		public.deletedGrant(t, w)
	})
}
func ridNativeSameNameDoesNotRestore(t *testing.T) {
	rid03BothModes(t, false, func(t *testing.T, w *ridLifecycleWorld) {
		public := rid05PublicConsumer(t, w, "same-name")
		g, body := rid05DeletedWorldObserved(t, w, public)
		w.oldCredentialRefusedObserved(t, public)
		before := w.snapshot(t)
		c2 := rid05NewSameName(t, w)
		public.sameName(t, w, c2)
		require.Equal(t, before, w.snapshot(t))
		w.issuerToken = w.f.ridToken(t, w.issuer)
		w.denied(t, "/iam/v1/accessBindings", w.issuerToken, body)
		w.unchangedActive(t, g)
		w.oldCredentialRefusedObserved(t, public)
		w.unchangedActive(t, g)
	})
}
func ridNativeActiveDelegateDeleteGuard(t *testing.T) {
	rid03BothModes(t, false, func(t *testing.T, w *ridLifecycleWorld) {
		public := rid05PublicConsumer(t, w, "delete-guard")
		g, _ := rid04Retire(t, w)
		public.prepare(t, w, g, nil)
		w.revokeCreatorKeys(t)
		// O explicitly creates one independent lawful delegation TO C. C remains
		// retired and has no keys; only this active delegate reference blocks Delete.
		op := w.f.ridOperation(t, "POST", "/iam/v1/grantDelegations", w.f.operator.Bearer(), w.gdCreateBody(w.f.tenantID, w.f.creator.ID), 0)
		blocking := ridResponseID(t, op)
		w.creatorReferenceCensus(t, blocking)
		before := w.snapshot(t)
		failed := w.f.ridOperation(t, "DELETE", "/iam/v1/serviceAccounts/"+w.f.creator.ID, w.f.operator.Bearer(), nil, 9)
		require.Equal(t, fmt.Sprintf("service account %s holds an active grant delegation %s; revoke it first", w.f.creator.ID, blocking), failed.Error.Message)
		require.Equal(t, before, w.snapshot(t))
		public.guardedDelete(t, w, blocking)
		w.f.ridOperation(t, "POST", "/iam/v1/grantDelegations/"+blocking+":revoke", w.f.operator.Bearer(), map[string]any{}, 0)
		w.creatorReferenceCensus(t, "")
		if public == nil {
			w.f.ridOperation(t, "DELETE", "/iam/v1/serviceAccounts/"+w.f.creator.ID, w.f.operator.Bearer(), nil, 0)
		} else {
			public.deleteTwin(t, w, blocking)
		}
		code, _ := w.f.ridRequest(t, "GET", "/iam/v1/serviceAccounts/"+w.f.creator.ID, w.f.operator.Bearer(), nil)
		require.Equal(t, 404, code)
		w.unchangedActive(t, g)
	})
}
func ridNativeCreatorExplicitReplacement(t *testing.T) {
	rid03BothModes(t, false, func(t *testing.T, w *ridLifecycleWorld) {
		public := rid05PublicConsumer(t, w, "recovery")
		g, body := rid05DeletedWorldObserved(t, w, public)
		w.oldCredentialRefusedObserved(t, public)
		c2 := rid05NewSameName(t, w)
		public.sameName(t, w, c2)
		w.f.ridAdmin(t, c2, true)
		w.f.ridAuthorityMaterialized(t, c2, true)
		key := w.f.ridKey(t, c2, w.f.creator.AccountID, "replacement-creator")
		token := w.f.ridToken(t, key)
		// Name and even explicit C2 authority cannot revive a GD authored by old C.
		w.issuerToken = w.f.ridToken(t, w.issuer)
		w.denied(t, "/iam/v1/accessBindings", w.issuerToken, body)
		public.noRevival(t, w, c2)
		old := map[string]*iamv1.GrantDelegation{}
		for _, account := range w.accounts {
			for _, gd := range w.delegations(t, account) {
				require.Equal(t, w.f.creator.ID, gd.DelegatedBy.Id)
				old[gd.Id] = proto.Clone(gd).(*iamv1.GrantDelegation)
				w.f.ridOperation(t, "POST", "/iam/v1/grantDelegations/"+gd.Id+":revoke", w.f.operator.Bearer(), map[string]any{}, 0)
			}
			op := w.f.ridOperation(t, "POST", "/iam/v1/grantDelegations", token, w.gdCreateBody(account, w.issuer.ID), 0)
			newID := ridResponseID(t, op)
			require.NotContains(t, old, newID)
			var created iamv1.GrantDelegation
			w.f.publicRead(t, "/iam/v1/grantDelegations/"+newID, &created)
			require.Equal(t, c2, created.DelegatedBy.Id)
			if account == w.f.tenantID {
				w.gd = &created
			}
		}
		var revokedGrant iamv1.AccessBinding
		w.f.publicRead(t, "/iam/v1/accessBindings/"+g.Id, &revokedGrant)
		require.Equal(t, iamv1.AccessBinding_REVOKED, revokedGrant.Status)
		require.Equal(t, "REVOCATION_REASON_DELEGATION_REVOKED", revokedGrant.GetRevocationReason().String())
		history := w.snapshot(t)
		public.beforeReapply(t, w, c2)
		w.delivery.CredentialFile = key.CredentialFile
		requireNativeOK(t, w.f.apply(t, w.delivery), len(w.accounts))
		w.f.renewOperator(t, w.f.given.ctx)
		require.Equal(t, history, w.snapshot(t))
		for _, account := range w.accounts {
			list := w.delegations(t, account)
			require.Len(t, list, 2)
			for _, gd := range list {
				if previous, ok := old[gd.Id]; ok {
					require.Equal(t, iamv1.GrantDelegation_REVOKED, gd.Status)
					require.Equal(t, previous.DelegatedBy.Id, gd.DelegatedBy.Id)
					require.True(t, proto.Equal(previous.CreatedAt, gd.CreatedAt))
					require.Equal(t, previous.RoleIds, gd.RoleIds)
					require.Equal(t, previous.TargetTypes, gd.TargetTypes)
					require.Equal(t, previous.SubjectTypes, gd.SubjectTypes)
					require.True(t, proto.Equal(previous.Delegate, gd.Delegate))
					require.Equal(t, previous.AccountId, gd.AccountId)
				} else {
					require.Equal(t, c2, gd.DelegatedBy.Id)
					require.Equal(t, iamv1.GrantDelegation_ACTIVE, gd.Status)
				}
			}
		}
		public.recoveryReady(t, w, c2)
		w.issuerToken = w.f.ridToken(t, w.issuer)
		public.recoveredGrant(t, w, c2)
		w.grant(t, body)
	})
}
