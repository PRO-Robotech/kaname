// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func (f *installationNativeWorld) ridAuthorityMaterialized(t *testing.T, id string, want bool) {
	t.Helper()
	conn, err := f.wire.ModuleWriter(filepath.Join(f.session.Root, "pki"))
	require.NoError(t, err)
	defer conn.Close()
	client := iamv1.NewInternalIAMServiceClient(conn)
	ctx, cancel := context.WithTimeout(f.given.ctx, 20*time.Second)
	defer cancel()
	for {
		o, e := client.Check(ctx, &iamv1.CheckRequest{SubjectId: "user:" + f.operator.UserID(), Relation: "system_admin", Object: "cluster:cluster_root", Consistency: iamv1.CheckRequest_HIGHER_CONSISTENCY})
		require.NoError(t, e)
		require.True(t, o.Allowed, "independent O remains authorized on same live judge")
		c, e := client.Check(ctx, &iamv1.CheckRequest{SubjectId: "service_account:" + id, Relation: "system_admin", Object: "cluster:cluster_root", Consistency: iamv1.CheckRequest_HIGHER_CONSISTENCY})
		require.NoError(t, e)
		if c.Allowed == want {
			requireNativeAuthority(t, f.given, "service_account", id, map[bool]int{true: 1, false: 0}[want])
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("current authority not materialized")
		case <-time.After(25 * time.Millisecond):
		}
	}
}
func rid04Retire(t *testing.T, w *ridLifecycleWorld) (*iamv1.AccessBinding, map[string]any) {
	t.Helper()
	f := w.f
	// C is a SYS service account; O owns A. No direct tenant role was given to C.
	require.NotEqual(t, f.creator.AccountID, f.tenantID)
	var owner string
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, f.tenantID).Scan(&owner))
	require.Equal(t, f.operator.UserID(), owner)
	require.Empty(t, f.ridList(t, "/iam/v1/accessBindings", "accessBindings", url.Values{"filter": {fmt.Sprintf("subject=%q", f.creator.ID)}}), "C has no direct tenant role")
	var memberships int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.group_members WHERE member_type='service_account' AND member_id=$1`, f.creator.ID).Scan(&memberships))
	require.Zero(t, memberships, "C has no group-derived tenant role")
	u := f.ridSA(t, f.tenantID, "rid-before-retirement")
	g := w.grant(t, w.bindingInput("service_account", u, w.pull, "registry.registries", w.object))
	u2 := f.ridSA(t, f.tenantID, "rid-after-retirement")
	body := w.bindingInput("service_account", u2, w.pull, "registry.registries", w.object)
	before := w.snapshot(t)
	f.ridAdmin(t, f.creator.ID, false)
	f.ridAuthorityMaterialized(t, f.creator.ID, false)
	require.Equal(t, before, w.snapshot(t), "retirement does not revoke historical grants or GD")
	// Renew the genuine I credential after retirement, so a stale token is not
	// the explanation for the current-creator authority refusal.
	w.issuerToken = f.ridToken(t, w.issuer)
	w.denied(t, "/iam/v1/accessBindings", w.issuerToken, body)
	return g, body
}
func (w *ridLifecycleWorld) unchangedActive(t *testing.T, g *iamv1.AccessBinding) {
	t.Helper()
	var got iamv1.AccessBinding
	w.f.publicRead(t, "/iam/v1/accessBindings/"+g.Id, &got)
	require.True(t, proto.Equal(g, &got))
	require.Equal(t, iamv1.AccessBinding_ACTIVE, got.Status)
	found := false
	for _, gd := range w.delegations(t, w.f.tenantID) {
		if gd.Id == w.gd.Id {
			found = true
			require.True(t, proto.Equal(w.gd, gd))
			require.Equal(t, iamv1.GrantDelegation_ACTIVE, gd.Status)
		}
	}
	require.True(t, found)
}
func ridNativeCreatorRetired(t *testing.T) {
	rid03BothModes(t, false, func(t *testing.T, w *ridLifecycleWorld) { g, _ := rid04Retire(t, w); w.unchangedActive(t, g) })
}
func ridNativeRetirementApplyDenied(t *testing.T) {
	rid03BothModes(t, false, func(t *testing.T, w *ridLifecycleWorld) {
		g, body := rid04Retire(t, w)
		w.refusedApply(t, installationResult{Stage: "preflight-authority", Code: "PERMISSION_DENIED", Field: "moduleSeedInstaller.credentialFile"})
		w.f.ridAuthorityMaterialized(t, w.f.creator.ID, false)
		w.issuerToken = w.f.ridToken(t, w.issuer)
		w.denied(t, "/iam/v1/accessBindings", w.issuerToken, body)
		w.unchangedActive(t, g)
	})
}
func ridNativeRetirementExplicitTwin(t *testing.T) {
	rid03BothModes(t, false, func(t *testing.T, w *ridLifecycleWorld) {
		g, body := rid04Retire(t, w)
		w.refusedApply(t, installationResult{Stage: "preflight-authority", Code: "PERMISSION_DENIED", Field: "moduleSeedInstaller.credentialFile"})
		before := w.snapshot(t)
		w.f.ridAdmin(t, w.f.creator.ID, true)
		w.f.ridAuthorityMaterialized(t, w.f.creator.ID, true)
		require.Equal(t, before, w.snapshot(t), "only explicit admin authority changed")
		w.issuerToken = w.f.ridToken(t, w.issuer)
		next := w.grant(t, body)
		require.Equal(t, w.gd.Id, next.DelegationId)
		requireNativeOK(t, w.f.apply(t, w.delivery), len(w.accounts))
		w.f.renewOperator(t, w.f.given.ctx)
		w.unchangedActive(t, g)
	})
}
