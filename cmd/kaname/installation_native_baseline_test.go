// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/servicemanifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/stretchr/testify/require"
)

// These are observations of stock migration data, never fixture seed writers.
// Keep the bootstrap identity and its authority while proving that the new O
// receives neither from the initial user/session Given.
type nativeBaseline struct {
	ServiceAccounts map[string]json.RawMessage `json:"serviceAccounts"`
	AdminGrants     map[string]json.RawMessage `json:"adminGrants"`
	SystemID        string                     `json:"systemId"`
	SystemOwner     string                     `json:"systemOwner"`
}

func readNativeBaseline(t *testing.T, w *ceremonyWorld) nativeBaseline {
	t.Helper()
	var b nativeBaseline
	var sas, admins []byte
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT
 COALESCE((SELECT jsonb_object_agg(id,to_jsonb(s)) FROM kaname.service_accounts s),'{}'::jsonb),
 COALESCE((SELECT jsonb_object_agg(id,to_jsonb(g)) FROM kaname.cluster_admin_grants g),'{}'::jsonb),
 (SELECT id FROM kaname.accounts WHERE name='system'),
 (SELECT owner_user_id FROM kaname.accounts WHERE name='system')`).Scan(&sas, &admins, &b.SystemID, &b.SystemOwner))
	require.NoError(t, json.Unmarshal(sas, &b.ServiceAccounts))
	require.NoError(t, json.Unmarshal(admins, &b.AdminGrants))
	return b
}

func (b nativeBaseline) requirePreserved(t *testing.T, w *ceremonyWorld, addedSAs, addedAdmins int) {
	t.Helper()
	now := readNativeBaseline(t, w)
	require.Equal(t, b.SystemID, now.SystemID)
	require.Equal(t, b.SystemOwner, now.SystemOwner)
	require.Len(t, now.ServiceAccounts, len(b.ServiceAccounts)+addedSAs)
	require.Len(t, now.AdminGrants, len(b.AdminGrants)+addedAdmins)
	for id, row := range b.ServiceAccounts {
		require.JSONEq(t, string(row), string(now.ServiceAccounts[id]), "stock SA must survive ordinary startup")
	}
	for id, row := range b.AdminGrants {
		require.JSONEq(t, string(row), string(now.AdminGrants[id]), "stock admin grant must survive ordinary startup")
	}
}

func requireNativeAuthority(t *testing.T, w *ceremonyWorld, kind, id string, count int) {
	t.Helper()
	var grants, facts int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT
 (SELECT count(*) FROM kaname.cluster_admin_grants WHERE cluster_id=$1 AND subject_type=$2 AND subject_id=$3 AND (granted_until IS NULL OR granted_until>now())),
 (SELECT count(*) FROM kaname.relation_fact WHERE object_type='cluster' AND object_id=$1 AND relation='system_admin' AND subject=$2||':'||$3)`, domain.ClusterSingletonID, kind, id).Scan(&grants, &facts))
	require.Equal(t, count, grants, "subject's durable current admin grant")
	require.Equal(t, count, facts, "subject's materialized current admin relation")
}

func requireNativeNoDelivery(t *testing.T, w *ceremonyWorld) {
	t.Helper()
	var delegations, issuers int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT
 (SELECT count(*) FROM kaname.grant_delegations),
 (SELECT count(*) FROM kaname.service_accounts WHERE name IN ('svc-ridfirst','svc-ridsecond'))`).Scan(&delegations, &issuers))
	require.Zero(t, delegations, "no GD before actual delivered startup")
	require.Zero(t, issuers, "no I before actual delivered startup")
}

func requireNativeManifestPremise(t *testing.T) {
	t.Helper()
	own, err := servicemanifest.Load()
	require.NoError(t, err)
	delivery := installruntime.NewRIDDeliveryFixture()
	var modules []*manifest.Manifest
	for _, raw := range [][]byte{delivery.First, delivery.Second} {
		m, err := manifest.Load(raw)
		require.NoError(t, err)
		modules = append(modules, m)
	}
	for _, order := range [][]*manifest.Manifest{modules, {modules[1], modules[0]}} {
		require.NoError(t, moduleseed.Preflight(own, order))
		_, err := prepareComposedModel(quietLogger(), order)
		require.NoError(t, err, "pure full-delivery preparation must be lawful before starting PostgreSQL")
	}
}

func TestInstallationNativeManifestPremise(t *testing.T) { requireNativeManifestPremise(t) }

func writeNativeBaseline(t *testing.T, evidence string, b nativeBaseline) {
	t.Helper()
	raw, err := json.Marshal(b)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(evidence, "migration-baseline.json"), raw, 0600))
}

func (f *installationNativeWorld) requireDeliveredPairs(t *testing.T, modules ...string) {
	if len(modules) == 0 {
		modules = []string{"ridfirst", "ridsecond"}
	}
	t.Helper()
	var count int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.grant_delegations`).Scan(&count))
	require.Equal(t, len(modules), count, "one observed tenant times the delivered issuers")
	seen := map[string]bool{}
	for _, module := range modules {
		var id, account, delegate, creatorType, creator, status, saAccount, role string
		var roles, targets, subjects []string
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT g.id,g.account_id,g.delegate_id,g.delegated_by_type,g.delegated_by_id,g.status,
    g.role_ids,g.target_types,g.subject_types,s.account_id,
    (SELECT id FROM kaname.roles WHERE name=$1||'.reader' AND owner_module=$1 AND cluster_id=$2 AND live)
   FROM kaname.grant_delegations g JOIN kaname.service_accounts s ON s.id=g.delegate_id
   WHERE g.module=$1 AND s.name='svc-'||$1`, module, domain.ClusterSingletonID).Scan(&id, &account, &delegate, &creatorType, &creator, &status, &roles, &targets, &subjects, &saAccount, &role))
		require.False(t, seen[id])
		seen[id] = true
		require.Equal(t, f.tenantID, account)
		require.Equal(t, f.baseline.SystemID, saAccount)
		require.NotEqual(t, f.creator.ID, delegate)
		require.Equal(t, "service_account", creatorType)
		require.Equal(t, f.creator.ID, creator)
		require.Equal(t, "ACTIVE", status)
		require.Equal(t, []string{role}, roles)
		require.Equal(t, []string{module + ".objects"}, targets)
		require.Equal(t, []string{string(domain.SubjectTypeServiceAccount)}, subjects)
		requireNativeAuthority(t, f.given, "service_account", delegate, 0)
	}
	f.baseline.requirePreserved(t, f.given, len(modules)+1, 2)
	requireNativeAuthority(t, f.given, "user", string(f.given.user), 1)
	requireNativeAuthority(t, f.given, "service_account", f.creator.ID, 1)
	f.lastPublic = f.requirePublicDeliveredPairs(t, modules...)
}
