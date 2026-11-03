// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// The history retains the entire primary GD row, including sub-second dates and
// physical axis order. Only the separate public projection canonicalizes sets.
type rid02NewmanHistory struct {
	Delegations []map[string]any           `json:"delegations"`
	Rows        map[string]json.RawMessage `json:"rows"`
}
type rid02NewmanExpectation struct {
	Phase             string           `json:"phase"`
	Mode              string           `json:"mode"`
	Operator          string           `json:"operatorId"`
	Creator           string           `json:"creatorId"`
	Issuer            string           `json:"issuerId"`
	System            string           `json:"systemId"`
	TenantNamedSystem string           `json:"tenantNamedSystem"`
	Accounts          []string         `json:"accounts"`
	Delegated         []string         `json:"delegatedAccounts"`
	ServiceAccounts   []map[string]any `json:"serviceAccounts"`
	Delegations       []map[string]any `json:"delegations"`
	Previous          []map[string]any `json:"previousDelegations"`
}

func rid02NewmanPhase(t *testing.T, f *installationNativeWorld, mode, phase string, wanted []string, previous *rid02NewmanHistory) *rid02NewmanHistory {
	t.Helper()
	require.Contains(t, []string{"S1", "S2"}, mode)
	require.Contains(t, []string{"BEFORE-REORDER", "AFTER-REORDER"}, phase)
	stem := "registry-installation-rid02"
	label := "rid02-" + strings.ToLower(mode+"-"+phase)
	caseID := stem + "-" + mode + "-" + phase
	if os.Getenv("KANAME_RID_NEWMAN") != "1" {
		rid08Write(t, f.session.Root, "newman-"+label, map[string]any{"state": "NOT_EXECUTED", "caseId": caseID, "wholeDoDAccepted": false})
		return nil
	}
	e, history := rid02ReadNewmanPrimary(t, f, mode, phase, wanted, previous)
	receipt := ridRunNewmanPhase(t, f, stem, caseID, label, map[string]any{"rid02Expected": e, "ridSystemId": e.System})
	require.True(t, receipt.OK)
	return history
}

// Independent primary-only snapshot: no REST observation supplies expected IDs,
// membership, role linkage, issuer identity, timestamps or expected pair count.
func rid02ReadNewmanPrimary(t *testing.T, f *installationNativeWorld, mode, phase string, wanted []string, previous *rid02NewmanHistory) (rid02NewmanExpectation, *rid02NewmanHistory) {
	t.Helper()
	n := 1
	if mode == "S2" {
		n = 3
	}
	require.Len(t, wanted, n)
	ctx, cancel := context.WithTimeout(f.given.ctx, 20*time.Second)
	defer cancel()
	tx, err := f.given.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() {
		cleanup, c := context.WithTimeout(context.Background(), time.Second)
		defer c()
		_ = tx.Rollback(cleanup)
	}()
	var recovery bool
	require.NoError(t, tx.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&recovery))
	require.False(t, recovery)
	e := rid02NewmanExpectation{Phase: phase, Mode: mode, Operator: string(f.given.user), Creator: f.creator.ID, System: f.baseline.SystemID,
		Accounts: []string{}, Delegated: append([]string{}, wanted...), ServiceAccounts: []map[string]any{}, Delegations: []map[string]any{}, Previous: []map[string]any{}}
	sort.Strings(e.Delegated)
	rows, err := tx.Query(ctx, "SELECT id,name,owner_user_id FROM kaname.accounts ORDER BY id")
	require.NoError(t, err)
	for rows.Next() {
		var id, name, owner string
		require.NoError(t, rows.Scan(&id, &name, &owner))
		e.Accounts = append(e.Accounts, id)
		if id == e.System {
			require.Equal(t, "system", name)
			require.Equal(t, f.baseline.SystemOwner, owner)
		} else {
			require.Contains(t, e.Delegated, id)
			require.Equal(t, e.Operator, owner)
		}
		if name == "system-tenant" {
			require.NotEqual(t, e.System, id)
			e.TenantNamedSystem = id
		}
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Len(t, e.Accounts, n+1)
	require.Contains(t, e.Accounts, e.System)
	require.NotContains(t, e.Delegated, e.System)
	if mode == "S2" {
		require.NotEmpty(t, e.TenantNamedSystem)
		require.Contains(t, e.Delegated, e.TenantNamedSystem)
	}
	sas, err := tx.Query(ctx, "SELECT id,name,description,labels,created_at,enabled FROM kaname.service_accounts WHERE account_id=$1 ORDER BY id", e.System)
	require.NoError(t, err)
	saIDs := map[string]bool{}
	for sas.Next() {
		var id, name, description string
		var labels map[string]string
		var created time.Time
		var enabled bool
		require.NoError(t, sas.Scan(&id, &name, &description, &labels, &created, &enabled))
		if labels == nil {
			labels = map[string]string{}
		}
		saIDs[id] = true
		if name == "svc-ridbounds" {
			require.Empty(t, e.Issuer)
			e.Issuer = id
			require.True(t, enabled)
		}
		e.ServiceAccounts = append(e.ServiceAccounts, map[string]any{"id": id, "accountId": e.System, "name": name, "description": description, "labels": labels, "enabled": enabled, "createdAt": created.UTC().Truncate(time.Second).Format(time.RFC3339)})
	}
	require.NoError(t, sas.Err())
	sas.Close()
	require.Len(t, f.baseline.ServiceAccounts, 2)
	require.Len(t, e.ServiceAccounts, 4)
	require.True(t, saIDs[e.Creator])
	require.NotEmpty(t, e.Issuer)
	require.NotEqual(t, e.Creator, e.Issuer)
	for id := range f.baseline.ServiceAccounts {
		require.True(t, saIDs[id])
		require.NotEqual(t, id, e.Issuer)
		require.NotEqual(t, id, e.Creator)
	}
	roles := []string{}
	for _, name := range []string{"ridbounds.reader00", "ridbounds.reader01"} {
		var id string
		require.NoError(t, tx.QueryRow(ctx, "SELECT id FROM kaname.roles WHERE name=$1 AND owner_module='ridbounds' AND cluster_id=$2 AND live", name, domain.ClusterSingletonID).Scan(&id))
		roles = append(roles, id)
	}
	sort.Strings(roles)
	history := &rid02NewmanHistory{Rows: map[string]json.RawMessage{}, Delegations: []map[string]any{}}
	gd, err := tx.Query(ctx, `SELECT g.id,g.account_id,g.delegate_id,g.delegated_by_type,g.delegated_by_id,g.module,g.status,
 g.role_ids,g.target_types,g.subject_types,g.created_at,g.revoked_at,g.revoked_by_type,g.revoked_by_id,to_jsonb(g)
 FROM kaname.grant_delegations g ORDER BY g.id`)
	require.NoError(t, err)
	pairs := map[string]bool{}
	for gd.Next() {
		var id, account, delegate, kind, creator, module, status string
		var actualRoles, targets, subjects []string
		var created time.Time
		var revoked *time.Time
		var revokedKind, revokedID *string
		var raw []byte
		require.NoError(t, gd.Scan(&id, &account, &delegate, &kind, &creator, &module, &status, &actualRoles, &targets, &subjects, &created, &revoked, &revokedKind, &revokedID, &raw))
		require.NotContains(t, history.Rows, id)
		require.NotContains(t, pairs, account)
		pairs[account] = true
		require.Contains(t, e.Delegated, account)
		require.NotEqual(t, e.System, account)
		require.Equal(t, "ridbounds", module)
		require.Equal(t, e.Issuer, delegate)
		require.Equal(t, e.Creator, creator)
		require.Equal(t, "service_account", kind)
		require.Equal(t, "ACTIVE", status)
		require.Nil(t, revoked)
		require.Nil(t, revokedKind)
		require.Nil(t, revokedID)
		sort.Strings(actualRoles)
		sort.Strings(targets)
		sort.Strings(subjects)
		require.Equal(t, roles, actualRoles)
		require.Equal(t, []string{"ridbounds.objects00", "ridbounds.objects01"}, targets)
		require.Equal(t, []string{"group", "service_account", "system_class", "user"}, subjects)
		publicSubjects := []string{}
		for _, subject := range subjects {
			publicSubjects = append(publicSubjects, "SUBJECT_TYPE_"+strings.ToUpper(subject))
		}
		projected := map[string]any{"id": id, "accountId": account, "module": module, "status": status, "createdAt": created.UTC().Truncate(time.Second).Format(time.RFC3339),
			"delegate": map[string]string{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": delegate}, "delegatedBy": map[string]string{"type": kind, "id": creator},
			"roleIds": actualRoles, "targetTypes": targets, "subjectTypes": publicSubjects}
		history.Rows[id] = append(json.RawMessage{}, raw...)
		history.Delegations = append(history.Delegations, projected)
	}
	require.NoError(t, gd.Err())
	gd.Close()
	require.Len(t, history.Rows, n)
	require.Len(t, pairs, n)
	e.Delegations = history.Delegations
	if phase == "AFTER-REORDER" {
		require.NotNil(t, previous, "same-world before projection mandatory")
		require.Equal(t, previous.Rows, history.Rows, "full stored GD rows remain byte-exact, including IDs and full precision created_at")
		require.Equal(t, previous.Delegations, history.Delegations)
		e.Previous = previous.Delegations
	} else {
		require.Nil(t, previous)
	}
	require.NoError(t, tx.Commit(ctx))
	return e, history
}
