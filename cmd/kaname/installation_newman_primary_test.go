// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

type rid08NewmanExpectation struct {
	Phase             string           `json:"phase"`
	Operator          string           `json:"operatorId"`
	Creator           string           `json:"creatorId"`
	System            string           `json:"systemId"`
	Accounts          []string         `json:"accounts"`
	Delegated         []string         `json:"delegatedAccounts"`
	ServiceAccounts   []map[string]any `json:"serviceAccounts"`
	Delegations       []map[string]any `json:"delegations"`
	Previous          []map[string]any `json:"previousDelegations"`
	TenantNamedSystem string           `json:"tenantNamedSystem"`
	Future            string           `json:"futureAccountId"`
}

func rid08NewmanPhase(t *testing.T, f *installationNativeWorld, phase string, wanted []string, previous []map[string]any, tenantNamedSystem, future, deleted string) []map[string]any {
	t.Helper()
	stem := "registry-installation-rid08"
	caseID := stem + "-" + strings.ToUpper(phase)
	if os.Getenv("KANAME_RID_NEWMAN") != "1" {
		rid08Write(t, f.session.Root, "newman-"+phase, map[string]any{"state": "NOT_EXECUTED", "caseId": caseID, "wholeDoDAccepted": false})
		return nil
	}
	expected := rid08ReadNewmanPrimary(t, f, phase, wanted, previous, tenantNamedSystem, future)
	variables := map[string]any{"rid08Expected": expected, "ridSystemId": f.baseline.SystemID, "ridDeletedAccountId": deleted}
	receipt := ridRunNewmanPhase(t, f, stem, caseID, phase, variables)
	require.True(t, receipt.OK)
	return expected.Delegations
}

// Первичные проекции получаются независимо от ЛЮБОГО публичного ответа.
// Чтения SQL не могут выдумать публичный исход: порождённая коллекция Newman
// сама выполняет запросы страниц/Get/идентичности и сравнивает каждое заявленное поле.
func rid08ReadNewmanPrimary(t *testing.T, f *installationNativeWorld, phase string, wanted []string, previous []map[string]any, tenantNamedSystem, future string) rid08NewmanExpectation {
	t.Helper()
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
	e := rid08NewmanExpectation{Phase: phase, Operator: string(f.given.user), Creator: f.creator.ID, System: f.baseline.SystemID,
		Accounts: []string{}, Delegated: append([]string{}, wanted...), ServiceAccounts: []map[string]any{}, Delegations: []map[string]any{}, Previous: append([]map[string]any{}, previous...), TenantNamedSystem: tenantNamedSystem, Future: future}
	sort.Strings(e.Delegated)
	accounts, err := tx.Query(ctx, "SELECT id FROM kaname.accounts ORDER BY id")
	require.NoError(t, err)
	for accounts.Next() {
		var id string
		require.NoError(t, accounts.Scan(&id))
		e.Accounts = append(e.Accounts, id)
	}
	require.NoError(t, accounts.Err())
	accounts.Close()
	require.Contains(t, e.Accounts, e.System)
	sas, err := tx.Query(ctx, "SELECT id,name,created_at FROM kaname.service_accounts WHERE account_id=$1 ORDER BY id", e.System)
	require.NoError(t, err)
	for sas.Next() {
		var id, name string
		var created time.Time
		require.NoError(t, sas.Scan(&id, &name, &created))
		e.ServiceAccounts = append(e.ServiceAccounts, map[string]any{"id": id, "accountId": e.System, "name": name, "createdAt": created.UTC().Truncate(time.Second).Format(time.RFC3339)})
	}
	require.NoError(t, sas.Err())
	sas.Close()
	require.Len(t, e.ServiceAccounts, 5)
	gd, err := tx.Query(ctx, `SELECT g.id,g.account_id,g.delegate_id,g.delegated_by_type,g.delegated_by_id,g.module,g.status,
 g.role_ids,g.target_types,g.subject_types,g.created_at,r.id
 FROM kaname.grant_delegations g
 LEFT JOIN kaname.roles r ON r.name=g.module||'.reader' AND r.owner_module=g.module AND r.cluster_id=$1 AND r.live
 ORDER BY g.id`, domain.ClusterSingletonID)
	require.NoError(t, err)
	seen := map[string]bool{}
	for gd.Next() {
		var id, account, delegate, creatorKind, creator, module, status string
		var role *string
		var roles, targets, subjects []string
		var created time.Time
		require.NoError(t, gd.Scan(&id, &account, &delegate, &creatorKind, &creator, &module, &status, &roles, &targets, &subjects, &created, &role))
		require.False(t, seen[id])
		seen[id] = true
		require.NotNil(t, role)
		require.Contains(t, e.Delegated, account)
		require.NotEqual(t, e.System, account)
		require.Contains(t, []string{"ridfirst", "ridsecond"}, module)
		require.Equal(t, e.Creator, creator)
		require.Equal(t, "service_account", creatorKind)
		require.Equal(t, "ACTIVE", status)
		require.Equal(t, []string{*role}, roles)
		require.Equal(t, []string{module + ".objects"}, targets)
		require.Equal(t, []string{"service_account"}, subjects)
		foundDelegate := false
		for _, sa := range e.ServiceAccounts {
			if sa["id"] == delegate {
				foundDelegate = true
				require.Equal(t, "svc-"+module, sa["name"])
			}
		}
		require.True(t, foundDelegate)
		require.NotEqual(t, e.Creator, delegate)
		e.Delegations = append(e.Delegations, map[string]any{
			"id": id, "accountId": account, "module": module, "status": status,
			"createdAt":   created.UTC().Truncate(time.Second).Format(time.RFC3339),
			"delegate":    map[string]string{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": delegate},
			"delegatedBy": map[string]string{"type": creatorKind, "id": creator},
			"roleIds":     roles, "targetTypes": targets, "subjectTypes": []string{"SUBJECT_TYPE_SERVICE_ACCOUNT"},
		})
	}
	require.NoError(t, gd.Err())
	gd.Close()
	require.Len(t, e.Delegations, 2*len(e.Delegated))
	require.NoError(t, tx.Commit(ctx))
	return e
}
