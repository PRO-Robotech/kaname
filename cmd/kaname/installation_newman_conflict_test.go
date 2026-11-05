// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type rid07NewmanInput struct {
	Axis, Mode                                 string
	Exact                                      bool
	OldPair, ActivePair, OldGrant, ActiveGrant string
}
type rid07LivePublicConsumer func(*testing.T, *ridLifecycleWorld, rid07NewmanInput, string)
type rid07NewmanSnapshot struct {
	Projection rid09NewmanProjection    `json:"projection"`
	Whole      ridWholeDeliverySnapshot `json:"-"`
}
type rid07NewmanExpectation struct {
	CaseID      string                 `json:"caseId"`
	Axis        string                 `json:"axis"`
	Mode        string                 `json:"mode"`
	Twin        bool                   `json:"twin"`
	Phase       string                 `json:"phase"`
	Operator    string                 `json:"operatorId"`
	Creator     string                 `json:"creatorId"`
	System      string                 `json:"systemId"`
	Tenant      string                 `json:"tenantId"`
	NamedSystem string                 `json:"tenantNamedSystem"`
	Issuer      string                 `json:"issuerId"`
	PairCreator string                 `json:"pairCreatorId"`
	PullRole    string                 `json:"pullRoleId"`
	PushRole    string                 `json:"pushRoleId"`
	OldPair     string                 `json:"oldPairId"`
	ActivePair  string                 `json:"activePairId"`
	OldGrant    string                 `json:"oldGrantId"`
	ActiveGrant string                 `json:"activeGrantId"`
	Snapshot    rid07NewmanSnapshot    `json:"snapshot"`
	Previous    *rid09NewmanProjection `json:"previousProjection"`
}

func rid07NewmanAxis(t *testing.T, axis string) string {
	t.Helper()
	names := map[string]string{"role": "ROLEIDS", "target": "TARGETTYPES", "subject": "SUBJECTTYPES", "creator": "DELEGATEDBY"}
	require.Contains(t, names, axis)
	return names[axis]
}
func rid07NewmanCaseID(t *testing.T, in rid07NewmanInput, phase string) string {
	t.Helper()
	require.Contains(t, []string{"before", "after"}, phase)
	require.Contains(t, []string{"S1", "S2"}, in.Mode)
	kind := "NEGATIVE"
	if in.Exact {
		kind = "TWIN"
	}
	return "registry-installation-rid07-" + rid07NewmanAxis(t, in.Axis) + "-" + in.Mode + "-" + kind + "-" + strings.ToUpper(phase)
}

// Вызывающий владеет общим бюджетом, включая все чтения проекций/необработанных данных,
// ожидания и финальный успешный возврат. Это представление контекста только чтения сохраняет
// зафиксированные тело SQL всей таблицы и пул; живое состояние фикстуры не меняется.
func rid07CaptureNewmanSnapshotContext(t *testing.T, ctx context.Context, f *installationNativeWorld) (rid07NewmanSnapshot, bool) {
	t.Helper()
	require.NoError(t, ctx.Err(), "aggregate RID07 snapshot budget expired before read")
	p := rid09ReadNewmanProjectionContext(t, ctx, f)
	readWorld, readGiven := *f, *f.given
	readGiven.ctx = ctx
	readWorld.given = &readGiven
	whole := ridReadWholeDelivery(t, &readWorld)
	after := rid09ReadNewmanProjectionContext(t, ctx, f)
	require.NoError(t, ctx.Err(), "aggregate RID07 snapshot budget expired before return")
	return rid07NewmanSnapshot{Projection: p, Whole: whole}, reflect.DeepEqual(p, after)
}
func rid07ReadNewmanSnapshot(t *testing.T, f *installationNativeWorld) rid07NewmanSnapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.given.ctx, 30*time.Second)
	defer cancel()
	snapshot, stable := rid07CaptureNewmanSnapshotContext(t, ctx, f)
	require.True(t, stable, "fixture NOT_ACCEPTED: primary moved while composing full raw history; no phase retry")
	require.NoError(t, ctx.Err(), "aggregate RID07 phase snapshot budget expired before success return")
	return snapshot
}

// Это наблюдение готовности до первой принятой публичной базы,
// без повтора настоящей фазы Newman. w.grant может возвращать стабильный nil
// materializedAt, поэтому требуем настоящего обогащения активного G и стабильности полного
// журнала проекций/необработанной истории/Operation между двумя полными чтениями.
func rid07NewmanBaseline(t *testing.T, w *ridLifecycleWorld, in rid07NewmanInput) rid07NewmanSnapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(w.f.given.ctx, 30*time.Second)
	defer cancel()
	var previous *rid07NewmanSnapshot
	for {
		require.NoError(t, ctx.Err(), "fixture NOT_ACCEPTED: aggregate RID07 baseline budget expired")
		snapshot, composed := rid07CaptureNewmanSnapshotContext(t, ctx, w.f)
		materialized := false
		for _, binding := range snapshot.Projection.Bindings {
			if binding["id"] == in.ActiveGrant {
				require.Equal(t, "ACTIVE", binding["status"])
				require.Equal(t, in.ActivePair, binding["delegationId"])
				materialized = binding["materializedAt"] != nil
			}
		}
		if materialized && composed && previous != nil &&
			reflect.DeepEqual(previous.Projection, snapshot.Projection) &&
			reflect.DeepEqual(previous.Whole.Delivery, snapshot.Whole.Delivery) &&
			reflect.DeepEqual(previous.Whole.OwnCeilings, snapshot.Whole.OwnCeilings) &&
			reflect.DeepEqual(previous.Whole.Bookkeeping["operations"], snapshot.Whole.Bookkeeping["operations"]) {
			require.NoError(t, ctx.Err(), "aggregate RID07 baseline budget expired before success return")
			return snapshot
		}
		previous = nil
		if materialized && composed {
			previous = &snapshot
		}
		select {
		case <-ctx.Done():
			t.Fatal("fixture NOT_ACCEPTED: aggregate30s RID07 baseline expired before materialized active G and stable full primary history")
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func rid07RequireNewmanPhaseStable(t *testing.T, a, b rid07NewmanSnapshot) {
	t.Helper()
	require.Equal(t, a.Projection, b.Projection, "complete projection and materializedAt preserved during one public phase")
	require.Equal(t, a.Whole.Delivery, b.Whole.Delivery, "all physical delivery/history rows unchanged during read-only phase")
	require.Equal(t, a.Whole.OwnCeilings, b.Whole.OwnCeilings)
	require.Equal(t, a.Whole.Bookkeeping["operations"], b.Whole.Bookkeeping["operations"], "no Operation mutation in one read-only phase")
}
func rid07DefaultNewmanConsumer(t *testing.T, w *ridLifecycleWorld, in rid07NewmanInput) rid07LivePublicConsumer {
	t.Helper()
	f := w.f
	if os.Getenv("KANAME_RID_NEWMAN") != "1" {
		for _, phase := range []string{"before", "after"} {
			id := rid07NewmanCaseID(t, in, phase)
			rid08Write(t, f.session.Root, "newman-"+strings.ToLower(id), map[string]any{"state": "NOT_EXECUTED", "caseId": id, "actualNewmanExecuted": false, "wholeDoDAccepted": false})
		}
		return nil
	}
	calls := 0
	var before *rid07NewmanSnapshot
	t.Cleanup(func() { require.Equal(t, 2, calls, "both exact same-world phases mandatory") })
	return func(t *testing.T, got *ridLifecycleWorld, current rid07NewmanInput, phase string) {
		t.Helper()
		require.Same(t, w, got)
		require.Equal(t, in, current)
		require.Less(t, calls, 2)
		require.Equal(t, calls == 0, phase == "before")
		calls++
		id := rid07NewmanCaseID(t, in, phase)
		var snapshot rid07NewmanSnapshot
		if phase == "before" {
			snapshot = rid07NewmanBaseline(t, w, in)
		} else {
			snapshot = rid07ReadNewmanSnapshot(t, f)
		}
		e := rid07NewmanExpectation{CaseID: id, Axis: rid07NewmanAxis(t, in.Axis), Mode: in.Mode, Twin: in.Exact, Phase: phase, Operator: string(f.given.user), Creator: f.creator.ID, System: f.baseline.SystemID, Tenant: f.tenantID, OldPair: in.OldPair, ActivePair: in.ActivePair, OldGrant: in.OldGrant, ActiveGrant: in.ActiveGrant, Snapshot: snapshot}
		rid07RequireNewmanPremise(t, w, in, &e)
		if phase == "after" {
			require.NotNil(t, before)
			e.Previous = &before.Projection
			require.Equal(t, before.Projection, e.Snapshot.Projection, "full public object/history/materializedAt preserved across conflict or exact twin apply")
			for table, rows := range before.Whole.Delivery {
				if table == "grant_delegations" || strings.HasPrefix(table, "access_binding") {
					require.Contains(t, e.Snapshot.Whole.Delivery, table)
					require.Equal(t, rows, e.Snapshot.Whole.Delivery[table], "all raw GD/G history, targets, materialization rows and identities unchanged")
				}
			}
			// Существующий нативный rid07CheckApplyOperations уже проверяет владельца, метаданные,
			// ответ/ошибку и количество каждой новой штатной GD Operation.
			// Здесь независимо ограничиваем весь журнал: все старые строки сохраняются побайтно,
			// а добавлять строки может ровно эта нативная граница, без общего игнорирования журнала.
			delta := len(w.accounts)
			if !in.Exact {
				for i, account := range w.accounts {
					if account == f.tenantID {
						delta = i + 1
					}
				}
			}
			oldOps, newOps := before.Whole.Bookkeeping["operations"], e.Snapshot.Whole.Bookkeeping["operations"]
			require.Equal(t, oldOps.Columns, newOps.Columns)
			require.Len(t, newOps.Rows, len(oldOps.Rows)+delta)
			for _, row := range oldOps.Rows {
				require.Contains(t, newOps.Rows, row, "every pre-existing full Operation row preserved")
			}
		}
		func() {
			defer func() {
				after := rid07ReadNewmanSnapshot(t, f)
				stable := reflect.DeepEqual(e.Snapshot.Projection, after.Projection) && reflect.DeepEqual(e.Snapshot.Whole.Delivery, after.Whole.Delivery) && reflect.DeepEqual(e.Snapshot.Whole.OwnCeilings, after.Whole.OwnCeilings) && reflect.DeepEqual(e.Snapshot.Whole.Bookkeeping["operations"], after.Whole.Bookkeeping["operations"])
				rid08Write(t, f.session.Root, "newman-"+strings.ToLower(id)+"-primary-bracket", map[string]any{"caseId": id, "fullPrimarySnapshotUnchangedDuringPhase": stable, "wholeDoDAccepted": false})
				rid07RequireNewmanPhaseStable(t, e.Snapshot, after)
			}()
			receipt := ridRunNewmanPhase(t, f, "registry-installation-rid07", id, strings.ToLower(id), map[string]any{"rid07Expected": e})
			require.True(t, receipt.OK)
		}()
		if phase == "before" {
			snapshot := e.Snapshot
			before = &snapshot
		}
	}
}
func rid07RequireNewmanPremise(t *testing.T, w *ridLifecycleWorld, in rid07NewmanInput, e *rid07NewmanExpectation) {
	t.Helper()
	p := e.Snapshot.Projection
	f := w.f
	n := 1
	if in.Mode == "S2" {
		n = 3
	}
	require.Len(t, w.accounts, n)
	require.Len(t, p.Accounts, n+1)
	accounts := map[string]bool{}
	for _, a := range p.Accounts {
		id := a["id"].(string)
		if id != e.System {
			require.Equal(t, e.Operator, a["ownerUserId"])
			accounts[id] = true
		}
		if a["name"] == "system-tenant" {
			e.NamedSystem = id
			require.NotEqual(t, e.System, id)
		}
	}
	for _, id := range w.accounts {
		require.True(t, accounts[id])
	}
	require.True(t, accounts[e.Tenant])
	if n == 3 {
		require.True(t, accounts[e.NamedSystem])
	} else {
		require.Empty(t, e.NamedSystem)
	}
	stockGroup := 0
	for _, g := range p.Groups {
		if g["accountId"] == e.System && g["name"] == "module-relation-writers" {
			stockGroup++
		}
	}
	require.Equal(t, 1, stockGroup)
	require.NotEmpty(t, p.Groups)
	wantSA := 7
	if in.Axis == "creator" {
		wantSA++
	}
	require.Len(t, p.ServiceAccounts, wantSA)
	sas := map[string]map[string]any{}
	other := ""
	for _, sa := range p.ServiceAccounts {
		id := sa["id"].(string)
		sas[id] = sa
		if sa["accountId"] == e.System && sa["name"] == "rid-public-issuer" {
			require.Empty(t, e.Issuer)
			e.Issuer = id
			require.Equal(t, true, sa["enabled"])
		}
		if sa["accountId"] == e.System && sa["name"] == "rid07-other-creator" {
			require.Empty(t, other)
			other = id
			require.Equal(t, true, sa["enabled"])
		}
	}
	require.NotEmpty(t, e.Issuer)
	require.Equal(t, w.issuer.ID, e.Issuer)
	require.NotEqual(t, e.Creator, e.Issuer)
	require.Contains(t, sas, e.Creator)
	for id := range f.baseline.ServiceAccounts {
		require.Contains(t, sas, id)
	}
	e.PairCreator = e.Creator
	if in.Axis == "creator" {
		require.NotEmpty(t, other)
		require.NotEqual(t, e.Creator, other)
		if !in.Exact {
			e.PairCreator = other
		}
	} else {
		require.Empty(t, other)
	}
	for _, r := range p.Roles {
		if r["name"] == "registry.puller" {
			require.Empty(t, e.PullRole)
			e.PullRole = r["id"].(string)
			require.Equal(t, "cluster_root", r["clusterId"])
		}
		if r["name"] == "registry.pusher" {
			require.Empty(t, e.PushRole)
			e.PushRole = r["id"].(string)
			require.Equal(t, "cluster_root", r["clusterId"])
		}
	}
	require.NotEmpty(t, e.PullRole)
	require.NotEmpty(t, e.PushRole)
	require.Equal(t, w.pull, e.PullRole)
	require.Equal(t, w.push, e.PushRole)
	require.Len(t, p.Delegations, n+1)
	activeAccounts := map[string]bool{}
	oldFound, newFound := false, false
	for _, g := range p.Delegations {
		require.Equal(t, "registry", g["module"])
		require.Equal(t, map[string]any{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": e.Issuer}, g["delegate"])
		account := g["accountId"].(string)
		require.True(t, accounts[account])
		require.NotEmpty(t, g["createdAt"])
		roles, targets, subjects, creator := []any{e.PullRole}, []any{"registry.registries"}, []any{"SUBJECT_TYPE_SERVICE_ACCOUNT"}, e.Creator
		if g["id"] == e.OldPair {
			oldFound = true
			require.Equal(t, e.Tenant, account)
			require.Equal(t, "REVOKED", g["status"])
			require.NotNil(t, g["revokedAt"])
			require.NotNil(t, g["revokedBy"])
		} else {
			require.Equal(t, "ACTIVE", g["status"])
			require.Nil(t, g["revokedAt"])
			require.Nil(t, g["revokedBy"])
			require.False(t, activeAccounts[account])
			activeAccounts[account] = true
			if g["id"] == e.ActivePair {
				newFound = true
				require.Equal(t, e.Tenant, account)
				creator = e.PairCreator
				if !in.Exact {
					switch in.Axis {
					case "role":
						roles = []any{e.PushRole}
					case "target":
						targets = []any{"registry.repositories"}
					case "subject":
						subjects = []any{"SUBJECT_TYPE_USER"}
					}
				}
			}
		}
		require.Equal(t, map[string]any{"type": "service_account", "id": creator}, g["delegatedBy"])
		require.ElementsMatch(t, roles, g["roleIds"])
		require.ElementsMatch(t, targets, g["targetTypes"])
		require.ElementsMatch(t, subjects, g["subjectTypes"])
	}
	require.True(t, oldFound)
	require.True(t, newFound)
	require.Len(t, activeAccounts, n)
	for _, account := range w.accounts {
		require.True(t, activeAccounts[account])
	}
	grants := map[string]map[string]any{}
	for _, g := range p.Bindings {
		grants[g["id"].(string)] = g
	}
	require.Contains(t, grants, e.OldGrant)
	require.Contains(t, grants, e.ActiveGrant)
	old, current := grants[e.OldGrant], grants[e.ActiveGrant]
	require.Equal(t, e.OldPair, old["delegationId"])
	require.Equal(t, "REVOKED", old["status"])
	require.NotNil(t, old["revokedAt"])
	require.Equal(t, e.ActivePair, current["delegationId"])
	require.Equal(t, "ACTIVE", current["status"])
	require.Nil(t, current["revokedAt"])
	require.NotNil(t, current["materializedAt"])
}
