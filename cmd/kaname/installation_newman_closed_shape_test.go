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

type rid12NewmanSnapshot struct {
	Projection rid09NewmanProjection    `json:"projection"`
	Whole      ridWholeDeliverySnapshot `json:"-"`
}
type rid12NewmanExpectation struct {
	CaseID      string              `json:"caseId"`
	Phase       string              `json:"phase"`
	Name        string              `json:"name"`
	Kind        string              `json:"kind"`
	Operator    string              `json:"operatorId"`
	Creator     string              `json:"creatorId"`
	System      string              `json:"systemId"`
	NamedSystem string              `json:"tenantNamedSystem"`
	Snapshot    rid12NewmanSnapshot `json:"snapshot"`
}

func rid12NewmanKind(in rid12NativeInput) string {
	if in.Invalid {
		return "NEGATIVE"
	}
	if in.NoGD {
		return "NO-GD"
	}
	return "TWIN"
}
func rid12NewmanCaseID(t *testing.T, in rid12NativeInput, phase string) string {
	t.Helper()
	require.Contains(t, []string{"before", "after-negative", "after-positive", "after-reorder"}, phase)
	suffix := "AFTER"
	if phase == "before" {
		suffix = "BEFORE"
	} else if phase == "after-reorder" {
		require.True(t, in.Repeat)
		suffix = "AFTER-REORDER"
	} else {
		require.Equal(t, in.Invalid, phase == "after-negative")
	}
	return "registry-installation-rid12-" + strings.ToUpper(in.Name) + "-" + rid12NewmanKind(in) + "-" + suffix
}
func rid12ReadNewmanSnapshot(t *testing.T, f *installationNativeWorld) rid12NewmanSnapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.given.ctx, 30*time.Second)
	defer cancel()
	require.NoError(t, ctx.Err(), "aggregate RID12 snapshot deadline before read")
	p := rid09ReadNewmanProjectionContext(t, ctx, f)
	readWorld, readGiven := *f, *f.given
	readGiven.ctx = ctx
	readWorld.given = &readGiven
	whole := ridReadWholeDelivery(t, &readWorld)
	require.Equal(t, p, rid09ReadNewmanProjectionContext(t, ctx, f), "fixture NOT_ACCEPTED: full primary projection moved while composing whole raw history")
	require.NoError(t, ctx.Err(), "aggregate RID12 snapshot deadline before success return")
	return rid12NewmanSnapshot{Projection: p, Whole: whole}
}
func rid12RequireNewmanStable(t *testing.T, a, b rid12NewmanSnapshot) {
	t.Helper()
	require.Equal(t, a.Projection, b.Projection, "complete public projection/materializedAt unchanged")
	require.Equal(t, a.Whole.Delivery, b.Whole.Delivery, "all raw delivery/history rows unchanged during one read-only phase")
	require.Equal(t, a.Whole.OwnCeilings, b.Whole.OwnCeilings)
	require.Equal(t, a.Whole.Bookkeeping["operations"], b.Whole.Bookkeeping["operations"], "read-only phase cannot add or rewrite Operations")
}
func rid12DefaultNewmanConsumer(t *testing.T, f *installationNativeWorld, in rid12NativeInput) rid12LivePublicConsumer {
	t.Helper()
	phases := []string{"before", "after-positive"}
	if in.Invalid {
		phases[1] = "after-negative"
	}
	if in.Repeat {
		phases = append(phases, "after-reorder")
	}
	if os.Getenv("KANAME_RID_NEWMAN") != "1" {
		for _, phase := range phases {
			id := rid12NewmanCaseID(t, in, phase)
			rid08Write(t, f.session.Root, "newman-"+strings.ToLower(id), map[string]any{"state": "NOT_EXECUTED", "caseId": id, "actualNewmanExecuted": false, "wholeDoDAccepted": false})
		}
		return nil
	}
	calls := 0
	refusalBeforeRestore := false
	var before, previous *rid12NewmanSnapshot
	t.Cleanup(func() { require.Equal(t, len(phases), calls, "all exact same-world RID12 phases mandatory") })
	return func(t *testing.T, got *installationNativeWorld, current rid12NativeInput, phase string) {
		t.Helper()
		require.Same(t, f, got)
		require.Equal(t, in, current)
		if phase == "refusal-before-restore" {
			// Это отключённая первичная контрольная точка, а не дополнительная публичная фаза.
			// Неудачный запуск завершён, ожидание выполнено; штатное восстановление базы
			// ещё не запускалось и потому не может починить или скрыть отклонённую запись.
			require.True(t, in.Invalid)
			require.Equal(t, 1, calls)
			require.False(t, refusalBeforeRestore)
			require.NotNil(t, before)
			after := rid12ReadNewmanSnapshot(t, f)
			require.Equal(t, before.Projection, after.Projection)
			ridRequireWholeDeliveryUnchanged(t, before.Whole, after.Whole)
			require.Equal(t, before.Whole.Bookkeeping["operations"], after.Whole.Bookkeeping["operations"], "rejected startup cannot add or rewrite Operations")
			rid08Write(t, f.session.Root, "rid12-public-refusal-before-restore", map[string]any{
				"beforeProjection": before.Projection, "afterProjection": after.Projection,
				"beforeWhole": before.Whole, "afterWhole": after.Whole,
				"failedStartupTerminalBeforeRestore": true, "wholeDoDAccepted": false,
			})
			refusalBeforeRestore = true
			return
		}
		require.Less(t, calls, len(phases))
		require.Equal(t, phases[calls], phase)
		calls++
		id := rid12NewmanCaseID(t, in, phase)
		e := rid12NewmanExpectation{CaseID: id, Phase: phase, Name: in.Name, Kind: rid12NewmanKind(in), Operator: string(f.given.user), Creator: f.creator.ID, System: f.baseline.SystemID, Snapshot: rid12ReadNewmanSnapshot(t, f)}
		rid12RequireNewmanPremise(t, f, in, &e)
		if phase != "before" {
			require.NotNil(t, before)
			if in.Invalid {
				require.True(t, refusalBeforeRestore, "complete rejected-startup primary state must be checked before normal base restoration")
				require.Equal(t, before.Projection, e.Snapshot.Projection)
				// Полное необработанное равенство без записей проверено на настоящей границе отказа
				// выше. Последующий штатный базовый запуск заново проецирует свои
				// временные метки каталога; он не должен переопределять эту границу отказа.
			}
			if phase == "after-reorder" {
				require.NotNil(t, previous)
				require.Equal(t, previous.Projection, e.Snapshot.Projection)
				// Перестановка — штатное успешное применение, а не интервал только чтения.
				// Сохраняем полную публичную проекцию и каждую необработанную строку
				// истории GD/G; нативный держатель отдельно сохраняет все свои
				// проверки каталога/ролей/SA/групп/идемпотентности и точной Operation.
				for table, rows := range previous.Whole.Delivery {
					if table == "grant_delegations" || strings.HasPrefix(table, "access_binding") {
						require.Contains(t, e.Snapshot.Whole.Delivery, table)
						require.Equal(t, rows, e.Snapshot.Whole.Delivery[table], "reorder preserves complete raw GD/G identities, timestamps and history")
					}
				}
			}
		}
		func() {
			defer func() {
				after := rid12ReadNewmanSnapshot(t, f)
				stable := reflect.DeepEqual(e.Snapshot.Projection, after.Projection) && reflect.DeepEqual(e.Snapshot.Whole.Delivery, after.Whole.Delivery) && reflect.DeepEqual(e.Snapshot.Whole.OwnCeilings, after.Whole.OwnCeilings) && reflect.DeepEqual(e.Snapshot.Whole.Bookkeeping["operations"], after.Whole.Bookkeeping["operations"])
				rid08Write(t, f.session.Root, "newman-"+strings.ToLower(id)+"-primary-bracket", map[string]any{"caseId": id, "fullPrimarySnapshotUnchangedDuringPhase": stable, "wholeDoDAccepted": false})
				rid12RequireNewmanStable(t, e.Snapshot, after)
			}()
			receipt := ridRunNewmanPhase(t, f, "registry-installation-rid12", id, strings.ToLower(id), map[string]any{"rid12Expected": e})
			require.True(t, receipt.OK)
		}()
		snapshot := e.Snapshot
		if phase == "before" {
			before = &snapshot
		}
		previous = &snapshot
	}
}
func rid12RequireNewmanPremise(t *testing.T, f *installationNativeWorld, in rid12NativeInput, e *rid12NewmanExpectation) {
	t.Helper()
	p := e.Snapshot.Projection
	delivered := e.Phase != "before" && !in.Invalid
	require.Len(t, p.Accounts, 4)
	// Каждый мир RID12 уже имеет готовую базу. Встроенный собственный манифест
	// сохраняет созданную миграцией legacy-группу SYS; own seed явно пуст.
	require.NotEmpty(t, p.Groups)
	stockWriterGroups := 0
	for _, group := range p.Groups {
		if group["accountId"] == e.System && group["name"] == "module-relation-writers" {
			stockWriterGroups++
		}
	}
	require.Equal(t, 1, stockWriterGroups, "canonical migration-provenance legacy group exists in every BEFORE/AFTER phase")
	normal := map[string]bool{}
	for _, a := range p.Accounts {
		id := a["id"].(string)
		if id != e.System {
			normal[id] = true
			require.Equal(t, e.Operator, a["ownerUserId"])
		}
		if a["name"] == "system-tenant" {
			e.NamedSystem = id
			require.NotEqual(t, e.System, id)
		}
	}
	require.Len(t, normal, 3)
	require.True(t, normal[e.NamedSystem])
	wantSA, wantGD := 3, 0
	if delivered {
		wantSA = 5
		if !in.NoGD {
			wantGD = 6
		}
	}
	require.Len(t, p.ServiceAccounts, wantSA)
	require.Len(t, p.Delegations, wantGD)
	sas := map[string]map[string]any{}
	for _, sa := range p.ServiceAccounts {
		require.Equal(t, e.System, sa["accountId"])
		sas[sa["id"].(string)] = sa
	}
	require.Contains(t, sas, e.Creator)
	require.Len(t, f.baseline.ServiceAccounts, 2)
	for id := range f.baseline.ServiceAccounts {
		require.Contains(t, sas, id)
	}
	if !delivered {
		return
	}
	declarations := rid12Declarations(t, in.Input)
	pairs := map[string]bool{}
	for module, m := range declarations {
		issuer := ""
		for id, sa := range sas {
			if sa["name"] == m.Seed.ServiceAccounts[0].Name {
				require.Empty(t, issuer)
				issuer = id
				require.NotEqual(t, e.Creator, id)
				require.NotContains(t, f.baseline.ServiceAccounts, id)
				require.Equal(t, true, sa["enabled"])
			}
		}
		require.NotEmpty(t, issuer, "I independently resolved by declared name plus SYS, never GD delegate")
		roles := map[string]string{}
		count := 0
		for _, r := range p.Roles {
			for _, declared := range m.Roles {
				if r["name"] == declared.ID {
					count++
					require.Equal(t, "cluster_root", r["clusterId"])
					roles[declared.ID] = r["id"].(string)
					require.Len(t, r["rules"], len(declared.Rules))
				}
			}
		}
		require.Equal(t, len(m.Roles), count, "all declarations including 17th nonselected role remain")
		found := 0
		for _, entry := range p.Catalog["modules"].([]any) {
			entry := entry.(map[string]any)
			if entry["module"] == module {
				found++
				resources := entry["resources"].([]any)
				require.Len(t, resources, len(m.Resources))
				for _, declared := range m.Resources {
					n := 0
					for _, r := range resources {
						if r.(map[string]any)["resource"] == declared.Name {
							n++
						}
					}
					require.Equal(t, 1, n)
				}
			}
		}
		require.Equal(t, 1, found, "complete declared catalog including 17th resource")
		if in.NoGD {
			continue
		}
		require.Len(t, m.Seed.GrantDelegations, 1)
		gd := m.Seed.GrantDelegations[0]
		wantedRoles := []any{}
		for _, name := range gd.RoleIDs {
			require.Contains(t, roles, name)
			wantedRoles = append(wantedRoles, roles[name])
		}
		for _, g := range p.Delegations {
			if g["module"] != module {
				continue
			}
			account := g["accountId"].(string)
			require.True(t, normal[account])
			key := module + "/" + account
			require.False(t, pairs[key])
			pairs[key] = true
			require.Equal(t, "ACTIVE", g["status"])
			require.Nil(t, g["revokedAt"])
			require.Nil(t, g["revokedBy"])
			require.Equal(t, map[string]any{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": issuer}, g["delegate"])
			require.Equal(t, map[string]any{"type": "service_account", "id": e.Creator}, g["delegatedBy"])
			require.ElementsMatch(t, wantedRoles, g["roleIds"])
			require.ElementsMatch(t, gd.TargetTypes, g["targetTypes"])
			require.ElementsMatch(t, gd.SubjectTypes, g["subjectTypes"])
		}
		for account := range normal {
			require.True(t, pairs[module+"/"+account])
		}
	}
	require.Len(t, pairs, wantGD)
}
