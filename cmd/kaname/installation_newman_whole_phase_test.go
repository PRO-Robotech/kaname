// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type rid09NewmanExpectation struct {
	CaseID      string                 `json:"caseId"`
	Phase       string                 `json:"phase"`
	Axis        string                 `json:"axis"`
	Reverse     bool                   `json:"reverse"`
	Twin        bool                   `json:"twin"`
	Operator    string                 `json:"operatorId"`
	Creator     string                 `json:"creatorId"`
	System      string                 `json:"systemId"`
	NamedSystem string                 `json:"tenantNamedSystem"`
	N           int                    `json:"n"`
	Projection  rid09NewmanProjection  `json:"projection"`
	Previous    *rid09NewmanProjection `json:"previousProjection"`
}

func rid09NewmanCaseID(t *testing.T, in rid09Input, phase string) string {
	t.Helper()
	require.Contains(t, []string{"roleIds", "targetTypes", "subjectTypes", "delegate"}, in.Axis)
	require.Contains(t, []string{"before", "after-negative", "after-positive"}, phase)
	if phase != "before" {
		require.Equal(t, in.Twin, phase == "after-positive")
	}
	order, kind, suffix := "M1-M2", "NEGATIVE", "BEFORE"
	if in.Reverse {
		order = "M2-M1"
	}
	if in.Twin {
		kind = "TWIN"
	}
	if phase != "before" {
		suffix = "AFTER"
	}
	return "registry-installation-rid09-" + strings.ToUpper(in.Axis) + "-" + order + "-" + kind + "-" + suffix
}

// Каждый вызов владеет ОДНИМ замыканием в ОДНОМ существующем нативном мире. Вызывающий сохраняет
// явных потребителей. Выключенный режим не имеет вызываемого/принятого публичного доказательства.
func rid09DefaultNewmanConsumer(t *testing.T, f *installationNativeWorld, in rid09Input) rid09LivePublicConsumer {
	t.Helper()
	if os.Getenv("KANAME_RID_NEWMAN") != "1" {
		phases := []string{"before", "after-negative"}
		if in.Twin {
			phases[1] = "after-positive"
		}
		for _, phase := range phases {
			id := rid09NewmanCaseID(t, in, phase)
			rid08Write(t, f.session.Root, "newman-"+strings.ToLower(id), map[string]any{"state": "NOT_EXECUTED", "caseId": id, "wholeDoDAccepted": false})
		}
		return nil
	}
	var before *rid09NewmanProjection
	calls := 0
	return func(t *testing.T, got *installationNativeWorld, current rid09Input, phase string) {
		t.Helper()
		require.Same(t, f, got)
		require.Equal(t, in, current)
		caseID := rid09NewmanCaseID(t, in, phase)
		require.Less(t, calls, 2, "one BEFORE and one AFTER only in each world")
		require.Equal(t, calls == 0, phase == "before")
		calls++
		e := rid09NewmanExpectation{CaseID: caseID, Phase: phase, Axis: in.Axis, Reverse: in.Reverse, Twin: in.Twin, Operator: string(f.given.user), Creator: f.creator.ID, System: f.baseline.SystemID, N: 3, Projection: rid09ReadNewmanProjection(t, f), Previous: before}
		rid09RequirePrimaryPremise(t, f, &e)
		if phase == "before" {
			snapshot := e.Projection
			before = &snapshot
		} else {
			require.NotNil(t, before, "same-world complete primary BEFORE is mandatory")
			if !in.Twin {
				require.Equal(t, *before, e.Projection, "negative startup preserves the ENTIRE independent public projection")
			}
		}
		// Мост может вызвать Fatal/Goexit до возврата при неудачной публичной
		// фазе. defer необходим для охвата и этой попытки.
		func() {
			defer func() {
				after := rid09ReadNewmanProjection(t, f)
				stable := reflect.DeepEqual(e.Projection, after)
				state := "PRIMARY_STABLE"
				if !stable {
					state = "FIXTURE_NOT_ACCEPTED"
				}
				rid08Write(t, f.session.Root, "newman-"+strings.ToLower(caseID)+"-primary-bracket", map[string]any{
					"state": state, "caseId": caseID, "publicProjectionUnchangedDuringPhase": stable,
					"materializationLedgerUnchangedDuringPhase": e.Projection.Materialization == after.Materialization,
					"wholeDoDAccepted":                          false,
				})
				require.Equal(t, e.Projection.Materialization, after.Materialization, "fixture NOT_ACCEPTED: materialization ledger moved during Newman; preserve reports and cleanup, no in-world retry")
				require.Equal(t, e.Projection, after, "fixture NOT_ACCEPTED: independently projected public state moved during Newman")
			}()
			receipt := ridRunNewmanPhase(t, f, "registry-installation-rid09", caseID, strings.ToLower(caseID), map[string]any{"rid09Expected": e})
			require.True(t, receipt.OK)
		}()
	}
}
func rid09RequirePrimaryPremise(t *testing.T, f *installationNativeWorld, e *rid09NewmanExpectation) {
	t.Helper()
	p := e.Projection
	delivered := e.Twin && e.Phase == "after-positive"
	wantSA, wantGD := 3, 0
	if delivered {
		wantSA, wantGD = 5, 6
	}
	require.Len(t, p.Accounts, 4)
	require.Len(t, p.ServiceAccounts, wantSA)
	require.Len(t, p.Delegations, wantGD)
	require.Len(t, f.baseline.ServiceAccounts, 2)
	require.NotContains(t, f.baseline.ServiceAccounts, e.Creator)
	accounts := map[string]bool{}
	normal := map[string]bool{}
	for _, a := range p.Accounts {
		id := a["id"].(string)
		require.False(t, accounts[id])
		accounts[id] = true
		if id == e.System {
			require.Equal(t, "system", a["name"])
			require.Equal(t, f.baseline.SystemOwner, a["ownerUserId"])
		} else {
			require.Equal(t, e.Operator, a["ownerUserId"])
			normal[id] = true
		}
		if a["name"] == "system-tenant" {
			e.NamedSystem = id
			require.NotEqual(t, e.System, id)
		}
	}
	require.True(t, accounts[e.System])
	require.Len(t, normal, 3)
	require.NotEmpty(t, e.NamedSystem)
	require.True(t, normal[e.NamedSystem])
	sas := map[string]map[string]any{}
	issuers := map[string]string{}
	for _, sa := range p.ServiceAccounts {
		id := sa["id"].(string)
		require.NotContains(t, sas, id)
		sas[id] = sa
		require.Equal(t, e.System, sa["accountId"])
		for _, module := range []string{"ridfirst", "ridsecond"} {
			if sa["name"] == "svc-"+module {
				require.NotContains(t, issuers, module)
				issuers[module] = id
				require.Equal(t, true, sa["enabled"])
				require.NotEqual(t, e.Creator, id)
			}
		}
	}
	require.Contains(t, sas, e.Creator)
	for id := range f.baseline.ServiceAccounts {
		require.Contains(t, sas, id)
	}
	roleIDs := map[string]string{}
	groupIDs := map[string]string{}
	for _, module := range []string{"ridfirst", "ridsecond"} {
		catalogCount := 0
		for _, m := range p.Catalog["modules"].([]any) {
			mod := m.(map[string]any)
			if mod["module"] == module {
				catalogCount++
				resources := mod["resources"].([]any)
				require.Len(t, resources, 1)
				r := resources[0].(map[string]any)
				require.Equal(t, "objects", r["resource"])
				require.ElementsMatch(t, []any{"get", "list"}, r["verbs"])
				require.Equal(t, true, r["hasVerbRelations"])
			}
		}
		roleCount, groupCount := 0, 0
		for _, r := range p.Roles {
			if r["name"] == module+".reader" {
				roleCount++
				roleIDs[module] = r["id"].(string)
				require.Equal(t, "cluster_root", r["clusterId"])
				require.Equal(t, map[string]any{"tierType": "iam.cluster", "tierId": "cluster_root"}, r["definitionTier"])
				rules := r["rules"].([]any)
				require.Len(t, rules, 1)
				rule := rules[0].(map[string]any)
				require.Equal(t, module, rule["module"])
				require.Equal(t, []any{"objects"}, rule["resources"])
				require.ElementsMatch(t, []any{"get", "list"}, rule["verbs"])
			}
		}
		for _, g := range p.Groups {
			if g["name"] == module+"-readers" {
				groupCount++
				require.Equal(t, e.System, g["accountId"])
				groupIDs[module] = g["id"].(string)
			}
		}
		if delivered {
			require.Equal(t, 1, catalogCount)
			require.Equal(t, 1, roleCount)
			require.Equal(t, 1, groupCount)
			require.Contains(t, issuers, module)
		} else {
			require.Zero(t, catalogCount)
			require.Zero(t, roleCount)
			require.Zero(t, groupCount)
			require.NotContains(t, issuers, module)
		}
	}
	if !delivered {
		return
	}
	require.NotNil(t, e.Previous)
	for _, old := range e.Previous.ServiceAccounts {
		require.Equal(t, old, sas[old["id"].(string)], "original full safe SA identities remain unchanged")
	}
	require.Len(t, p.Roles, len(e.Previous.Roles)+2)
	require.Len(t, p.Groups, len(e.Previous.Groups)+2)
	require.Len(t, p.Bindings, len(e.Previous.Bindings)+2)
	beforeMembers, nowMembers := 0, 0
	for _, m := range e.Previous.Members {
		beforeMembers += len(m)
	}
	for _, m := range p.Members {
		nowMembers += len(m)
	}
	require.Equal(t, beforeMembers+2, nowMembers)
	writers := ""
	for _, g := range p.Groups {
		if g["name"] == "module-relation-writers" && g["accountId"] == e.System {
			require.Empty(t, writers)
			writers = g["id"].(string)
		}
	}
	require.NotEmpty(t, writers)
	pairs := map[string]bool{}
	for _, g := range p.Delegations {
		module := g["module"].(string)
		require.Contains(t, issuers, module)
		account := g["accountId"].(string)
		require.True(t, normal[account])
		key := account + "/" + module
		require.False(t, pairs[key])
		pairs[key] = true
		require.Equal(t, "ACTIVE", g["status"])
		require.Nil(t, g["revokedAt"])
		require.Nil(t, g["revokedBy"])
		require.Equal(t, map[string]any{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": issuers[module]}, g["delegate"])
		require.Equal(t, map[string]any{"type": "service_account", "id": e.Creator}, g["delegatedBy"])
		require.Equal(t, []any{roleIDs[module]}, g["roleIds"])
		require.Equal(t, []any{module + ".objects"}, g["targetTypes"])
		require.Equal(t, []any{"SUBJECT_TYPE_SERVICE_ACCOUNT"}, g["subjectTypes"])
	}
	require.Len(t, pairs, 6)
	for _, module := range []string{"ridfirst", "ridsecond"} {
		matches := 0
		for _, m := range p.Members[writers] {
			if m["memberType"] == "service_account" && m["memberId"] == issuers[module] {
				matches++
			}
		}
		require.Equal(t, 1, matches)
		bindings := 0
		for _, b := range p.Bindings {
			if b["roleId"] == roleIDs[module] && b["subjectId"] == groupIDs[module] {
				bindings++
				require.Equal(t, "group", b["subjectType"])
				require.Equal(t, "iam.cluster", b["scopeType"])
				require.Equal(t, "cluster_root", b["scopeId"])
				require.Equal(t, "ACTIVE", b["status"])
				require.Equal(t, true, b["system"])
				require.Equal(t, true, b["deletionProtection"])
				require.Equal(t, []any{map[string]any{"type": "SUBJECT_TYPE_GROUP", "id": groupIDs[module]}}, b["subjects"])
				require.Equal(t, map[string]any{"allInScope": map[string]any{}}, b["target"])
				require.Nil(t, b["revokedAt"])
			}
		}
		require.Equal(t, 1, bindings)
	}
}
