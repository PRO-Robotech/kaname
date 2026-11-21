// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

var rid11RestoreEpochSchemas = map[string][]string{
	"authority_policy_epoch":  {"key", "generation", "revision"},
	"authority_binding_epoch": {"scope", "generation", "revision"},
}

type rid11RestoreEpochPlan struct{ Policy, Binding map[string]bool }

// StartBase задаёт только manifests и registration writers. Проверяем действующие
// умолчания и отвергаем окружение, выбравшее иной протокол производителя.
func rid11LegacyRestorationEnvironment(environment []string) bool {
	v := viper.New()
	config.RegisterDefaults(v)
	if v.GetString("authority-protocol.participation") != "legacy" || v.GetBool("authority-protocol.full-semantics") {
		return false
	}
	seen := map[string]bool{}
	for _, entry := range environment {
		name, value, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, "KANAME_AUTHORITY_PROTOCOL") {
			continue
		}
		if seen[name] {
			return false
		}
		seen[name] = true
		switch name {
		case "KANAME_AUTHORITY_PROTOCOL__PARTICIPATION":
			if value != "legacy" {
				return false
			}
		case "KANAME_AUTHORITY_PROTOCOL__FULL_SEMANTICS":
			if value != "false" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// Координаты берутся из BEFORE и независимо выведенного плана производителей.
// ReplaceRoleVerbs/ReplaceRuleRefs удаляют и вставляют даже одинаковые строки;
// syncAllSystemRoleSelectorsTx безусловно обновляет часы сохранённых селекторов.
// Legacy-триггеры используют authority_policy_keys и authority_binding_epoch_scope
// (20261113220000, 20261114000000). Последний policy-триггер 20261115150000
// без resource manifest не меняет epochs для members/ledger/outbox.
func rid11BuildRestoreEpochPlan(raw map[string][]rid09PrimaryRow, restore rid11RestorePlan, bindings rid11BindingRestorePlan) (rid11RestoreEpochPlan, bool) {
	p := rid11RestoreEpochPlan{Policy: map[string]bool{}, Binding: map[string]bool{}}
	roles, ok := rid11BindingIndex(raw, "roles")
	if !ok {
		return p, false
	}
	projects, ok := rid11BindingIndex(raw, "projects")
	if !ok {
		return p, false
	}
	roleScope := func(id string) (string, bool) {
		r, exists := roles[id]
		if !exists {
			return "", false
		}
		account := rid03S(r, "account_id")
		if account == "" && rid03S(r, "project_id") != "" {
			project, found := projects[rid03S(r, "project_id")]
			if !found {
				return "", false
			}
			account = rid03S(project, "account_id")
			if account == "" {
				return "", false
			}
		}
		return account, true
	}
	touch := func(table string, row rid09PrimaryRow) bool {
		id := rid03S(row, "role_id")
		if !restore.Eligible[id] {
			return true
		}
		scope, valid := roleScope(id)
		if !valid {
			return false
		}
		if table == "role_rule_selectors" && (rid03S(row, "arm") != "anchor" || !rid03SameCell(row, "container_type", nil)) {
			scope = ""
		}
		p.Policy["role:"+id] = true
		p.Binding[scope] = true
		return true
	}
	for table := range rid11RestoreSchemas {
		for _, row := range raw[table] {
			if !touch(table, row) {
				return p, false
			}
		}
		if table != "role_rule_selectors" {
			for _, row := range restore.Raw[table] {
				if !touch(table, row) {
					return p, false
				}
			}
		}
	}
	for _, row := range restore.Selectors {
		if !touch("role_rule_selectors", row) {
			return p, false
		}
	}
	carriers, ok := rid11BindingIndex(raw, "access_bindings")
	if !ok {
		return p, false
	}
	groups, ok := rid11BindingIndex(raw, "groups")
	if !ok {
		return p, false
	}
	serviceAccounts, ok := rid11BindingIndex(raw, "service_accounts")
	if !ok {
		return p, false
	}
	// Триггер выдачи читает синхронизированную проекцию селекторов. Посторонние
	// селекторы сохранены, селекторы допустимых ролей заменены планом.
	globalRoles := map[string]bool{}
	selector := func(row rid09PrimaryRow) {
		if rid03S(row, "arm") != "anchor" || !rid03SameCell(row, "container_type", nil) {
			globalRoles[rid03S(row, "role_id")] = true
		}
	}
	for _, row := range raw["role_rule_selectors"] {
		if !restore.Eligible[rid03S(row, "role_id")] {
			selector(row)
		}
	}
	for _, row := range restore.Selectors {
		selector(row)
	}
	for member := range bindings.Policy.Members {
		carrier, exists := carriers[member.Binding]
		if !exists || rid03S(carrier, "role_id") != member.Role || rid03S(carrier, "resource_type") != "account" {
			return p, false
		}
		scope := rid03S(carrier, "resource_id")
		if scope == "" {
			return p, false
		}
		if globalRoles[member.Role] {
			scope = ""
		}
		if member.Type == "iam.group" {
			group, exists := groups[member.ID]
			if !exists {
				return p, false
			}
			if rid03S(group, "account_id") == "" || rid03S(group, "account_id") != rid03S(carrier, "resource_id") {
				scope = ""
			}
		} else if member.Type != "iam.serviceAccount" {
			return p, false
		}
		p.Binding[scope] = true
	}
	// Закрытый план допускает только факты IAM group/SA для субъекта user.
	// Заголовки и субъекты выдач неизменны: carriers:role и latch не растут.
	for tuple := range bindings.Policy.DirectTuples {
		kind, id, valid := strings.Cut(tuple.Subject, ":")
		if !valid || kind != "user" || id == "" || strings.ContainsAny(id, "#*") {
			return p, false
		}
		var object rid09PrimaryRow
		switch tuple.Type {
		case "iam_group":
			object = groups[tuple.ID]
		case "iam_service_account":
			object = serviceAccounts[tuple.ID]
		default:
			return p, false
		}
		account := rid03S(object, "account_id")
		if account == "" {
			return p, false
		}
		p.Policy[tuple.Subject] = true
		p.Policy["scope:"+account] = true
	}
	// Эти роли и области уже материализованы в BEFORE. Отсутствие обязательного
	// ключа отвергает предпосылку, а не разрешает добавление строки.
	for table, keys := range map[string]map[string]bool{"authority_policy_epoch": p.Policy, "authority_binding_epoch": p.Binding} {
		key := rid11RestoreEpochSchemas[table][0]
		present := map[string]bool{}
		rows, exists := raw[table]
		if !exists {
			return p, false
		}
		for _, row := range rows {
			k, valid := rid03Cell[string](row, key)
			if !valid || present[k] || !rid11RestoreKeys(row, rid11RestoreEpochSchemas[table]) {
				return p, false
			}
			present[k] = true
		}
		for k := range keys {
			if !present[k] {
				return p, false
			}
		}
	}
	return p, true
}

func rid11RestoreEpochsValid(p rid11RestoreEpochPlan, a, b rid03NewmanSnapshot) bool {
	for table, keys := range map[string]map[string]bool{"authority_policy_epoch": p.Policy, "authority_binding_epoch": p.Binding} {
		schema := rid11RestoreEpochSchemas[table]
		if !rid03EpochTransitionValid(a.Raw[table], b.Raw[table], schema[0], keys) {
			return false
		}
		for _, snapshot := range []rid03NewmanSnapshot{a, b} {
			rows, rawExists := snapshot.Raw[table]
			whole, wholeExists := snapshot.Whole.Delivery[table]
			if !rawExists || !wholeExists {
				return false
			}
			cols := append([]string{}, whole.Columns...)
			sort.Strings(cols)
			want := append([]string{}, schema...)
			sort.Strings(want)
			hashes, valid := rid11BindingWholeHashes(rows)
			if !valid || !reflect.DeepEqual(cols, want) || !reflect.DeepEqual(hashes, whole.Rows) {
				return false
			}
		}
	}
	return true
}

func TestRID11RestorationEpochTransitionIsClosed(t *testing.T) {
	row := func(key, gen string, revision int64) rid09PrimaryRow {
		return rid11RestoreRow(map[string]any{"key": key, "generation": gen, "revision": revision})
	}
	snapshot := func(rows []rid09PrimaryRow) rid03NewmanSnapshot {
		binding := []rid09PrimaryRow{rid11RestoreRow(map[string]any{"scope": "", "generation": "17", "revision": 3})}
		s := rid03NewmanSnapshot{Raw: map[string][]rid09PrimaryRow{"authority_policy_epoch": rows, "authority_binding_epoch": binding}, Whole: ridWholeDeliverySnapshot{Delivery: map[string]ridWholeTable{}}}
		for table, raw := range s.Raw {
			hashes, ok := rid11BindingWholeHashes(raw)
			require.True(t, ok)
			s.Whole.Delivery[table] = ridWholeTable{Columns: rid11RestoreEpochSchemas[table], Rows: hashes}
		}
		return s
	}
	p := rid11RestoreEpochPlan{Policy: map[string]bool{"role:one": true}, Binding: map[string]bool{}}
	a := snapshot([]rid09PrimaryRow{row("role:one", "42", 2), row("role:other", "43", 4)})
	b := snapshot([]rid09PrimaryRow{row("role:one", "42", 6), row("role:other", "43", 4)})
	require.True(t, rid11RestoreEpochsValid(p, a, b))
	for name, rows := range map[string][]rid09PrimaryRow{
		"missing mandatory bump": a.Raw["authority_policy_epoch"],
		"foreign bump":           {row("role:one", "42", 6), row("role:other", "43", 5)},
		"generation replacement": {row("role:one", "44", 6), row("role:other", "43", 4)},
		"deletion":               {row("role:one", "42", 6)},
		"new key":                {row("role:one", "42", 6), row("role:other", "43", 4), row("role:new", "44", 1)},
	} {
		t.Run(name, func(t *testing.T) { require.False(t, rid11RestoreEpochsValid(p, a, snapshot(rows))) })
	}
	bad := snapshot(b.Raw["authority_policy_epoch"])
	whole := bad.Whole.Delivery["authority_policy_epoch"]
	whole.Rows = []string{"not-the-raw-hash"}
	bad.Whole.Delivery["authority_policy_epoch"] = whole
	require.False(t, rid11RestoreEpochsValid(p, a, bad))
	require.False(t, rid11RestoreEpochsValid(p, bad, b))
	require.True(t, rid11LegacyRestorationEnvironment(nil))
	require.True(t, rid11LegacyRestorationEnvironment([]string{"KANAME_AUTHORITY_PROTOCOL__PARTICIPATION=legacy", "KANAME_AUTHORITY_PROTOCOL__FULL_SEMANTICS=false"}))
	require.False(t, rid11LegacyRestorationEnvironment([]string{"KANAME_AUTHORITY_PROTOCOL__PARTICIPATION=participant"}))
	require.False(t, rid11LegacyRestorationEnvironment([]string{"KANAME_AUTHORITY_PROTOCOL__FULL_SEMANTICS=true"}))
}

func TestRID11RestorationEpochFootprintComesFromBeforeProducers(t *testing.T) {
	r := rid11RestoreRow
	raw := map[string][]rid09PrimaryRow{
		"roles": {
			r(map[string]any{"id": "rol_one1", "account_id": "tenant", "project_id": nil}),
			r(map[string]any{"id": "rol_two2", "account_id": nil, "project_id": "prj_main"}),
			r(map[string]any{"id": "rol_empty", "account_id": "unwritten", "project_id": nil}),
		},
		"projects":            {r(map[string]any{"id": "prj_main", "account_id": "project-tenant"})},
		"groups":              {r(map[string]any{"id": "grp_main", "account_id": "tenant"})},
		"service_accounts":    {r(map[string]any{"id": "sva_main", "account_id": "tenant"})},
		"access_bindings":     {r(map[string]any{"id": "acb_main", "role_id": "rol_one1", "resource_type": "account", "resource_id": "tenant"})},
		"role_verb":           {r(map[string]any{"role_id": "rol_one1"})},
		"role_rule_ref":       {r(map[string]any{"role_id": "rol_two2"})},
		"role_rule_selectors": {}, "role_selector_verbs_pending": {},
	}
	restore := rid11RestorePlan{Raw: raw, Eligible: map[string]bool{"rol_one1": true, "rol_two2": true, "rol_empty": true}, Selectors: map[string]rid09PrimaryRow{
		"one-anchor": r(map[string]any{"role_id": "rol_one1", "arm": "anchor", "container_type": nil}),
		"two-names":  r(map[string]any{"role_id": "rol_two2", "arm": "names", "container_type": nil}),
	}}
	bindings := rid11BindingRestorePlan{Policy: rid03DeltaPolicy{
		Members:      map[rid03Member]bool{{Binding: "acb_main", Role: "rol_one1", Type: "iam.group", ID: "grp_main"}: true},
		DirectTuples: map[rid03Tuple]bool{{Subject: "user:owner", Relation: "viewer", Type: "iam_group", ID: "grp_main"}: true},
	}}
	for _, key := range []string{"role:rol_one1", "role:rol_two2", "user:owner", "scope:tenant", "role:untouched"} {
		raw["authority_policy_epoch"] = append(raw["authority_policy_epoch"], r(map[string]any{"key": key, "generation": "17", "revision": 2}))
	}
	for _, key := range []string{"", "tenant", "project-tenant"} {
		raw["authority_binding_epoch"] = append(raw["authority_binding_epoch"], r(map[string]any{"scope": key, "generation": "17", "revision": 2}))
	}
	p, ok := rid11BuildRestoreEpochPlan(raw, restore, bindings)
	require.True(t, ok)
	require.Equal(t, map[string]bool{"role:rol_one1": true, "role:rol_two2": true, "user:owner": true, "scope:tenant": true}, p.Policy)
	require.Equal(t, map[string]bool{"": true, "tenant": true, "project-tenant": true}, p.Binding)
	// Одинаковые строки всё равно удаляются и вставляются. Допустимая роль без
	// прежних и выведенных строк не получает разрешения менять свой epoch.
	require.False(t, p.Policy["role:rol_empty"])
	require.False(t, p.Policy["role:untouched"])
	require.False(t, p.Policy["carriers:role:rol_one1"])
	require.False(t, p.Policy["carrier_latch:role:rol_one1"])
	raw["authority_policy_epoch"] = raw["authority_policy_epoch"][1:]
	_, ok = rid11BuildRestoreEpochPlan(raw, restore, bindings)
	require.False(t, ok, "a missing mandatory BEFORE key is not permission to create it")
}
