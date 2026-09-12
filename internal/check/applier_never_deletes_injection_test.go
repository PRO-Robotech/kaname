// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// applier_never_deletes_injection_test.go — доказательство падучести
// TestMODRD15ApplierNeverDeletesARoleRow в обе стороны, на синтетическом
// файле.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const applierInjectedDeletingPort = `package moduleroles

type RoleWriter interface {
	UpsertSystemRole()
	RemoveRole(id string) error
}
`

const applierInjectedDeletingSQL = `package moduleroles

func (w *roleWriter) purgeStale(ctx int) error {
	const q = ` + "`" + `
		DELETE FROM kaname.roles WHERE id = $1` + "`" + `
	_ = q
	return nil
}
`

// applierLawfulTwin — законные близнецы обеих осей: RetireRole (пометка,
// UPDATE), ReplaceRuleRefs (снимает ПРОЕКЦИЮ, не строку роли),
// DeleteRoleRuleSelectors (предмет — проекция, не строка роли), и оператор
// DELETE над ДРУГОЙ таблицей плюс проза, объясняющая сам запрет.
const applierLawfulTwin = `package moduleroles

// Применитель не производит DELETE FROM roles — строка роли не удаляется.
type RoleWriter interface {
	UpsertSystemRole()
	RetireRole(id string) error
	ReplaceRuleRefs(id string) error
	DeleteRoleRuleSelectors(id string) error
}

func (w *roleWriter) cleanupOrphans(ctx int) error {
	const q = ` + "`" + `DELETE FROM kaname.role_rule_selectors WHERE role_id = $1` + "`" + `
	_ = q
	return nil
}
`

// TestApplierNeverDeletesInjection_PortVerb — ось 1: удаляющий глагол над
// строкой роли — находка; та же форма над проекцией — молчание.
func TestApplierNeverDeletesInjection_PortVerb(t *testing.T) {
	t.Parallel()
	sites, census, err := check.ScanApplierDeletes("synthetic/port.go", []byte(applierInjectedDeletingPort))
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if census.InterfaceMethods == 0 {
		t.Fatalf("осмотрено ноль методов — разбирается не то дерево")
	}
	var found bool
	for _, s := range sites {
		if s.Kind == "port-verb" && strings.Contains(s.What, "RemoveRole") {
			found = true
		}
	}
	if !found {
		t.Fatalf("ИНЪЕКЦИЯ: удаляющий глагол RemoveRole над строкой роли не найден: %+v", sites)
	}

	twin, _, err := check.ScanApplierDeletes("synthetic/twin.go", []byte(applierLawfulTwin))
	if err != nil {
		t.Fatalf("разбор близнеца: %v", err)
	}
	for _, s := range twin {
		if s.Kind == "port-verb" {
			t.Errorf("ЗАКОННЫЙ БЛИЗНЕЦ: гейт покраснел на глаголе %s — RetireRole есть "+
				"UPDATE (пометка), ReplaceRuleRefs/DeleteRoleRuleSelectors удаляют ПРОЕКЦИЮ, "+
				"не строку роли", s.What)
		}
	}
}

// TestApplierNeverDeletesInjection_SQLLiteral — ось 2: DELETE над `roles` —
// находка; DELETE над проекцией и проза, объясняющая запрет, — молчание.
func TestApplierNeverDeletesInjection_SQLLiteral(t *testing.T) {
	t.Parallel()
	sites, census, err := check.ScanApplierDeletes("synthetic/sql.go", []byte(applierInjectedDeletingSQL))
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if census.StringLiterals == 0 {
		t.Fatalf("осмотрено ноль строковых литералов — разбирается не то дерево")
	}
	var found bool
	for _, s := range sites {
		if s.Kind == "sql-literal" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ИНЪЕКЦИЯ: DELETE FROM kaname.roles не найден разбором: %+v", sites)
	}

	twin, _, err := check.ScanApplierDeletes("synthetic/twin.go", []byte(applierLawfulTwin))
	if err != nil {
		t.Fatalf("разбор близнеца: %v", err)
	}
	for _, s := range twin {
		if s.Kind == "sql-literal" {
			t.Errorf("ЗАКОННЫЙ БЛИЗНЕЦ: гейт покраснел на DELETE над проекцией "+
				"(role_rule_selectors), а не над строкой роли: %+v", s)
		}
	}

	// Проза, объясняющая сам запрет, несёт слово DELETE и имя таблицы
	// ПОСРЕДИ комментария — гейт судит узел разбора, а не подстроку текста.
	prose, _, err := check.ScanApplierDeletes("synthetic/prose.go", []byte(applierLawfulTwin))
	if err != nil {
		t.Fatalf("разбор прозы: %v", err)
	}
	for _, s := range prose {
		if s.Kind == "sql-literal" && strings.Contains(s.What, "roles") {
			t.Errorf("гейт нашёл DELETE FROM roles в комментарии, объясняющем сам запрет "+
				"(судит подстроку, а не узел разбора): %+v", s)
		}
	}
}

// TestApplierPortVerbDeletesTheRoleRow_Predicate — предикат оси 1 отдельно,
// со всеми граничными случаями, включая fail-closed на неназванном предмете.
func TestApplierPortVerbDeletesTheRoleRow_Predicate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		want bool
	}{
		{"RemoveRole", true},
		{"DeleteRole", true},
		{"DropRoles", true},
		{"PurgeRole", true},
		{"Purge", true},           // предмет не назван — fail-closed находка
		{"RemoveRuleRefs", false}, // предмет — проекция, не строка роли
		{"ReplaceRuleRefs", false},
		{"RetireRole", false}, // не входит в перечень глаголов вовсе
		{"UpsertSystemRole", false},
	}
	for _, c := range cases {
		got, _ := check.ApplierPortVerbDeletesTheRoleRow(c.name)
		if got != c.want {
			t.Errorf("ApplierPortVerbDeletesTheRoleRow(%q) = %v, ожидалось %v", c.name, got, c.want)
		}
	}
}
