// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// conditionSite — one `<subject type> with <condition>` entry in the canonical
// model.
type conditionSite struct {
	Type      string // object type the relation is defined on
	Relation  string // relation name
	Subject   string // subject type the condition restricts (`user` in `[user with …]`)
	Condition string // condition name after `with`
	Line      int    // 1-based line in the canonical DSL
}

func (s conditionSite) String() string {
	return s.Type + "#" + s.Relation + " [" + s.Subject + " with " + s.Condition + "]"
}

var reWith = regexp.MustCompile(`(\w+) with (\w+)`)

// parseConditionSites finds every `<subject> with <condition>` entry and
// attributes it to the type/relation it constrains.
func parseConditionSites(t *testing.T) ([]conditionSite, int) {
	t.Helper()
	raw, err := os.ReadFile(canonicalModelPath(t))
	require.NoError(t, err)
	return conditionSitesOf(string(raw))
}

// conditionSitesOf — the same parse over a named text (the gate's injection
// proofs feed it a model that is not the canonical one).
func conditionSitesOf(dsl string) ([]conditionSite, int) {
	lines := strings.Split(dsl, "\n")
	var sites []conditionSite
	var curType string
	for i, line := range lines {
		if m := reType.FindStringSubmatch(line); m != nil {
			curType = m[1]
			continue
		}
		// A `condition <name>(...)` block ends the type bodies. Its own body may
		// mention parameter names; it declares nothing about relations.
		if strings.HasPrefix(line, "condition ") {
			curType = ""
			continue
		}
		if curType == "" {
			continue
		}
		m := reDefine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		for _, w := range reWith.FindAllStringSubmatch(line, -1) {
			sites = append(sites, conditionSite{
				Type: curType, Relation: m[1], Subject: w[1], Condition: w[2], Line: i + 1,
			})
		}
	}
	return sites, len(lines)
}

// TestConditionedRelationHasAProducer — a relation may require a condition only
// if something produces a fact that carries it.
//
// Ограничение типа читается на записи: когда оно для субъектного типа выглядит
// как `[user with <cond>]`, БЕЗУСЛОВНАЯ строка для этого субъекта — безусловное
// основание. Условие лежит на самой строке прямого факта
// (`relation_fact.condition_name`), и вопрос о доступе вычисляет его сам; значит
// условие в силе ровно тогда, когда ЕДИНСТВЕННЫЙ писатель факта — свёртка
// журнала (`kaname.relation_fact_fold_row`) — его прикладывает.
//
// Производитель судится по ДЕЙСТВУЮЩЕМУ определению писателя: последняя
// миграция, определяющая свёртку строки, и перечень условий в её теле. Сверка —
// в обе стороны: запись модели без строки перечня есть объявленное и не
// действующее требование (оговорка, которая ничего не сужает); строка перечня
// без записи модели — условие, которого модель не объявляет (сужение, которого
// никто не решал). Ведомости исключений нет: kaname#133 (исход (а)) дал
// производителя обеим условным записям, и новое `with` без производителя —
// находка, а не строка ведомости.
//
// Поведение — что факт из строки журнала действительно несёт условие и что
// условие решает исход — держат интеграционные пробы Ф11-34…44, -48
// (`internal/handler/loginlanehttp/mfa_fresh_condition_integration_test.go`) и
// `migrations.TestPersonMachineEntryFactCarriesTheModelsCondition`.
func TestConditionedRelationHasAProducer(t *testing.T) {
	sites, lineCount := parseConditionSites(t)
	require.NotZero(t, lineCount, "read zero lines of the canonical model")
	require.NotEmpty(t, sites,
		"found zero `with <condition>` clauses in the canonical model — either the model "+
			"stopped using conditions (then delete this gate together with the producer list "+
			"of the fact writer) or the parser broke. A gate that inspects nothing must be RED, not green.")
	rows, file := foldConditionRowsOfTree(t)
	t.Logf("census: %d lines of the canonical model read, %d `with` clause(s) attributed; "+
		"fact writer %s attaches %d condition row(s)", lineCount, len(sites), file, len(rows))

	for _, f := range conditionProducerFindings(sites, rows) {
		t.Errorf("%s:%s (writer: %s)", canonicalModelRelPath, f, file)
	}
}

// foldConditionRow — one row of the writer's condition list.
type foldConditionRow struct {
	Type, Relation, Subject, Condition string
}

func (r foldConditionRow) key() string {
	return r.Type + "#" + r.Relation + " [" + r.Subject + " with " + r.Condition + "]"
}

// reFoldDef — the writer's definition; reFoldValues — its condition list;
// reFoldRow — one row of it.
var (
	reFoldDef    = regexp.MustCompile(`(?i)CREATE (OR REPLACE )?FUNCTION kaname\.relation_fact_fold_row\(`)
	reFoldValues = regexp.MustCompile(`(?s)FROM \(VALUES(.*?)\)\s*AS c\(object_type, relation, subject_type, condition_name\)`)
	reFoldRow    = regexp.MustCompile(`\('(\w+)',\s*'(\w+)',\s*'(\w+)',\s*'(\w+)'\)`)
)

// foldConditionRowsOfTree reads the CURRENT definition of the fact writer: the
// Up section of the newest migration that defines it.
func foldConditionRowsOfTree(t *testing.T) ([]foldConditionRow, string) {
	t.Helper()
	dir := filepath.Join("..", "migrations")
	names, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	require.NoError(t, err)
	require.NotEmpty(t, names, "no migrations read from %s — the writer cannot be located", dir)
	sort.Strings(names)
	var lastFile, lastUp string
	for _, n := range names {
		raw, err := os.ReadFile(n)
		require.NoError(t, err)
		up, _, _ := strings.Cut(string(raw), "-- +goose Down")
		if reFoldDef.MatchString(up) {
			lastFile, lastUp = filepath.Base(n), up
		}
	}
	require.NotEmpty(t, lastFile, "no migration among %d defines kaname.relation_fact_fold_row — "+
		"the fact writer is not where this gate looks for it", len(names))
	return foldConditionRowsOf(lastUp), lastFile
}

// foldConditionRowsOf parses the condition list out of one definition text.
func foldConditionRowsOf(up string) []foldConditionRow {
	var rows []foldConditionRow
	for _, block := range reFoldValues.FindAllStringSubmatch(up, -1) {
		for _, m := range reFoldRow.FindAllStringSubmatch(block[1], -1) {
			rows = append(rows, foldConditionRow{Type: m[1], Relation: m[2], Subject: m[3], Condition: m[4]})
		}
	}
	return rows
}

// conditionProducerFindings — the comparison itself, both directions.
func conditionProducerFindings(sites []conditionSite, rows []foldConditionRow) []string {
	produced := map[string]bool{}
	for _, r := range rows {
		produced[r.key()] = true
	}
	declared := map[string]bool{}
	var findings []string
	for _, s := range sites {
		if declared[s.String()] {
			continue
		}
		declared[s.String()] = true
		if !produced[s.String()] {
			findings = append(findings, fmt.Sprintf("%d declares %s, and the fact writer attaches no such "+
				"condition: an unconditioned row is an unconditioned ground, so the clause narrows "+
				"nothing. Either give the condition a row in the writer's list, or drop the clause.",
				s.Line, s))
		}
	}
	for _, r := range rows {
		if !declared[r.key()] {
			findings = append(findings, fmt.Sprintf("the fact writer attaches %s, which the canonical "+
				"model does not declare — a narrowing nobody decided. Drop the row or declare the clause.",
				r.key()))
		}
	}
	sort.Strings(findings)
	return findings
}

// Инъекции гейта настоящим входом: модель и тело писателя из дерева, по ОДНОМУ
// изменённому факту. Без них зелёный гейт неотличим от гейта, который не
// сравнивает ничего.
func TestConditionedRelationHasAProducer_Injections(t *testing.T) {
	sites, _ := parseConditionSites(t)
	rows, _ := foldConditionRowsOfTree(t)
	require.NotEmpty(t, rows, "ПРЕДПОСЫЛКА: перечень писателя прочитан непустым")
	require.Empty(t, conditionProducerFindings(sites, rows), "близнец: дерево как есть — находок нет")

	// Снятая строка писателя — запись модели без производителя.
	f := conditionProducerFindings(sites, rows[1:])
	require.Len(t, f, 1, "снятая строка писателя обязана дать ровно одну находку")
	require.Contains(t, f[0], rows[0].key())

	// Строка писателя без записи модели.
	extra := append(append([]foldConditionRow{}, rows...),
		foldConditionRow{Type: "compute_instance", Relation: "ssh", Subject: "service_account", Condition: "mfa_fresh"})
	f = conditionProducerFindings(sites, extra)
	require.Len(t, f, 1, "лишняя строка писателя обязана дать ровно одну находку")
	require.Contains(t, f[0], "service_account with mfa_fresh")

	// Тело писателя без перечня (прежний писатель) — находок столько, сколько
	// записей модели.
	require.Empty(t, foldConditionRowsOf("CREATE FUNCTION kaname.relation_fact_fold_row(p text) AS $$ BEGIN END $$;"))
	f = conditionProducerFindings(sites, nil)
	require.Len(t, f, len(sites), "писатель без условий — каждая запись модели находка")
}

// TestConditionProducerPremise — the premise the gate above rests on, asserted
// rather than assumed.
//
// The claim is: nothing derived from an AccessBinding can carry a condition. The
// reconciler is the only producer of binding-derived tuples, and the value it
// emits is `domain.MembershipTuple`. If that value ever gains a condition field,
// the claim is no longer true, this test fails, and the gate above — which looks
// for conditions only in the journal fold — has to learn the second writer;
// that is the point. A gate whose justification can rot
// silently is worth less than no gate.
//
// Read by reflection, not by grep: a field is a field, and a comment that says
// "condition" is not one.
func TestConditionProducerPremise(t *testing.T) {
	rt := reflect.TypeOf(domain.MembershipTuple{})
	var fields []string
	for i := 0; i < rt.NumField(); i++ {
		fields = append(fields, rt.Field(i).Name)
	}
	require.NotEmpty(t, fields, "domain.MembershipTuple has no fields — reflection premise broken")
	t.Logf("premise: domain.MembershipTuple carries %v", fields)

	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), "condition") {
			t.Fatalf("domain.MembershipTuple now carries a condition-bearing field %q. The premise "+
				"of TestConditionedRelationHasAProducer no longer holds: binding-derived tuples CAN "+
				"now be conditioned. Re-examine TestConditionedRelationHasAProducer: a binding-derived "+
				"tuple would be a second fact writer, and its conditions would have to be compared "+
				"with the model the same way the journal fold's are.", f)
		}
	}
}
