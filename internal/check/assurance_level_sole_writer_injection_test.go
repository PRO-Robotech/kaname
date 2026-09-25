// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// assurance_level_sole_writer_injection_test.go — доказательство способности
// гейта «правило одно» упасть И смолчать, по обеим половинам.
//
// Инъекция герметична: синтетический исходник и синтетический накат подаются
// прямо в разбор. Оси — производство уровня каждой названной формой (краснеет),
// чтение каждой названной формой (молчит), поле уровня в строке способа входа
// (краснеет — кодом и миграцией), четыре законные копии и запись сессии (молчат,
// когда названы ведомостью), объявление оси при таблице сессии (молчит) и вне её
// (краснеет).
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

func levelScan(t *testing.T, rel, src string) ([]check.LevelUse, check.LevelUseCensus) {
	t.Helper()
	uses, census, err := check.ScanAssuranceLevelUses(rel, []byte(src), check.AssuranceHomeImport)
	if err != nil {
		t.Fatalf("разбор инъекции %s: %v", rel, err)
	}
	if census.ImportingHome == 0 {
		t.Fatalf("инъекция не импортирует дом правила — разбор её не читает, и молчание ниже сказано ни о чём: %+v", census)
	}
	return uses, census
}

func kinds(uses []check.LevelUse, kind check.LevelUseKind) []check.LevelUse {
	var out []check.LevelUse
	for _, u := range uses {
		if u.Kind == kind {
			out = append(out, u)
		}
	}
	return out
}

const levelImport = `import "github.com/PRO-Robotech/kaname/internal/assurance"`

// TestLevelSoleWriterGateRedsOnEveryProductionForm — КРАСНОЕ: уровень произведён
// мимо правила.
func TestLevelSoleWriterGateRedsOnEveryProductionForm(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		kind check.LevelUseKind
	}{
		{"присваивание константы", `package pg
` + levelImport + `
type rec struct{ level assurance.Level }
func (r *rec) raise() { r.level = assurance.Level2 }
`, check.LevelUseProduction},
		{"поле составного литерала", `package pg
` + levelImport + `
type rec struct{ level assurance.Level }
func fresh() rec { return rec{level: assurance.Level1} }
`, check.LevelUseProduction},
		{"возврат константы", `package pg
` + levelImport + `
func best() assurance.Level { return assurance.Level3 }
`, check.LevelUseProduction},
		{"аргумент вызова", `package pg
` + levelImport + `
func store(l assurance.Level) {}
func seed() { store(assurance.Level2) }
`, check.LevelUseProduction},
		{"преобразование строки в уровень", `package pg
` + levelImport + `
func read(s string) assurance.Level { return assurance.Level(s) }
`, check.LevelUseConversion},
		{"через псевдоним импорта", `package pg
import lv "github.com/PRO-Robotech/kaname/internal/assurance"
var def = lv.Level1
`, check.LevelUseProduction},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const rel = "internal/repo/kaname/pg/session.go"
			uses, census := levelScan(t, rel, tc.src)
			if census.AxisReferences == 0 {
				t.Fatalf("форма ВНЕ наблюдения: обращений к оси прочитано 0 (%+v)", census)
			}
			hits := kinds(uses, tc.kind)
			if len(hits) != 1 {
				t.Fatalf("форма %q НЕ стала находкой рода %v: %v при переписи %+v", tc.name, tc.kind, uses, census)
			}
			if !strings.Contains(hits[0].String(), rel) {
				t.Errorf("находка не называет координату: %s", hits[0])
			}
		})
	}
}

// TestLevelSoleWriterGateStaysSilentOnReads — ЧТЕНИЯ: сравнение, case, вызов
// правила — не производство.
func TestLevelSoleWriterGateStaysSilentOnReads(t *testing.T) {
	t.Parallel()
	const src = `package edge
` + levelImport + `
func classify(l assurance.Level, ps []assurance.Presentation) int {
	if l == assurance.Level3 || l != assurance.Level1 {
		return 3
	}
	switch l {
	case assurance.Level2:
		return 2
	}
	got, ok := assurance.LevelOf(ps)
	_ = got
	_ = ok
	return len(assurance.PresentableLevels(nil))
}
`
	uses, census := levelScan(t, "internal/service/x.go", src)
	if census.Comparisons < 3 || census.RuleCalls < 1 {
		t.Fatalf("положительный контроль: сравнений %d, вызовов правила %d — чтения не прочитаны", census.Comparisons, census.RuleCalls)
	}
	if got := kinds(uses, check.LevelUseProduction); len(got) != 0 {
		t.Fatalf("чтение объявлено производством: %v", got)
	}
	if got := kinds(uses, check.LevelUseConversion); len(got) != 0 {
		t.Fatalf("вызов правила объявлен преобразованием: %v", got)
	}
}

// TestLevelSoleWriterGateSeesTheFieldAndTheLedgerNamesIt — поле уровня в
// структуре: находка вне ведомости, молчание для названного держателя.
func TestLevelSoleWriterGateSeesTheFieldAndTheLedgerNamesIt(t *testing.T) {
	t.Parallel()
	const src = `package pg
` + levelImport + `
// SessionRecord — запись сессии: единственное состояние уровня.
type SessionRecord struct {
	ID    string
	Level assurance.Level
}
// SignInMethodRow — строка способа входа: уровня здесь быть не должно (Н60).
type SignInMethodRow struct {
	Kind  string
	Level assurance.Level
}
// StepUpEvent — запись журнала повышения: чтение записи.
type StepUpEvent struct{ Before, After assurance.Level }
type plain struct{ Name string }
`
	uses, _ := levelScan(t, "internal/repo/kaname/pg/session.go", src)
	fields := kinds(uses, check.LevelUseStructField)
	var names []string
	for _, f := range fields {
		names = append(names, f.Holder)
	}
	if strings.Join(names, ",") != "SessionRecord,SignInMethodRow,StepUpEvent" {
		t.Fatalf("держатели поля уровня прочитаны как %v; ожидались SessionRecord, SignInMethodRow, StepUpEvent (по одному на тип)", names)
	}
	for _, f := range fields {
		if !strings.Contains(f.String(), "internal/repo/kaname/pg/session.go") {
			t.Errorf("держатель без координаты: %s", f)
		}
	}
	// Файл, не импортирующий дом, читается как «обращений нет», а не как чистый.
	_, census, err := check.ScanAssuranceLevelUses("internal/service/y.go", []byte("package svc\nvar x = 1\n"), check.AssuranceHomeImport)
	if err != nil {
		t.Fatal(err)
	}
	if census.ImportingHome != 0 || census.AxisReferences != 0 {
		t.Errorf("файл без импорта дома посчитан импортирующим: %+v", census)
	}
}

// TestLevelSoleWriterMigrationHalf — объявление оси в схеме: при таблице сессии
// — молчит, в другой таблице — находка, перечень не той формы — не ось.
func TestLevelSoleWriterMigrationHalf(t *testing.T) {
	t.Parallel()
	up := `
CREATE TABLE kaname.sessions (
  id text PRIMARY KEY,
  assurance_level text NOT NULL CONSTRAINT sessions_assurance_level_ck CHECK (assurance_level IN ('1', '2', '3'))
);
CREATE TABLE kaname.sign_in_methods (
  kind text NOT NULL,
  assurance_level text NOT NULL CHECK (assurance_level = ANY (ARRAY['1'::text, '2'::text, '3'::text]))
);
ALTER TABLE kaname.other ADD CONSTRAINT other_state_ck CHECK (state IN ('1', '2'));
ALTER TABLE kaname.third ADD CONSTRAINT third_kind_ck CHECK (kind IN ('1', '2', '3', '4'));
`
	// Накат подаётся ЗАБЕЛЁННЫМ тем же средством, что у гейта: комментарии
	// снимает вызывающий, а не разбор.
	cols := check.ScanAssuranceAxisColumns("internal/migrations/1_x.sql", migrations.SQLBlankComments(up))
	if len(cols) != 2 {
		t.Fatalf("столбцов оси найдено %d при ожидаемых 2 (перечни «1,2» и «1,2,3,4» — не ось): %v", len(cols), cols)
	}
	if cols[0].Table != "kaname.sessions" || cols[0].Column != "assurance_level" {
		t.Errorf("первый столбец оси прочитан как %+v", cols[0])
	}
	if cols[1].Table != "kaname.sign_in_methods" {
		t.Errorf("второй столбец оси прочитан как %+v", cols[1])
	}
	if !strings.Contains(cols[1].String(), "sign_in_methods") {
		t.Errorf("находка не называет таблицу: %s", cols[1])
	}
	if got := check.ScanAssuranceAxisColumns("internal/migrations/2_x.sql",
		migrations.SQLBlankComments("-- level IN ('1','2','3')\nSELECT 1;\n")); len(got) != 0 {
		t.Errorf("комментарий прочитан как объявление оси: %v", got)
	}
}

// TestLevelSoleWriterAxisCopyLedger — ведомость снимков схемы в обе стороны:
// снимок в названной таблице молчит; тот же столбец в неназванной — находка с
// таблицей; запись ведомости без столбца — находка «нечего исключать»; дом без
// объявления — находка. Близнец и инъекция отличаются одним фактом — таблицей.
func TestLevelSoleWriterAxisCopyLedger(t *testing.T) {
	t.Parallel()
	const home, snapshot = "kaname.sessions", "kaname.grants"
	copies := map[string]string{snapshot: "снимок уровня на выдаче"}
	site := func(table string) check.AxisColumnSite {
		return check.AxisColumnSite{File: "internal/migrations/9_x.sql", Line: 1, Table: table, Column: "acr"}
	}

	if got := check.JudgeAssuranceAxisColumns([]check.AxisColumnSite{site(home), site(snapshot)}, home, copies); len(got) != 0 {
		t.Errorf("близнец: снимок в названной таблице дал находки: %v", got)
	}
	got := check.JudgeAssuranceAxisColumns([]check.AxisColumnSite{site(home), site("kaname.other")}, home, copies)
	joined := strings.Join(got, "\n")
	if len(got) != 2 || !strings.Contains(joined, "kaname.other") || !strings.Contains(joined, "нечего исключать") {
		t.Errorf("инъекция: столбец оси вне дома и ведомости и запись ведомости без столбца — ожидались обе находки: %v", got)
	}
	if got := check.JudgeAssuranceAxisColumns([]check.AxisColumnSite{site(snapshot)}, home, copies); len(got) != 1 ||
		!strings.Contains(got[0], home) {
		t.Errorf("дом без объявления оси не назван: %v", got)
	}
}
