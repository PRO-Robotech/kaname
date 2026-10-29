// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migration_role_subtable_writer_emits_injection_test.go — IAM-CCR-24 приёмки
// `catalog-consequence-reaches-role-readers.md`: гейт §3.2а СПОСОБЕН упасть и
// СПОСОБЕН смолчать (kaname#76).
//
// Инъекция зовёт ТУ ЖЕ функцию, что и гейт дерева, над ТЕМ ЖЕ корпусом дерева,
// к которому добавлена одна синтетическая миграция новее нижней границы
// популяции. У каждой оси — законный близнец, отличающийся одним фактом:
// вызовом функции события в том же разделе.
package check_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// injRoleSubtableRel — синтетическая миграция: номер заведомо новее всякой
// живой, значит в популяции гейта при любом дереве.
const injRoleSubtableRel = check.MigrationsDirRel + "/99991231235959_synthetic_role_subtable_writer.sql"

// injEmitCall — вызов функции события в форме, какой его пишет миграция.
const injEmitCall = "SELECT kaname.resource_journal_emit_role_composition(ARRAY(SELECT DISTINCT role_id FROM gone));\n"

// treeMigrationCorpus — корпус миграций ДЕРЕВА. Инъекция идёт поверх живой
// цепочки, а не синтетической: нижняя граница популяции выводится обходом, и
// подставь проба свою — она доказывала бы работу на входе, которого в дереве нет.
func treeMigrationCorpus(t *testing.T) check.TreeCorpus {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	migs, err := check.MigrationCorpus(gateTree(t, root).tree)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	return migs
}

// withSynthetic — копия корпуса с одной добавленной миграцией.
func withSynthetic(base check.TreeCorpus, body string) check.TreeCorpus {
	out := make(check.TreeCorpus, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	out[injRoleSubtableRel] = body
	return out
}

// auditSynthetic — находки гейта о синтетической миграции и только о ней.
func auditSynthetic(t *testing.T, base check.TreeCorpus, body string) []check.RoleSubtableFinding {
	t.Helper()
	findings, census, err := check.AuditRoleSubtableWriters(withSynthetic(base, body))
	if err != nil {
		t.Fatalf("гейт не исполнился: %v", err)
	}
	if census.Files != len(base)+1 {
		t.Fatalf("гейт прочитал файлов %d из %d — синтетическая миграция вне обхода",
			census.Files, len(base)+1)
	}
	var out []check.RoleSubtableFinding
	for _, f := range findings {
		if f.File == injRoleSubtableRel {
			out = append(out, f)
		}
	}
	return out
}

func requireRoleSubtableFinding(t *testing.T, got []check.RoleSubtableFinding, section, table, why string) {
	t.Helper()
	for _, f := range got {
		if f.Section == section && (table == "" || f.Table == table) {
			return
		}
	}
	t.Fatalf("%s: находки о разделе %s (таблица %q) нет; получено %+v", why, section, table, got)
}

func requireRoleSubtableSilent(t *testing.T, got []check.RoleSubtableFinding, why string) {
	t.Helper()
	if len(got) > 0 {
		t.Fatalf("%s: законный близнец дал находку %+v", why, got)
	}
}

// TestRoleSubtableGate_IAMCCR24_WriterWithoutCallIsFound — основная ось и её
// близнец: снятие объявления правила с переселением, функция не зовётся.
func TestRoleSubtableGate_IAMCCR24_WriterWithoutCallIsFound(t *testing.T) {
	base := treeMigrationCorpus(t)
	writer := `-- +goose Up
WITH gone AS (
  DELETE FROM kaname.role_rule_ref rr
   WHERE EXISTS (SELECT 1 FROM kaname.roles r WHERE r.id = rr.role_id AND r.is_system = false)
     AND rr.module = 'probe'
  RETURNING rr.role_id, rr.module, rr.resource, rr.verb
)
INSERT INTO kaname.role_grant_orphan (role_id, object_type, verb, source, reason, applied_by)
SELECT role_id, module || '.' || resource, COALESCE(verb, ''), 'rule_ref', 'снято', 'migration:99991231235959' FROM gone;
-- +goose Down
SELECT 1;
`
	requireRoleSubtableFinding(t, auditSynthetic(t, base, writer), "Up", "role_rule_ref",
		"миграция пишет подтаблицу роли без функции события")

	twin := strings.Replace(writer, "-- +goose Down", injEmitCall+"-- +goose Down", 1)
	requireRoleSubtableSilent(t, auditSynthetic(t, base, twin), "вызов функции в том же разделе")
}

// TestRoleSubtableGate_IAMCCR24_SectionsAreJudgedApart — ось раздельности
// разделов: запись в `Down`, вызов только в `Up`.
func TestRoleSubtableGate_IAMCCR24_SectionsAreJudgedApart(t *testing.T) {
	base := treeMigrationCorpus(t)
	split := `-- +goose Up
` + injEmitCall + `
-- +goose Down
DELETE FROM kaname.role_verb WHERE object_type = 'probe.widgets';
`
	requireRoleSubtableFinding(t, auditSynthetic(t, base, split), "Down", "role_verb",
		"запись в Down при вызове только в Up — суждение по файлу дало бы молчание")

	twin := split + injEmitCall
	requireRoleSubtableSilent(t, auditSynthetic(t, base, twin), "вызов в том же разделе, что запись")
}

// TestRoleSubtableGate_IAMCCR24_EveryWriteFormIsFound — формы записи, которые
// образец гейта (`INSERT\s+INTO\s+kaname\.roles`) пропустил бы. У каждой —
// близнец с вызовом в том же разделе.
func TestRoleSubtableGate_IAMCCR24_EveryWriteFormIsFound(t *testing.T) {
	base := treeMigrationCorpus(t)
	forms := []struct{ name, stmt, table string }{
		{"строчные буквы", "delete from kaname.role_verb where verb = 'get';", "role_verb"},
		{"имя без схемы", "DELETE FROM role_verb WHERE verb = 'get';", "role_verb"},
		{"имя в кавычках", `DELETE FROM "kaname"."role_verb" WHERE verb = 'get';`, "role_verb"},
		{"ONLY", "DELETE FROM ONLY kaname.role_verb WHERE verb = 'get';", "role_verb"},
		{"вставка", "INSERT INTO kaname.role_rule_ref (role_id, module, resource, verb) VALUES ('r', 'm', 'x', 'get');", "role_rule_ref"},
		{"правка", "UPDATE kaname.role_rule_selectors SET object_types = ARRAY['m.x'];", "role_rule_selectors"},
		{"TRUNCATE", "TRUNCATE TABLE kaname.roles_unrelated, kaname.role_rule_selectors;", "role_rule_selectors"},
		{"MERGE", "MERGE INTO kaname.role_verb t USING src s ON t.role_id = s.role_id WHEN MATCHED THEN DELETE;", "role_verb"},
		{"COPY … FROM", "COPY kaname.role_verb (role_id, object_type, verb) FROM stdin;", "role_verb"},
		{"тело DO", "DO $$ BEGIN DELETE FROM kaname.role_verb WHERE verb = 'get'; END $$;", "role_verb"},
	}
	for _, f := range forms {
		body := "-- +goose Up\n" + f.stmt + "\n-- +goose Down\nSELECT 1;\n"
		requireRoleSubtableFinding(t, auditSynthetic(t, base, body), "Up", f.table, "форма «"+f.name+"»")
		twin := "-- +goose Up\n" + f.stmt + "\n" + injEmitCall + "-- +goose Down\nSELECT 1;\n"
		requireRoleSubtableSilent(t, auditSynthetic(t, base, twin), "форма «"+f.name+"» с вызовом")
	}
	t.Logf("перепись: форм записи доказано инъекцией %d, у каждой — близнец", len(forms))
}

// TestRoleSubtableGate_IAMCCR24_DynamicSQLIsNotJudged — динамический SQL с
// именем подтаблицы в литерале — отказ «не судится», а не молчание: даже
// вызов функции рядом его не снимает, потому что множество записанного
// разбор не видит.
func TestRoleSubtableGate_IAMCCR24_DynamicSQLIsNotJudged(t *testing.T) {
	base := treeMigrationCorpus(t)
	dyn := "-- +goose Up\nDO $$ BEGIN EXECUTE format('DELETE FROM kaname.%I WHERE true', 'role_verb'); END $$;\n" +
		injEmitCall + "-- +goose Down\nSELECT 1;\n"
	requireRoleSubtableFinding(t, auditSynthetic(t, base, dyn), "Up", "",
		"динамический SQL с именем подтаблицы роли")

	// Близнец: тот же динамический SQL над ЧУЖОЙ таблицей.
	twin := "-- +goose Up\nDO $$ BEGIN EXECUTE format('DELETE FROM kaname.%I WHERE true', 'audit_outbox'); END $$;\n" +
		"-- +goose Down\nSELECT 1;\n"
	requireRoleSubtableSilent(t, auditSynthetic(t, base, twin), "динамический SQL над чужой таблицей")
}

// TestRoleSubtableGate_IAMCCR24_CommentIsNotAWrite — упоминание таблицы в
// комментарии записью не является.
func TestRoleSubtableGate_IAMCCR24_CommentIsNotAWrite(t *testing.T) {
	base := treeMigrationCorpus(t)
	body := "-- +goose Up\n-- DELETE FROM kaname.role_verb когда-то стоял здесь\n" +
		"/* UPDATE kaname.role_rule_selectors SET x = 1; */\nSELECT 1;\n-- +goose Down\nSELECT 1;\n"
	requireRoleSubtableSilent(t, auditSynthetic(t, base, body), "запись в комментарии")
}

// TestRoleSubtableGate_IAMCCR24_NoTransactionWriterIsFound — раздел без
// транзакции, пишущий подтаблицы роли, — находка и при вызове функции: запись и
// событие там не атомарны.
func TestRoleSubtableGate_IAMCCR24_NoTransactionWriterIsFound(t *testing.T) {
	base := treeMigrationCorpus(t)
	body := "-- +goose NO TRANSACTION\n-- +goose Up\nDELETE FROM kaname.role_verb WHERE verb = 'get';\n" +
		injEmitCall + "-- +goose Down\nSELECT 1;\n"
	requireRoleSubtableFinding(t, auditSynthetic(t, base, body), "Up", "role_verb",
		"раздел без транзакции пишет подтаблицу роли")

	twin := strings.Replace(body, "-- +goose NO TRANSACTION\n", "", 1)
	requireRoleSubtableSilent(t, auditSynthetic(t, base, twin), "тот же раздел в транзакции")
}

// TestRoleSubtableGate_EmptyChainIsARefusal — цепочка без файлов — отказ, а не
// проход; цепочка без миграции, заводящей функцию, — тоже: нижнюю границу
// популяции вывести не из чего.
func TestRoleSubtableGate_EmptyChainIsARefusal(t *testing.T) {
	if _, _, err := check.AuditRoleSubtableWriters(check.TreeCorpus{}); err == nil {
		t.Fatal("пустая цепочка дала проход — «находок ноль» неотличимо от «прочитано ноль»")
	}
	noFloor := check.TreeCorpus{
		check.MigrationsDirRel + "/0001_initial.sql": "-- +goose Up\nDELETE FROM kaname.role_verb;\n",
	}
	if _, _, err := check.AuditRoleSubtableWriters(noFloor); err == nil {
		t.Fatal("цепочка без миграции, заводящей функцию события, дала проход — граница " +
			"популяции не выведена, и молчание гейта ни о чём")
	}
}
