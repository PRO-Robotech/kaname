// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// ИСПОЛНЯЕМЫЙ SQL СУДИТСЯ ТЕМ ЖЕ РАЗБОРОМ, ЧТО И ОПЕРАТОР В ФАЙЛЕ
//
// Признак динамического случая был ПАРНЫМ: слово `EXECUTE` плюс отдельный
// перечень глаголов. Перечень не рос вместе с разбором, и формы, про которые
// прямо написано «менять план — их единственное назначение», в динамическом
// виде МОЛЧАЛИ. Замер до починки: семь форм из восьми молчат, восьмая краснеет.
//
// Эта проба — замок на то, что второго перечня больше нет: она гоняет КАЖДУЮ
// форму, которую знает разбор, в динамическом виде, и требует того же исхода,
// что у оператора в файле.
func TestExecutedSQLIsJudgedByTheSameParser(t *testing.T) {
	measured := []string{"access_bindings"}

	// inDo — та же форма, обёрнутая в исполняемый блок с подстановкой имени.
	inDo := func(inner string) string {
		return "DO $$\nDECLARE r record;\nBEGIN\n  FOR r IN SELECT t FROM pg_class LOOP\n" +
			"    EXECUTE format('" + inner + "', r.t);\n  END LOOP;\nEND;\n$$;"
	}

	cases := []struct {
		name      string
		inner     string
		wantRead  bool
		wantWrite bool
	}{
		{"правка таблицы", "ALTER TABLE kaname.%I ADD COLUMN x text", true, true},
		{"создание таблицы", "CREATE TABLE kaname.%I (id text)", true, true},
		{"снятие таблицы", "DROP TABLE kaname.%I", true, true},
		{"индекс", "CREATE INDEX i ON kaname.%I (id)", true, true},
		{"снятие индекса", "DROP INDEX kaname.%I", true, true},
		{"расширенная статистика", "CREATE STATISTICS kaname.%I_stx ON a, b FROM kaname.%I", true, true},
		{"политика построчной безопасности", "CREATE POLICY p ON kaname.%I USING (true)", true, true},
		{"внешняя таблица", "ALTER FOREIGN TABLE kaname.%I ADD COLUMN x text", true, true},
		{"представление", "CREATE OR REPLACE VIEW kaname.%I AS SELECT 1", true, true},
		{"схема", "DROP SCHEMA %I CASCADE", true, true},
		{"перестроение", "REINDEX TABLE kaname.%I", true, true},
		{"сбор статистики", "ANALYZE kaname.%I", true, true},
		{"правило", "CREATE RULE r AS ON SELECT TO kaname.%I DO INSTEAD SELECT 1", true, true},
		{
			// РАЗВЕДЕНИЕ ОБЛАСТЕЙ СОХРАНЯЕТСЯ И В ДИНАМИКЕ. Триггер исполняется
			// на записи: прибору чтения он безразличен, прибору записи — нет.
			// Прежняя непрозрачность красила оператор целиком и ОБОИМ, то есть
			// теряла это различие.
			name: "триггер", inner: "CREATE TRIGGER t AFTER INSERT ON kaname.%I FOR EACH ROW EXECUTE FUNCTION f()",
			wantRead: false, wantWrite: true,
		},
		{
			name: "входящий внешний ключ", inner: "ALTER TABLE kaname.other ADD CONSTRAINT c FOREIGN KEY (x) REFERENCES kaname.%I(id)",
			wantRead: false, wantWrite: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := inDo(c.inner)
			if got := migrationTouches(src, measured, scopeReadPlan, corpusIndex{}); got != c.wantRead {
				t.Fatalf("прибор ЧТЕНИЯ: вердикт %v, ожидался %v", got, c.wantRead)
			}
			if got := migrationTouches(src, measured, scopeWriteCost, corpusIndex{}); got != c.wantWrite {
				t.Fatalf("прибор ЗАПИСИ: вердикт %v, ожидался %v", got, c.wantWrite)
			}
		})
	}

	// ПОДСТАНОВКА И ПОЛНОЕ ИМЯ — РАЗНЫЕ ИСХОДЫ, и это вторая половина пары.
	// Прежний признак не различал их: любой исполняемый DDL делал оператор
	// задевающим ЛЮБУЮ измеряемую таблицу, и выписанный оператор над чужой
	// таблицей краснел зря.
	literal := func(sql string) string {
		return "DO $$ BEGIN EXECUTE '" + sql + "'; END $$;"
	}
	if !migrationTouches(literal("ALTER TABLE kaname.access_bindings ADD COLUMN x text"),
		measured, scopeReadPlan, corpusIndex{}) {
		t.Fatal("выписанный исполняемый оператор над ИЗМЕРЯЕМОЙ таблицей отсеян")
	}
	if migrationTouches(literal("ALTER TABLE kaname.limits ADD COLUMN x text"),
		measured, scopeReadPlan, corpusIndex{}) {
		t.Fatal("выписанный исполняемый оператор над ЧУЖОЙ таблицей признан влияющим: " +
			"подстановка и полное имя судятся одинаково, то есть субъект не читается")
	}

	// ЛИТЕРАЛ, КОТОРЫЙ НИЧЕГО НЕ ИСПОЛНЯЕТ, оператором не является.
	if migrationTouches(
		"DO $$ BEGIN RAISE EXCEPTION 'ALTER TABLE kaname.access_bindings здесь запрещён'; END $$;",
		measured, scopeReadPlan, corpusIndex{}) {
		t.Fatal("текст оператора в сообщении об отказе принят за исполнение")
	}

	// ГЛУБИНА. Оператор лежит литералом ВНУТРИ тела блока — то есть на втором
	// уровне. Разбор в один уровень видит только тело и молчит: именно так
	// первая редакция этой починки промолчала по всем формам сразу.
	if depth := len(executedLiterals(inDo("ALTER TABLE kaname.%I ADD COLUMN x text"))); depth < 2 {
		t.Fatalf("литералов собрано %d: спуск идёт не глубже одного уровня, а исполняемый "+
			"оператор лежит внутри тела блока", depth)
	}
	t.Logf("перепись: форм в динамическом виде проверено %d, у каждой обе области прибора",
		len(cases))
}

// TestParserAndExecutedSQLShareOneDictionary — у разбора и у исполняемого SQL
// ОДИН словарь форм, и это проверяется обходом, а не чтением кода.
//
// Каждая форма, которую разбор судит в файле, обязана судиться и в
// динамическом виде. Расхождение здесь и было критической находкой.
func TestParserAndExecutedSQLShareOneDictionary(t *testing.T) {
	measured := []string{"access_bindings"}

	// Формы взяты из того же перечня, что судит разбор: голова оператора.
	forms := map[string]string{
		"create table":      "CREATE TABLE kaname.access_bindings (id text)",
		"alter table":       "ALTER TABLE kaname.access_bindings ADD COLUMN x text",
		"drop table":        "DROP TABLE kaname.access_bindings",
		"create index":      "CREATE INDEX i ON kaname.access_bindings (id)",
		"create view":       "CREATE VIEW kaname.access_bindings AS SELECT 1",
		"drop schema":       "DROP SCHEMA kaname CASCADE",
		"create statistics": "CREATE STATISTICS kaname.s ON a, b FROM kaname.access_bindings",
		"create policy":     "CREATE POLICY p ON kaname.access_bindings USING (true)",
		"foreign table":     "ALTER FOREIGN TABLE kaname.access_bindings ADD COLUMN x text",
		"analyze":           "ANALYZE kaname.access_bindings",
		"reindex":           "REINDEX TABLE kaname.access_bindings",
		"cluster":           "CLUSTER kaname.access_bindings USING pk",
		"vacuum":            "VACUUM FULL kaname.access_bindings",
		"create rule":       "CREATE RULE r AS ON SELECT TO kaname.access_bindings DO INSTEAD SELECT 1",
	}

	names := make([]string, 0, len(forms))
	for k := range forms {
		names = append(names, k)
	}
	sort.Strings(names)

	var mismatched []string
	for _, k := range names {
		inFile := migrationTouches(forms[k]+";", measured, scopeReadPlan, corpusIndex{})
		executed := migrationTouches("DO $$ BEGIN EXECUTE '"+forms[k]+"'; END $$;",
			measured, scopeReadPlan, corpusIndex{})
		if inFile != executed {
			mismatched = append(mismatched, fmt.Sprintf("%s: в файле %v, исполняемый %v",
				k, inFile, executed))
		}
	}
	t.Logf("перепись: форм сверено %d", len(forms))
	if len(mismatched) > 0 {
		t.Errorf("разбор и исполняемый SQL судят РАЗНО — значит словарей снова два:\n  %s\n"+
			"  Второй перечень не растёт вместе с разбором и расходится с ним молча: формы, "+
			"заведённые позже, в динамическом виде замолкают.",
			strings.Join(mismatched, "\n  "))
	}
}
