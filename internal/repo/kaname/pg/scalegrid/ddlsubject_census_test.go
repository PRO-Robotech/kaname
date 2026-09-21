// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// migrationCorpus — тексты ВСЕХ миграций дерева, ключ — имя файла.
//
// Перепись берётся обходом, а не перечнем: перечень не двигался бы от новой
// миграции и продолжал бы знать снятые.
func migrationCorpus(t *testing.T) map[string]string {
	t.Helper()
	root := repoRootFromPackageDir(t)
	dir, err := under(root, migrateDir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: каталог миграций не приведён к посадке: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав %s: %v", dir, err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: чтение %s: %v", e.Name(), rerr)
		}
		out[e.Name()] = string(body)
	}
	if len(out) == 0 {
		t.Fatal("в каталоге миграций НОЛЬ файлов: обход пуст, и «находок нет» здесь " +
			"означало бы «читать было нечего»")
	}
	return out
}

// TestDdlRecogniserKnowsEveryFormInTheCorpus — распознаватель знает КАЖДУЮ
// форму оператора определения, встречающуюся в дереве.
//
// Распознаватель, не знающий формы, не молчит: неизвестный вид объекта даёт
// осторожный исход «задевает», и молчания не возникает by construction. Но
// осторожный исход — это лишний файл под отпечатком и лишний прогон на два
// часа, поэтому корпус обязан быть разобран ЦЕЛИКОМ, и это отдельное
// утверждение, а не следствие зелёного отпечатка.
func TestDdlRecogniserKnowsEveryFormInTheCorpus(t *testing.T) {
	corpus := migrationCorpus(t)

	files := make([]string, 0, len(corpus))
	for name := range corpus {
		files = append(files, name)
	}
	sort.Strings(files)

	var statements, ddl int
	byObject := map[string]int{}
	unknown := map[string][]string{}
	opaque := map[string]int{}

	for _, name := range files {
		for _, stmt := range sqlStatements(corpus[name]) {
			statements++
			toks := sqlTokens(stmt)
			if len(toks) == 0 {
				continue
			}
			verb := toks[0].word
			if verb != "create" && verb != "alter" && verb != "drop" {
				continue
			}
			ddl++
			s := ddlStatementOf(stmt, corpusIndex{})
			if s.opaque {
				opaque[name]++
				byObject["<динамический DDL>"]++
				continue
			}
			if s.unknownObject != "" {
				unknown[name] = append(unknown[name], verb+" "+s.unknownObject)
				continue
			}
			byObject[verb+" "+objectWordOf(toks)]++
		}
	}

	kinds := make([]string, 0, len(byObject))
	for k := range byObject {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)

	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: файлов миграций %d, операторов %d, из них определения %d",
		len(files), statements, ddl)
	for _, k := range kinds {
		t.Logf("  форма %-34s — операторов %d", k, byObject[k])
	}
	if len(opaque) > 0 {
		for _, name := range files {
			if opaque[name] > 0 {
				t.Logf("  ДИНАМИЧЕСКИЙ DDL: %s — операторов %d (субъект подставляется "+
					"во время выполнения, статически не выводится)", name, opaque[name])
			}
		}
	}

	// ПРЕДПОСЫЛКА: обход нашёл предмет. Ноль операторов определения означал бы,
	// что распознаватель судил пустоту, а зелёное было бы неотличимо от
	// «читать было нечего».
	if ddl == 0 {
		t.Fatal("в корпусе НОЛЬ операторов определения: распознаватель судил пустоту")
	}
	if len(byObject) < 2 {
		t.Fatalf("корпус свёлся к %d форме: положительный контроль обязан быть НЕПУСТЫМ "+
			"и разнообразным, иначе он ничего не держит", len(byObject))
	}

	if len(unknown) > 0 {
		var lines []string
		for _, name := range files {
			if forms := unknown[name]; len(forms) > 0 {
				lines = append(lines, fmt.Sprintf("    %s: %s", name, strings.Join(forms, ", ")))
			}
		}
		t.Errorf("распознаватель НЕ ЗНАЕТ форм, встреченных в дереве:\n%s\n"+
			"  Исход по ним осторожный («задевает»), поэтому молчания нет — но каждая такая "+
			"форма стоит лишнего файла под отпечатком и пересъёмки на два часа.\n"+
			"  ИСХОД ОДИН: разобрать форму в ddlsubject.go и назвать субъект, который она "+
			"меняет.\n"+
			"  Объявить вид безвредным СЛОВОМ нельзя: запись словаря безвредных несёт три "+
			"оператора доказательства, и без них молчания не покупает. Именно этой дверью "+
			"в прибор вошли расширенная статистика и политика построчной безопасности — обе "+
			"меняют план чтения, обе лежали в словаре без единого довода, и перепись форм их "+
			"не видела ПО ПОСТРОЕНИЮ: вид, объявленный знакомым, ею не ищется.",
			strings.Join(lines, "\n"))
	}
}

// objectWordOf — вид объекта в голове оператора, для переписи.
func objectWordOf(toks []sqlToken) string {
	i := 1
	for i < len(toks) && (toks[i].word == "or" || toks[i].word == "replace" ||
		toks[i].word == "global" || toks[i].word == "local" || toks[i].word == "temp" ||
		toks[i].word == "temporary" || toks[i].word == "unlogged" ||
		toks[i].word == "unique" || toks[i].word == "concurrently") {
		i++
	}
	if i >= len(toks) {
		return "?"
	}
	if toks[i].word == "materialized" && i+1 < len(toks) {
		return "materialized " + toks[i+1].word
	}
	if toks[i].word == "constraint" && i+1 < len(toks) {
		return "constraint " + toks[i+1].word
	}
	return toks[i].word
}

// TestMigrationSelectionOnTheRealTree — инъекция НАСТОЯЩИМ входом из дерева.
//
// Синтетика доказывает, что предикат различает формы; она не доказывает, что
// формы в дереве именно те, о которых мы думаем. Поэтому здесь судятся
// настоящие файлы, а рядом с каждым дефектом стоит законный близнец — файл той
// же эпохи и того же вида, отличающийся РОВНО ОДНИМ фактом: по какую сторону
// оператора стоит измеряемое имя.
func TestMigrationSelectionOnTheRealTree(t *testing.T) {
	corpus := migrationCorpus(t)
	root := repoRootFromPackageDir(t)

	fp, err := ComputeFingerprint(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: отпечаток не вычислен: %v", err)
	}
	if len(fp.Tables) == 0 {
		t.Fatal("из кода вердикта не выведено НИ ОДНОГО имени таблицы: судить было нечего")
	}

	index := buildCorpusIndex(corpus)
	if len(index.dynamicDDLFuncs) == 0 {
		t.Log("функций с динамическим DDL в корпусе нет — случай ниже проверяет осторожный " +
			"исход на дереве, где его предмета уже не осталось")
	}

	// Пары взяты из ИСТОРИИ пересъёмок 16–17 сентября: каждая из этих миграций
	// в своё время стоила одного полного прогона отчёта.
	cases := []struct {
		file string
		want bool
		why  string
	}{
		{"20260916190000_human_session_is_our_record.sql", false,
			"измеряемая kaname.users только в REFERENCES чужого определения"},
		{"20260917015400_recovery_code_is_our_record.sql", false,
			"измеряемая kaname.users только в REFERENCES чужого определения"},
		{"20260917221000_access_keys_are_our_record.sql", false,
			"измеряемая kaname.users только в REFERENCES чужого определения"},
		{"20260915111233_login_methods_live_in_their_own_rows.sql", true,
			"ЗАКОННЫЙ БЛИЗНЕЦ: ALTER TABLE kaname.users ADD COLUMN — субъект измеряемый"},
		{"20260916012708_invite_row_carries_its_deadline.sql", true,
			"ЗАКОННЫЙ БЛИЗНЕЦ: ALTER TABLE kaname.users ADD COLUMN — субъект измеряемый"},
		{"20260917210000_memberships_carry_a_cursor_index_for_their_owner.sql", true,
			"ЗАКОННЫЙ БЛИЗНЕЦ: CREATE INDEX ON kaname.memberships — именно эта миграция " +
				"сдвинула план (Index Only Scan→memberships стал Index Scan→memberships)"},
		{"20260906085136_cluster_anchor_gets_a_way_back.sql", false,
			"ОПРЕДЕЛЯЕТ функцию с динамическим DDL, но не зовёт её: определение тела " +
				"структуры не меняет"},
		{"20260906214500_cluster_anchor_moves_to_its_declared_spelling.sql", true,
			"ЗАКОННЫЙ БЛИЗНЕЦ определителя: ЗОВЁТ ту же функцию внутри DO-блока — " +
				"динамический ALTER TABLE по обходу каталога схемы исполняется здесь, " +
				"и субъект статически не выводится"},
	}

	var caught, silent int
	for _, c := range cases {
		body, ok := corpus[c.file]
		if !ok {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s в дереве нет — фикстура пережила свой предмет", c.file)
		}
		got := migrationTouches(body, fp.Tables, scopeReadPlan, index)
		if got != c.want {
			t.Errorf("%s: вердикт %v, ожидался %v\n  довод: %s", c.file, got, c.want, c.why)
			continue
		}
		if got {
			caught++
		} else {
			silent++
		}
	}
	t.Logf("перепись инъекции по дереву: файлов в корпусе %d; проверено %d; "+
		"взято под отпечаток %d; отсеяно %d", len(corpus), len(cases), caught, silent)
	if caught == 0 || silent == 0 {
		t.Fatal("инъекция односторонняя: предикат, отвечающий одинаково на всё, прошёл бы её")
	}
}

// TestScopeSeparatesReadPlanFromWriteCost — одна и та же форма значима для
// одного прибора и безразлична другому, и отличаются случаи РОВНО ОДНИМ фактом.
//
// Без этой пары сужение неотличимо от снятия форм вовсе: триггер и входящий
// ключ исчезли бы из наблюдения у ОБОИХ приборов, а у прибора записи они лежат
// ровно на измеряемом пути.
func TestScopeSeparatesReadPlanFromWriteCost(t *testing.T) {
	tables := []string{"kaname.resource_mirror"}

	cases := []struct {
		name string
		sql  string
	}{
		{
			name: "триггер на измеряемой таблице",
			sql: "CREATE TRIGGER resource_mirror_journal AFTER INSERT ON kaname.resource_mirror " +
				"FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('mirror');",
		},
		{
			name: "входящий внешний ключ на измеряемую таблицу",
			sql: "CREATE TABLE kaname.mirror_notes (\n" +
				"  object_type text NOT NULL, object_id text NOT NULL,\n" +
				"  CONSTRAINT mirror_notes_fk FOREIGN KEY (object_type, object_id)\n" +
				"    REFERENCES kaname.resource_mirror(object_type, object_id) ON DELETE CASCADE\n" +
				");",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			read := migrationTouches(c.sql, tables, scopeReadPlan, corpusIndex{})
			write := migrationTouches(c.sql, tables, scopeWriteCost, corpusIndex{})
			if read {
				t.Errorf("прибор ЧТЕНИЯ взял форму, которая исполняется на записи: "+
					"план чтения %s от неё не меняется", tables[0])
			}
			if !write {
				t.Errorf("прибор ЗАПИСИ пропустил форму, лежащую на измеряемом пути: "+
					"стоимость записи и удаления строки %s от неё меняется", tables[0])
			}
			t.Logf("чтение %v · запись %v — отличие РОВНО в области прибора", read, write)
		})
	}

	// Законный близнец обеих половин: субъект измеряемый — берут ОБА прибора.
	twin := "ALTER TABLE kaname.resource_mirror ADD COLUMN note text;"
	if !migrationTouches(twin, tables, scopeReadPlan, corpusIndex{}) ||
		!migrationTouches(twin, tables, scopeWriteCost, corpusIndex{}) {
		t.Fatal("правку САМОЙ измеряемой таблицы пропустил хотя бы один прибор: " +
			"разделение областей выродилось в снятие наблюдения")
	}
}
