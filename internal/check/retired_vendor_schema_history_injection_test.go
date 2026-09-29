// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// Законная форма «история схемы снятого идентификатора» — падучесть в ОБЕ
// стороны на синтетике. Идентификатор строится из словаря класса
// (`check.RetiredVendorMarks`), как и во всех фикстурах этого гейта: так
// каждая метка, которая бывает частью имени SQL, гоняется поимённо.
//
// Законный близнец — ровно то, что делает снятие столбца: свод завёл столбец,
// его проверку и индекс; миграция снятия сверяет строки, снимает всё явно и в
// откате восстанавливает; проба миграции засевает прежнее состояние и
// спрашивает столбец после отката. Каждый дефект ниже меняет ОДИН факт против
// этого близнеца.

// identMarks — метки словаря, которые бывают частью имени SQL. Метка с
// косой чертой (путь образа) идентификатором не бывает; её граница — своя проба.
func identMarks(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, m := range check.RetiredVendorMarks {
		if strings.Trim(m, "abcdefghijklmnopqrstuvwxyz0123456789_") == "" {
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		t.Fatalf("предпосылка: в словаре %v нет ни одной метки-идентификатора — законной формы судить не на чем",
			check.RetiredVendorMarks)
	}
	return out
}

const (
	histDir     = "internal/migrations/"
	histInitial = histDir + "0001_initial.sql"
	histDrop    = histDir + "20260928231124_mirror_leaves.sql"
	histLater   = histDir + "20260929000000_later.sql"
	histProbe   = histDir + "mirror_leaves_integration_test.go"
)

// histFixture — близнец: свод, миграция снятия и её проба. `col` — имя
// столбца, несущее метку.
func histFixture(col string) map[string]string {
	return map[string]string{
		histInitial: "-- +goose Up\n" +
			"CREATE TABLE kaname.t (\n" +
			"    id text,\n" +
			"    " + col + " text,\n" +
			"    CONSTRAINT t_" + col + "_check CHECK ((" + col + " IS NULL) OR (length(" + col + ") >= 1))\n" +
			");\n" +
			"CREATE UNIQUE INDEX t_" + col + "_unique ON kaname.t USING btree (" + col + ");\n" +
			"COMMENT ON COLUMN kaname.t." + col + " IS 'Имя у прежнего поставщика.';\n" +
			"-- +goose Down\n" +
			"DROP TABLE kaname.t;\n",
		histDrop: "-- +goose Up\n" +
			"SELECT count(*) FROM kaname.t\n" +
			" WHERE " + col + " IS NOT NULL\n" +
			"   AND " + col + " <> id;\n" +
			"ALTER TABLE kaname.t\n" +
			"    DROP CONSTRAINT t_" + col + "_check;\n" +
			"DROP INDEX kaname.t_" + col + "_unique;\n" +
			"ALTER TABLE kaname.t DROP COLUMN " + col + ";\n" +
			"-- +goose Down\n" +
			"ALTER TABLE kaname.t ADD COLUMN " + col + " text;\n" +
			"UPDATE kaname.t SET " + col + " = id;\n" +
			"ALTER TABLE kaname.t ADD CONSTRAINT t_" + col + "_check CHECK ((" + col + " IS NULL));\n" +
			"CREATE UNIQUE INDEX t_" + col + "_unique ON kaname.t USING btree (" + col + ");\n",
		histProbe: "package migrations_test\n\n" +
			"const mirrorColumn = \"" + col + "\"\n\n" +
			"const seed = `INSERT INTO kaname.t (id, " + col + ") VALUES ('a', 'b')`\n" +
			"const after = `SELECT " + col + " FROM kaname.t WHERE id = $1`\n",
	}
}

// histLinesOf — строк фикстуры, несущих имя столбца: столько привязок гейт
// насчитал бы, не знай он законной формы.
func histLinesOf(files map[string]string, col string) int {
	n := 0
	for _, body := range files {
		for _, line := range strings.Split(body, "\n") {
			if strings.Contains(line, col) {
				n++
			}
		}
	}
	return n
}

func withFiles(base map[string]string, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// TestSchemaHistory_RemovedIdentifierIsNotABinding — ЗАКОННЫЙ БЛИЗНЕЦ: столбец,
// его проверка и индекс сняты историей, и ни одна строка истории — свода,
// снятия, отката, пробы — не привязка. Перепись называет эти строки числом.
func TestSchemaHistory_RemovedIdentifierIsNotABinding(t *testing.T) {
	t.Parallel()
	for _, mark := range identMarks(t) {
		t.Run(mark, func(t *testing.T) {
			t.Parallel()
			col := mark + "_client_id"
			files := histFixture(col)
			v := judgeVendor(t, vendorCorpus(files), nil)
			silent(t, v)
			if v.Census.Bindings != 0 {
				t.Fatalf("строки истории снятого засчитаны привязками: %s", v.Census)
			}
			if want := histLinesOf(files, col); v.Census.HistoryLines != want {
				t.Fatalf("строк истории снятого %d, в фикстуре их %d: граница обязана быть названа числом — %s",
					v.Census.HistoryLines, want, v.Census)
			}
			if v.Census.HistoryMigrations != 2 || v.Census.HistoryRemoved != 3 {
				t.Fatalf("перепись истории: миграций %d (хотели 2), снятых идентификаторов %d (хотели 3) — %s",
					v.Census.HistoryMigrations, v.Census.HistoryRemoved, v.Census)
			}
			want := []string{col, "t_" + col + "_check", "t_" + col + "_unique"}
			if got := strings.Join(v.RemovedBySchemaHistory, ","); got != strings.Join(sortedCopy(want), ",") {
				t.Fatalf("снятые историей идентификаторы %q, хотели %q", got, sortedCopy(want))
			}
		})
	}
}

// TestSchemaHistory_EveryDropFormIsKnown — каждая форма снятия, которую знает
// распознаватель, узнаётся поимённо: столбец с IF EXISTS, индекс с
// CONCURRENTLY, IF EXISTS и схемой, ограничение с IF EXISTS, таблица со схемой
// в кавычках. Снятие столбца без слова COLUMN не узнаётся — это граница, и её
// проба стоит среди дефектов ниже.
func TestSchemaHistory_EveryDropFormIsKnown(t *testing.T) {
	t.Parallel()
	mark := identMarks(t)[0]
	col := mark + "_x"
	for name, tc := range map[string]struct{ create, drop string }{
		"столбец IF EXISTS": {
			"CREATE TABLE kaname.t (\n    " + col + " text\n);\n",
			"ALTER TABLE kaname.t DROP COLUMN IF EXISTS " + col + ";\n"},
		"индекс CONCURRENTLY IF EXISTS со схемой": {
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS " + col + " ON kaname.t (id);\n",
			"DROP INDEX CONCURRENTLY IF EXISTS kaname." + col + ";\n"},
		"ограничение IF EXISTS": {
			"ALTER TABLE kaname.t ADD CONSTRAINT " + col + " CHECK (true);\n",
			"ALTER TABLE kaname.t DROP CONSTRAINT IF EXISTS " + col + ";\n"},
		"таблица со схемой в кавычках": {
			"CREATE TABLE IF NOT EXISTS kaname." + col + " (id text);\n",
			"DROP TABLE IF EXISTS \"kaname\".\"" + col + "\";\n"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			files := map[string]string{
				histInitial: "-- +goose Up\n" + tc.create + "-- +goose Down\n",
				histDrop:    "-- +goose Up\n" + tc.drop + "-- +goose Down\n",
			}
			v := judgeVendor(t, vendorCorpus(files), nil)
			silent(t, v)
			if v.Census.HistoryRemoved != 1 || v.Census.HistoryLines != 2 {
				t.Fatalf("форма снятия не узнана: %s", v.Census)
			}
		})
	}
}

// TestSchemaHistory_EachDefectCountsTheWholeHistory — ДЕФЕКТЫ: каждый меняет
// один факт против близнеца, и тогда идентификатор снятым НЕ считается — все
// его строки истории становятся привязками, рост краснеет по файлам.
func TestSchemaHistory_EachDefectCountsTheWholeHistory(t *testing.T) {
	t.Parallel()
	mark := identMarks(t)[0]
	col := mark + "_client_id"
	twin := histFixture(col)
	for name, files := range map[string]map[string]string{
		// Снятия нет вовсе: столбец живёт.
		"снятия нет": {histInitial: twin[histInitial], histProbe: twin[histProbe]},
		// Снятие стоит только в откате: накат столбец заводит, откат снимает.
		"снятие только в откате": {histInitial: twin[histInitial],
			histDrop: "-- +goose Up\nSELECT 1;\n-- +goose Down\nALTER TABLE kaname.t DROP COLUMN " + col + ";\n" +
				"ALTER TABLE kaname.t DROP CONSTRAINT t_" + col + "_check;\nDROP INDEX kaname.t_" + col + "_unique;\n"},
		// Снятие — текст строкового литерала, а не оператор.
		"снятие внутри литерала": withFiles(twin, map[string]string{
			histDrop: "-- +goose Up\nSELECT 'ALTER TABLE kaname.t DROP COLUMN " + col + "';\n" +
				"SELECT 'DROP CONSTRAINT t_" + col + "_check', 'DROP INDEX kaname.t_" + col + "_unique';\n"}),
		// Снятие — текст комментария.
		"снятие в комментарии": withFiles(twin, map[string]string{
			histDrop: "-- +goose Up\nSELECT 1; /* DROP COLUMN " + col + " */\n" +
				"SELECT 2; -- DROP CONSTRAINT t_" + col + "_check DROP INDEX t_" + col + "_unique\n"}),
		// Тот же накат после снятия заводит имя заново.
		"заведён заново тем же накатом": withFiles(twin, map[string]string{
			histDrop: strings.Replace(twin[histDrop], "-- +goose Down\n",
				"ALTER TABLE kaname.t ADD COLUMN "+col+" text;\n"+
					"ALTER TABLE kaname.t ADD CONSTRAINT t_"+col+"_check CHECK (true);\n"+
					"CREATE UNIQUE INDEX t_"+col+"_unique ON kaname.t (id);\n-- +goose Down\n", 1)}),
		// Поздняя миграция снова говорит об имени.
		"поздняя миграция называет имя": withFiles(twin, map[string]string{
			histLater: "-- +goose Up\nALTER TABLE kaname.u ADD COLUMN " + col + " text;\n" +
				"ALTER TABLE kaname.u ADD CONSTRAINT t_" + col + "_check CHECK (true);\n" +
				"CREATE INDEX t_" + col + "_unique ON kaname.u (id);\n-- +goose Down\n"}),
		// Имя заведено в двух таблицах, снято в одной.
		"заведено дважды, снято однажды": withFiles(twin, map[string]string{
			histInitial: strings.Replace(twin[histInitial], "-- +goose Down\n",
				"CREATE TABLE kaname.u (\n    "+col+" text,\n"+
					"    CONSTRAINT t_"+col+"_check CHECK (true)\n);\n"+
					"CREATE INDEX t_"+col+"_unique ON kaname.u (id);\n-- +goose Down\n", 1)}),
		// Условие 3 отдельно от счёта заведений: поздняя миграция заводит имя
		// формой, которой распознаватель заведений не знает (`CREATE TABLE …
		// AS`), — держит её то, что она имя НАЗЫВАЕТ.
		"поздняя миграция называет имя незнакомой формой": {
			histInitial: "-- +goose Up\nCREATE TABLE kaname.t (\n    id text,\n    " + col + " text\n);\n-- +goose Down\n",
			histDrop:    "-- +goose Up\nALTER TABLE kaname.t DROP COLUMN " + col + ";\n-- +goose Down\n",
			histLater:   "-- +goose Up\nCREATE TABLE kaname.u AS SELECT id AS " + col + " FROM kaname.t;\n-- +goose Down\n"},
		// Условие 2 отдельно от счёта заведений: тот же накат после снятия
		// заводит имя незнакомой формой.
		"тот же накат называет имя после снятия": {
			histInitial: "-- +goose Up\nCREATE TABLE kaname.t (\n    id text,\n    " + col + " text\n);\n-- +goose Down\n",
			histDrop: "-- +goose Up\nALTER TABLE kaname.t DROP COLUMN " + col + ";\n" +
				"CREATE TABLE kaname.u AS SELECT id AS " + col + " FROM kaname.t;\n-- +goose Down\n"},
		// Снятие столбца без слова COLUMN распознаватель не знает: граница
		// названа, и цена её — привязка, видимая ростом, а не молчание.
		"снятие без слова COLUMN": {
			histInitial: "-- +goose Up\nCREATE TABLE kaname.t (\n    " + col + " text\n);\n-- +goose Down\n",
			histDrop:    "-- +goose Up\nALTER TABLE kaname.t DROP " + col + ";\n-- +goose Down\n"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v := judgeVendor(t, vendorCorpus(files), nil)
			if len(v.Findings) == 0 || v.Census.Bindings == 0 {
				t.Fatalf("дефект «%s» прощён законной формой: %s", name, v.Census)
			}
			for _, f := range v.Findings {
				if f.Kind != check.RetiredVendorGrown {
					t.Fatalf("дефект обязан давать рост, а не %q: %s", f.Kind, f)
				}
			}
			if v.Census.HistoryRemoved != 0 || v.Census.HistoryLines != 0 {
				t.Fatalf("дефект «%s»: имя числится снятым историей — %s", name, v.Census)
			}
		})
	}
}

// TestSchemaHistory_OnlyTheRemovedIdentifierIsForgiven — законная форма
// прощает строку, лишь если КАЖДОЕ имя поставщика в ней — снятый историей
// идентификатор, и лишь в каталоге истории схемы.
func TestSchemaHistory_OnlyTheRemovedIdentifierIsForgiven(t *testing.T) {
	t.Parallel()
	mark := identMarks(t)[0]
	col := mark + "_client_id"
	twin := histFixture(col)

	// Строка несёт снятый идентификатор И живое имя поставщика.
	mixed := withFiles(twin, map[string]string{
		histProbe: twin[histProbe] + "const admin = \"" + col + "\" + \"" + mark + "admin\"\n"})
	f := onlyFinding(t, judgeVendor(t, vendorCorpus(mixed), nil), check.RetiredVendorGrown, histProbe)
	if f.Actual != 1 || !strings.Contains(f.Bindings[0].Text, mark+"admin") {
		t.Fatalf("строка с живым именем обязана остаться привязкой: %+v", f.Bindings)
	}

	// Ссылка на снятый столбец вне каталога истории — привязка.
	outside := withFiles(twin, map[string]string{
		"internal/repo/t.go": "package repo\n\nconst q = `SELECT " + col + " FROM kaname.t`\n"})
	f = onlyFinding(t, judgeVendor(t, vendorCorpus(outside), nil), check.RetiredVendorGrown, "internal/repo/t.go")
	if f.Actual != 1 {
		t.Fatalf("ссылка вне истории схемы обязана быть привязкой: %+v", f.Bindings)
	}

	// Вложенный каталог — не история схемы.
	nested := withFiles(twin, map[string]string{
		histDir + "testdata/x.sql": "SELECT " + col + " FROM kaname.t;\n"})
	onlyFinding(t, judgeVendor(t, vendorCorpus(nested), nil), check.RetiredVendorGrown, histDir+"testdata/x.sql")

	// Путь, несущий имя поставщика, — ось пути, и история её не прощает.
	named := withFiles(twin, map[string]string{histDir + "drop_" + mark + "_test.go": "package migrations_test\n"})
	f = onlyFinding(t, judgeVendor(t, vendorCorpus(named), nil), check.RetiredVendorGrown, histDir+"drop_"+mark+"_test.go")
	if f.Bindings[0].Axis != check.RetiredVendorAxisPath {
		t.Fatalf("имя в пути обязано судиться осью пути: %+v", f.Bindings)
	}
}

// TestSchemaHistory_ImagePathMarkIsNeverHistory — метка пути образа
// идентификатором SQL не бывает, и строка истории с ней остаётся привязкой.
func TestSchemaHistory_ImagePathMarkIsNeverHistory(t *testing.T) {
	t.Parallel()
	var imageMark string
	for _, m := range check.RetiredVendorMarks {
		if strings.Contains(m, "/") {
			imageMark = m
		}
	}
	if imageMark == "" {
		t.Fatalf("предпосылка: в словаре %v нет метки пути образа — границы, которую судит проба, нет; "+
			"снимите пробу вместе с меткой", check.RetiredVendorMarks)
	}
	col := identMarks(t)[0] + "_client_id"
	files := withFiles(histFixture(col), map[string]string{
		histLater: "-- +goose Up\nCOMMENT ON TABLE kaname.u IS '" + imageMark + "x:v1';\n-- +goose Down\n"})
	f := onlyFinding(t, judgeVendor(t, vendorCorpus(files), nil), check.RetiredVendorGrown, histLater)
	if f.Actual != 1 {
		t.Fatalf("строка с меткой пути образа обязана быть привязкой: %+v", f.Bindings)
	}
}

// TestSchemaHistory_NoMigrationsNothingIsForgiven — каталог истории без
// миграций: снимать нечем, проба миграции судится как всякий файл.
func TestSchemaHistory_NoMigrationsNothingIsForgiven(t *testing.T) {
	t.Parallel()
	col := identMarks(t)[0] + "_client_id"
	files := map[string]string{histProbe: histFixture(col)[histProbe]}
	f := onlyFinding(t, judgeVendor(t, vendorCorpus(files), nil), check.RetiredVendorGrown, histProbe)
	if f.Actual != 3 {
		t.Fatalf("без миграций строки пробы обязаны судиться привязками: %+v", f.Bindings)
	}
	v := judgeVendor(t, vendorCorpus(files), nil)
	if v.Census.HistoryMigrations != 0 || v.Census.HistoryLines != 0 {
		t.Fatalf("перепись истории без миграций: %s", v.Census)
	}
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
