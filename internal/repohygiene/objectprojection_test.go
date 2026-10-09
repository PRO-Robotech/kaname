// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// objectprojection_test.go — у проекции объекта ОДИН производитель (приёмка
// NTF-3, kacho#2918, сценарий NTF3-180 (г); Р30 «Поколение и проекция»,
// редакция 39; Д133, Д134 B2).
//
// # Что судится
//
// Проекция объекта — зеркало `resource_mirror`, рёбра предков
// `resource_parent_edge` и голова объекта `object_head` (поколение, включая
// надгробие снятия). Пишет её ОДИН производитель — триггер `resource-event`
// базы службы доступа на приёме регистрации либо снятия: сравнение с головой,
// запись проекции и поколения либо исход REJECTED_STALE без единой записи. Ни
// сценарий использования, ни сверщик, ни заполнение в миграции эти таблицы не
// пишут.
//
// Три источника, каждый своим разбором:
//
//   - код Go вне проб: запись (INSERT INTO / UPDATE / DELETE FROM / MERGE INTO)
//     в строковом литерале — узел разбора, а не подстрока (комментарий,
//     объясняющий инвариант, записью не является). Каждая — находка с файлом и
//     строкой;
//   - SQL миграций ВНЕ тел функций: строки в долларовых кавычках, строковые
//     литералы и комментарии вымарываются до поиска, поэтому найденное —
//     исполняемый оператор миграции, то есть заполнение. Каждое — находка;
//   - функции базы, сыгранной цепью миграций дерева (`pg_proc.prosrc` — текущее
//     тело, а не история определений): писатель проекции обязан быть ровно
//     один, привязан триггером и писать все три таблицы.
//
// Требования: каждая таблица проекции существует; записей из Go 0; записей
// миграциями вне функций 0; функций-писателей ровно 1, она — функция триггера,
// и пишет каждую таблицу проекции. Перепись печатается всегда; пустой обход
// любого источника — красный, а не «нарушений нет».
//
// # Чего гейт НЕ судит — граница названа
//
//   - пакеты гейтов (`internal/check`, `internal/repohygiene`): их литералы —
//     образцы распознавателей, а не исполняемый SQL;
//   - имя таблицы, собранное из частей (`fmt.Sprintf`, склейка, константа
//     другого пакета), `pgx.CopyFrom` и динамический SQL функции
//     (`EXECUTE format(…)`) — слепая зона образца;
//   - надгробие и запись снятого отдельными таблицами: имён им приёмка не дала
//     (вопрос к приёмке); если они заводятся отдельно от головы, их имена
//     добавляются в `projectionTables` тем же изменением;
//   - единственность читателя ограды — гейт `TestAudienceFenceReadsOnlyRevisionedTables`.
package repohygiene_test

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// projectionTables — таблицы проекции объекта (Р30).
var projectionTables = []string{"resource_mirror", "resource_parent_edge", "object_head"}

// projectionVerbs — глаголы записи. Чтение законно и в перечень не входит.
var projectionVerbs = []string{"INSERT INTO", "UPDATE", "DELETE FROM", "MERGE INTO"}

// projectionGateDirs — пакеты гейтов: их литералы — образцы распознавателей.
var projectionGateDirs = []string{"internal/check", "internal/repohygiene"}

// projSite — координата записи проекции.
type projSite struct {
	at    string
	verb  string
	table string
}

// projWriter — функция базы, пишущая проекцию.
type projWriter struct {
	fn       string
	tables   []string
	triggers []string
}

// projFacts — всё, что гейт узнал из трёх источников.
type projFacts struct {
	schema     string
	tables     []string
	goFiles    int
	goLiterals int
	goMentions int
	sqlFiles   int
	funcsRead  int
	present    map[string]bool
	goSites    []projSite
	sqlSites   []projSite
	writers    []projWriter
}

// projSkippedDir — каталог вне обхода Go.
func projSkippedDir(rel string, gateDirs []string) bool {
	base := filepath.Base(rel)
	if base == ".git" || base == "vendor" || base == "node_modules" || base == "testdata" {
		return true
	}
	for _, g := range gateDirs {
		if rel == g {
			return true
		}
	}
	return false
}

// projGoSites обходит не-пробные файлы Go под root и собирает записи проекции
// в строковых литералах.
func projGoSites(t *testing.T, root, schema string, tables, gateDirs []string, f *projFacts) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel != "." && projSkippedDir(rel, gateDirs) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") || strings.HasSuffix(rel, ".pb.go") {
			return nil
		}
		src, err := os.ReadFile(path) // #nosec G304 -- путь из обхода своего дерева
		if err != nil {
			return err
		}
		f.goFiles++
		for i, table := range tables {
			sites, census, serr := check.ScanFactWrites(rel, src, schema+"."+table, projectionVerbs)
			if serr != nil {
				return fmt.Errorf("%s не разбирается: %w", rel, serr)
			}
			if i == 0 {
				f.goLiterals += census.Strings
			}
			f.goMentions += census.TableInStrings
			for _, s := range sites {
				f.goSites = append(f.goSites, projSite{at: fmt.Sprintf("%s:%d", s.File, s.Line), verb: s.Verb, table: table})
			}
		}
		return nil
	})
	require.NoError(t, err, "обход Go")
}

// projBlankSQL вымарывает комментарии, строковые литералы и тела в долларовых
// кавычках, сохраняя переводы строк (номера строк остаются верными).
func projBlankSQL(src string) string {
	b := []byte(src)
	blank := func(from, to int) {
		for i := from; i < to && i < len(b); i++ {
			if b[i] != '\n' {
				b[i] = ' '
			}
		}
	}
	dollarTag := regexp.MustCompile(`^\$[A-Za-z_]*\$`)
	for i := 0; i < len(b); {
		switch {
		case b[i] == '-' && i+1 < len(b) && b[i+1] == '-':
			end := strings.IndexByte(string(b[i:]), '\n')
			if end < 0 {
				end = len(b) - i
			}
			blank(i, i+end)
			i += end
		case b[i] == '/' && i+1 < len(b) && b[i+1] == '*':
			end := strings.Index(string(b[i+2:]), "*/")
			stop := len(b)
			if end >= 0 {
				stop = i + 2 + end + 2
			}
			blank(i, stop)
			i = stop
		case b[i] == '\'':
			j := i + 1
			for j < len(b) {
				if b[j] == '\'' {
					if j+1 < len(b) && b[j+1] == '\'' {
						j += 2
						continue
					}
					break
				}
				j++
			}
			blank(i, j+1)
			i = j + 1
		case b[i] == '$':
			tag := dollarTag.Find(b[i:])
			if tag == nil {
				i++
				continue
			}
			end := strings.Index(string(b[i+len(tag):]), string(tag))
			stop := len(b)
			if end >= 0 {
				stop = i + len(tag) + end + len(tag)
			}
			blank(i, stop)
			i = stop
		default:
			i++
		}
	}
	return string(b)
}

// projWriteRE — запись в таблицу схемы; имя схемы необязательно (тело функции
// может опираться на search_path).
func projWriteRE(schema, table string) *regexp.Regexp {
	return regexp.MustCompile(`(?is)\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM|MERGE\s+INTO)\s+(?:ONLY\s+)?(?:` +
		regexp.QuoteMeta(schema) + `\.)?` + regexp.QuoteMeta(table) + `\b`)
}

// projSQLSites — записи проекции в миграциях вне тел функций.
func projSQLSites(t *testing.T, dir, schema string, tables []string, f *projFacts) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err, "каталог миграций %s", dir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- путь из обхода своего дерева
		require.NoError(t, err)
		f.sqlFiles++
		text := projBlankSQL(string(src))
		for _, table := range tables {
			for _, loc := range projWriteRE(schema, table).FindAllStringSubmatchIndex(text, -1) {
				line := 1 + strings.Count(text[:loc[0]], "\n")
				verb := strings.Join(strings.Fields(strings.ToUpper(text[loc[2]:loc[3]])), " ")
				f.sqlSites = append(f.sqlSites, projSite{at: fmt.Sprintf("%s:%d", e.Name(), line), verb: verb, table: table})
			}
		}
	}
}

// projDBFacts — таблицы проекции в базе и функции, которые их пишут.
func projDBFacts(t *testing.T, ctx context.Context, pool *pgxpool.Pool, schema string, tables []string, f *projFacts) {
	t.Helper()
	f.present = map[string]bool{}
	for _, table := range tables {
		var ok bool
		require.NoError(t, pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, schema+"."+table).Scan(&ok))
		f.present[table] = ok
	}

	rows, err := pool.Query(ctx, `
		SELECT p.oid, p.oid::regprocedure::text, p.prosrc
		  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_%'
		   AND p.prokind = 'f'`)
	require.NoError(t, err)
	type fn struct {
		oid  uint32
		name string
		src  string
	}
	var fns []fn
	for rows.Next() {
		var x fn
		require.NoError(t, rows.Scan(&x.oid, &x.name, &x.src))
		fns = append(fns, x)
	}
	rows.Close()
	require.NoError(t, rows.Err())
	f.funcsRead = len(fns)

	for _, x := range fns {
		body := projBlankSQL(x.src)
		var wrote []string
		for _, table := range tables {
			if projWriteRE(schema, table).MatchString(body) {
				wrote = append(wrote, table)
			}
		}
		if len(wrote) == 0 {
			continue
		}
		w := projWriter{fn: x.name, tables: wrote}
		trows, err := pool.Query(ctx, `
			SELECT tgname || ' ON ' || tgrelid::regclass::text FROM pg_trigger
			 WHERE NOT tgisinternal AND tgfoid = $1 ORDER BY 1`, x.oid)
		require.NoError(t, err)
		for trows.Next() {
			var s string
			require.NoError(t, trows.Scan(&s))
			w.triggers = append(w.triggers, s)
		}
		trows.Close()
		require.NoError(t, trows.Err())
		f.writers = append(f.writers, w)
	}
	sort.Slice(f.writers, func(i, j int) bool { return f.writers[i].fn < f.writers[j].fn })
}

// projectionVerdict — находки по фактам. Тот же предикат зовёт инъекция.
func projectionVerdict(f projFacts) []string {
	var out []string
	if f.goFiles == 0 || f.goLiterals == 0 {
		out = append(out, fmt.Sprintf("обход Go пуст: файлов %d, литералов %d — «записей нет» значило бы «ничего не прочитано»",
			f.goFiles, f.goLiterals))
	}
	if f.sqlFiles == 0 {
		out = append(out, "обход миграций пуст: файлов .sql 0")
	}
	if f.funcsRead == 0 {
		out = append(out, "функций базы прочитано 0 — производителя искать не в чем")
	}
	for _, table := range f.tables {
		if !f.present[table] {
			out = append(out, fmt.Sprintf("таблицы %s.%s нет — у проекции нет этой части (Р30)", f.schema, table))
		}
	}
	for _, s := range f.goSites {
		out = append(out, fmt.Sprintf("%s  %s %s.%s — запись проекции из кода Go; единственный производитель — триггер resource-event",
			s.at, s.verb, f.schema, s.table))
	}
	for _, s := range f.sqlSites {
		out = append(out, fmt.Sprintf("%s  %s %s.%s — запись проекции миграцией вне функции (заполнение)",
			s.at, s.verb, f.schema, s.table))
	}
	switch len(f.writers) {
	case 0:
		out = append(out, fmt.Sprintf("у проекции нет производителя в базе: ни одна функция не пишет %s", strings.Join(f.tables, ", ")))
	case 1:
	default:
		var names []string
		for _, w := range f.writers {
			names = append(names, fmt.Sprintf("%s → %s", w.fn, strings.Join(w.tables, ", ")))
		}
		out = append(out, fmt.Sprintf("производителей проекции в базе %d, ожидается один: %s", len(f.writers), strings.Join(names, "; ")))
	}
	for _, w := range f.writers {
		if len(w.triggers) == 0 {
			out = append(out, fmt.Sprintf("функция %s пишет %s, но не привязана триггером", w.fn, strings.Join(w.tables, ", ")))
		}
	}
	if len(f.writers) == 1 {
		wrote := map[string]bool{}
		for _, t := range f.writers[0].tables {
			wrote[t] = true
		}
		for _, table := range f.tables {
			if f.present[table] && !wrote[table] {
				out = append(out, fmt.Sprintf("таблицу %s.%s единственный производитель %s не пишет", f.schema, table, f.writers[0].fn))
			}
		}
	}
	return out
}

// projectionCensus — перепись, печатаемая всегда.
func projectionCensus(f projFacts) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  таблицы проекции: %s.{%s}\n", f.schema, strings.Join(f.tables, ", "))
	for _, table := range f.tables {
		fmt.Fprintf(&b, "    %s: есть в базе — %v\n", table, f.present[table])
	}
	fmt.Fprintf(&b, "  Go: файлов %d, литералов %d, литералов с именем таблицы %d, записей %d\n",
		f.goFiles, f.goLiterals, f.goMentions, len(f.goSites))
	fmt.Fprintf(&b, "  миграции: файлов .sql %d, записей вне функций %d\n", f.sqlFiles, len(f.sqlSites))
	fmt.Fprintf(&b, "  база: функций прочитано %d, писателей проекции %d\n", f.funcsRead, len(f.writers))
	for _, w := range f.writers {
		fmt.Fprintf(&b, "    %s → %s; триггеры: %v\n", w.fn, strings.Join(w.tables, ", "), w.triggers)
	}
	return b.String()
}

// collectProjection — сбор фактов по дереву root и базе pool.
func collectProjection(t *testing.T, ctx context.Context, pool *pgxpool.Pool, root, migrationsDir, schema string, tables []string) projFacts {
	t.Helper()
	f := projFacts{schema: schema, tables: tables}
	projGoSites(t, root, schema, tables, projectionGateDirs, &f)
	projSQLSites(t, migrationsDir, schema, tables, &f)
	projDBFacts(t, ctx, pool, schema, tables, &f)
	sort.Slice(f.goSites, func(i, j int) bool { return f.goSites[i].at < f.goSites[j].at })
	return f
}

// TestObjectProjectionHasOneProducer — сам гейт.
func TestObjectProjectionHasOneProducer(t *testing.T) {
	if testing.Short() {
		t.Skip("гейт поднимает Postgres с цепью миграций дерева")
	}
	root := platformtree.Require(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	f := collectProjection(t, ctx, pool, root, filepath.Join(root, "internal", "migrations"), "kaname", projectionTables)
	t.Logf("перепись гейта одного производителя проекции:\n%s", projectionCensus(f))
	if v := projectionVerdict(f); len(v) > 0 {
		t.Fatalf("гейт одного производителя проекции (NTF3-180 (г)): находок %d\n  · %s", len(v), strings.Join(v, "\n  · "))
	}
}
