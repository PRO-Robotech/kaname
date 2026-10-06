// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// audiencefence_test.go — гейт ограды вопроса об аудитории (приёмка NTF-3,
// kacho#2918, сценарий NTF3-180; Р30 «Какие строки читает вопрос с оградой»,
// «Колонка версии прав», редакция 39; Д133, Д134 B1).
//
// # Что судится
//
// Множество F — таблицы, которые читает вопрос с оградой, — выводится РАЗБОРОМ
// запросов дерева, а не перечнем автора: запрос вопроса с оградой — строковый
// литерал Go вне проб, несущий предикат ограды `pg_visible_in_snapshot(`
// (Р30: версия строки видна в снимке `R_E`; токен — полный снимок, поэтому
// иная законная форма ограды — сравнение с нижней границей снимка — Р30
// запрещена, и распознавателю знать её не нужно). Таблицы запроса — ссылки
// `kaname.<имя>` в литерале, кроме вызовов функций.
//
// Множество V — таблицы базы, сыгранной цепью миграций дерева, у которых есть
// колонка `authz_rev`. У каждой таблицы V судится поведение, а не текст:
//
//   - тип колонки `xid8`, умолчания у колонки нет (NTF3-180 (б));
//   - есть построчный триггер `BEFORE`, покрывающий INSERT и UPDATE, чья
//     функция пишет `authz_rev`;
//   - на копии строки во временной таблице с ТЕМ ЖЕ триггером: INSERT ставит
//     версию своей транзакции, в том числе поверх явного значения;
//     переписывание тем же содержимым версию не двигает (NTF3-180 (д)); правка
//     каждого столбца по очереди — и те, что версию двигают, печатаются
//     перечнем значимых столбцов таблицы; пустой перечень — находка.
//
// Требования: F непусто; V непусто; F = V; F не содержит таблиц объектной
// стороны (NTF3-180 (в)). Перепись печатается всегда.
//
// # Чего гейт НЕ судит
//
// Единственного производителя проекции (`TestObjectProjectionHasOneProducer`,
// NTF3-180 (г)) — это предмет полосы поколения объекта (B2), не этой.
//
// Запрос, собранный подстановкой из нескольких литералов, судится по
// литералу, несущему предикат ограды: таблица, приходящая подстановкой из
// другого литерала, в F не попадёт. Это граница распознавателя, названная
// здесь, а не умолчанная.
package repohygiene_test

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// fencePredicate — признак запроса вопроса с оградой.
const fencePredicate = "pg_visible_in_snapshot("

// objectSideTables — таблицы объектной стороны (Р30): зеркало, рёбра предков и
// областей, материализованные кортежи привязок. Вопрос с оградой их не читает:
// метки и цепь берутся из фактов события.
var objectSideTables = map[string]bool{
	"resource_mirror":               true,
	"resource_parent_edge":          true,
	"resource_scope_edge":           true,
	"access_binding_emitted_tuples": true,
}

// fenceQuery — один запрос вопроса с оградой и таблицы, которые он читает.
type fenceQuery struct {
	at     string
	tables []string
}

// fenceWalk — итог обхода дерева.
type fenceWalk struct {
	files, literals int
	queries         []fenceQuery
}

// tableRefRE — ссылка на таблицу схемы; вызов функции схемы отсекается
// проверкой следующего символа.
func tableRefRE(schema string) *regexp.Regexp {
	return regexp.MustCompile(`\b` + regexp.QuoteMeta(schema) + `\.([a-z_][a-z0-9_]*)\b(\s*\()?`)
}

// triggerDefRE — форма `pg_get_triggerdef`: имя, момент и события, таблица,
// остаток (FOR EACH ROW [WHEN …] EXECUTE FUNCTION …).
var triggerDefRE = regexp.MustCompile(`^CREATE (?:CONSTRAINT )?TRIGGER \S+ (.+?) ON \S+( FOR EACH .*)$`)

// literalValue — значение строкового выражения из литералов и их сложения.
func literalValue(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, ok1 := literalValue(x.X)
		r, ok2 := literalValue(x.Y)
		return l + r, ok1 && ok2
	case *ast.ParenExpr:
		return literalValue(x.X)
	}
	return "", false
}

// walkFenceQueries обходит не-пробные файлы Go под dirs и собирает запросы с
// предикатом ограды.
func walkFenceQueries(t *testing.T, schema string, dirs ...string) fenceWalk {
	t.Helper()
	re := tableRefRE(schema)
	var w fenceWalk
	fset := token.NewFileSet()
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
			if err != nil {
				return fmt.Errorf("%s не разбирается: %w", path, err)
			}
			w.files++
			seen := map[ast.Node]bool{}
			ast.Inspect(f, func(n ast.Node) bool {
				e, ok := n.(ast.Expr)
				if !ok || seen[n] {
					return true
				}
				s, ok := literalValue(e)
				if !ok {
					return true
				}
				// Сложение литералов судится целиком, его части повторно — нет.
				ast.Inspect(n, func(m ast.Node) bool { seen[m] = true; return true })
				w.literals++
				if !strings.Contains(s, fencePredicate) {
					return false
				}
				q := fenceQuery{at: fset.Position(e.Pos()).String()}
				set := map[string]bool{}
				for _, m := range re.FindAllStringSubmatch(s, -1) {
					if m[2] != "" {
						continue // вызов функции схемы, не таблица
					}
					set[m[1]] = true
				}
				for tbl := range set {
					q.tables = append(q.tables, tbl)
				}
				sort.Strings(q.tables)
				w.queries = append(w.queries, q)
				return false
			})
			return nil
		})
		require.NoErrorf(t, err, "обход %s", dir)
	}
	return w
}

// revisioned — таблица с колонкой версии прав и итог суда над ней.
type revisioned struct {
	table       string
	significant []string
	findings    []string
}

// columnInfo — столбец таблицы для сборки строки-копии.
type columnInfo struct {
	name, typ           string
	notNull, hasDefault bool
}

// syntheticValue / changedValue — значение для вставки и правка, меняющая
// значение, по типу столбца. Незнакомый тип — находка, а не молчание.
func syntheticValue(typ string) (string, bool) {
	switch typ {
	case "text", "character varying":
		return "'x'", true
	case "smallint", "integer", "bigint":
		return "1", true
	case "boolean":
		return "false", true
	case "jsonb":
		return "'{}'::jsonb", true
	case "timestamp with time zone":
		return "now()", true
	case "text[]":
		return "'{x}'::text[]", true
	case "uuid":
		return "gen_random_uuid()", true
	}
	return "", false
}

func changedValue(col, typ string) (string, bool) {
	q := pgx.Identifier{col}.Sanitize()
	switch typ {
	case "text", "character varying":
		return "coalesce(" + q + ", '') || '~'", true
	case "smallint", "integer", "bigint":
		return "coalesce(" + q + ", 0) + 1", true
	case "boolean":
		return "NOT coalesce(" + q + ", false)", true
	case "jsonb":
		return "coalesce(" + q + `, '{}'::jsonb) || '{"arv_gate":1}'::jsonb`, true
	case "timestamp with time zone":
		return "coalesce(" + q + " + interval '1 second', now())", true
	case "text[]":
		return "coalesce(" + q + ", '{}'::text[]) || 'y'::text", true
	case "uuid":
		return "gen_random_uuid()", true
	}
	return "", false
}

// judgeRevisioned судит все таблицы схемы с колонкой `authz_rev`.
func judgeRevisioned(t *testing.T, ctx context.Context, pool *pgxpool.Pool, schema string) []revisioned {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT c.relname, format_type(a.atttypid, a.atttypmod), a.atthasdef
		  FROM pg_attribute a
		  JOIN pg_class c ON c.oid = a.attrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = $1 AND a.attname = 'authz_rev' AND NOT a.attisdropped
		   AND c.relkind IN ('r', 'p')
		 ORDER BY c.relname`, schema)
	require.NoError(t, err)
	type col struct {
		table, typ string
		hasDef     bool
	}
	var cols []col
	for rows.Next() {
		var c col
		require.NoError(t, rows.Scan(&c.table, &c.typ, &c.hasDef))
		cols = append(cols, c)
	}
	rows.Close()
	require.NoError(t, rows.Err())

	out := make([]revisioned, 0, len(cols))
	for _, c := range cols {
		r := revisioned{table: c.table}
		if c.typ != "xid8" {
			r.findings = append(r.findings, fmt.Sprintf("%s.%s: authz_rev типа %s, а не xid8", schema, c.table, c.typ))
		}
		if c.hasDef {
			r.findings = append(r.findings, fmt.Sprintf("%s.%s: у authz_rev умолчание столбца — версию ставит "+
				"умолчание, а не триггер BEFORE INSERT OR UPDATE (NTF3-180 (б))", schema, c.table))
		}
		judgeTrigger(t, ctx, pool, schema, &r)
		out = append(out, r)
	}
	return out
}

// judgeTrigger — триггер версии таблицы и его поведение на строке-копии.
func judgeTrigger(t *testing.T, ctx context.Context, pool *pgxpool.Pool, schema string, r *revisioned) {
	t.Helper()
	fq := pgx.Identifier{schema, r.table}.Sanitize()
	rows, err := pool.Query(ctx, `
		SELECT tg.tgname, pg_get_triggerdef(tg.oid), tg.tgtype
		  FROM pg_trigger tg
		  JOIN pg_proc p ON p.oid = tg.tgfoid
		 WHERE tg.tgrelid = $1::regclass AND NOT tg.tgisinternal
		   AND p.prosrc ILIKE '%authz_rev%'
		 ORDER BY tg.tgname`, fq)
	require.NoError(t, err)
	type trig struct {
		name, def string
		typ       int16
	}
	var trigs []trig
	for rows.Next() {
		var tr trig
		require.NoError(t, rows.Scan(&tr.name, &tr.def, &tr.typ))
		trigs = append(trigs, tr)
	}
	rows.Close()
	require.NoError(t, rows.Err())

	const (
		typRow, typBefore, typInsert, typUpdate = 1, 2, 4, 16
	)
	var ins, upd bool
	var names []string
	for _, tr := range trigs {
		if tr.typ&typRow == 0 || tr.typ&typBefore == 0 {
			r.findings = append(r.findings, fmt.Sprintf("%s.%s: триггер %s пишет authz_rev, но он не построчный BEFORE",
				schema, r.table, tr.name))
			continue
		}
		ins = ins || tr.typ&typInsert != 0
		upd = upd || tr.typ&typUpdate != 0
		names = append(names, tr.name)
	}
	if !ins || !upd {
		r.findings = append(r.findings, fmt.Sprintf("%s.%s: нет построчного триггера BEFORE INSERT OR UPDATE, "+
			"пишущего authz_rev (INSERT %v, UPDATE %v)", schema, r.table, ins, upd))
		return
	}
	trigNames := strings.Join(names, ", ")

	// Строка-копия: временная таблица той же формы с ТЕМ ЖЕ триггером версии и
	// без прочих триггеров и ограничений. Своё соединение — временная таблица
	// живёт в сессии.
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	_, err = conn.Exec(ctx, `DROP TABLE IF EXISTS pg_temp.arv_gate_probe; CREATE TEMP TABLE arv_gate_probe (LIKE `+fq+` INCLUDING DEFAULTS INCLUDING GENERATED)`)
	require.NoErrorf(t, err, "строка-копия %s не создана", fq)
	defer func() { _, _ = conn.Exec(context.Background(), `DROP TABLE IF EXISTS pg_temp.arv_gate_probe`) }()
	for i, tr := range trigs {
		m := triggerDefRE.FindStringSubmatchIndex(tr.def)
		require.NotNilf(t, m, "определение триггера %s не в форме pg_get_triggerdef: %s", tr.name, tr.def)
		def := fmt.Sprintf("CREATE TRIGGER arv_gate_%d %s ON pg_temp.arv_gate_probe%s",
			i, tr.def[m[2]:m[3]], tr.def[m[4]:])
		_, err = conn.Exec(ctx, def)
		require.NoErrorf(t, err, "триггер %s не перенесён на строку-копию: %s", tr.name, def)
	}
	// Фикстура: на строке-копии ровно перенесённые триггеры — иначе суд шёл бы
	// над таблицей без триггера и молча.
	var moved int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM pg_trigger
		WHERE tgrelid = 'pg_temp.arv_gate_probe'::regclass AND NOT tgisinternal`).Scan(&moved))
	require.Equalf(t, len(trigs), moved, "на строку-копию %s перенесено %d триггеров из %d", fq, moved, len(trigs))

	crow, err := conn.Query(ctx, `
		SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull, a.atthasdef
		  FROM pg_attribute a
		 WHERE a.attrelid = 'pg_temp.arv_gate_probe'::regclass AND a.attnum > 0 AND NOT a.attisdropped
		   AND a.attgenerated = '' AND a.attname <> 'authz_rev'
		 ORDER BY a.attnum`)
	require.NoError(t, err)
	var columns []columnInfo
	for crow.Next() {
		var c columnInfo
		require.NoError(t, crow.Scan(&c.name, &c.typ, &c.notNull, &c.hasDefault))
		columns = append(columns, c)
	}
	crow.Close()
	require.NoError(t, crow.Err())

	var names2, vals []string
	for _, c := range columns {
		if !c.notNull || c.hasDefault {
			continue
		}
		v, ok := syntheticValue(c.typ)
		if !ok {
			r.findings = append(r.findings, fmt.Sprintf("%s.%s: столбец %s типа %s не знаком сборщику строки-копии — "+
				"поведение триггера не судится", schema, r.table, c.name, c.typ))
			return
		}
		names2 = append(names2, pgx.Identifier{c.name}.Sanitize())
		vals = append(vals, v)
	}
	insertSQL := `INSERT INTO pg_temp.arv_gate_probe (` + strings.Join(names2, ", ") + `) VALUES (` + strings.Join(vals, ", ") + `)`
	if len(names2) == 0 {
		insertSQL = `INSERT INTO pg_temp.arv_gate_probe DEFAULT VALUES`
	}

	inTx := func(sql string) (rev, xid string) {
		tx, err := conn.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		require.NoError(t, tx.QueryRow(ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid))
		var v *string
		require.NoErrorf(t, tx.QueryRow(ctx, sql+` RETURNING authz_rev::text`).Scan(&v), "строка-копия %s: %s", fq, sql)
		require.NoError(t, tx.Commit(ctx))
		if v == nil {
			return "NULL", xid
		}
		return *v, xid
	}

	rev, xid := inTx(insertSQL)
	if rev != xid {
		r.findings = append(r.findings, fmt.Sprintf("%s.%s: INSERT не поставил версию своей транзакции (%s при %s); "+
			"триггер %s", schema, r.table, rev, xid, trigNames))
	}
	var noop []string
	for _, c := range columns {
		q := pgx.Identifier{c.name}.Sanitize()
		noop = append(noop, q+" = "+q)
	}
	if len(noop) > 0 {
		after, _ := inTx(`UPDATE pg_temp.arv_gate_probe SET ` + strings.Join(noop, ", "))
		if after != rev {
			r.findings = append(r.findings, fmt.Sprintf("%s.%s: триггер %s ставит новую версию на UPDATE без изменения "+
				"значимых столбцов (переписывание тем же содержимым) — нужно сравнение IS DISTINCT FROM по значимым "+
				"столбцам (NTF3-180 (д))", schema, r.table, trigNames))
		}
		rev = after
	}
	for _, c := range columns {
		set, ok := changedValue(c.name, c.typ)
		if !ok {
			continue
		}
		after, xid := inTx(`UPDATE pg_temp.arv_gate_probe SET ` + pgx.Identifier{c.name}.Sanitize() + ` = ` + set)
		if after != rev {
			if after != xid {
				r.findings = append(r.findings, fmt.Sprintf("%s.%s: правка %s поставила версию %s, не равную своей "+
					"транзакции %s", schema, r.table, c.name, after, xid))
			}
			r.significant = append(r.significant, c.name)
		}
		rev = after
	}
	if len(r.significant) == 0 {
		r.findings = append(r.findings, fmt.Sprintf("%s.%s: ни одна правка столбца версию не двигает — "+
			"изменение права прошло бы мимо ограды", schema, r.table))
	}
	ex, xid3 := inTx(`INSERT INTO pg_temp.arv_gate_probe (` + strings.Join(append([]string{"authz_rev"}, names2...), ", ") +
		`) VALUES (` + strings.Join(append([]string{"'1'::xid8"}, vals...), ", ") + `)`)
	if ex != xid3 {
		r.findings = append(r.findings, fmt.Sprintf("%s.%s: явное authz_rev в INSERT прошло мимо триггера %s (NTF3-180 (б))",
			schema, r.table, trigNames))
	}
}

// fenceVerdict — сравнение F и V; находки поимённо.
func fenceVerdict(w fenceWalk, revs []revisioned) []string {
	var findings []string
	if w.files == 0 {
		findings = append(findings, "обход дерева прочитал 0 файлов Go — вердикт беспредметен")
	}
	if len(w.queries) == 0 {
		findings = append(findings, fmt.Sprintf("запросов вопроса с оградой 0 (литералов с %q нет среди %d литералов "+
			"в %d файлах) — множество читаемых таблиц пусто", fencePredicate, w.literals, w.files))
	}
	if len(revs) == 0 {
		findings = append(findings, "таблиц с колонкой authz_rev 0")
	}
	read := map[string][]string{}
	for _, q := range w.queries {
		for _, tbl := range q.tables {
			read[tbl] = append(read[tbl], q.at)
		}
	}
	have := map[string]bool{}
	for _, r := range revs {
		have[r.table] = true
		findings = append(findings, r.findings...)
	}
	for tbl, at := range read {
		if objectSideTables[tbl] {
			findings = append(findings, fmt.Sprintf("вопрос с оградой читает таблицу объектной стороны %s (%s) — "+
				"метки и цепь берутся из фактов события (NTF3-180 (в))", tbl, strings.Join(at, ", ")))
			continue
		}
		if !have[tbl] {
			findings = append(findings, fmt.Sprintf("вопрос с оградой читает таблицу %s без колонки authz_rev (%s) — "+
				"её правка прошла бы мимо ограды (NTF3-180 (а))", tbl, strings.Join(at, ", ")))
		}
	}
	for _, r := range revs {
		if _, ok := read[r.table]; !ok && len(w.queries) > 0 {
			findings = append(findings, fmt.Sprintf("таблица %s несёт authz_rev, а вопрос с оградой её не читает — "+
				"множества не равны", r.table))
		}
	}
	sort.Strings(findings)
	return findings
}

// censusOf — перепись: печатается всегда.
func censusOf(w fenceWalk, revs []revisioned) string {
	var b strings.Builder
	fmt.Fprintf(&b, "файлов Go %d, литералов %d, запросов вопроса с оградой %d\n", w.files, w.literals, len(w.queries))
	for _, q := range w.queries {
		fmt.Fprintf(&b, "  запрос %s читает: %s\n", q.at, strings.Join(q.tables, ", "))
	}
	fmt.Fprintf(&b, "таблиц с authz_rev %d\n", len(revs))
	for _, r := range revs {
		fmt.Fprintf(&b, "  %s: значимые столбцы [%s]\n", r.table, strings.Join(r.significant, ", "))
	}
	return b.String()
}

// TestAudienceFenceReadsOnlyRevisionedTables — NTF3-180 на дереве службы
// доступа: таблицы вопроса с оградой равны таблицам с колонкой версии прав и
// её триггером, сравнивающим значимые столбцы.
func TestAudienceFenceReadsOnlyRevisionedTables(t *testing.T) {
	if testing.Short() {
		t.Skip("гейт поднимает Postgres с цепью миграций дерева")
	}
	root := platformtree.Require(t)
	w := walkFenceQueries(t, "kaname", filepath.Join(root, "internal"), filepath.Join(root, "cmd"))

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	revs := judgeRevisioned(t, ctx, pool, "kaname")

	t.Logf("перепись гейта ограды:\n%s", censusOf(w, revs))
	if f := fenceVerdict(w, revs); len(f) > 0 {
		t.Fatalf("гейт ограды (NTF3-180): находок %d\n  · %s", len(f), strings.Join(f, "\n  · "))
	}
}
