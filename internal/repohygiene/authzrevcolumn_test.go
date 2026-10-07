// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authzrevcolumn_test.go — гейт писателя версии прав (приёмка NTF-3,
// kacho#2918, сценарий NTF3-180 (б), (д) и перечень значимых столбцов; Р30
// «Колонка версии прав», редакция 39; Д133, Д134 B1; полоса K1).
//
// # Что судится
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
// Требования: V непусто; ни одной находки у таблиц V. Перепись печатается
// всегда.
//
// # Чего гейт НЕ судит
//
// Равенства V множеству F — таблиц, которые читает вопрос об аудитории с
// оградой (NTF3-180 (а), (в)). F выводится разбором запроса вопроса, и судить
// равенство можно только на дереве, где этот запрос есть: гейт равенства
// входит в дерево одним изменением с запросом, который он судит. Здесь —
// писатель версии, у которого читатель не предполагается.
//
// Единственного производителя проекции (NTF3-180 (г)) — это предмет полосы
// поколения объекта.
package repohygiene_test

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
)

// triggerDefRE — форма `pg_get_triggerdef`: имя, момент и события, таблица,
// остаток (FOR EACH ROW [WHEN …] EXECUTE FUNCTION …).
var triggerDefRE = regexp.MustCompile(`^CREATE (?:CONSTRAINT )?TRIGGER \S+ (.+?) ON \S+( FOR EACH .*)$`)

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

// revisionVerdict — находки по таблицам V поимённо; пустое V — находка.
func revisionVerdict(revs []revisioned) []string {
	var findings []string
	if len(revs) == 0 {
		findings = append(findings, "таблиц с колонкой authz_rev 0 — вердикт беспредметен")
	}
	for _, r := range revs {
		findings = append(findings, r.findings...)
	}
	sort.Strings(findings)
	return findings
}

// revisionCensus — перепись: печатается всегда.
func revisionCensus(revs []revisioned) string {
	var b strings.Builder
	fmt.Fprintf(&b, "таблиц с authz_rev %d\n", len(revs))
	for _, r := range revs {
		fmt.Fprintf(&b, "  %s: значимые столбцы [%s]\n", r.table, strings.Join(r.significant, ", "))
	}
	return b.String()
}

// TestAuthzRevisionIsStampedByItsTrigger — NTF3-180 (б), (д) на базе службы
// доступа: у каждой таблицы с колонкой версии прав версию ставит построчный
// триггер BEFORE INSERT OR UPDATE, сравнивающий значимые столбцы.
func TestAuthzRevisionIsStampedByItsTrigger(t *testing.T) {
	if testing.Short() {
		t.Skip("гейт поднимает Postgres с цепью миграций дерева")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	revs := judgeRevisioned(t, ctx, pool, "kaname")

	t.Logf("перепись гейта версии прав:\n%s", revisionCensus(revs))
	if f := revisionVerdict(revs); len(f) > 0 {
		t.Fatalf("гейт версии прав (NTF3-180 (б), (д)): находок %d\n  · %s", len(f), strings.Join(f, "\n  · "))
	}
}
