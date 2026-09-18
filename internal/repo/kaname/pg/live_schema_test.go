// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// live_schema_test.go — ДЕЙСТВУЮЩАЯ схема: что цепочка миграций ОСТАВЛЯЕТ в
// базе, прочитанное из `pg_catalog`, а не выведенное из текста DDL.
//
// Общий помощник двух гейтов пакета: `TestRefusalTextNeverNamesARetiredConstraint`
// (ветвь отображения отказа не называет ограничения, которого нет) и
// `TestIAMCT113_CatalogKeysCarryTheDeclaredForm` (форма ключей и ведомость её
// послаблений).
//
// # Почему каталог, а не текст миграций (kaname#278)
//
// Оба гейта прежде узнавали живость ограничения по тексту DDL: один применял
// Up-половины регулярными выражениями, другой читал одну базовую миграцию. Текст
// знает только ЯВНОЕ снятие — `DROP CONSTRAINT`, `DROP INDEX`, `DROP TABLE`. Но
// сервер снимает и неявно: `DROP COLUMN` уносит все индексы и ключи, в которые
// колонка входит, а `… CASCADE` — ещё и триггеры, держащие её в `UPDATE OF`.
// Ни одна строка DDL при этом не называет снятое. Распознаватель по тексту
// обязан был бы знать все правила зависимостей сервера — то есть повторить
// сервер; каталог отвечает на тот же вопрос по построению.
//
// Замер, из которого это выведено, — инъекция А задачи: `DROP COLUMN
// users.account_id` уносит ключ `users_account_fk` и индекс
// `users_account_email_unique`; оба прежних гейта остались зелёными.
//
// # Что считается «именем, которое сервер способен назвать» в `ConstraintName`
//
// Форм три, и каждая прочитана своим запросом:
//
//   - ограничение (`pg_constraint`: CHECK, внешний ключ, первичный, уникальный,
//     исключения, ограничивающий триггер, ограничение домена);
//   - УНИКАЛЬНЫЙ индекс без ограничения (`CREATE UNIQUE INDEX`): на 23505 сервер
//     кладёт в `ConstraintName` имя индекса. Неуникальный индекс отказа не
//     производит никогда — его имя живым не считается, хотя объект есть;
//   - имя, которое триггерная функция поднимает `RAISE … USING CONSTRAINT = '…'`.
//     Оно живо, только пока функцию исполняет ЖИВОЙ (не выключенный) триггер:
//     `DROP COLUMN … CASCADE` сносит триггер, а функция остаётся — и её имя
//     становится ровно тем неявно снятым, которого текст не видит.
//
// # Предпосылка базы проверяется, а не подразумевается
//
// Гейт судит ЦЕЛУЮ цепочку. База, накатившая не все миграции, даёт вердикт о
// схеме, которой в поставке нет, поэтому число применённых версий сверяется с
// числом файлов `migrations.FS`, а голова — с наибольшей версией файла.
// Расхождение — «проверка НЕ ИСПОЛНЯЛАСЬ», а не находка.

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// liveConstraint — строка `pg_constraint`.
type liveConstraint struct {
	name     string
	relation string // схема.таблица либо схема.домен
	kind     string // contype: c f p u t x
	// deferrable / initiallyDeferred — condeferrable / condeferred.
	deferrable        bool
	initiallyDeferred bool
	// onDelete / onUpdate — confdeltype / confupdtype; у не-ключа пусто.
	onDelete, onUpdate string
}

// restrictBesideDeferrable — `RESTRICT` (при удалении ЛИБО при изменении)
// рядом с `DEFERRABLE`. Форма, которую DDL принимает и которая молча инертна:
// действие `RESTRICT` не откладывается никогда.
func (c liveConstraint) restrictBesideDeferrable() bool {
	return c.kind == "f" && c.deferrable && (c.onDelete == "r" || c.onUpdate == "r")
}

// liveIndex — строка `pg_index`.
type liveIndex struct {
	name, table string
	unique      bool
}

// liveRaise — имя, поднимаемое функцией `RAISE … USING CONSTRAINT = '…'`.
type liveRaise struct {
	name     string
	function string // схема.имя
	// triggerFunction — функция возвращает `trigger`, то есть исполнить её
	// способен только триггер, и достижимость читается каталогом.
	triggerFunction bool
	// executed — функцию исполняет хотя бы один триггер, срабатывающий в обычной
	// сессии (tgenabled 'O' либо 'A'); выключенный и реплика-триггер не в счёт.
	executed bool
}

// liveSchema — действующая схема пользовательских пространств имён.
type liveSchema struct {
	constraints []liveConstraint
	indexes     []liveIndex
	raises      []liveRaise
	// functionsRead — функций plpgsql прочитано; нужно переписи, чтобы «имён,
	// поднимаемых функциями, 0» отличалось от «функций не прочитано».
	functionsRead int
	// unrecognizedRaise — функции, где слот `CONSTRAINT =` есть, а литерала
	// распознаватель не нашёл (переменная, выражение): форма, которой он не
	// знает. Не пусто — предпосылка гейта нарушена.
	unrecognizedRaise []string

	// Заполняются только у схемы ЦЕПОЧКИ (liveSchemaOfTheChain).
	migrationsApplied, migrationsInChain int
	headVersion                          int64
}

// userSchemaFilter — пространства имён, которые принадлежат продукту: всё, кроме
// системных. Имя схемы продукта здесь не выписывается намеренно — схему
// переименовывали, и литерал пережил бы переименование молча.
const userSchemaFilter = `n.nspname !~ '^pg_' AND n.nspname <> 'information_schema'`

const liveConstraintsSQL = `
SELECT c.conname,
       n.nspname || '.' || COALESCE(cl.relname, ty.typname, ''),
       c.contype::text, c.condeferrable, c.condeferred,
       btrim(c.confdeltype::text), btrim(c.confupdtype::text)
FROM pg_catalog.pg_constraint c
JOIN pg_catalog.pg_namespace n ON n.oid = c.connamespace
LEFT JOIN pg_catalog.pg_class cl ON cl.oid = c.conrelid
LEFT JOIN pg_catalog.pg_type ty ON ty.oid = c.contypid
WHERE ` + userSchemaFilter

const liveIndexesSQL = `
SELECT i.relname, n.nspname || '.' || t.relname, x.indisunique
FROM pg_catalog.pg_index x
JOIN pg_catalog.pg_class i ON i.oid = x.indexrelid
JOIN pg_catalog.pg_class t ON t.oid = x.indrelid
JOIN pg_catalog.pg_namespace n ON n.oid = i.relnamespace
WHERE ` + userSchemaFilter

// tgenabled: 'O' — обычный (origin/local), 'A' — ALWAYS, 'R' — только в режиме
// реплики, 'D' — выключен. В ОБЫЧНОЙ сессии (session_replication_role='origin')
// срабатывают только 'O' и 'A'; 'R' и 'D' — нет. Поэтому имя, поднимаемое
// функцией, живо лишь когда её исполняет триггер 'O' либо 'A': реплика-триггер в
// обычной сессии молчит, и его имя сервер не назовёт.
const liveFunctionsSQL = `
SELECT n.nspname || '.' || p.proname, p.prosrc,
       p.prorettype = 'pg_catalog.trigger'::pg_catalog.regtype,
       EXISTS (SELECT 1 FROM pg_catalog.pg_trigger tg
               WHERE tg.tgfoid = p.oid AND tg.tgenabled IN ('O', 'A'))
FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
JOIN pg_catalog.pg_language l ON l.oid = p.prolang
WHERE l.lanname = 'plpgsql' AND ` + userSchemaFilter

var (
	// reRaiseSlot — всякий слот `CONSTRAINT =` (или `:=`) в теле функции.
	reRaiseSlot = regexp.MustCompile(`(?i)\bCONSTRAINT\s*:?=`)
	// reRaiseName — слот, чьё значение — строковый литерал имени.
	reRaiseName = regexp.MustCompile(`(?i)\bCONSTRAINT\s*:?=\s*'([A-Za-z0-9_]+)'`)
)

// readLiveSchema читает действующую схему из каталога.
func readLiveSchema(ctx context.Context, conn *pgx.Conn) (liveSchema, error) {
	var s liveSchema

	rows, err := conn.Query(ctx, liveConstraintsSQL)
	if err != nil {
		return s, fmt.Errorf("pg_constraint: %w", err)
	}
	for rows.Next() {
		var c liveConstraint
		if err := rows.Scan(&c.name, &c.relation, &c.kind, &c.deferrable, &c.initiallyDeferred,
			&c.onDelete, &c.onUpdate); err != nil {
			rows.Close()
			return s, fmt.Errorf("pg_constraint: %w", err)
		}
		s.constraints = append(s.constraints, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return s, fmt.Errorf("pg_constraint: %w", err)
	}

	rows, err = conn.Query(ctx, liveIndexesSQL)
	if err != nil {
		return s, fmt.Errorf("pg_index: %w", err)
	}
	for rows.Next() {
		var ix liveIndex
		if err := rows.Scan(&ix.name, &ix.table, &ix.unique); err != nil {
			rows.Close()
			return s, fmt.Errorf("pg_index: %w", err)
		}
		s.indexes = append(s.indexes, ix)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return s, fmt.Errorf("pg_index: %w", err)
	}

	rows, err = conn.Query(ctx, liveFunctionsSQL)
	if err != nil {
		return s, fmt.Errorf("pg_proc: %w", err)
	}
	for rows.Next() {
		var fn, src string
		var isTrigger, executed bool
		if err := rows.Scan(&fn, &src, &isTrigger, &executed); err != nil {
			rows.Close()
			return s, fmt.Errorf("pg_proc: %w", err)
		}
		s.functionsRead++
		body := stripPLpgSQLComments(src)
		names := reRaiseName.FindAllStringSubmatch(body, -1)
		if len(reRaiseSlot.FindAllStringIndex(body, -1)) != len(names) {
			s.unrecognizedRaise = append(s.unrecognizedRaise, fn)
		}
		for _, m := range names {
			s.raises = append(s.raises, liveRaise{name: m[1], function: fn, triggerFunction: isTrigger, executed: executed})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return s, fmt.Errorf("pg_proc: %w", err)
	}
	sort.Strings(s.unrecognizedRaise)
	return s, nil
}

// stripPLpgSQLComments снимает комментарии тела функции, НЕ трогая строковых
// литералов: имя, упомянутое в объяснении, не поднимается никем, а `--` внутри
// текста сообщения комментарием не является.
func stripPLpgSQLComments(src string) string {
	var b strings.Builder
	for i := 0; i < len(src); {
		switch {
		case src[i] == '\'':
			j := i + 1
			for j < len(src) {
				if src[j] == '\'' {
					if j+1 < len(src) && src[j+1] == '\'' {
						j += 2
						continue
					}
					j++
					break
				}
				j++
			}
			b.WriteString(src[i:j])
			i = j
		case strings.HasPrefix(src[i:], "--"):
			if nl := strings.IndexByte(src[i:], '\n'); nl >= 0 {
				i += nl
			} else {
				i = len(src)
			}
		case strings.HasPrefix(src[i:], "/*"):
			depth, j := 1, i+2
			for j < len(src) && depth > 0 {
				switch {
				case strings.HasPrefix(src[j:], "/*"):
					depth++
					j += 2
				case strings.HasPrefix(src[j:], "*/"):
					depth--
					j += 2
				default:
					j++
				}
			}
			b.WriteByte(' ')
			i = j
		default:
			b.WriteByte(src[i])
			i++
		}
	}
	return b.String()
}

// constraintsNamed — все ограничения с этим именем (имя ограничения уникально
// в пределах таблицы, а не схемы).
func (s liveSchema) constraintsNamed(name string) []liveConstraint {
	var out []liveConstraint
	for _, c := range s.constraints {
		if c.name == name {
			out = append(out, c)
		}
	}
	return out
}

// foreignKeysNamed — внешние ключи с этим именем.
func (s liveSchema) foreignKeysNamed(name string) []liveConstraint {
	var out []liveConstraint
	for _, c := range s.constraintsNamed(name) {
		if c.kind == "f" {
			out = append(out, c)
		}
	}
	return out
}

// foreignKeysByRef — внешние ключи с этой парой «таблица + имя». Имя ограничения
// уникально лишь В ПРЕДЕЛАХ ТАБЛИЦЫ, поэтому ведомость послаблений сопоставляется
// парой, а не именем: тот же ключ на другой таблице — чужой предмет, и прощать
// его вместе с названным значило бы открыть ему слепую зону.
func (s liveSchema) foreignKeysByRef(table, name string) []liveConstraint {
	var out []liveConstraint
	for _, c := range s.foreignKeysNamed(name) {
		if c.relation == table {
			out = append(out, c)
		}
	}
	return out
}

func (s liveSchema) foreignKeys() []liveConstraint {
	var out []liveConstraint
	for _, c := range s.constraints {
		if c.kind == "f" {
			out = append(out, c)
		}
	}
	return out
}

// producesName — способна ли действующая схема положить имя в `ConstraintName`.
func (s liveSchema) producesName(name string) bool {
	if len(s.constraintsNamed(name)) > 0 {
		return true
	}
	for _, ix := range s.indexes {
		if ix.name == name && ix.unique {
			return true
		}
	}
	for _, r := range s.raises {
		if r.name == name && r.triggerFunction && r.executed {
			return true
		}
	}
	return false
}

// absenceOf — ПОЧЕМУ имя не производится: диагностика находки. Находка,
// называющая симптом («имени нет»), посылает искать не там; здесь названо, что
// именно в схеме есть под этим именем и почему оно отказа не даст.
func (s liveSchema) absenceOf(name string) string {
	for _, r := range s.raises {
		if r.name == name && !r.triggerFunction {
			return "имя поднимает НЕ триггерная функция " + r.function + ": исполняется ли она, " +
				"каталог не говорит — ПРЕДПОСЫЛКА гейта нарушена, распознаватель обязан узнать эту форму, " +
				"прежде чем судить"
		}
	}
	var orphans []string
	for _, r := range s.raises {
		if r.name == name && r.triggerFunction && !r.executed {
			orphans = append(orphans, r.function)
		}
	}
	if len(orphans) > 0 {
		sort.Strings(orphans)
		return "имя поднимает функция " + strings.Join(orphans, ", ") + ", но ни один срабатывающий " +
			"в обычной сессии триггер её не исполняет — триггер снят (явно либо неявно: " +
			"DROP COLUMN/DROP TABLE … CASCADE), выключен либо включён только для реплики"
	}
	for _, ix := range s.indexes {
		if ix.name == name && !ix.unique {
			return "в схеме есть НЕуникальный индекс с этим именем на " + ix.table +
				" — отказа он не производит, и сервер его не назовёт"
		}
	}
	return "в действующей схеме нет ни ограничения, ни уникального индекса, ни исполняемой " +
		"триггером функции, поднимающей это имя: снято явно либо унесено неявно " +
		"(DROP COLUMN, DROP TABLE, CASCADE)"
}

// census — перепись действующей схемы одной строкой.
func (s liveSchema) census() string {
	unique, raisedLive := 0, 0
	for _, ix := range s.indexes {
		if ix.unique {
			unique++
		}
	}
	for _, r := range s.raises {
		if r.triggerFunction && r.executed {
			raisedLive++
		}
	}
	head := ""
	if s.migrationsInChain > 0 {
		head = fmt.Sprintf("миграций применено %d из %d (голова %d) · ",
			s.migrationsApplied, s.migrationsInChain, s.headVersion)
	}
	return fmt.Sprintf("%sограничений %d (внешних ключей %d) · уникальных индексов %d · "+
		"функций plpgsql прочитано %d · имён, поднимаемых исполняемыми триггерами, %d",
		head, len(s.constraints), len(s.foreignKeys()), unique, s.functionsRead, raisedLive)
}

// liveSchemaConn — соединение с базой, закрываемое по окончании пробы.
func liveSchemaConn(t *testing.T, dsn string) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: соединение с базой не установлено: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// liveSchemaOfTheChain — действующая схема ПОСТАВЛЯЕМОЙ цепочки: клон шаблона,
// который TestMain пакета накатил `migrations.FS` целиком.
//
// Ярус — контейнерный: под `-short` проба пропускает себя с названной причиной,
// а исполняет её задание `integration` конвейера (`.github/scripts/run-integration.sh`
// отбирает пакет по импорту `corelib/pgtest`).
func liveSchemaOfTheChain(t *testing.T) liveSchema {
	t.Helper()
	if testing.Short() {
		t.Skip("гейт судит ДЕЙСТВУЮЩУЮ схему — накат цепочки на настоящую базу; под -short " +
			"база не поднимается, гейт исполняет контейнерное задание (run-integration.sh)")
	}
	ctx := context.Background()
	conn := liveSchemaConn(t, pgtest.NewDB(t))

	s, err := readLiveSchema(ctx, conn)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: каталог не прочитан: %v", err)
	}

	files, ferr := fs.Glob(migrations.FS, "*.sql")
	if ferr != nil || len(files) == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: миграций в поставке не прочитано (%v)", ferr)
	}
	var fileHead int64
	for _, f := range files {
		digits := f[:len(f)-len(strings.TrimLeft(f, "0123456789"))]
		v, perr := strconv.ParseInt(digits, 10, 64)
		if perr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: имя миграции %q не несёт версии: %v", f, perr)
		}
		if v > fileHead {
			fileHead = v
		}
	}
	if err := conn.QueryRow(ctx,
		`SELECT count(DISTINCT version_id), COALESCE(max(version_id), 0)
		   FROM goose_db_version WHERE version_id > 0 AND is_applied`,
	).Scan(&s.migrationsApplied, &s.headVersion); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: журнал применения не прочитан: %v", err)
	}
	s.migrationsInChain = len(files)
	if s.migrationsApplied != s.migrationsInChain || s.headVersion != fileHead {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: база несёт не всю цепочку — применено %d из %d, "+
			"голова %d при наибольшей версии файла %d; вердикт был бы о схеме, которой в поставке нет",
			s.migrationsApplied, s.migrationsInChain, s.headVersion, fileHead)
	}
	if len(s.constraints) == 0 {
		t.Fatal("проверка НЕ ИСПОЛНЯЛАСЬ: ограничений в действующей схеме 0 — каталог прочитан не там")
	}
	return s
}

// liveSchemaAfter — действующая схема ПУСТОЙ базы после синтетического DDL.
// Производитель входа инъекций: вход подаётся настоящему серверу, и снятие —
// явное или неявное — решает он, а не распознаватель пробы.
func liveSchemaAfter(t *testing.T, ddl ...string) liveSchema {
	t.Helper()
	if testing.Short() {
		t.Skip("инъекция идёт настоящим сервером — под -short база не поднимается")
	}
	ctx := context.Background()
	conn := liveSchemaConn(t, pgtest.NewEmptyDB(t))
	for i, stmt := range ddl {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: синтетический DDL %d не принят сервером: %v", i, err)
		}
	}
	s, err := readLiveSchema(ctx, conn)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: каталог не прочитан: %v", err)
	}
	return s
}
