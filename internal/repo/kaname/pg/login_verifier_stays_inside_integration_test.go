// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_verifier_stays_inside_integration_test.go — ГЕЙТ: проверочный материал
// способа входа лежит в базе РОВНО В ОДНОМ месте, и ни один механизм базы не
// уносит его оттуда без ведома писателя (фаза Ф2, `kacho#1268`).
//
// # Предмет
//
// Материал пароля — хеш, созданный прежним поставщиком либо нашей функцией. Его
// копия в журнале ресурсов, в очереди аудита, в представлении, в статистике
// планировщика либо в любой таблице, заведённой завтра, живёт своим сроком
// хранения и уезжает к своему читателю. Хеш не пароль, но перебор офлайн по нему
// возможен, и срок хранения копии становится сроком, в течение которого это
// возможно.
//
// # Что гейт судит — ИСХОД, а не объявление. Две оси, у каждой перечень форм
//
// ОСЬ ПЕРВАЯ — КОПИИ. Материал с меткой пишется НАСТОЯЩИМ путём адаптера двум
// людям, таблица анализируется (ANALYZE), после чего метку ищут в каждой колонке
// КАЖДОГО отношения, способного нести копию. Отношения выводятся из каталога по
// виду `pg_class.relkind`, во всех схемах базы, кроме системных, — таблица,
// заведённая завтра в любой схеме, попадает под перепись в день появления:
//
//	r  обычная таблица             — хранит строки;
//	p  секционированная таблица    — читается через родителя, секции — тоже r;
//	m  материализованное представление — хранит результат запроса;
//	v  представление               — копии не хранит, но ОТДАЁТ материал вторым путём.
//
// Колонка ЛЮБОГО типа приводится к тексту: копия в составном типе, массиве,
// JSON — тоже копия; двоичное значение ищется ещё и в шестнадцатеричной форме
// своего вывода. Остальные виды отношений копию не несут либо несут её через
// судимое: i/I (индекс) копирует колонки СВОЕЙ таблицы — индекс по колонке
// материала судит ось вторая, индекс чужой таблицы копирует то, что уже нашла
// перепись её строк; t (хранилище длинных значений) читается через свою
// таблицу; S (последовательность) и c (составной тип) строк не хранят; f
// (внешняя таблица) хранит строки на ЧУЖОМ сервере — копия там уже вне этой
// базы, и доставить её туда может только механизм, который судит ось вторая.
// Внешнюю таблицу перепись не читает намеренно: чтение было бы сетевым
// вызовом к чужому серверу посреди пробы.
//
// Сверх отношений пользовательских схем — СТАТИСТИКА ПЛАНИРОВЩИКА
// (`pg_statistic`): после ANALYZE она хранит выборку значений колонки и живёт до
// следующего анализа, переживая удаление строки. Миграция выключает её сбор для
// колонки материала (`SET STATISTICS 0`); гейт анализирует таблицу сам и ищет
// метку в выборках.
//
// Метка обязана найтись ровно в `kaname.user_login_methods.verifier` — это
// положительный контроль: без него «нигде нет» было бы верно и о переписи, не
// читающей ничего.
//
// ОСЬ ВТОРАЯ — МЕХАНИЗМЫ, исполняющиеся без ведома писателя. Перепись копий
// различить их не может by construction: уведомление, публикация и вызов
// функции не лежат ни в одной таблице. Каждый — отдельным правилом каталога:
//
//   - ТРИГГЕРЫ на таблице секрета, кроме порождённых ссылочной целостностью;
//   - ПРАВИЛА ПЕРЕЗАПИСИ на ней — `DO ALSO` исполняется в операторе писателя;
//   - ПОЛИТИКИ СТРОК на ней — их выражение исполняется при записи;
//   - ОГРАНИЧЕНИЯ сверх объявленного набора — выражение проверки исполняется при
//     каждой записи (набор ЗАКРЫТ, как и состав колонок);
//   - ДОМЕННЫЙ ТИП колонки — ограничения домена исполняются со значением;
//   - ЗАВИСИМЫЕ ОТ КОЛОНКИ материала по каталогу зависимостей (`pg_depend`):
//     представления, правила других таблиц, индексы, расширенная статистика,
//     порождённые колонки, функции со стандартным телом SQL. Законно одно —
//     проверка непустоты материала;
//   - ИСПОЛЬЗУЮЩИЕ ТИП СТРОКИ таблицы — значение этого типа несёт материал;
//   - ПОДПРОГРАММЫ, чей текст называет таблицу (без комментариев), — их
//     исполняет не писатель, а тот, кто их зовёт: триггер соседней таблицы,
//     событийный триггер;
//   - ПУБЛИКАЦИИ логической репликации, захватывающие таблицу, — по таблице,
//     по схеме либо все таблицы.
//
// # Чего гейт НЕ судит — границы, названные вслух
//
//   - журнал самого сервера базы: сообщение о нарушении ограничения проверки
//     несёт строку целиком в `DETAIL`, а журналирование операторов может нести
//     значения их параметров. Первое достижимо только обходом доменной проверки
//     — вид и материал судит тип до вставки, переводчик отказов службы `DETAIL`
//     не читает (`pgmaperr_login_method_test.go`); второе — предмет настроек
//     сервера в профиле развёртывания, а не схемы;
//   - слот логического декодирования с модулем, отличным от `pgoutput`: он
//     читает журнал упреждающей записи мимо публикаций. Посадка пробы работает с
//     `wal_level=replica`, слот в ней не заводится, и опытом это не доказуемо —
//     это предмет конфигурации сервера;
//   - имя таблицы, собранное подпрограммой ВО ВРЕМЯ ИСПОЛНЕНИЯ (`EXECUTE` со
//     склейкой частей): текст подпрограммы его не содержит;
//   - физическая копия (резервная копия, журнал): у неё тот же читатель, что у
//     самой таблицы;
//   - путь кода Go до базы: его держит гейт дерева `internal/check`
//     `TestLoginVerifierStaysInside`.
//
// Способность упасть доказана инъекцией — `TestLoginVerifierContainmentGateInjection`:
// у каждой формы обеих осей своя сцена, у каждого правила — законный близнец.
package pg_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// lmSentinel — метка, которая обязана выглядеть чужой: совпасть с законным
// содержимым схемы она не может, поэтому любое её вхождение — копия материала.
const lmSentinel = "$2a$12$LMSTAYSINSIDE.sentinel.f2p1.copy.is.a.leak"

// lmSecretHome — единственное законное место материала.
const lmSecretHome = "kaname.user_login_methods.verifier"

// lmDeclaredConstraints — объявленный набор ограничений таблицы секрета.
// Набор ЗАКРЫТ: ограничение, заведённое позже, исполняет своё выражение при
// каждой записи и требует решения, а не проходит незамеченным.
var lmDeclaredConstraints = []string{
	"user_login_methods_pkey",
	"user_login_methods_user_fk",
	"user_login_methods_kind_check",
	"user_login_methods_verifier_check",
}

// lmVerifierDependent — единственный законный зависимый от колонки материала.
const lmVerifierDependent = "user_login_methods_verifier_check"

type lmContainment struct {
	// Hits — где метка найдена: «схема.отношение.колонка» → строк.
	Hits map[string]int
	// Перепись оси копий.
	Relations      map[string]int // вид отношения → осмотрено
	Unpopulated    []string       // материализованные представления без данных
	ScannedColumns int
	StatRows       int      // строк статистики таблицы секрета — ANALYZE прошёл
	StatHits       []string // выборки статистики, хранящие метку
	// Ось механизмов.
	UserTriggers       []string
	InternalTriggers   int
	Rules              []string
	Policies           []string
	DeclaredSeen       int
	ForeignConstraints []string
	DomainColumns      []string
	ColumnDependents   []string
	RowtypeDependents  []string
	RoutinesRead       int
	NamingRoutines     []string
	Publications       []string
}

// Findings — нарушения обеих осей. Пустой перечень — вердикт, только если
// метка найдена в своём доме (см. HomeSeen) и перепись не пуста (lmRequireCensus).
func (c lmContainment) Findings() []string {
	var out []string
	for where, n := range c.Hits {
		if where != lmSecretHome {
			out = append(out, fmt.Sprintf("материал найден вне своего дома: %s (строк %d)", where, n))
		}
	}
	for _, s := range c.StatHits {
		out = append(out, fmt.Sprintf("статистика планировщика (pg_statistic) хранит выборку материала: %s — "+
			"копия живёт до следующего анализа и переживает удаление строки", s))
	}
	add := func(list []string, format string) {
		for _, x := range list {
			out = append(out, fmt.Sprintf(format, x))
		}
	}
	add(c.UserTriggers, "на таблице секрета стоит триггер %q — он видит строку целиком и исполняется без ведома писателя")
	add(c.Rules, "на таблице секрета стоит правило перезаписи %q — оно исполняется в операторе писателя и видит строку")
	add(c.Policies, "на таблице секрета стоит политика строк %q — её выражение исполняется при записи и видит строку")
	add(c.ForeignConstraints, "на таблице секрета ограничение %s вне объявленного набора — его выражение исполняется при каждой записи")
	add(c.DomainColumns, "колонка таблицы секрета доменного типа (%s) — ограничения домена исполняются при записи со значением")
	add(c.ColumnDependents, "от колонки материала зависит %s — он читает материал помимо адаптера")
	add(c.RowtypeDependents, "тип строки таблицы секрета использует %s — значение этого типа несёт материал")
	add(c.NamingRoutines, "подпрограмма %s называет таблицу секрета — её исполняет тот, кто её зовёт, мимо писателя")
	add(c.Publications, "публикация %q отдаёт таблицу секрета подписчику логической репликации")
	sort.Strings(out)
	return out
}

// HomeSeen — положительный контроль переписи.
func (c lmContainment) HomeSeen() bool { return c.Hits[lmSecretHome] > 0 }

func (c lmContainment) Census() string {
	kinds := make([]string, 0, len(c.Relations))
	for k, n := range c.Relations {
		kinds = append(kinds, fmt.Sprintf("%s=%d", k, n))
	}
	sort.Strings(kinds)
	return fmt.Sprintf("перепись: отношений осмотрено по видам [%s], без данных %d, колонок %d; метка найдена в %d местах; "+
		"строк статистики таблицы секрета %d, выборок с меткой %d; триггеров: пользовательских %d, ссылочной целостности %d; "+
		"правил %d; политик %d; ограничений объявленных %d из %d, чужих %d; доменных колонок %d; зависимых от колонки материала "+
		"сверх законного %d; использующих тип строки %d; подпрограмм прочитано %d, называющих таблицу %d; публикаций %d",
		strings.Join(kinds, " "), len(c.Unpopulated), c.ScannedColumns, len(c.Hits),
		c.StatRows, len(c.StatHits), len(c.UserTriggers), c.InternalTriggers,
		len(c.Rules), len(c.Policies), c.DeclaredSeen, len(lmDeclaredConstraints), len(c.ForeignConstraints),
		len(c.DomainColumns), len(c.ColumnDependents), len(c.RowtypeDependents),
		c.RoutinesRead, len(c.NamingRoutines), len(c.Publications))
}

// lmRequireCensus — премисы: каждое правило читало каталог. Без них «нарушений
// ноль» было бы верно и о правиле, не прочитавшем ничего.
func lmRequireCensus(t *testing.T, c lmContainment) {
	t.Helper()
	require.NotZero(t, c.ScannedColumns, "колонок осмотрено ноль — вердикт беспредметен")
	require.True(t, c.HomeSeen(),
		"метка не найдена даже в своём доме %s — перепись не читает то, о чём судит", lmSecretHome)
	require.NotZero(t, c.StatRows,
		"у таблицы секрета нет ни одной строки статистики — ANALYZE не прошёл, и «выборок с меткой ноль» сказано ни о чём")
	require.NotZero(t, c.InternalTriggers,
		"триггеров ссылочной целостности ноль — вопрос о триггерах не читает каталог")
	require.Equal(t, len(lmDeclaredConstraints), c.DeclaredSeen,
		"объявленные ограничения не найдены все — правило ограничений не читает каталог")
	require.NotZero(t, c.RoutinesRead, "подпрограмм прочитано ноль — правило подпрограмм беспредметно")
}

// lmQueryStrings — один столбец строк.
func lmQueryStrings(t *testing.T, pool *pgxpool.Pool, q string, args ...any) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(), q, args...)
	require.NoError(t, err, "запрос каталога: %s", q)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		require.NoError(t, rows.Scan(&v))
		out = append(out, v)
	}
	require.NoError(t, rows.Err())
	return out
}

// lmUserSchemas — предикат схем, которые судит перепись: все, кроме системных.
const lmUserSchemas = `n.nspname NOT IN ('pg_catalog', 'information_schema')
	   AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp\_%'`

// lmScanContainment спрашивает каталог и каждую колонку.
func lmScanContainment(t *testing.T, pool *pgxpool.Pool, needle string) lmContainment {
	t.Helper()
	ctx := context.Background()
	c := lmContainment{Hits: map[string]int{}, Relations: map[string]int{}}
	hexNeedle := hex.EncodeToString([]byte(needle))

	// ANALYZE — часть пути, который судится: служба живёт с автоанализом, и
	// выборка статистики появляется без ведома писателя.
	_, err := pool.Exec(ctx, `ANALYZE kaname.user_login_methods`)
	require.NoError(t, err)

	// ── ось первая: копии ─────────────────────────────────────────────────────
	type relation struct {
		oid                uint32
		schema, name, kind string
		populated          bool
	}
	rows, err := pool.Query(ctx, `
		SELECT c.oid, n.nspname, c.relname, c.relkind::text, c.relispopulated
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE c.relkind IN ('r', 'p', 'm', 'v') AND `+lmUserSchemas+`
		 ORDER BY n.nspname, c.relname`)
	require.NoError(t, err)
	var rels []relation
	for rows.Next() {
		var r relation
		require.NoError(t, rows.Scan(&r.oid, &r.schema, &r.name, &r.kind, &r.populated))
		rels = append(rels, r)
	}
	require.NoError(t, rows.Err())
	rows.Close()

	for _, r := range rels {
		c.Relations[r.kind]++
		if !r.populated {
			c.Unpopulated = append(c.Unpopulated, r.schema+"."+r.name)
			continue
		}
		cols := lmQueryStrings(t, pool, `
			SELECT attname FROM pg_attribute
			 WHERE attrelid = $1 AND attnum > 0 AND NOT attisdropped ORDER BY attnum`, r.oid)
		if len(cols) == 0 {
			continue
		}
		exprs := make([]string, 0, len(cols))
		for _, col := range cols {
			ident := pgx.Identifier{col}.Sanitize()
			exprs = append(exprs, fmt.Sprintf(
				"count(*) FILTER (WHERE strpos(%[1]s::text, $1) > 0 OR strpos(%[1]s::text, $2) > 0)", ident))
		}
		q := fmt.Sprintf(`SELECT %s FROM %s`, strings.Join(exprs, ", "), pgx.Identifier{r.schema, r.name}.Sanitize())
		counts := make([]int64, len(cols))
		dest := make([]any, len(cols))
		for i := range counts {
			dest[i] = &counts[i]
		}
		require.NoError(t, pool.QueryRow(ctx, q, needle, hexNeedle).Scan(dest...), "отношение %s.%s", r.schema, r.name)
		for i, n := range counts {
			if n > 0 {
				c.Hits[r.schema+"."+r.name+"."+cols[i]] = int(n)
			}
		}
		c.ScannedColumns += len(cols)
	}

	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_statistic WHERE starelid = 'kaname.user_login_methods'::regclass`).Scan(&c.StatRows))
	c.StatHits = lmQueryStrings(t, pool, `
		SELECT s.starelid::regclass::text || '.' || a.attname
		  FROM pg_statistic s
		  JOIN pg_attribute a ON a.attrelid = s.starelid AND a.attnum = s.staattnum
		 WHERE strpos(concat_ws('|', s.stavalues1::text, s.stavalues2::text, s.stavalues3::text,
		                             s.stavalues4::text, s.stavalues5::text), $1) > 0
		    OR strpos(concat_ws('|', s.stavalues1::text, s.stavalues2::text, s.stavalues3::text,
		                             s.stavalues4::text, s.stavalues5::text), $2) > 0
		 ORDER BY 1`, needle, hexNeedle)

	// ── ось вторая: механизмы ─────────────────────────────────────────────────
	trows, err := pool.Query(ctx, `
		SELECT tgname, tgisinternal FROM pg_trigger
		 WHERE tgrelid = 'kaname.user_login_methods'::regclass ORDER BY tgname`)
	require.NoError(t, err)
	for trows.Next() {
		var name string
		var internal bool
		require.NoError(t, trows.Scan(&name, &internal))
		if internal {
			c.InternalTriggers++
		} else {
			c.UserTriggers = append(c.UserTriggers, name)
		}
	}
	require.NoError(t, trows.Err())
	trows.Close()

	c.Rules = lmQueryStrings(t, pool, `
		SELECT rulename::text FROM pg_rewrite WHERE ev_class = 'kaname.user_login_methods'::regclass ORDER BY 1`)
	c.Policies = lmQueryStrings(t, pool, `
		SELECT polname::text FROM pg_policy WHERE polrelid = 'kaname.user_login_methods'::regclass ORDER BY 1`)

	crows, err := pool.Query(ctx, `
		SELECT conname::text, contype::text, pg_get_constraintdef(oid) FROM pg_constraint
		 WHERE conrelid = 'kaname.user_login_methods'::regclass ORDER BY conname`)
	require.NoError(t, err)
	declared := map[string]bool{}
	for _, n := range lmDeclaredConstraints {
		declared[n] = true
	}
	for crows.Next() {
		var name, kind, def string
		require.NoError(t, crows.Scan(&name, &kind, &def))
		switch {
		case declared[name]:
			c.DeclaredSeen++
		case kind == "n":
			// Ограничение «не NULL» каталога (новые версии сервера): выражения не
			// исполняет.
		default:
			c.ForeignConstraints = append(c.ForeignConstraints, fmt.Sprintf("%q (%s)", name, def))
		}
	}
	require.NoError(t, crows.Err())
	crows.Close()

	c.DomainColumns = lmQueryStrings(t, pool, `
		SELECT a.attname || ' — ' || format_type(a.atttypid, a.atttypmod)
		  FROM pg_attribute a JOIN pg_type ty ON ty.oid = a.atttypid
		 WHERE a.attrelid = 'kaname.user_login_methods'::regclass AND a.attnum > 0 AND NOT a.attisdropped
		   AND ty.typtype = 'd' ORDER BY 1`)

	c.ColumnDependents = lmQueryStrings(t, pool, `
		SELECT pg_describe_object(d.classid, d.objid, d.objsubid)
		  FROM pg_depend d
		 WHERE d.refclassid = 'pg_class'::regclass
		   AND d.refobjid = 'kaname.user_login_methods'::regclass
		   AND d.refobjsubid = (SELECT attnum FROM pg_attribute
		                         WHERE attrelid = 'kaname.user_login_methods'::regclass AND attname = 'verifier')
		   AND NOT (d.classid = 'pg_constraint'::regclass AND d.objid IN (
		         SELECT oid FROM pg_constraint
		          WHERE conrelid = 'kaname.user_login_methods'::regclass AND (conname = $1 OR contype = 'n')))
		 ORDER BY 1`, lmVerifierDependent)

	c.RowtypeDependents = lmQueryStrings(t, pool, `
		SELECT pg_describe_object(d.classid, d.objid, d.objsubid)
		  FROM pg_depend d
		 WHERE d.refclassid = 'pg_type'::regclass
		   AND d.refobjid = (SELECT reltype FROM pg_class WHERE oid = 'kaname.user_login_methods'::regclass)
		   AND d.deptype <> 'i'
		 ORDER BY 1`)

	prows, err := pool.Query(ctx, `
		SELECT p.oid::regprocedure::text, coalesce(p.prosrc, ''), coalesce(pg_get_function_sqlbody(p.oid), '')
		  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE `+lmUserSchemas+`
		 ORDER BY 1`)
	require.NoError(t, err)
	tableWord := regexp.MustCompile(`(^|[^A-Za-z0-9_])user_login_methods($|[^A-Za-z0-9_])`)
	for prows.Next() {
		var name, src, body string
		require.NoError(t, prows.Scan(&name, &src, &body))
		c.RoutinesRead++
		if tableWord.MatchString(lmStripSQLComments(src)) || tableWord.MatchString(lmStripSQLComments(body)) {
			c.NamingRoutines = append(c.NamingRoutines, name)
		}
	}
	require.NoError(t, prows.Err())
	prows.Close()

	c.Publications = lmQueryStrings(t, pool, `
		SELECT DISTINCT pubname::text FROM pg_publication_tables
		 WHERE schemaname = 'kaname' AND tablename = 'user_login_methods' ORDER BY 1`)
	return c
}

// lmDollarTag — метка строки в долларах: пустая либо идентификатор, не
// начинающийся с цифры (`$1` меткой не является).
var lmDollarTag = regexp.MustCompile(`^\$([A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)?\$`)

// lmStripSQLComments снимает комментарии SQL и PL/pgSQL, оставляя строки: в
// строке живёт динамический SQL, и он — исполняемая часть, а не пояснение.
// Знает строку в одинарных кавычках (и E-строку с обратной косой), имя в
// двойных кавычках, строку в долларах с меткой и вложенный блочный комментарий.
func lmStripSQLComments(src string) string {
	var b strings.Builder
	for i := 0; i < len(src); {
		switch {
		case strings.HasPrefix(src[i:], "--"):
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case strings.HasPrefix(src[i:], "/*"):
			depth := 0
			for i < len(src) {
				if strings.HasPrefix(src[i:], "/*") {
					depth++
					i += 2
					continue
				}
				if strings.HasPrefix(src[i:], "*/") {
					depth--
					i += 2
					if depth == 0 {
						break
					}
					continue
				}
				i++
			}
			b.WriteByte(' ')
		case src[i] == '\'' || src[i] == '"':
			q := src[i]
			escapes := q == '\'' && i > 0 && (src[i-1] == 'E' || src[i-1] == 'e')
			b.WriteByte(q)
			i++
			for i < len(src) {
				ch := src[i]
				b.WriteByte(ch)
				i++
				if escapes && ch == '\\' && i < len(src) {
					b.WriteByte(src[i])
					i++
					continue
				}
				if ch == q {
					if i < len(src) && src[i] == q {
						b.WriteByte(q)
						i++
						continue
					}
					break
				}
			}
		case src[i] == '$':
			tag := lmDollarTag.FindString(src[i:])
			if tag == "" {
				// `$1` — параметр, а не начало строки в долларах.
				b.WriteByte(src[i])
				i++
				continue
			}
			closing := strings.Index(src[i+len(tag):], tag)
			if closing < 0 {
				b.WriteString(src[i:])
				i = len(src)
				continue
			}
			b.WriteString(src[i : i+len(tag)+closing+len(tag)])
			i += len(tag) + closing + len(tag)
		default:
			b.WriteByte(src[i])
			i++
		}
	}
	return b.String()
}

// lmWriteSentinel пишет метку НАСТОЯЩИМ путём адаптера — предмет гейта есть то,
// что делает запись, а не то, что сделал бы сырой оператор. Людей двое и метка
// одна: выборка статистики держит значение, встреченное чаще одного раза, —
// одиночная строка не проверила бы статистику ни в какую сторону.
func lmWriteSentinel(t *testing.T, pool *pgxpool.Pool, tag string) {
	t.Helper()
	repo := pg.NewLoginMethodRepo(pool)
	for _, person := range lmPeople(t, pool, tag, 2) {
		_, err := repo.Create(context.Background(), domain.LoginMethod{
			UserID: person, Kind: domain.LoginMethodPassword, Verifier: lmVerifier(t, lmSentinel),
		})
		require.NoError(t, err)
	}
}

// TestLoginVerifierStaysInsideTheSchema — гейт.
//
// Что делать, если он сработал, — исходов три, четвёртого нет:
//
//  1. копию снимают: писатель обязан класть идентификатор человека и вид
//     способа, а не строку;
//  2. механизм на таблице секрета нужен по существу → предмет требует РЕШЕНИЯ:
//     доказать инъекцией в этом файле, что он материала не читает и не уносит,
//     после чего правило сужается к конкретному имени — приёмкой, а не
//     комментарием;
//  3. копия нужна другому месту по существу (например, проверяющему П2) →
//     её место — не таблица, а память процесса на время проверки.
func TestLoginVerifierStaysInsideTheSchema(t *testing.T) {
	pool := lmPool(t)
	lmWriteSentinel(t, pool, "lmstay")

	c := lmScanContainment(t, pool, lmSentinel)
	t.Log(c.Census())
	lmRequireCensus(t, c)
	for _, f := range c.Findings() {
		t.Error(f)
	}
}

// lmLeakFunction — функция, уносящая переданное значение уведомлением. Её тело
// таблицы секрета не называет: сцены, которые её зовут, обязан поймать не
// разбор текста подпрограмм, а правило своего механизма.
const lmLeakFunction = `
	CREATE FUNCTION kaname.lm_probe_leak(v text) RETURNS boolean LANGUAGE plpgsql AS $$
	BEGIN
	  PERFORM pg_notify('lm_probe_leak_fn', v);
	  RETURN true;
	END; $$;`

// lmInjection — сцена инъекции: база отличается от чистой ОДНИМ внесённым фактом.
type lmInjection struct {
	name string
	// before — внесённый факт; исполняется ДО записи метки.
	before string
	// after — действие после записи: обновить представление, снять копию
	// запросом, задеть соседнюю таблицу. Пусто — ничего.
	after string
	// listen — канал уведомления. Непусто — сцена ДОКАЗЫВАЕТ утечку: слушатель
	// обязан получить материал, иначе внесённый факт не сработал.
	listen string
	// quietListen — канал законного близнеца: уведомление обязано прийти и НЕ
	// нести метку — написание, которое близнец читает, база разрешила в другое
	// отношение.
	quietListen string
	// copyAt — где обязана найтись копия (подстрока «таблица.колонка»); пусто —
	// вне дома метки нет.
	copyAt string
	// want — подстрока находки; пусто — гейт обязан смолчать (законный близнец).
	want string
}

func lmInjections() []lmInjection {
	return []lmInjection{
		// ── механизм: триггер на таблице секрета ──────────────────────────────
		{name: "триггер копирует строку целиком в журнал ресурсов", before: `
			CREATE FUNCTION kaname.lm_probe_copy_row() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
			  INSERT INTO kaname.resource_journal (resource_kind, resource_id, event_type, payload)
			  VALUES ('iam_user', NEW.user_id, 'UPDATED', to_jsonb(NEW));
			  RETURN NEW;
			END; $$;
			CREATE TRIGGER lm_probe_copy_row AFTER INSERT ON kaname.user_login_methods
			  FOR EACH ROW EXECUTE FUNCTION kaname.lm_probe_copy_row();`,
			copyAt: "resource_journal.payload", want: "lm_probe_copy_row"},
		{name: "триггер пишет материал в таблицу, заведённую после гейта", before: `
			CREATE TABLE kaname.lm_probe_sink (note text);
			CREATE FUNCTION kaname.lm_probe_sink_fn() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
			  INSERT INTO kaname.lm_probe_sink (note) VALUES ('copied: ' || NEW.verifier);
			  RETURN NEW;
			END; $$;
			CREATE TRIGGER lm_probe_sink_trg AFTER INSERT ON kaname.user_login_methods
			  FOR EACH ROW EXECUTE FUNCTION kaname.lm_probe_sink_fn();`,
			copyAt: "lm_probe_sink.note", want: "lm_probe_sink_trg"},
		{name: "триггер отправляет строку уведомлением мимо таблиц", before: `
			CREATE FUNCTION kaname.lm_probe_notify() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
			  PERFORM pg_notify('lm_probe_leak', to_jsonb(NEW)::text);
			  RETURN NEW;
			END; $$;
			CREATE TRIGGER lm_probe_notify AFTER INSERT ON kaname.user_login_methods
			  FOR EACH ROW EXECUTE FUNCTION kaname.lm_probe_notify();`,
			listen: "lm_probe_leak", want: "lm_probe_notify"},
		{name: "триггер пишет в журнал только идентификатор — правило о триггерах всё равно срабатывает", before: `
			CREATE FUNCTION kaname.lm_probe_id_only() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
			  INSERT INTO kaname.resource_journal (resource_kind, resource_id, event_type, payload)
			  VALUES ('iam_user', NEW.user_id, 'UPDATED', jsonb_build_object('id', NEW.user_id));
			  RETURN NEW;
			END; $$;
			CREATE TRIGGER lm_probe_id_only AFTER INSERT ON kaname.user_login_methods
			  FOR EACH ROW EXECUTE FUNCTION kaname.lm_probe_id_only();`,
			want: "lm_probe_id_only"},

		// ── механизм: правило перезаписи ──────────────────────────────────────
		{name: "правило на таблице секрета уносит материал уведомлением", before: `
			CREATE RULE lm_probe_rule AS ON INSERT TO kaname.user_login_methods
			  DO ALSO SELECT pg_notify('lm_probe_rule', NEW.verifier);`,
			listen: "lm_probe_rule", want: "lm_probe_rule"},
		{name: "правило на таблице секрета без материала — правило о правилах всё равно срабатывает", before: `
			CREATE RULE lm_probe_rule_plain AS ON INSERT TO kaname.user_login_methods DO ALSO NOTIFY lm_probe_rule_plain;`,
			want: "lm_probe_rule_plain"},
		{name: "законный близнец: правило на соседней таблице таблицы секрета не касается", before: `
			CREATE RULE lm_probe_neighbour_rule AS ON UPDATE TO kaname.users DO ALSO NOTIFY lm_probe_neighbour_rule;`,
			after: `UPDATE kaname.users SET display_name = display_name`},

		// ── механизм: подпрограмма, читающая таблицу секрета ──────────────────
		{name: "триггер на СОСЕДНЕЙ таблице читает материал и отправляет его", before: `
			CREATE FUNCTION kaname.lm_probe_neighbour_reads() RETURNS trigger LANGUAGE plpgsql AS $$
			DECLARE v text;
			BEGIN
			  SELECT verifier INTO v FROM kaname.user_login_methods WHERE user_id = NEW.id LIMIT 1;
			  PERFORM pg_notify('lm_probe_neighbour', coalesce(v, ''));
			  RETURN NEW;
			END; $$;
			CREATE TRIGGER lm_probe_neighbour_reads AFTER UPDATE ON kaname.users
			  FOR EACH ROW EXECUTE FUNCTION kaname.lm_probe_neighbour_reads();`,
			after:  `UPDATE kaname.users SET display_name = display_name WHERE id IN (SELECT user_id FROM kaname.user_login_methods)`,
			listen: "lm_probe_neighbour", want: "lm_probe_neighbour_reads"},
		{name: "законный близнец: триггер соседа читает соседа, таблица секрета названа только в комментарии", before: `
			CREATE FUNCTION kaname.lm_probe_neighbour_own() RETURNS trigger LANGUAGE plpgsql AS $$
			DECLARE v text;
			BEGIN
			  -- user_login_methods здесь не читается: только собственный адрес
			  /* и в блочном комментарии тоже: kaname.user_login_methods */
			  SELECT email INTO v FROM kaname.users WHERE id = NEW.id;
			  PERFORM pg_notify('lm_probe_neighbour_own', coalesce(v, ''));
			  RETURN NEW;
			END; $$;
			CREATE TRIGGER lm_probe_neighbour_own AFTER UPDATE ON kaname.users
			  FOR EACH ROW EXECUTE FUNCTION kaname.lm_probe_neighbour_own();`,
			after: `UPDATE kaname.users SET display_name = display_name`},
		{name: "событийный триггер читает материал при любом DDL", before: `
			CREATE FUNCTION kaname.lm_probe_evt() RETURNS event_trigger LANGUAGE plpgsql AS $$
			BEGIN
			  PERFORM pg_notify('lm_probe_evt', coalesce((SELECT string_agg(verifier, ',') FROM kaname.user_login_methods), ''));
			END; $$;
			CREATE EVENT TRIGGER lm_probe_evt ON ddl_command_end EXECUTE FUNCTION kaname.lm_probe_evt();`,
			after:  `CREATE TABLE kaname.lm_probe_ddl (x int)`,
			listen: "lm_probe_evt", want: "lm_probe_evt"},
		{name: "функция со стандартным телом SQL читает материал", before: `
			CREATE FUNCTION kaname.lm_probe_sqlfn(u text) RETURNS text LANGUAGE sql
			BEGIN ATOMIC
			  SELECT verifier FROM kaname.user_login_methods WHERE user_id = u;
			END;`,
			want: "lm_probe_sqlfn"},

		// ── механизм: политика строк, ограничение, домен ──────────────────────
		// Суперпользователь обходит политики строк всегда, а роль пробы — он.
		// Поэтому внесённый факт исполняет ПИСАТЕЛЬ без этого права: иначе
		// политика не исполнилась бы, и сцена была бы беспредметна.
		{name: "политика строк зовёт функцию с материалом", before: lmLeakFunction + `
			DO $$ BEGIN
			  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lm_probe_writer') THEN
			    CREATE ROLE lm_probe_writer NOLOGIN;
			  END IF;
			END $$;
			GRANT USAGE ON SCHEMA kaname TO lm_probe_writer;
			GRANT SELECT, UPDATE ON kaname.user_login_methods TO lm_probe_writer;
			ALTER TABLE kaname.user_login_methods ENABLE ROW LEVEL SECURITY;
			ALTER TABLE kaname.user_login_methods FORCE ROW LEVEL SECURITY;
			CREATE POLICY lm_probe_policy ON kaname.user_login_methods
			  USING (true) WITH CHECK (kaname.lm_probe_leak(verifier));`,
			after: `SET ROLE lm_probe_writer;
			  UPDATE kaname.user_login_methods SET verifier = verifier;
			  RESET ROLE`,
			listen: "lm_probe_leak_fn", want: "lm_probe_policy"},
		{name: "политика строк без материала — правило политик всё равно срабатывает", before: `
			CREATE POLICY lm_probe_policy_plain ON kaname.user_login_methods USING (true) WITH CHECK (true);`,
			want: "lm_probe_policy_plain"},
		{name: "ограничение сверх объявленных, материала не касающееся", before: `
			ALTER TABLE kaname.user_login_methods ADD CONSTRAINT lm_probe_kind_check CHECK (kind <> 'lm-probe');`,
			want: "lm_probe_kind_check"},
		{name: "ограничение проверки зовёт функцию с материалом", before: lmLeakFunction + `
			ALTER TABLE kaname.user_login_methods ADD CONSTRAINT lm_probe_check CHECK (kaname.lm_probe_leak(verifier));`,
			listen: "lm_probe_leak_fn", want: "lm_probe_check"},
		{name: "домен колонки материала зовёт функцию со значением", before: lmLeakFunction + `
			CREATE DOMAIN kaname.lm_probe_domain AS text CHECK (kaname.lm_probe_leak(VALUE));
			ALTER TABLE kaname.user_login_methods ALTER COLUMN verifier TYPE kaname.lm_probe_domain;`,
			listen: "lm_probe_leak_fn", want: "lm_probe_domain"},

		// ── механизм: публикация логической репликации ────────────────────────
		{name: "публикация отдаёт таблицу секрета подписчику", before: `
			CREATE PUBLICATION lm_probe_pub FOR TABLE kaname.user_login_methods;`,
			want: "lm_probe_pub"},
		{name: "публикация всей схемы захватывает таблицу секрета", before: `
			CREATE PUBLICATION lm_probe_pub_schema FOR TABLES IN SCHEMA kaname;`,
			want: "lm_probe_pub_schema"},
		{name: "законный близнец: публикация соседней таблицы", before: `
			CREATE PUBLICATION lm_probe_pub_users FOR TABLE kaname.users;`},

		// ── вид отношения: представления ──────────────────────────────────────
		{name: "материализованное представление с материалом, обновлённое после записи", before: `
			CREATE MATERIALIZED VIEW kaname.lm_probe_mv AS SELECT user_id, verifier FROM kaname.user_login_methods;`,
			after:  `REFRESH MATERIALIZED VIEW kaname.lm_probe_mv`,
			copyAt: "lm_probe_mv.verifier", want: "lm_probe_mv"},
		{name: "материализованное представление с материалом, ещё пустое", before: `
			CREATE MATERIALIZED VIEW kaname.lm_probe_mv_empty AS SELECT user_id, verifier FROM kaname.user_login_methods;`,
			want: "lm_probe_mv_empty"},
		{name: "законный близнец: материализованное представление без материала", before: `
			CREATE MATERIALIZED VIEW kaname.lm_probe_mv_ids AS SELECT user_id, kind FROM kaname.user_login_methods;`,
			after: `REFRESH MATERIALIZED VIEW kaname.lm_probe_mv_ids`},
		{name: "представление отдаёт материал", before: `
			CREATE VIEW kaname.lm_probe_v AS SELECT * FROM kaname.user_login_methods;`,
			copyAt: "lm_probe_v.verifier", want: "lm_probe_v"},
		{name: "законный близнец: представление без материала", before: `
			CREATE VIEW kaname.lm_probe_v_ids AS SELECT user_id, kind FROM kaname.user_login_methods;`},

		// ── вид отношения: таблицы и формы колонки ────────────────────────────
		{name: "копия запросом CREATE TABLE AS после записи", after: `
			CREATE TABLE kaname.lm_probe_ctas AS SELECT user_id, verifier FROM kaname.user_login_methods`,
			copyAt: "lm_probe_ctas.verifier", want: "lm_probe_ctas"},
		{name: "копия в таблице ДРУГОЙ схемы", after: `
			CREATE SCHEMA lm_probe_other;
			CREATE TABLE lm_probe_other.copy AS SELECT verifier FROM kaname.user_login_methods`,
			copyAt: "lm_probe_other.copy.verifier", want: "lm_probe_other.copy"},
		{name: "копия в секционированной таблице", after: `
			CREATE TABLE kaname.lm_probe_parted (user_id text, verifier text) PARTITION BY LIST (user_id);
			CREATE TABLE kaname.lm_probe_parted_all PARTITION OF kaname.lm_probe_parted DEFAULT;
			INSERT INTO kaname.lm_probe_parted SELECT user_id, verifier FROM kaname.user_login_methods`,
			copyAt: "lm_probe_parted.verifier", want: "lm_probe_parted_all.verifier"},
		{name: "колонка типа строки таблицы секрета, ещё пустая", before: `
			CREATE TABLE kaname.lm_probe_rows_empty (r kaname.user_login_methods);`,
			want: "lm_probe_rows_empty"},
		{name: "копия в колонке составного типа строки таблицы секрета", before: `
			CREATE TABLE kaname.lm_probe_rows (r kaname.user_login_methods);`,
			after:  `INSERT INTO kaname.lm_probe_rows SELECT m FROM kaname.user_login_methods m`,
			copyAt: "lm_probe_rows.r", want: "lm_probe_rows"},
		{name: "копия в массиве двоичных значений", after: `
			CREATE TABLE kaname.lm_probe_bytes AS
			  SELECT ARRAY[convert_to(verifier, 'UTF8')] AS b FROM kaname.user_login_methods`,
			copyAt: "lm_probe_bytes.b", want: "lm_probe_bytes"},
		{name: "порождённая колонка несёт материал", before: `
			ALTER TABLE kaname.user_login_methods ADD COLUMN lm_probe_gen text GENERATED ALWAYS AS ('copy:' || verifier) STORED;`,
			copyAt: "user_login_methods.lm_probe_gen", want: "lm_probe_gen"},

		// ── вид отношения: индекс и статистика ────────────────────────────────
		// Индекс копирует колонку в свои страницы; уникальный вдобавок кладёт
		// значение нарушенного ключа в DETAIL каждого отказа. Правило одно —
		// зависимость от колонки материала, — и сцена берёт неуникальный: метку
		// гейт пишет двоим, и уникальный отверг бы саму запись.
		{name: "индекс по материалу — копия колонки в индексе", before: `
			CREATE INDEX lm_probe_idx ON kaname.user_login_methods (verifier);`,
			want: "lm_probe_idx"},
		{name: "законный близнец: индекс по владельцу", before: `
			CREATE INDEX lm_probe_idx_user ON kaname.user_login_methods (user_id);`},
		{name: "расширенная статистика по материалу", before: `
			CREATE STATISTICS lm_probe_stx (mcv) ON kind, verifier FROM kaname.user_login_methods;`,
			want: "lm_probe_stx"},
		{name: "статистика планировщика собирает выборку материала", before: `
			ALTER TABLE kaname.user_login_methods ALTER COLUMN verifier SET STATISTICS -1;`,
			want: "pg_statistic"},
	}
}

// lmReadsThrough — триггер СОСЕДНЕЙ таблицы читает материал оператором read,
// где таблица записана испытуемым написанием, и отправляет прочитанное
// уведомлением в канал fn.
//
// Что написание называет — решает БАЗА, а не чтение текста: слушатель получает
// метку, только если база разрешила написание в таблицу секрета. У законного
// близнеца (other — отношение-двойник, которое заводится сценой) слушатель
// получает пустое значение: база разрешила написание в ДРУГОЕ отношение, и
// находка гейта там была бы ложной.
func lmReadsThrough(name, fn, other, read string) lmInjection {
	sc := lmInjection{
		name: name,
		before: other + `
			CREATE FUNCTION kaname.` + fn + `() RETURNS trigger LANGUAGE plpgsql AS $body$
			DECLARE v text;
			BEGIN
			  ` + read + `
			  PERFORM pg_notify('` + fn + `', coalesce(v, ''));
			  RETURN NEW;
			END; $body$;
			CREATE TRIGGER ` + fn + ` AFTER UPDATE ON kaname.users
			  FOR EACH ROW EXECUTE FUNCTION kaname.` + fn + `();`,
		after: `UPDATE kaname.users SET display_name = display_name WHERE id IN (SELECT user_id FROM kaname.user_login_methods)`,
	}
	if other == "" {
		sc.listen, sc.want = fn, fn
	} else {
		sc.quietListen = fn
	}
	return sc
}

// lmSpellingInjections — таблица секрета в тексте подпрограммы: по сцене на
// каждое написание имени, выведенное из грамматики (см. шапку), и законные
// близнецы по каждой различающей оси.
func lmSpellingInjections() []lmInjection {
	const w = ` WHERE user_id = NEW.id LIMIT 1;`
	const dw = ` WHERE user_id = $1 LIMIT 1`
	return []lmInjection{
		// ── имя вне строки ────────────────────────────────────────────────────
		lmReadsThrough("имя без кавычек в верхнем регистре со схемой", "lm_sp_upper", "",
			`SELECT verifier INTO v FROM KANAME.USER_LOGIN_METHODS`+w),
		lmReadsThrough("имя без кавычек в смешанном регистре без схемы (путь поиска)", "lm_sp_mixed", "",
			`SELECT verifier INTO v FROM User_Login_Methods`+w),
		lmReadsThrough("имя в кавычках точно, схема в кавычках", "lm_sp_quoted", "",
			`SELECT verifier INTO v FROM "kaname"."user_login_methods"`+w),
		lmReadsThrough("ONLY и псевдоним, верхний регистр", "lm_sp_only", "",
			`SELECT m.verifier INTO v FROM ONLY KANAME.USER_LOGIN_METHODS AS m WHERE m.user_id = NEW.id LIMIT 1;`),
		lmReadsThrough("имя U&\"…\" с экранированием Юникода", "lm_sp_uident", "",
			`SELECT verifier INTO v FROM kaname.U&"user\005flogin_methods"`+w),
		lmReadsThrough("имя U&\"…\" со своим знаком экранирования UESCAPE", "lm_sp_uescape", "",
			`SELECT verifier INTO v FROM kaname.U&"user!005flogin_methods" UESCAPE '!'`+w),
		// ── имя внутри строки: динамический SQL и разбор имени ────────────────
		lmReadsThrough("EXECUTE строки с именем в верхнем регистре", "lm_sp_exec", "",
			`EXECUTE 'SELECT verifier FROM KANAME.USER_LOGIN_METHODS`+dw+`' INTO v USING NEW.id;`),
		lmReadsThrough("EXECUTE E-строки с экранированием в имени", "lm_sp_estr", "",
			`EXECUTE E'SELECT verifier FROM kaname.user\x5flogin_methods`+dw+`' INTO v USING NEW.id;`),
		lmReadsThrough("EXECUTE строки, продолженной через перевод строки", "lm_sp_cont", "",
			"EXECUTE 'SELECT verifier FROM kaname.user_login_'\n\t\t\t  'methods"+dw+"' INTO v USING NEW.id;"),
		lmReadsThrough("EXECUTE строк, склеенных оператором ||", "lm_sp_concat", "",
			`EXECUTE 'SELECT verifier FROM kaname.user_login_' || 'methods`+dw+`' INTO v USING NEW.id;`),
		lmReadsThrough("EXECUTE строки в долларах с именем в верхнем регистре", "lm_sp_dollar", "",
			`EXECUTE $q$SELECT verifier FROM KANAME.USER_LOGIN_METHODS`+dw+`$q$ INTO v USING NEW.id;`),
		lmReadsThrough("приведение строки с именем в верхнем регистре к regclass", "lm_sp_regclass", "",
			`EXECUTE format('SELECT verifier FROM %s`+dw+`', 'KANAME.USER_LOGIN_METHODS'::regclass) INTO v USING NEW.id;`),
		lmReadsThrough("приведение строки U&'…' к regclass", "lm_sp_ustr", "",
			`EXECUTE format('SELECT verifier FROM %s`+dw+`', U&'kaname.user\005flogin_methods'::regclass) INTO v USING NEW.id;`),
		lmReadsThrough("format с именем аргументом %I", "lm_sp_format", "",
			`EXECUTE format('SELECT verifier FROM %I.%I`+dw+`', 'kaname', 'user_login_methods') INTO v USING NEW.id;`),
		// ── законные близнецы: написание называет ДРУГОЕ отношение ─────────────
		lmReadsThrough("законный близнец: имя в кавычках в верхнем регистре — другое отношение", "lm_tw_quoted",
			`CREATE TABLE kaname."USER_LOGIN_METHODS" (user_id text, verifier text);`,
			`SELECT verifier INTO v FROM kaname."USER_LOGIN_METHODS"`+w),
		lmReadsThrough("законный близнец: имя в кавычках внутри строки regclass — другое отношение", "lm_tw_regclass",
			`CREATE TABLE kaname."USER_LOGIN_METHODS" (user_id text, verifier text);`,
			`EXECUTE format('SELECT verifier FROM %s`+dw+`', '"kaname"."USER_LOGIN_METHODS"'::regclass) INTO v USING NEW.id;`),
		lmReadsThrough("законный близнец: зеркало с общей частью имени", "lm_tw_mirror",
			`CREATE TABLE kaname.w6_user_login_methods_mirror (user_id text, verifier text);`,
			`SELECT verifier INTO v FROM kaname.w6_user_login_methods_mirror`+w),
		lmReadsThrough("законный близнец: имя, продолженное знаком доллара", "lm_tw_dollar",
			`CREATE TABLE kaname.user_login_methods$x (user_id text, verifier text);`,
			`SELECT verifier INTO v FROM kaname.user_login_methods$x`+w),
		lmReadsThrough("законный близнец: имя, продолженное буквой вне ASCII", "lm_tw_nonascii",
			`CREATE TABLE kaname.user_login_methodsé (user_id text, verifier text);`,
			`SELECT verifier INTO v FROM kaname.user_login_methodsé`+w),
		lmReadsThrough("законный близнец: имя таблицы в комментарии внутри строки EXECUTE", "lm_tw_comment",
			`CREATE TABLE kaname.lm_probe_twin (user_id text, verifier text);`,
			`EXECUTE 'SELECT verifier FROM kaname.lm_probe_twin /* не user_login_methods */`+dw+`' INTO v USING NEW.id;`),
	}
}

// TestLoginVerifierContainmentGateInjection — способность упасть и смолчать.
//
// Каждая сцена — своя база и отличается от чистой ОДНИМ внесённым фактом. Сцена
// с каналом доказывает, что утечка НАСТОЯЩАЯ: слушатель получил материал.
func TestLoginVerifierContainmentGateInjection(t *testing.T) {
	for i, sc := range append(lmInjections(), lmSpellingInjections()...) {
		t.Run(sc.name, func(t *testing.T) {
			pool := lmPool(t)
			ctx := context.Background()
			if sc.before != "" {
				_, err := pool.Exec(ctx, sc.before)
				require.NoError(t, err, "внесённый факт не создан — сцена беспредметна")
			}
			var listener *pgxpool.Conn
			if channel := sc.listen + sc.quietListen; channel != "" {
				var err error
				listener, err = pool.Acquire(ctx)
				require.NoError(t, err)
				defer listener.Release()
				_, err = listener.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize())
				require.NoError(t, err)
			}
			lmWriteSentinel(t, pool, fmt.Sprintf("lminj%d", i))
			if sc.after != "" {
				_, err := pool.Exec(ctx, sc.after)
				require.NoError(t, err, "действие после записи не исполнилось — сцена беспредметна")
			}
			if listener != nil {
				wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				n, err := listener.Conn().WaitForNotification(wctx)
				require.NoError(t, err, "уведомление не пришло — внесённый факт не сработал, сцена беспредметна")
				if sc.quietListen != "" {
					require.NotContains(t, n.Payload, lmSentinel,
						"близнец прочёл материал — написание называет таблицу секрета, и близнецом сцена не является")
				} else {
					require.Contains(t, n.Payload, lmSentinel, "слушатель получил материал: утечка настоящая")
				}
			}

			c := lmScanContainment(t, pool, lmSentinel)
			t.Log(c.Census())
			lmRequireCensus(t, c)

			findings := strings.Join(c.Findings(), "\n")
			t.Logf("находки:\n%s", findings)
			if sc.copyAt != "" {
				found := false
				for where := range c.Hits {
					found = found || strings.Contains(where, sc.copyAt)
				}
				require.True(t, found, "копия %s не найдена — перепись слепа к этому месту (%v)", sc.copyAt, c.Hits)
			} else {
				for where := range c.Hits {
					require.Equal(t, lmSecretHome, where, "вне дома метки быть не должно")
				}
			}
			if sc.want == "" {
				require.Empty(t, c.Findings(), "законный близнец: гейт обязан смолчать")
				return
			}
			require.Contains(t, findings, sc.want, "находка обязана называть внесённое по имени")
		})
	}
}
