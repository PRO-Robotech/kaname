// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_verifier_stays_inside_integration_test.go — ГЕЙТ: проверочный материал
// способа входа лежит в схеме РОВНО В ОДНОМ месте (фаза Ф2, `kacho#1268`).
//
// # Предмет
//
// Материал пароля — хеш, созданный прежним поставщиком либо нашей функцией. Его
// копия в журнале ресурсов, в очереди аудита, в очереди кортежей прав либо в
// любой таблице, заведённой завтра, живёт своим сроком хранения и уезжает к
// своему читателю. Хеш не пароль, но перебор офлайн по нему возможен, и срок
// хранения копии становится сроком, в течение которого это возможно.
//
// # Что гейт судит — ИСХОД, а не объявление
//
// Первое правило — ПЕРЕПИСЬ СХЕМЫ ПОСЛЕ ЗАПИСИ. Материал с меткой пишется
// НАСТОЯЩИМ путём адаптера, после чего каждая текстовая, JSON и двоичная колонка
// КАЖДОЙ таблицы схемы спрашивается о метке. Перечень таблиц берётся у каталога
// базы, а не выписывается: таблица, заведённая завтра, попадает под перепись в
// день появления. Метка обязана найтись ровно в `user_login_methods.verifier` —
// это положительный контроль: без него «нигде нет» было бы верно и о переписи,
// не читающей ничего.
//
// Второе правило — ТРИГГЕРОВ НА ТАБЛИЦЕ СЕКРЕТА НЕТ, кроме порождённых ссылочной
// целостностью. Триггер — единственный механизм базы, исполняющийся в
// транзакции записи без ведома писателя и видящий строку ЦЕЛИКОМ. Правило
// строже первого намеренно, и причина измерена инъекцией (г): триггер,
// отправляющий строку уведомлением, ПЕРЕПИСЬ ТАБЛИЦ НЕ ВИДИТ — уведомление не
// лежит ни в одной таблице, а уезжает к слушателю. Первое правило этого
// различить не может by construction; второе — может.
//
// # Чего гейт НЕ судит
//
//   - журнал самого сервера базы: сообщение о нарушении ограничения проверки
//     несёт строку целиком в `DETAIL`, и сервер пишет его в свой журнал.
//     Достижимо только обходом доменной проверки — вид и материал судит тип до
//     вставки. Переводчик отказов службы `DETAIL` не читает (`pgmaperr.go`), и
//     это закреплено `pgmaperr_login_method_test.go`;
//   - путь кода Go до базы: его держит гейт дерева `internal/check`
//     `TestLoginVerifierStaysInside` (единственный выход материала — `Reveal`, и
//     его вызывающие перечислены).
//
// Способность упасть доказана инъекцией — `TestLoginVerifierContainmentGateInjection`.
package pg_test

import (
	"context"
	"fmt"
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
const lmSecretHome = "user_login_methods.verifier"

type lmContainment struct {
	// Где метка найдена: «таблица.колонка» → число строк.
	Hits map[string]int
	// Перепись схемы.
	BaseTables, ScannedTables, ScannedColumns int
	// Триггеры таблицы секрета.
	UserTriggers     []string
	InternalTriggers int
}

// Findings — нарушения обоих правил. Пустой перечень — вердикт, только если
// метка найдена в своём доме (см. HomeSeen).
func (c lmContainment) Findings() []string {
	var out []string
	for where, n := range c.Hits {
		if where != lmSecretHome {
			out = append(out, fmt.Sprintf("материал найден вне своего дома: %s (строк %d)", where, n))
		}
	}
	for _, tg := range c.UserTriggers {
		out = append(out, fmt.Sprintf("на таблице секрета стоит триггер %q — он видит строку целиком "+
			"и исполняется без ведома писателя", tg))
	}
	sort.Strings(out)
	return out
}

// HomeSeen — положительный контроль переписи.
func (c lmContainment) HomeSeen() bool { return c.Hits[lmSecretHome] > 0 }

func (c lmContainment) Census() string {
	return fmt.Sprintf("перепись: базовых таблиц схемы %d, осмотрено таблиц %d, колонок %d; "+
		"метка найдена в %d местах; триггеров таблицы секрета: пользовательских %d, ссылочной целостности %d",
		c.BaseTables, c.ScannedTables, c.ScannedColumns, len(c.Hits), len(c.UserTriggers), c.InternalTriggers)
}

// lmScanContainment спрашивает каталог схемы и каждую колонку.
func lmScanContainment(t *testing.T, pool *pgxpool.Pool, needle string) lmContainment {
	t.Helper()
	ctx := context.Background()
	c := lmContainment{Hits: map[string]int{}}

	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.tables
		 WHERE table_schema = 'kaname' AND table_type = 'BASE TABLE'`).Scan(&c.BaseTables))

	rows, err := pool.Query(ctx, `
		SELECT col.table_name, col.column_name, col.data_type
		  FROM information_schema.columns col
		  JOIN information_schema.tables tab
		    ON tab.table_schema = col.table_schema AND tab.table_name = col.table_name
		 WHERE col.table_schema = 'kaname' AND tab.table_type = 'BASE TABLE'
		   AND col.data_type IN ('text', 'character varying', 'character', 'jsonb', 'json', 'bytea', 'ARRAY')
		 ORDER BY col.table_name, col.column_name`)
	require.NoError(t, err)
	type column struct{ table, name, dtype string }
	var cols []column
	for rows.Next() {
		var col column
		require.NoError(t, rows.Scan(&col.table, &col.name, &col.dtype))
		cols = append(cols, col)
	}
	require.NoError(t, rows.Err())
	rows.Close()

	tables := map[string]bool{}
	for _, col := range cols {
		ident := pgx.Identifier{col.name}.Sanitize()
		expr := ident + "::text"
		if col.dtype == "bytea" {
			expr = "encode(" + ident + ", 'escape')"
		}
		q := fmt.Sprintf(`SELECT count(*) FROM %s WHERE position($1 in %s) > 0`,
			pgx.Identifier{"kaname", col.table}.Sanitize(), expr)
		var n int
		require.NoError(t, pool.QueryRow(ctx, q, needle).Scan(&n), "колонка %s.%s", col.table, col.name)
		if n > 0 {
			c.Hits[col.table+"."+col.name] = n
		}
		tables[col.table] = true
		c.ScannedColumns++
	}
	c.ScannedTables = len(tables)

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
	return c
}

// lmWriteSentinel пишет метку НАСТОЯЩИМ путём адаптера — предмет гейта есть то,
// что делает запись, а не то, что сделал бы сырой оператор.
func lmWriteSentinel(t *testing.T, pool *pgxpool.Pool, tag string) {
	t.Helper()
	people := lmPeople(t, pool, tag, 1)
	_, err := pg.NewLoginMethodRepo(pool).Create(context.Background(), domain.LoginMethod{
		UserID: people[0], Kind: domain.LoginMethodPassword, Verifier: lmVerifier(t, lmSentinel),
	})
	require.NoError(t, err)
}

// TestLoginVerifierStaysInsideTheSchema — гейт.
//
// Что делать, если он сработал, — исходов три, четвёртого нет:
//
//  1. копию снимают: писатель обязан класть идентификатор человека и вид
//     способа, а не строку;
//  2. триггер на таблице секрета нужен по существу → предмет требует РЕШЕНИЯ:
//     его функция не читает материал, и это доказывается инъекцией в этом
//     файле, после чего правило о триггерах сужается к конкретному имени —
//     приёмкой, а не комментарием;
//  3. копия нужна другому месту по существу (например, проверяющему П2) →
//     её место — не таблица, а память процесса на время проверки.
func TestLoginVerifierStaysInsideTheSchema(t *testing.T) {
	pool := lmPool(t)
	lmWriteSentinel(t, pool, "lmstay")

	c := lmScanContainment(t, pool, lmSentinel)
	t.Log(c.Census())

	require.NotZero(t, c.ScannedColumns, "колонок осмотрено ноль — вердикт беспредметен")
	require.True(t, c.HomeSeen(),
		"метка не найдена даже в своём доме %s — перепись не читает то, о чём судит", lmSecretHome)
	require.NotZero(t, c.InternalTriggers,
		"триггеров ссылочной целостности ноль — вопрос о триггерах не читает каталог, "+
			"и «пользовательских ноль» сказано ни о чём")
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
		{name: "уникальный индекс по материалу — копия в индексе и канал DETAIL", before: `
			CREATE UNIQUE INDEX lm_probe_idx ON kaname.user_login_methods (verifier);`,
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

// TestLoginVerifierContainmentGateInjection — способность упасть и смолчать.
//
// Каждая сцена — своя база и отличается от чистой ОДНИМ внесённым фактом. Сцена
// с каналом доказывает, что утечка НАСТОЯЩАЯ: слушатель получил материал.
func TestLoginVerifierContainmentGateInjection(t *testing.T) {
	for i, sc := range lmInjections() {
		t.Run(sc.name, func(t *testing.T) {
			pool := lmPool(t)
			ctx := context.Background()
			if sc.before != "" {
				_, err := pool.Exec(ctx, sc.before)
				require.NoError(t, err, "внесённый факт не создан — сцена беспредметна")
			}
			var listener *pgxpool.Conn
			if sc.listen != "" {
				var err error
				listener, err = pool.Acquire(ctx)
				require.NoError(t, err)
				defer listener.Release()
				_, err = listener.Exec(ctx, "LISTEN "+pgx.Identifier{sc.listen}.Sanitize())
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
				require.Contains(t, n.Payload, lmSentinel, "слушатель получил материал: утечка настоящая")
			}

			c := lmScanContainment(t, pool, lmSentinel)
			t.Log(c.Census())
			require.True(t, c.HomeSeen(), "положительный контроль: метка в своём доме")

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
					require.True(t, strings.HasSuffix(where, lmSecretHome),
						"вне дома метки быть не должно, а она найдена в %s", where)
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
