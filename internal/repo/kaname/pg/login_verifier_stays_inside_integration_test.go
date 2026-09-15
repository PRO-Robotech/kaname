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

// TestLoginVerifierContainmentGateInjection — способность упасть и смолчать.
//
// Каждая сцена — своя база, и отличается от чистой ОДНИМ фактом: внесённым
// триггером.
func TestLoginVerifierContainmentGateInjection(t *testing.T) {
	type scene struct {
		name string
		// Внесённый факт.
		setup string
		// Что обязано найтись; пусто — перепись таблиц обязана смолчать.
		wantHit string
		// Обязано ли сработать правило о триггерах.
		wantTrigger bool
	}
	scenes := []scene{
		{
			name: "а) журнал ресурсов получает строку целиком",
			setup: `
				CREATE FUNCTION kaname.lm_probe_copy_row() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN
				  INSERT INTO kaname.resource_journal (resource_kind, resource_id, event_type, payload)
				  VALUES ('iam_user', NEW.user_id, 'UPDATED', to_jsonb(NEW));
				  RETURN NEW;
				END; $$;
				CREATE TRIGGER lm_probe_copy_row AFTER INSERT ON kaname.user_login_methods
				  FOR EACH ROW EXECUTE FUNCTION kaname.lm_probe_copy_row();`,
			wantHit:     "resource_journal.payload",
			wantTrigger: true,
		},
		{
			name: "б) таблица, заведённая после гейта, получает материал",
			setup: `
				CREATE TABLE kaname.lm_probe_sink (note text);
				CREATE FUNCTION kaname.lm_probe_sink_fn() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN
				  INSERT INTO kaname.lm_probe_sink (note) VALUES ('copied: ' || NEW.verifier);
				  RETURN NEW;
				END; $$;
				CREATE TRIGGER lm_probe_sink_trg AFTER INSERT ON kaname.user_login_methods
				  FOR EACH ROW EXECUTE FUNCTION kaname.lm_probe_sink_fn();`,
			wantHit:     "lm_probe_sink.note",
			wantTrigger: true,
		},
		{
			name: "в) законный близнец: журнал получает только идентификатор",
			setup: `
				CREATE FUNCTION kaname.lm_probe_id_only() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN
				  INSERT INTO kaname.resource_journal (resource_kind, resource_id, event_type, payload)
				  VALUES ('iam_user', NEW.user_id, 'UPDATED', jsonb_build_object('id', NEW.user_id));
				  RETURN NEW;
				END; $$;
				CREATE TRIGGER lm_probe_id_only AFTER INSERT ON kaname.user_login_methods
				  FOR EACH ROW EXECUTE FUNCTION kaname.lm_probe_id_only();`,
			wantHit:     "",
			wantTrigger: true,
		},
	}
	for i, sc := range scenes {
		t.Run(sc.name, func(t *testing.T) {
			pool := lmPool(t)
			_, err := pool.Exec(context.Background(), sc.setup)
			require.NoError(t, err, "внесённый факт не создан — сцена беспредметна")
			lmWriteSentinel(t, pool, fmt.Sprintf("lminj%d", i))

			c := lmScanContainment(t, pool, lmSentinel)
			t.Log(c.Census())
			require.True(t, c.HomeSeen(), "положительный контроль: метка в своём доме")

			findings := strings.Join(c.Findings(), "\n")
			if sc.wantHit != "" {
				require.Contains(t, c.Hits, sc.wantHit, "копия не найдена — перепись слепа к этому месту")
				require.Contains(t, findings, sc.wantHit, "находка обязана называть координату копии")
			} else {
				for where := range c.Hits {
					require.Equal(t, lmSecretHome, where,
						"законный близнец: вне дома метки нет, и перепись обязана смолчать")
				}
			}
			if sc.wantTrigger {
				require.NotEmpty(t, c.UserTriggers, "правило о триггерах обязано назвать внесённый триггер")
			}
		})
	}

	// г) Уведомление. Перепись таблиц его не видит — и это доказывается
	// СЛУШАТЕЛЕМ, получившим материал: утечка настоящая, а таблицы молчат.
	t.Run("г) уведомление уносит строку мимо таблиц", func(t *testing.T) {
		pool := lmPool(t)
		ctx := context.Background()
		_, err := pool.Exec(ctx, `
			CREATE FUNCTION kaname.lm_probe_notify() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
			  PERFORM pg_notify('lm_probe_leak', to_jsonb(NEW)::text);
			  RETURN NEW;
			END; $$;
			CREATE TRIGGER lm_probe_notify AFTER INSERT ON kaname.user_login_methods
			  FOR EACH ROW EXECUTE FUNCTION kaname.lm_probe_notify();`)
		require.NoError(t, err)

		listener, err := pool.Acquire(ctx)
		require.NoError(t, err)
		defer listener.Release()
		_, err = listener.Exec(ctx, `LISTEN lm_probe_leak`)
		require.NoError(t, err)

		lmWriteSentinel(t, pool, "lmnotify")

		wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		n, err := listener.Conn().WaitForNotification(wctx)
		require.NoError(t, err, "уведомление не пришло — внесённый факт не сработал, сцена беспредметна")
		require.Contains(t, n.Payload, lmSentinel, "слушатель получил материал: утечка настоящая")

		c := lmScanContainment(t, pool, lmSentinel)
		t.Log(c.Census())
		for where := range c.Hits {
			require.Equal(t, lmSecretHome, where, "перепись таблиц уведомления не видит — так и заявлено")
		}
		require.NotEmpty(t, c.UserTriggers,
			"правило о триггерах — единственное, что различает эту утечку, и оно обязано сработать")
	})
}
