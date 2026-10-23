// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// relation_fact_late_grant_integration_test.go — запоздалая запись после
// снятия того же кортежа права не восстанавливает (сценарий NTF3-184, задача
// https://github.com/PRO-Robotech/kaname/issues/636).
//
// # Предмет
//
// Прямой факт `kaname.relation_fact` складывает свёртка журнала намерений
// (`kaname.relation_fact_from_journal` → `kaname.relation_fact_fold_row`).
// Строка, упорядоченная ВЛАДЕЛЬЦЕМ (поле `source_version` полезной нагрузки),
// сравнивается с фактом по версии владельца: запись применяется, только если
// новее хранимой; снятие удаляет факт не новее своей версии. После снятия
// строки факта нет, и сравнивать запоздалую запись было не с чем: запись `t1`,
// пришедшая после снятия `t2 > t1`, ложилась заново — право возвращалось тому,
// у кого его сняли.
//
// Снятие оставляет след — надгробие `kaname.relation_fact_removal` с версией
// последнего применённого снятия кортежа; запись не новее надгробия факта не
// создаёт. След остаётся и тогда, когда снимать было нечего: снятие,
// доставленное раньше своей записи, отвергает и её.
//
// # Чего проба НЕ касается
//
// Строки без версии владельца (выведенные выдачей) упорядочены меткой журнала,
// и их порядок решён иначе: выдача, начавшая транзакцию раньше снятия и
// свёрнутая после него, ложится заново (kaname#919, kaname#923). Надгробие их
// не судит; законный близнец по другую сторону предмета —
// `TestEmitDeleteTx_GrantBegunBeforeTheRemovalOfAStandingFactSurvives` пакета
// `fga_outbox` (снятие СТОЯЩЕГО факта, а затем выдача, начатая раньше него).
//
// # Как построено
//
// Строки журнала кладутся прямо в `kaname.fga_outbox` той формой, какую кладёт
// путь публикации: кортеж и версия владельца. Отношение — глагол `v_get`:
// строку без версии владельца с глаголом свёртка не переносит вовсе, так что
// предмет здесь — только порядок по версии владельца.
//
// Пропускается под `go test -short`.
package internal_iam_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

const (
	lateGrantSubject  = "user:usr-O"
	lateGrantRelation = "v_get"
	lateGrantType     = "storage_volume"
)

// journalGrant кладёт строку журнала намерений о прямом кортеже с версией
// владельца `at`.
func journalGrant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, eventType, objectID string, at time.Time) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.fga_outbox (event_type, payload)
		VALUES ($1, jsonb_build_object('user', $2::text, 'relation', $3::text,
		                               'object', $4::text, 'source_version', $5::timestamptz))`,
		eventType, lateGrantSubject, lateGrantRelation, lateGrantType+":"+objectID, at)
	require.NoError(t, err, "строка журнала %s %s", eventType, at)
}

// grantFact — строка прямого факта кортежа и её версия.
func grantFact(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objectID string) (time.Time, bool) {
	t.Helper()
	var v time.Time
	err := pool.QueryRow(ctx, `
		SELECT source_version FROM kaname.relation_fact
		 WHERE object_type = $1 AND object_id = $2 AND relation = $3 AND subject = $4`,
		lateGrantType, objectID, lateGrantRelation, lateGrantSubject).Scan(&v)
	if err == pgx.ErrNoRows {
		return time.Time{}, false
	}
	require.NoError(t, err)
	return v, true
}

// removalRows — число строк надгробия кортежа.
func removalRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objectID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.relation_fact_removal
		 WHERE object_type = $1 AND object_id = $2 AND relation = $3 AND subject = $4`,
		lateGrantType, objectID, lateGrantRelation, lateGrantSubject).Scan(&n))
	return n
}

// TestRelationFact_NTF3_184_LateGrantNotNewerThanItsRemovalDoesNotRevive —
// запись `t1`, снятие `t2 > t1`, повторная запись с прежней версией `t1`:
// строки факта нет. Близнец по одному факту — повторная запись с версией
// `t3 > t2`: строка есть с версией `t3`. Равная версия записи снятия не
// уступает: на равных версиях порядок — порядок журнала.
func TestRelationFact_NTF3_184_LateGrantNotNewerThanItsRemovalDoesNotRevive(t *testing.T) {
	if testing.Short() {
		t.Skip("integration (Postgres)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	t1 := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Minute)
	t3 := t2.Add(time.Minute)

	var typ string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT data_type FROM information_schema.columns
		 WHERE table_schema = 'kaname' AND table_name = 'relation_fact' AND column_name = 'source_version'`).Scan(&typ))
	require.Equal(t, "timestamp with time zone", typ, "relation_fact.source_version не переводится в поколение")

	afterRemoval := func(t *testing.T, objectID string, lateAt time.Time) (time.Time, bool) {
		t.Helper()
		journalGrant(t, ctx, pool, "fga.tuple.write", objectID, t1)
		v, ok := grantFact(t, ctx, pool, objectID)
		require.True(t, ok, "положительный контроль: запись t1 даёт строку факта")
		require.True(t, v.Equal(t1), "версия факта после записи t1: %s", v)

		journalGrant(t, ctx, pool, "fga.tuple.delete", objectID, t2)
		_, ok = grantFact(t, ctx, pool, objectID)
		require.False(t, ok, "снятие t2 снимает строку факта")

		journalGrant(t, ctx, pool, "fga.tuple.write", objectID, lateAt)
		return grantFact(t, ctx, pool, objectID)
	}

	t.Run("запоздалая запись t1 после снятия t2", func(t *testing.T) {
		v, ok := afterRemoval(t, "vol-41late", t1)
		require.False(t, ok, "запись t1 не новее снятия t2 воскресила право (версия %s)", v)
	})
	t.Run("близнец: запись t3 новее снятия t2", func(t *testing.T) {
		v, ok := afterRemoval(t, "vol-41fresh", t3)
		require.True(t, ok, "запись t3 новее снятия t2 строки не дала")
		require.True(t, v.Equal(t3), "версия факта: %s, ожидается %s", v, t3)
		// Рост надгробий ограничен кортежами, снятыми и не выданными заново:
		// применённая запись снимает след своего кортежа.
		require.Zero(t, removalRows(t, ctx, pool, "vol-41fresh"),
			"применённая запись t3 не сняла надгробие своего кортежа")
	})
	t.Run("близнец: запись с версией снятия t2", func(t *testing.T) {
		v, ok := afterRemoval(t, "vol-41equal", t2)
		require.True(t, ok, "запись с версией, равной снятию, строки не дала: на равных версиях порядок — порядок журнала")
		require.True(t, v.Equal(t2), "версия факта: %s, ожидается %s", v, t2)
	})

	// Снятие, доставленное РАНЬШЕ своей записи: факта ещё нет, и след снятия
	// обязан остаться — иначе его запись `t1` ляжет следом.
	beforeGrant := func(t *testing.T, objectID string, lateAt time.Time) (time.Time, bool) {
		t.Helper()
		journalGrant(t, ctx, pool, "fga.tuple.delete", objectID, t2)
		_, ok := grantFact(t, ctx, pool, objectID)
		require.False(t, ok, "положительный контроль: снятие без факта факта не даёт")

		journalGrant(t, ctx, pool, "fga.tuple.write", objectID, lateAt)
		return grantFact(t, ctx, pool, objectID)
	}

	t.Run("снятие t2 раньше своей записи t1", func(t *testing.T) {
		v, ok := beforeGrant(t, "vol-42late", t1)
		require.False(t, ok, "запись t1, пришедшая после снятия t2 без факта, легла фактом (версия %s)", v)
	})
	t.Run("близнец: снятие t2 раньше записи t3", func(t *testing.T) {
		v, ok := beforeGrant(t, "vol-42fresh", t3)
		require.True(t, ok, "запись t3 новее снятия t2 строки не дала")
		require.True(t, v.Equal(t3), "версия факта: %s, ожидается %s", v, t3)
	})

	// Применённая запись новее снятия снимает его след: последующее снятие
	// поднимает надгробие заново, и запоздалая запись между ними отвергается.
	t.Run("второе снятие t4 после записи t3", func(t *testing.T) {
		const obj = "vol-43again"
		t4 := t3.Add(time.Minute)
		v, ok := afterRemoval(t, obj, t3)
		require.True(t, ok, "положительный контроль: запись t3 после снятия t2 дала строку (версия %s)", v)
		journalGrant(t, ctx, pool, "fga.tuple.delete", obj, t4)
		_, ok = grantFact(t, ctx, pool, obj)
		require.False(t, ok, "снятие t4 снимает строку факта")
		journalGrant(t, ctx, pool, "fga.tuple.write", obj, t3)
		v, ok = grantFact(t, ctx, pool, obj)
		require.False(t, ok, "запись t3 не новее снятия t4 воскресила право (версия %s)", v)
	})
}
