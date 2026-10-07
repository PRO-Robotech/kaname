// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// relation_fact_late_grant_integration_test.go — запоздалая запись выдачи после
// её снятия права не восстанавливает (приёмка NTF-3, kacho#2918, сценарий
// NTF3-184; Р30 «Поколение и проекция», §1.15, редакция 39; Д134 B2).
//
// # Предмет и чего он НЕ касается
//
// Перевод в поколение `bigint` сужен до зеркала, рёбер предков и головы
// объекта. `relation_fact.source_version` остаётся `timestamptz` и держит свой
// порядок записи и снятия — страж от воскрешения снятого права: запись
// применяется, только если новее хранимой; снятие удаляет строку не новее
// своей. Держит его триггер журнала `kaname.relation_fact_from_journal`
// (миграция `20260916020000_…`), который этой под-фазой НЕ правится — проба его
// только пробует. Поэтому на дереве до реализации она обязана быть зелёной:
// это замок существующего свойства, а не красный, открывающий реализацию.
//
// # Как построено
//
// Строки журнала намерений кладутся прямо в `kaname.fga_outbox` той формой,
// какую кладёт упорядоченный владельцем путь: кортеж и версия владельца
// `source_version` в полезной нагрузке. Почему версия владельца, а не время
// строки журнала: отношение-глагол (`v_*`) без версии владельца триггер не
// переносит вовсе (его выводит выдача) — с временем строки ни запись, ни
// близнец не дали бы строки, и проба не различала бы ничего. Это расхождение
// с буквой «Дано» вынесено вопросом к приёмке.
//
// Вопрос об аудитории (последняя часть «Тогда») — предмет полосы ограды, не
// этой; здесь наблюдается прямой факт, из которого вопрос строит ответ.
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

// grantFact — строка прямого факта выдачи и её версия.
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

// TestRelationFact_NTF3_184_LateGrantNotNewerThanItsRemovalDoesNotRevive —
// запись `t1`, снятие `t2 > t1`, повторная запись с прежней версией `t1`:
// строки факта нет. Близнец по одному факту — повторная запись с версией
// `t3 > t2`: строка есть с версией `t3`. Тип версии факта — `timestamptz`.
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

	run := func(t *testing.T, objectID string, lateAt time.Time) (time.Time, bool) {
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
		v, ok := run(t, "vol-41late", t1)
		require.False(t, ok, "запись t1 не новее снятия t2 воскресила право (версия %s)", v)
	})
	t.Run("близнец: запись t3 новее снятия t2", func(t *testing.T) {
		v, ok := run(t, "vol-41fresh", t3)
		require.True(t, ok, "запись t3 новее снятия t2 строки не дала")
		require.True(t, v.Equal(t3), "версия факта: %s, ожидается %s", v, t3)
	})
}
