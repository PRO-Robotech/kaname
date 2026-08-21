// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// set_atomicity_integration_test.go — ФОРМА СТРОКИ журнала: что именно несёт одна
// строка и как база её достраивает.
//
// ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ, И ПОЧЕМУ ИМЕННО НА СТРОКЕ. Единица, которой едет выдача, —
// весь набор отношений одного субъекта на одном объекте. Это свойство РЯДА, и доказать
// его можно только настоящей вставкой: в ней участвуют триггеры и ограничения таблицы,
// а не то, что автор эмиттера имел в виду.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ОТСЮДА УШЛО ВМЕСТЕ СО СНЯТИЕМ ВНЕШНЕГО ДВИЖКА — и куда переехал предмет
//
// Здесь стояла пара проб «набор никогда не наблюдается наполовину»: они прогоняли
// строки декодером и применителем дренажа и смотрели на ЧУЖОЕ хранилище после каждого
// применения. Ни декодера, ни применителя, ни дренажа больше нет, и окна, в котором
// подмножество было бы видно, тоже нет: строка журнала попадает в ту же транзакцию,
// что и изменение, а прямой факт складывает ТРИГГЕР
// (`kacho_iam.relation_fact_from_journal`) — то есть доставка стала тождеством коммита.
//
// Живой преемник того предмета — «набор проецируется ЦЕЛИКОМ, а не одним эхом» — уже
// утверждается там, где живёт его потребитель:
// `relverdict/journal_projection_integration_test.go`
// (`TestFactProjection_SetProjectsEveryRelationNotOnlyTheEcho` и соседи). Второй раз
// он здесь не пересказывается: два места об одном предмете расходятся молча.
//
// Осталось то, чей предмет — сама таблица и её строка.
//
// Skipped under `go test -short` (needs Docker).
package fga_outbox_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/fga_outbox"
)

// TestOutboxPartitionKeyCoversTheWholeGrantSet — ключ строки рендерит БАЗА, и рендерит
// его по паре (субъект, объект), а не по тройке.
//
// Ключ заполняет триггер `kacho_iam.fga_outbox_tuple_key()` (миграция 0099), а не
// пишущая сторона: второй рендер того же имени в коде разошёлся бы с этим молча.
// Полезная нагрузка, из которой ключ не собирается, отвергается на INSERT — то есть
// строка, которую нельзя спроецировать, в таблицу не попадает вовсе.
//
// Положительный контроль — вторая половина: два РАЗНЫХ субъекта на одном объекте
// обязаны получить РАЗНЫЕ ключи. Без него проба зеленела бы и на вырожденном ключе
// (одно значение на всю таблицу), который «покрывает набор» тождественно.
func TestOutboxPartitionKeyCoversTheWholeGrantSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	const (
		alice  = "user:usr_partition_alice"
		bob    = "user:usr_partition_bob"
		object = "vpc_address:vaddr_partition"
	)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, []clients.RelationTuple{
		{User: alice, Relation: "v_get", Object: object},
		{User: alice, Relation: "v_update", Object: object},
	}))
	// Отзыв набора alice — другая форма строки, ключ обязан быть тот же.
	require.NoError(t, fga_outbox.EmitDeleteTx(ctx, tx, []clients.RelationTuple{
		{User: alice, Relation: "v_get", Object: object},
	}))
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, []clients.RelationTuple{
		{User: bob, Relation: "v_get", Object: object},
	}))
	require.NoError(t, tx.Commit(ctx))

	keys := map[string][]string{} // ключ → субъекты, которых он несёт
	rows, err := pool.Query(ctx, `
		SELECT `+fga_outbox.PartitionColumn+`, payload->>'user'
		  FROM kacho_iam.fga_outbox
		 WHERE payload->>'object' = $1
		 ORDER BY id ASC`, object)
	require.NoError(t, err)
	for rows.Next() {
		var key, user string
		require.NoError(t, rows.Scan(&key, &user))
		keys[key] = append(keys[key], user)
	}
	rows.Close()
	require.NoError(t, rows.Err())

	require.Len(t, keys, 2, "один ключ на пару (субъект, объект), получено %v", keys)
	for key, subjects := range keys {
		for _, s := range subjects {
			require.Equal(t, subjects[0], s,
				fmt.Sprintf("ключ %q обязан нести ровно одного субъекта, получено %v", key, subjects))
		}
	}
}

// TestSetRowCarriesTheEchoOnlyForGrants — асимметрия эха, закреплённая на СТРОКЕ.
//
// Строка ВЫДАЧИ набора несёт оба поля: `relations` (весь набор) и `relation`
// (совместимое эхо — первый элемент). Строка ОТЗЫВА набора несёт только `relations`.
//
// Почему это не косметика и почему проверяется именно строка. Проекция журнала
// (`relation_fact_from_journal`, миграция 0100) читает набор ПЕРВЫМ и скаляр — только
// когда набора нет. Порядок обратным быть не может ровно из-за этой асимметрии: на
// выдаче присутствуют оба поля, и читатель, взявший скаляр, забрал бы ОДНО отношение
// из нескольких и молча потерял остальные. А отзыв набора скаляра не несёт вовсе,
// поэтому читатель, ключующийся на скаляре, не может снять одно отношение набора и
// объявить отзыв исполненным — он такую строку не разберёт совсем.
//
// Утверждение сделано на том, что видит любой читатель строки, а не на том, что
// вернула бы одна конкретная его реализация.
func TestSetRowCarriesTheEchoOnlyForGrants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pg.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	const (
		subject = "user:usr_echo"
		object  = "vpc_address:vaddr_echo"
	)
	set := []clients.RelationTuple{
		{User: subject, Relation: "v_get", Object: object},
		{User: subject, Relation: "v_update", Object: object},
	}

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, set))
	require.NoError(t, fga_outbox.EmitDeleteTx(ctx, tx, set))
	require.NoError(t, tx.Commit(ctx))

	rows, err := pool.Query(ctx, `
		SELECT event_type,
		       coalesce(payload->>'relation', ''),
		       jsonb_array_length(coalesce(payload->'relations', '[]'::jsonb))
		  FROM kacho_iam.fga_outbox
		 WHERE payload->>'object' = $1
		 ORDER BY id ASC`, object)
	require.NoError(t, err)
	type row struct {
		eventType string
		echo      string
		setSize   int
	}
	var got []row
	for rows.Next() {
		var r row
		require.NoError(t, rows.Scan(&r.eventType, &r.echo, &r.setSize))
		got = append(got, r)
	}
	rows.Close()
	require.NoError(t, rows.Err())

	require.Len(t, got, 2, "одна строка на направление")
	require.Equal(t, 2, got[0].setSize)
	require.Equal(t, "v_get", got[0].echo,
		"строка ВЫДАЧИ набора несёт эхо — и именно поэтому чтение набора обязано идти первым")
	require.Equal(t, 2, got[1].setSize)
	require.Empty(t, got[1].echo,
		"строка ОТЗЫВА набора эха НЕ несёт: читатель, ключующийся на скаляре, не вправе снять "+
			"одно отношение набора и счесть отзыв исполненным")
}
