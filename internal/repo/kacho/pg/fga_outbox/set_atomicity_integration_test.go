// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/fga_outbox"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/iampgtest"
)

// Здесь стояла проба TestOutboxPartitionKeyCoversTheWholeGrantSet — она
// закрепляла КЛЮЧ УПОРЯДОЧИВАНИЯ строки: что его рендерит база триггером и что
// рендерит по паре (субъект, объект).
//
// Она снята вместе со своим предметом (kacho#1033). Ключ существовал ради клейма
// дренажа «только голова партиции»; дренажа не стало вместе с внешним движком
// прав (стадия S6 эпика #747), а колонку сняла миграция 20260822160000. Писатель
// ключа — триггер `fga_outbox_tuple_key_trigger` — пережил обоих и после снятия
// колонки отвергал каждую вставку в журнал; он снят миграцией 20260823001000.
//
// Проба, пережившая свой предмет, — не «лишняя», а находка: она либо утверждает
// о механизме, которого нет, либо не может упасть. Здесь было первое.
//
// Что журнал по-прежнему ПРИНИМАЕТ строку тем же набором колонок, каким её
// вставляет EmitWriteTx, утверждает TestJournalAcceptsAWriteAfterEveryMigration
// в пакете pg; что ни один триггер схемы не называет полей, которых у строки
// нет, — TestTriggerBodyMatchesRowShape там же.

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
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
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
