// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// provider_compensation_retention_integration_test.go — уборка доставленных
// строк очереди компенсаций у внешнего провайдера на ЖИВОЙ базе (#2069).
//
// # Что здесь предмет
//
// Предикат SQL: `sent_at IS NOT NULL AND sent_at < now() − grace`. Дублёр
// повторил бы мою же посылку о том, что он означает, и зеленел бы на любой
// ошибке в нём — включая ту, ради которой уборка и заводится: снятие
// НЕдоставленной строки, то есть потерю намерения, которое не доехало.
//
// Часы — БАЗЫ: момент времени не входит в сигнатуру уборщика, предикат целиком
// в SQL. Спать при этом не приходится — уборщик зовётся методом, а не тикером.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/outbox"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// putCompensationRow кладёт строку очереди с заданной отметкой доставки.
// Оператором базы, а не через эмиссию: предмет — предикат уборки, а не путь
// записи.
//
// `sentOffset` отрицателен для уже доставленной строки; nil означает
// «не доставлена».
func putCompensationRow(
	t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	clientID string, sentOffset *time.Duration, attempts int,
) {
	t.Helper()
	payload := `{"client_id":"` + clientID + `","origin":"test","reason":"retention probe"}`
	var err error
	if sentOffset == nil {
		_, err = pool.Exec(ctx,
			`INSERT INTO kaname.provider_compensation_outbox
			        (event_type, payload, resource_kind, resource_id, attempt_count)
			 VALUES ('provider.oauth_client.delete', $1::jsonb, 'oauth_client', $2, $3)`,
			payload, clientID, attempts)
	} else {
		_, err = pool.Exec(ctx,
			`INSERT INTO kaname.provider_compensation_outbox
			        (event_type, payload, resource_kind, resource_id, attempt_count, sent_at)
			 VALUES ('provider.oauth_client.delete', $1::jsonb, 'oauth_client', $2, $3,
			         now() + make_interval(secs => $4))`,
			payload, clientID, attempts, sentOffset.Seconds())
	}
	require.NoError(t, err, "посев строки очереди компенсаций")
}

// compensationRowsLeft — идентификаторы оставшихся строк, по возрастанию.
func compensationRowsLeft(t *testing.T, ctx context.Context, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT resource_id FROM kaname.provider_compensation_outbox ORDER BY resource_id`)
	require.NoError(t, err)
	defer rows.Close()
	var left []string
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		left = append(left, s)
	}
	require.NoError(t, rows.Err())
	return left
}

// TestProviderCompensation_DeliveredRowsAreSweptAndTheRestAreNot — уборка
// снимает ДОСТАВЛЕННУЮ строку старше порога и НЕ ТРОГАЕТ ни свежую доставленную,
// ни ожидающую, ни отравленную.
//
// Отрицание здесь стоит в паре с положительным контролем НЕ ради формы: проба,
// утверждающая только «лишнее не снято», зеленела бы на уборщике, который не
// снимает ничего вовсе.
func TestProviderCompensation_DeliveredRowsAreSweptAndTheRestAreNot(t *testing.T) {
	ctx, pool := retentionPool(t)
	sweeper := kanamepg.NewProviderCompensationSweeper(pool)
	grace := outbox.DeliveredRetention

	oldSent := -(grace + time.Hour)
	youngSent := -(grace / 2)
	putCompensationRow(t, ctx, pool, "cli-old", &oldSent, 0)     // подлежит уборке
	putCompensationRow(t, ctx, pool, "cli-young", &youngSent, 0) // внутри окна
	putCompensationRow(t, ctx, pool, "cli-pending", nil, 0)      // не доставлена
	putCompensationRow(t, ctx, pool, "cli-poisoned", nil, 10)    // отравлена: доставки нет

	require.Len(t, compensationRowsLeft(t, ctx, pool), 4, "условие пробы: четыре строки посеяны")

	removed, full, err := sweeper.SweepDeliveredCompensations(ctx, grace, 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed, "снята обязана быть ровно доставленная строка старше порога")
	require.False(t, full, "партия не полна — сигнал «упёрлись в партию» ложным быть не вправе")

	left := compensationRowsLeft(t, ctx, pool)
	require.Equal(t, []string{"cli-pending", "cli-poisoned", "cli-young"}, left,
		"уборка тронула не ту полосу")

	// Повторный проход на том же дереве снимает НОЛЬ: предикат не «съедает»
	// остаток по кругу.
	removed, _, err = sweeper.SweepDeliveredCompensations(ctx, grace, 100)
	require.NoError(t, err)
	require.EqualValues(t, 0, removed, "повторный проход снял лишнее — предикат не сужен возрастом")

	t.Logf("перепись: посеяно 4 (доставленных 2 · недоставленных 2) · снято 1 · осталось %d · порог %s",
		len(left), grace)
}

// TestProviderCompensation_SweepReportsAFullBatch — признак «партия ушла
// полной». Без него проход не отличает «убрал всё, что было» от «упёрся в
// партию», и уборка со скоростью одна партия за тик не догоняла бы внешний темп
// НИКОГДА, оставаясь зелёной по всякой проверке «вызвался ли».
func TestProviderCompensation_SweepReportsAFullBatch(t *testing.T) {
	ctx, pool := retentionPool(t)
	sweeper := kanamepg.NewProviderCompensationSweeper(pool)
	grace := outbox.DeliveredRetention
	old := -(grace + time.Hour)

	for _, id := range []string{"cli-b1", "cli-b2", "cli-b3"} {
		putCompensationRow(t, ctx, pool, id, &old, 0)
	}

	removed, full, err := sweeper.SweepDeliveredCompensations(ctx, grace, 2)
	require.NoError(t, err)
	require.EqualValues(t, 2, removed, "партия ограничена значением, а не «удалить всё»")
	require.True(t, full, "партия ушла полной — признак обязан это сказать")

	removed, full, err = sweeper.SweepDeliveredCompensations(ctx, grace, 2)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed, "остаток догоняется следующей партией")
	require.False(t, full, "остаток меньше партии — признак полноты обязан погаснуть")

	t.Logf("перепись: посеяно 3 · партия 2 · снято 2 затем 1 · признак полноты true затем false")
}

// TestProviderCompensation_SweepRejectsANonPositiveBatch — негодная партия
// отвергается ДО обращения к базе: молча снятый ноль строк выглядел бы как
// исправная уборка, не убирающая ничего.
func TestProviderCompensation_SweepRejectsANonPositiveBatch(t *testing.T) {
	ctx, pool := retentionPool(t)
	sweeper := kanamepg.NewProviderCompensationSweeper(pool)

	_, _, err := sweeper.SweepDeliveredCompensations(ctx, outbox.DeliveredRetention, 0)
	require.Error(t, err, "нулевая партия обязана быть отвергнута, а не проглочена")
}
