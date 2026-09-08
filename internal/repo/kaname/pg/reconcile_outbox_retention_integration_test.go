// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_outbox_retention_integration_test.go — учёт попыток, отсечка и
// уборка очереди сверки прав на ЖИВОЙ базе (#2050).
//
// # Что здесь предмет
//
// Таблица объявляла столбцы учёта попыток (`attempt_count`, `last_error`), и их
// не писал НИКТО; дренированные строки не снимались НИКОГДА. Первое создавало
// ВИД учёта — читатель схемы заключал, что отсечка есть; второе давало
// неограниченный рост под штатным потоком регистраций ресурсов.
//
// # Почему на живой базе, а не дублёром
//
// Предмет — предикаты SQL: `attempt_count < MaxAttempts` в клейме и
// `sent_at < now() − grace` в уборке. Дублёр повторил бы мою же посылку о том,
// что они означают, и зеленел бы на любой ошибке в них.
//
// Часы — БАЗЫ: момент времени не входит в сигнатуру уборщика, предикат целиком
// в SQL. Спать при этом не приходится — уборщик зовётся методом, а не тикером.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/reconcile_outbox"
)

// putReconcileEvent кладёт строку очереди с заданными отметкой применения и
// числом попыток. Оператором базы, а не через эмиссию: предмет — предикаты
// чтения и уборки, а не путь записи.
//
// `sentOffset` отрицателен для уже применённой строки; nil означает
// «не применена».
func putReconcileEvent(
	t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	objectID string, sentOffset *time.Duration, attempts int,
) int64 {
	t.Helper()
	var id int64
	var err error
	if sentOffset == nil {
		err = pool.QueryRow(ctx,
			`INSERT INTO kaname.resource_reconcile_outbox
			        (object_type, object_id, event_type, attempt_count)
			 VALUES ('compute.instance', $1, $2, $3)
			 RETURNING id`,
			objectID, reconcile_outbox.EventUpsert, attempts).Scan(&id)
	} else {
		err = pool.QueryRow(ctx,
			`INSERT INTO kaname.resource_reconcile_outbox
			        (object_type, object_id, event_type, attempt_count, sent_at)
			 VALUES ('compute.instance', $1, $2, $3, now() + make_interval(secs => $4))
			 RETURNING id`,
			objectID, reconcile_outbox.EventUpsert, attempts, sentOffset.Seconds()).Scan(&id)
	}
	require.NoError(t, err, "посев строки очереди сверки")
	return id
}

func countReconcileRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.resource_reconcile_outbox`).Scan(&n))
	return n
}

// TestReconcileOutbox_FailureIsRecordedAndPoisonLeavesTheClaim — учёт попытки
// пишет ОБА объявленных столбца, а строка, пересёкшая порог, из клейма выпадает.
func TestReconcileOutbox_FailureIsRecordedAndPoisonLeavesTheClaim(t *testing.T) {
	ctx, pool := retentionPool(t)

	id := putReconcileEvent(t, ctx, pool, "cinst-poison", nil, 0)

	// Строка видна клейму, пока не отравлена, — положительный контроль. Без него
	// «отравленная не клеймится» зеленело бы на клейме, не берущем ничего.
	got, err := reconcile_outbox.ClaimBatch(ctx, pool, 10)
	require.NoError(t, err)
	require.Len(t, got, 1, "неотравленная строка обязана клеймиться")
	require.Equal(t, id, got[0].ID)

	// Учёт: оба столбца пишутся, счётчик возвращается ПОСЛЕ учёта.
	const cause = "сосед отверг регистрацию: отношение вне закрытого набора"
	attempts, err := reconcile_outbox.RecordFailure(ctx, pool, id, cause)
	require.NoError(t, err)
	require.Equal(t, 1, attempts, "счётчик обязан вернуться после учёта, а не до")

	var storedAttempts int
	var storedErr *string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT attempt_count, last_error FROM kaname.resource_reconcile_outbox WHERE id = $1`,
		id).Scan(&storedAttempts, &storedErr))
	require.Equal(t, 1, storedAttempts, "attempt_count не записан")
	require.NotNil(t, storedErr, "last_error не записан — «отравлено» неотличимо от «отравлено чем»")
	require.Equal(t, cause, *storedErr)

	// Довести до порога и убедиться, что строка вышла из клейма.
	for attempts < reconcile_outbox.MaxAttempts {
		attempts, err = reconcile_outbox.RecordFailure(ctx, pool, id, cause)
		require.NoError(t, err)
	}
	got, err = reconcile_outbox.ClaimBatch(ctx, pool, 10)
	require.NoError(t, err)
	require.Empty(t, got,
		"отравленная строка по-прежнему клеймится — отсечки нет, каждый проход тратится на заведомый отказ")

	// Отсечка НЕ снимает строку: её видит скан состояния как отравленную, и она
	// остаётся единственным свидетельством о неприменимом событии.
	require.Equal(t, 1, countReconcileRows(t, ctx, pool),
		"отсечка не вправе уничтожать след неприменимого события")

	t.Logf("перепись: строк очереди 1 · попыток учтено %d · порог %d · клеймится после отсечки %d",
		attempts, reconcile_outbox.MaxAttempts, len(got))
}

// TestReconcileOutbox_DrainedRowsAreSweptAndTheRestAreNot — уборка снимает
// применённые строки старше порога и НЕ трогает ни молодых, ни неприменённых.
//
// Три полосы вместе, а не отрицание в одиночку: «старая снята» зеленело бы на
// уборщике, опустошающем таблицу, а «молодая осталась» — на уборщике, не
// снимающем ничего.
func TestReconcileOutbox_DrainedRowsAreSweptAndTheRestAreNot(t *testing.T) {
	ctx, pool := retentionPool(t)
	sweeper := kanamepg.NewReconcileOutboxSweeper(pool)
	grace := reconcile_outbox.DrainedRetention

	oldSent := -(grace + time.Hour)
	youngSent := -(grace / 2)
	putReconcileEvent(t, ctx, pool, "cinst-old", &oldSent, 0)     // подлежит уборке
	putReconcileEvent(t, ctx, pool, "cinst-young", &youngSent, 0) // внутри окна
	putReconcileEvent(t, ctx, pool, "cinst-pending", nil, 0)      // не применена
	putReconcileEvent(t, ctx, pool, "cinst-poisoned", nil, reconcile_outbox.MaxAttempts)

	require.Equal(t, 4, countReconcileRows(t, ctx, pool), "условие пробы: четыре строки посеяны")

	removed, full, err := sweeper.SweepDrainedReconcileEvents(ctx, grace, 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed, "снята обязана быть ровно применённая строка старше порога")
	require.False(t, full, "партия не полна — сигнал «упёрлись в партию» ложным быть не вправе")

	var left []string
	rows, err := pool.Query(ctx,
		`SELECT object_id FROM kaname.resource_reconcile_outbox ORDER BY object_id`)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		left = append(left, s)
	}
	require.NoError(t, rows.Err())
	require.Equal(t, []string{"cinst-pending", "cinst-poisoned", "cinst-young"}, left,
		"уборка тронула не ту полосу")

	// Повторный проход на том же дереве снимает НОЛЬ: предикат не «съедает»
	// остаток по кругу.
	removed, _, err = sweeper.SweepDrainedReconcileEvents(ctx, grace, 100)
	require.NoError(t, err)
	require.EqualValues(t, 0, removed, "повторный проход снял лишнее — предикат не сужен возрастом")

	t.Logf("перепись: посеяно 4 (применённых 2 · неприменённых 2) · снято 1 · осталось %d · порог %s",
		len(left), grace)
}

// TestReconcileOutbox_SweepReportsAFullBatch — признак «партия ушла полной».
// Без него проход не отличает «убрал всё, что было» от «упёрся в партию», и
// уборка со скоростью одна партия за тик не догоняла бы внешний темп НИКОГДА,
// оставаясь зелёной по всякой проверке «вызвался ли».
func TestReconcileOutbox_SweepReportsAFullBatch(t *testing.T) {
	ctx, pool := retentionPool(t)
	sweeper := kanamepg.NewReconcileOutboxSweeper(pool)
	grace := reconcile_outbox.DrainedRetention
	old := -(grace + time.Hour)

	const seeded = 5
	for i := range seeded {
		putReconcileEvent(t, ctx, pool, "cinst-full-"+string(rune('a'+i)), &old, 0)
	}

	removed, full, err := sweeper.SweepDrainedReconcileEvents(ctx, grace, 2)
	require.NoError(t, err)
	require.EqualValues(t, 2, removed)
	require.True(t, full, "партия ушла полной, а проход об этом не сказал")

	removed, full, err = sweeper.SweepDrainedReconcileEvents(ctx, grace, 100)
	require.NoError(t, err)
	require.EqualValues(t, seeded-2, removed)
	require.False(t, full, "остаток меньше партии — признак полноты ложен")

	t.Logf("перепись: посеяно %d · снято партиями 2 + %d · таблица %d",
		seeded, seeded-2, countReconcileRows(t, ctx, pool))
}
