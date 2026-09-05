// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_compensation_wiring.go — дренаж очереди компенсаций частично
// исполненной саги «зарегистрировать OAuth-клиента у провайдера → закоммитить
// свою строку» + наблюдаемость этой очереди.
//
// Почему это отдельный дренаж, а не ветка в fga_outbox: у той очереди другой
// предмет (наши tuple'ы), другой применитель и другой режим отказа. Общей у
// них остаётся МЕХАНИКА — corelib drainer: claim под FOR UPDATE SKIP LOCKED,
// at-least-once, backoff, poison-gate. Она переиспользуется, а не копируется.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"
	outboxmetrics "github.com/PRO-Robotech/kacho/pkg/outbox/metrics"

	"github.com/PRO-Robotech/kacho-iam/internal/observability/metrics"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
)

// compensationMaxAttempts — порог отравления. Компенсация обязана дожать
// провайдера через сколь угодно долгую недоступность (транзиентная строка
// держится ниже порога и ретраится вечно), поэтому порог отсекает только то,
// что повтором не чинится — нерастолковываемый payload, завёрнутый декодером в
// ErrPermanent.
const compensationMaxAttempts = 10

// buildProviderCompensationDrainer собирает дренаж очереди компенсаций.
//
// Ошибка сборки ФАТАЛЬНА для старта: очередь без исполнителя означает, что
// намерения копятся, а занятое у провайдера не освобождается — при этом всё
// выглядит работающим (запись-то проходит). Молчаливо поднятый сервис с мёртвым
// дренажом — ровно тот класс, который мы ловим в коде.
func buildProviderCompensationDrainer(
	pool *pgxpool.Pool, cfg config.Config, obs clients.CompensationObserver, logger *slog.Logger,
) (func() error, error) {
	releaser := mustProviderAdminClient(cfg)

	drainerLogger := logger.With(slog.String("component", "provider_compensation_drainer"))
	d, err := drainer.New[clients.ProviderCompensationEvent](
		pool,
		drainer.Config{
			Table:        clients.ProviderCompensationTable,
			Channel:      clients.ProviderCompensationChannel,
			BatchSize:    32,
			PollFallback: 30 * time.Second,
			MaxAttempts:  compensationMaxAttempts,
			BackoffMin:   time.Second,
			BackoffMax:   30 * time.Second,
			ApplyTimeout: 5 * time.Second,
			// PartitionColumn намеренно пуст: поток коммутативен, сериализовать
			// порядок нечем и незачем (условие (а) из drainer.Config.PartitionColumn).
			// Перечень видов события и вывод из него здесь НЕ повторяются: они живут
			// одним экземпляром в записи repohygiene.commutativeDrainExempt, где
			// перечень машинно сверяется со словарём, закрытым миграцией, — и тот же
			// гейт покраснеет, если очередь получит вид события, ломающий
			// коммутативность. Прежняя редакция этого комментария перечень
			// пересказывала — «единственный вид события: снять клиента» — и была
			// ложна уже в день написания: словарь к тому дню допускал два вида, а
			// коммутативность обосновывалась ключом, которого у второго вида нет by
			// construction. Вывод уцелел, основание — нет.

			// Постоянный отказ применения НЕ травится (kacho#455). Травление
			// покупает разблокировку партиции, а её тут нет — значит покупает
			// ничего, платя потерей намерения: недоставленное снятие означает, что
			// снятое у нас осталось выданным у провайдера.
			//
			// Отказ разбора травится по-прежнему, и это безопасно: КАЖДОЕ его
			// условие закрыто ограничением миграций 0079/0080 — тело обязано быть
			// объектом jsonb, вид события взят из закрытого CHECK'ом словаря, и
			// ровно один предмет из двух непуст. То есть строки, на которой разбор
			// откажет, записать НЕЛЬЗЯ; проверяется это пробой
			// TestPoisonPathHasNoProducer.
			PermanentPolicy: drainer.RetryPermanent,
		},
		clients.DecodeProviderCompensation,
		clients.NewProviderCompensationApplier(releaser, obs),
		drainerLogger,
	)
	if err != nil {
		return nil, fmt.Errorf("init provider compensation drainer: %w", err)
	}

	return func() error {
		logger.Info("kacho-iam provider compensation drainer starting",
			"table", clients.ProviderCompensationTable,
			"channel", clients.ProviderCompensationChannel)
		return d.Run(context.Background())
	}, nil
}

// runProviderCompensationMetrics — периодический скан очереди: глубина, возраст
// самой старой недоставленной строки, число отравленных.
//
// Без него застрявшая компенсация тиха: счётчики записанных и исполненных
// намерений отвечают на «доезжает ли вообще», а возраст — на «висит ли ЭТА
// строка дольше N». Обе величины нужны, ни одна не заменяет другую.
//
// Разложения по направлению здесь нет и не может быть: все виды события этой
// очереди — СНЯТИЯ, обратной половины у потока не существует by construction,
// поэтому разложение разложило бы её на неё саму и на пустоту. Перечень видов
// и обоснование здесь НЕ повторяются: они живут одним экземпляром в записи
// исключения гейта repohygiene.TestEveryDrainedOutboxIsSplitByDirection, и там
// же перечень машинно сверяется со словарём, который закрывает миграция. Прежняя
// редакция этого комментария перечень пересказывала — «событие ровно одного
// вида» — и стала ложной в тот день, когда приехал второй вид.
func runProviderCompensationMetrics(
	ctx context.Context, pool *pgxpool.Pool, rec *metrics.OutboxRecorder, logger *slog.Logger,
) {
	collector := outboxmetrics.NewCollector(pool, rec, outboxmetrics.CollectorConfig{
		Table:       clients.ProviderCompensationTable,
		MaxAttempts: compensationMaxAttempts,
		Interval:    15 * time.Second,
	})
	// Исход скана — через единственного производителя (#2062).
	collector.Run(ctx, metrics.OutboxScanObserver(rec, clients.ProviderCompensationTable, logger,
		"provider compensation outbox metrics scan failed"))
}
