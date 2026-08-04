// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
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
			// PartitionColumn намеренно пуст: единственный вид события —
			// «снять клиента», два таких события одного client_id коммутируют и
			// идемпотентны, поэтому финальное состояние сходится при любом
			// порядке (условие (а) из drainer.Config.PartitionColumn). Порядок
			// сериализовать нечем и незачем.
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
func runProviderCompensationMetrics(
	ctx context.Context, pool *pgxpool.Pool, rec outboxmetrics.Recorder, logger *slog.Logger,
) {
	collector := outboxmetrics.NewCollector(pool, rec, outboxmetrics.CollectorConfig{
		Table:       clients.ProviderCompensationTable,
		MaxAttempts: compensationMaxAttempts,
		Interval:    15 * time.Second,
	})
	collector.Run(ctx, func(err error) {
		logger.Warn("provider compensation outbox metrics scan failed", "err", err)
	})
}
