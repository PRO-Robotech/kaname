// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_compensation_wiring.go — наблюдаемость очереди компенсаций саги
// «зарегистрировать клиента у внешнего поставщика → закоммитить свою строку».
//
// Дренажа здесь больше нет: у очереди нет ни производителя, ни исполнителя —
// оба сняты вместе с административной дорогой к поставщику (kaname#363).
// Таблица же в схеме осталась, и строки, записанные прежней посадкой, в ней
// могли остаться; перепись ниже держит их видимыми (разбор —
// `internal/clients/provider_compensation_outbox.go`).
package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	outboxmetrics "github.com/PRO-Robotech/corelib/outbox/metrics"

	"github.com/PRO-Robotech/kaname/internal/observability/metrics"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

// compensationMaxAttempts — порог отравления, которым прежний дренаж отмечал
// строку, не поддавшуюся повтору. Перепись считает отравленными строки на этом
// пороге, поэтому он остаётся тем же числом, что писал дренаж: иначе строки,
// отравленные прежним дренажом, перестали бы читаться отравленными.
const compensationMaxAttempts = 10

// runProviderCompensationMetrics — периодический скан очереди: глубина, возраст
// самой старой недоставленной строки, число отравленных.
//
// Писать в очередь и исполнять её больше некому (kaname#363), и именно поэтому
// скан остаётся: без него строки, пережившие снятие прежней посадки, были бы
// невидимы — ни один счётчик записанных или исполненных намерений о них уже не
// скажет. Ненулевая глубина здесь означает остаток, который исполнить нечем,
// и снимается он вместе с таблицей, отдельным предметом миграции.
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
