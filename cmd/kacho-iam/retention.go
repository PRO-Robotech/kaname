// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retention.go — провязка фоновой уборки таблиц, чей рост задаёт внешний
// (задача #1292, приёмка `retention-sweep-has-a-caller.md`).
//
// # Предмет
//
// Два уборщика по сроку были ОБЪЯВЛЕНЫ и не имели ни одного прод-вызывающего, у
// третьей таблицы уборщика не было вовсе. Восемь мест дерева при этом утверждали
// в настоящем времени, что сборщик работает: две строки применённой миграции,
// шапки двух методов, комментарий контракта, комментарий домена, шапка второй
// применённой миграции и записка архитектуры. Провязка делает все восемь
// истинными разом; впредь свойство держит гейт дерева
// `internal/repohygiene` `TestDeclaredRetentionSweepersHaveAProductionCaller`,
// а не этот комментарий.
//
// # Почему ОДНА петля на все предметы
//
// Несколько петель — несколько расписаний об одном предмете, и они расходятся
// молча. Петля владеет реестром: добавление уборщика — одна запись, а не новая
// петля. Четвёртым предметом заведены окна темпа заведения аккаунтов (#1364), и
// добавление стоило ровно одной строки — ровно то, ради чего петля одна.
package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/retention"
	"github.com/PRO-Robotech/kacho-iam/internal/observability/metrics"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// startRetentionSweeper поднимает фоновую уборку и подключает её величины к
// съёму.
//
// Отказывает, а не предупреждает: величины уже проверены стражем старта
// конфигурации, поэтому отказ здесь означает расхождение построителя со
// стражем — то есть ровно то состояние, в котором стенд поднимать нельзя.
func startRetentionSweeper(
	ctx context.Context,
	pool *pgxpool.Pool,
	cfg config.Config,
	reg *metrics.Registry,
	logger *slog.Logger,
) error {
	sweeper, err := retention.New(
		cfg.Retention.Sweep(),
		retention.Subjects(
			kachopg.NewClientAssertionReplayRepo(pool),
			kachopg.NewSessionRevocationRepo(pool),
			kachopg.NewMintedTokenRevocationRepo(pool),
			kachopg.NewIdentityAdmissionWindowRepo(pool),
			// Пятым предметом — журнал смены субъекта (#1758). Наблюдатель
			// границы устоявшегося у него СВОЙ, а не общий с читателем, и это
			// безопасно by construction: граница монотонна, поэтому величина,
			// наблюдённая до оператора, остаётся нижней оценкой — снимется не
			// больше, чем позволено.
			kachopg.NewSubjectChangeJournalSweeper(pool, logger),
			// Шестым предметом — очередь сверки прав (#2050). Её дренированные
			// строки не снимались никогда, при том что приём уборки уже был и
			// применён к соседней очереди.
			kachopg.NewReconcileOutboxSweeper(pool),
			// Седьмым предметом — очередь компенсаций у внешнего провайдера
			// (#2069). Её доставленные строки не снимались никогда, и реестр
			// роста таблиц объявлял её долгом; уборщик СВОЙ, потому что общий
			// уборщик платформы требует ключа партиции, а он у этой очереди
			// пуст намеренно — поток коммутативен.
			kachopg.NewProviderCompensationSweeper(pool),
		),
		logger.With(slog.String("component", "retention_sweep")),
	)
	if err != nil {
		return fmt.Errorf("фоновая уборка: %w", err)
	}

	// Величина обязана иметь читателя: накопитель без него считает в никуда.
	if reg != nil {
		reg.NewRetentionCollector(func() metrics.RetentionCounts {
			c := sweeper.Stats()
			return metrics.RetentionCounts{Passes: c.Passes, Removed: c.Removed, Failures: c.Failures}
		})
	}

	sweeper.Start(ctx)
	logger.Info("retention sweep is on",
		slog.String("interval", cfg.Retention.Interval.String()),
		slog.Int("batch", cfg.Retention.Batch),
		slog.Int("max_batches_per_pass", cfg.Retention.MaxBatchesPerPass))
	return nil
}
