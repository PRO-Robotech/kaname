// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/expiredcredsweep"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// expiredCredentialStore приводит адаптер Postgres к порту use-case.
//
// Типы порта объявляет ВЫЗЫВАЮЩИЙ, поэтому преобразование живёт здесь, а не
// протекает формой адаптера вверх.
type expiredCredentialStore struct {
	inner *kanamepg.ExpiredCredentialReclaimer
}

func (s expiredCredentialStore) ReclaimExpiredCredentials(
	ctx context.Context, spec expiredcredsweep.Spec,
) (expiredcredsweep.Result, error) {
	res, err := s.inner.ReclaimExpiredCredentials(ctx, kanamepg.ExpiredCredentialReclaimSpec{
		MinDelay:  spec.MinDelay,
		Grace:     spec.Grace,
		BatchSize: spec.BatchSize,
		DryRun:    spec.DryRun,
	})
	return expiredcredsweep.Result{
		Found:     res.Found,
		Reclaimed: res.Reclaimed,
		ByKind:    res.ByKind,
	}, err
}

// startExpiredCredentialReclaim провязывает снятие истёкших удостоверений.
//
// # Почему провязка — часть работы, а не её оформление
//
// В сервисе уже лежат ДВА объявленных уборщика по сроку, и у каждого ноль
// вызывающих в прод-коде; при этом три места дерева утверждают, что сборщик
// работает. Механизм, написанный и не позванный, — контроль, у которого нет
// возможности исполниться: он выглядит существующим и не делает ничего.
// Провязка здесь и есть то, чем эта работа отличается от тех двух.
//
// # Отсрочка приходит ПАРОЙ, и обе величины считает конфигурация
//
// Нижняя граница ВЫЧИСЛЯЕТСЯ из слагаемых по действующему сроку докерного
// токена; верхняя объявлена секцией. Их согласие проверил страж старта — сюда
// они попадают уже проверенными, и второй проверки здесь нет намеренно: две
// проверки одного предмета разошлись бы молча.
func startExpiredCredentialReclaim(
	ctx context.Context, pool *pgxpool.Pool, cfg config.Config, reg *metrics.Registry, logger *slog.Logger,
) {
	c := cfg.Jobs.ExpiredCredentialReclaim
	log := logger.With(slog.String("component", "expired_credential_reclaim"))

	// ВЕЛИЧИНЫ ЗАВОДЯТСЯ ДО РАЗВИЛКИ ВЫКЛЮЧАТЕЛЯ, и это несущее (#2499).
	// Выключенный уборщик прогонов не делает вовсе, поэтому его состояние
	// выражается ТОЛЬКО рядом включённости: заведи его после развилки — и
	// «выключен оператором» осталось бы одной строкой журнала, уходящей вместе
	// со сроком его хранения.
	//
	// Полоса величин здесь ТА ЖЕ, что у первого уборщика по сроку: прогоны ·
	// найденные и снятые строки · отказавшие прогоны. Две полосы наблюдения об
	// одном виде механизма — расхождение, которому нечем себя выдать.
	values := reg.ExpiredCredentialSweepRecorder(expiredcredsweep.Outcomes())
	values.SetEnabled(c.Enabled)

	if !c.Enabled {
		// Выключенный уборщик ГОВОРИТ О СЕБЕ при старте: молча выключенная
		// уборка неотличима от работающей, у которой нечего снимать. Строка
		// журнала остаётся сверху величины, а не вместо неё: она называет цену
		// решения словами, чего ряд не умеет.
		log.Warn("снятие истёкших удостоверений ВЫКЛЮЧЕНО — истёкшие удостоверения продолжат занимать места под потолком, " +
			"и освобождать их придётся отзывом вручную")
		return
	}

	minDelay := c.MinGrace(cfg.APIServer.RegistryToken.TokenTTL())
	sw := expiredcredsweep.New(
		expiredCredentialStore{inner: kanamepg.NewExpiredCredentialReclaimer(pool, "kaname")},
		expiredcredsweep.Spec{
			MinDelay:  minDelay,
			Grace:     c.Grace,
			BatchSize: c.BatchSize,
			DryRun:    c.DryRun,
		},
		c.Interval,
		log,
	).WithObserver(values)
	go sw.Run(ctx)

	log.Info("снятие истёкших удостоверений запущено",
		slog.String("interval", c.Interval.String()),
		slog.String("grace", c.Grace.String()),
		slog.String("min_delay", minDelay.String()),
		slog.Int("batch_size", c.BatchSize),
		slog.Bool("dry_run", c.DryRun))
}
