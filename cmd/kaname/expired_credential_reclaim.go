// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/expiredcredsweep"
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
	ctx context.Context, pool *pgxpool.Pool, cfg config.Config, logger *slog.Logger,
) {
	c := cfg.Jobs.ExpiredCredentialReclaim
	log := logger.With(slog.String("component", "expired_credential_reclaim"))

	if !c.Enabled {
		// Выключенный уборщик ГОВОРИТ О СЕБЕ при старте: молча выключенная
		// уборка неотличима от работающей, у которой нечего снимать.
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
	)
	go sw.Run(ctx)

	log.Info("снятие истёкших удостоверений запущено",
		slog.String("interval", c.Interval.String()),
		slog.String("grace", c.Grace.String()),
		slog.String("min_delay", minDelay.String()),
		slog.Int("batch_size", c.BatchSize),
		slog.Bool("dry_run", c.DryRun))
}
