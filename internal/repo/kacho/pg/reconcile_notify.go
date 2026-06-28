// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// reconcile_notify.go — LISTEN/NOTIFY-источник пробуждений для reconciler-worker
// (порт seed.NotifyWatcher). Переводит дренаж resource_reconcile_outbox с poll-
// only на event-driven в паритет с corelib fga_outbox drainer: каждый INSERT
// события шлет pg_notify (AFTER INSERT триггер, миграция 0042), worker просыпается
// и дренажит очередь в пределах одного reconcile-прохода. Poll (DrainInterval)
// остается fallback'ом на пропущенный NOTIFY.

import (
	"context"
	"fmt"
	"time"
)

// reconcileOutboxChannel — канал pg_notify очереди reconcile-событий (миграция
// 0042). Должен совпадать с literal в триггере resource_reconcile_outbox_notify.
const reconcileOutboxChannel = "kacho_iam_resource_reconcile_outbox"

// Watch реализует seed.NotifyWatcher: LISTEN на reconcileOutboxChannel и сигнал в
// wakeup на каждый NOTIFY (+ один раз на каждый успешный (пере)коннект — catch-up
// на случай уведомления, пришедшего в окно реконнекта). На обрыве conn —
// exp-backoff и pool.Reset (idle-conn'ы к тому же backend'у тоже могли умереть),
// зеркалит listen-loop corelib drainer. Блокирует до отмены ctx.
func (a *ReconcileAdapter) Watch(ctx context.Context, wakeup chan<- struct{}) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := a.listenOnce(ctx, wakeup)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			// Forсим пересоздание idle-conn'ов: FATAL-shutdown backend'а часто
			// бьет по всем conn'ам процесса, а ShouldPing-default ждет слишком долго.
			a.pool.Reset()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// listenOnce держит одну LISTEN-подписку на hijacked-conn'е до обрыва/отмены.
// Conn забирается из pool через Hijack: LISTEN живет на одном соединении, и его
// нельзя возвращать в pool (idle-reset уничтожит подписку).
func (a *ReconcileAdapter) listenOnce(ctx context.Context, wakeup chan<- struct{}) error {
	pc, err := a.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("reconcile notify: pool.Acquire: %w", err)
	}
	conn := pc.Hijack()
	defer func() {
		// Закрываем на background-ctx с дедлайном: parent ctx уже может быть Done,
		// а мы все равно хотим попытку close с реальным таймаутом, а не навечно.
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
	}()

	if _, err := conn.Exec(ctx, "LISTEN "+reconcileOutboxChannel); err != nil {
		return fmt.Errorf("reconcile notify: LISTEN: %w", err)
	}
	// Свежий коннект — будим worker (catch-up safety).
	signalReconcileWakeup(wakeup)

	for {
		notif, err := conn.WaitForNotification(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if notif == nil {
			continue
		}
		// payload (id строки) игнорируем — worker делает claim по всему батчу,
		// нам нужен только факт «есть работа».
		signalReconcileWakeup(wakeup)
	}
}

// signalReconcileWakeup — неблокирующий сигнал в буферизованный wakeup-канал.
func signalReconcileWakeup(c chan<- struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}
