// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// signing_key_sweep_cell_test.go — проход сметателя выведенных ключей
// НАБЛЮДАЕМ (#314).
//
// Счётчик снятий один не различает «сметатель ходит, снимать нечего» и
// «сметатель не ходит»: оба дают ноль снятий. Различает их только клетка
// проходов, и печататься она обязана всегда, включая ноль, — иначе правилу
// тревоги, читающему ноль как сигнал, нечего читать.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func signingKeySeries(t *testing.T, r *Registry, event string) (float64, bool) {
	t.Helper()
	return labelledCounter(t, r, SigningKeyEventsMetric, map[string]string{"event": event})
}

func TestSigningKeyCollector_SweepPassCellSeparatesAnIdleSweeperFromADeadOne(t *testing.T) {
	// Состояние A — сметатель не ходил ни разу.
	dead := NewRegistry()
	dead.NewSigningKeyCollector(func() SigningKeyCounts { return SigningKeyCounts{} })

	// Состояние B — сметатель прошёл трижды, снимать было нечего.
	idle := NewRegistry()
	idle.NewSigningKeyCollector(func() SigningKeyCounts { return SigningKeyCounts{Sweeps: 3} })

	remA, okA := signingKeySeries(t, dead, SigningKeyEventRemoved)
	remB, okB := signingKeySeries(t, idle, SigningKeyEventRemoved)
	require.True(t, okA)
	require.True(t, okB)
	require.Equal(t, remA, remB, "предпосылка пробы: по снятиям эти два состояния НЕ различаются")

	swA, okA := signingKeySeries(t, dead, SigningKeyEventSwept)
	swB, okB := signingKeySeries(t, idle, SigningKeyEventSwept)
	require.True(t, okA, "клетка проходов обязана печататься и нулевой: правилу тревоги нечего читать иначе")
	require.True(t, okB)
	require.Equal(t, 0.0, swA)
	require.Equal(t, 3.0, swB)
}
