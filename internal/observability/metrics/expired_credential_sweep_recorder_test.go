// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// expired_credential_sweep_recorder_test.go — у второго уборщика те же величины,
// что у первого (задача продукта #2499).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Уборщиков одного вида два. У первого (уборка по сроку) — три семейства, и
// справка прямо объявляет смысл нуля. У второго (снятие истёкших удостоверений)
// не было ни одной величины: наблюдение — строка на прогон и предупреждение при
// старте, когда уборщик выключен.
//
// Три состояния второго не различала НИ ОДНА величина: «выключен оператором» ·
// «включён и отказывает каждый прогон» · «включён и находит ноль». Первое
// объявлялось единожды при старте и уходило вместе со сроком хранения журнала.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ
//
//	Р1  клетки исходов заведены НУЛЁМ при регистрации, и ряд включённости есть
//	    ДО первого прогона;
//	Р2  три состояния дают ТРИ различных наблюдаемых вывода;
//	Р3  величина двигается на событии и не двигается без него;
//	Р4  пустой набор исходов — отказ.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var sweepOutcomesForTest = []string{"ok", "dry-run", "failed"}

func sweepPassCell(t *testing.T, r *Registry, outcome string) (value float64, present bool) {
	t.Helper()
	return labelledCounter(t, r, ExpiredCredentialReclaimPassesMetric, map[string]string{"outcome": outcome})
}

// plainValue — значение ряда без меток (счётчик либо измеритель).
func plainValue(t *testing.T, r *Registry, name string) (value float64, present bool) {
	t.Helper()
	mfs, err := r.reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			if len(m.GetLabel()) != 0 {
				continue
			}
			if m.GetCounter() != nil {
				return m.GetCounter().GetValue(), true
			}
			if m.GetGauge() != nil {
				return m.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

// TestExpiredCredentialSweep_CellsExistBeforeTheFirstPass — Р1.
func TestExpiredCredentialSweep_CellsExistBeforeTheFirstPass(t *testing.T) {
	reg := NewRegistry()
	reg.ExpiredCredentialSweepRecorder(sweepOutcomesForTest)

	for _, outcome := range sweepOutcomesForTest {
		value, present := sweepPassCell(t, reg, outcome)
		require.Truef(t, present, "клетки %s{outcome=%q} нет ДО первого прогона — "+
			"«отказов не было» тогда неотличимо от «клетки нет»",
			ExpiredCredentialReclaimPassesMetric, outcome)
		require.Zero(t, value)
	}
	for _, name := range []string{
		ExpiredCredentialReclaimEnabledMetric,
		ExpiredCredentialReclaimFoundMetric,
		ExpiredCredentialReclaimReclaimedMetric,
	} {
		value, present := plainValue(t, reg, name)
		require.Truef(t, present, "ряда %s нет ДО первого прогона", name)
		require.Zerof(t, value, "ряд %s заведён не нулём", name)
	}
}

// TestExpiredCredentialSweep_ThreeStatesAreTold — Р2: три состояния, три вывода.
func TestExpiredCredentialSweep_ThreeStatesAreTold(t *testing.T) {
	// А — выключен оператором.
	off := NewRegistry()
	off.ExpiredCredentialSweepRecorder(sweepOutcomesForTest).SetEnabled(false)

	// Б — включён и отказывает каждый прогон.
	failing := NewRegistry()
	recFailing := failing.ExpiredCredentialSweepRecorder(sweepOutcomesForTest)
	recFailing.SetEnabled(true)
	recFailing.SweepObserved("failed", 0, 0)
	recFailing.SweepObserved("failed", 0, 0)

	// В — включён и находит ноль.
	idle := NewRegistry()
	recIdle := idle.ExpiredCredentialSweepRecorder(sweepOutcomesForTest)
	recIdle.SetEnabled(true)
	recIdle.SweepObserved("ok", 0, 0)

	enabledOff, _ := plainValue(t, off, ExpiredCredentialReclaimEnabledMetric)
	enabledFailing, _ := plainValue(t, failing, ExpiredCredentialReclaimEnabledMetric)
	enabledIdle, _ := plainValue(t, idle, ExpiredCredentialReclaimEnabledMetric)
	require.Zero(t, enabledOff, "выключенный уборщик обязан говорить о себе величиной, "+
		"а не единственной строкой журнала при старте")
	require.Equal(t, 1.0, enabledFailing)
	require.Equal(t, 1.0, enabledIdle)

	failedFailing, _ := sweepPassCell(t, failing, "failed")
	failedIdle, _ := sweepPassCell(t, idle, "failed")
	okIdle, _ := sweepPassCell(t, idle, "ok")
	require.Equal(t, 2.0, failedFailing)
	require.Zero(t, failedIdle)
	require.Equal(t, 1.0, okIdle, "исправный прогон без находки обязан двигать ряд прогонов — "+
		"иначе «нечего снимать» неотличимо от мёртвой петли")
}

// TestExpiredCredentialSweep_CountsBothNumbers — Р3: найдено и снято — ДВА числа.
func TestExpiredCredentialSweep_CountsBothNumbers(t *testing.T) {
	reg := NewRegistry()
	rec := reg.ExpiredCredentialSweepRecorder(sweepOutcomesForTest)

	rec.SweepObserved("dry-run", 7, 0)

	found, _ := plainValue(t, reg, ExpiredCredentialReclaimFoundMetric)
	reclaimed, _ := plainValue(t, reg, ExpiredCredentialReclaimReclaimedMetric)
	require.Equal(t, 7.0, found, "найденное не наблюдается — «нашёл и не снял» невыразимо")
	require.Zero(t, reclaimed)

	for _, outcome := range []string{"ok", "failed"} {
		value, _ := sweepPassCell(t, reg, outcome)
		require.Zerof(t, value, "клетка %q двинулась без своего события", outcome)
	}
}

// TestExpiredCredentialSweep_EmptyOutcomeSetIsRefused — Р4.
func TestExpiredCredentialSweep_EmptyOutcomeSetIsRefused(t *testing.T) {
	require.Panics(t, func() { NewRegistry().ExpiredCredentialSweepRecorder(nil) },
		"пустой набор исходов принят молча: клеток не будет ни одной")
}
