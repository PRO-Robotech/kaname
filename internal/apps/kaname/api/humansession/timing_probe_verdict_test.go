// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

import (
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Способность критерия Ф1-48 упасть — на СИНТЕТИЧЕСКИХ выборках, без часов и
// без машины: ровно то утверждение, которое инъекция Ф1-49 доказывает на живом
// прогоне (`KACHO_LOGIN_TIMING_INJECT`), здесь доказано детерминированно и
// гоняется на каждой отправке (kaname#223).
//
// Дефект и законный близнец отличаются РОВНО ОДНИМ фактом — сдвигом выборки
// одной полосы на величину выше её размаха.

// synthLane — полоса из двенадцати обращений с размахом в единицы миллисекунд.
func synthLane(name string, shift time.Duration) *timingLane {
	l := &timingLane{name: name}
	for i := 0; i < timingLaneN; i++ {
		l.samples = append(l.samples, 100*time.Millisecond+time.Duration(i)*time.Millisecond+shift)
	}
	return l
}

func synthRows(lanes ...*timingLane) []timingRow {
	var rows []timingRow
	for _, l := range lanes {
		m, q := l.stats()
		rows = append(rows, timingRow{lane: l, median: m, iqr: q})
	}
	return rows
}

// TestTimingCriterion_IsSilentOnIndistinguishableLanes — положительный контроль.
func TestTimingCriterion_IsSilentOnIndistinguishableLanes(t *testing.T) {
	rows := synthRows(synthLane("A", 0), synthLane("B", 0), synthLane("C", 0))
	failures, lines := timingPairFailures(rows)
	require.Empty(t, failures, "неразличимые полосы названы различимыми")
	require.Len(t, lines, 3, "печать обязана нести каждую пару: полос 3 — пар 3")
}

// TestTimingCriterion_InjectionNamesTheInjectedLane — Ф1-49 на синтетике:
// сдвиг одной полосы выше размаха — красное, и КАЖДАЯ нарушившая пара несёт
// имя этой полосы; пары без неё молчат.
func TestTimingCriterion_InjectionNamesTheInjectedLane(t *testing.T) {
	const injected = "B-ручка"
	rows := synthRows(synthLane("A", 0), synthLane(injected, 50*time.Millisecond), synthLane("C", 0))
	failures, lines := timingPairFailures(rows)
	require.Len(t, failures, 2, "сдвиг полосы %q не дал красного на обеих её парах", injected)
	for _, line := range lines {
		// Строка печати не противоречит своему вердикту: «≤» у красной пары
		// читалось бы как выполненный критерий.
		require.Equal(t, strings.Contains(line, "КРАСНОЕ"), strings.Contains(line, " > IQR"),
			"знак сравнения разошёлся с вердиктом: %s", line)
	}
	for _, f := range failures {
		require.Contains(t, f, injected, "красное пришло не от внесённого различия: %s", f)
	}
}

// TestTimingInjectKnob_NamedLaneIsSelected — ручка выбирает полосу по имени.
func TestTimingInjectKnob_NamedLaneIsSelected(t *testing.T) {
	lanes := []*timingLane{synthLane("A", 0), synthLane("адреса нет", 0)}
	l, err := timingInjectedLane(lanes, "адреса нет")
	require.NoError(t, err)
	require.NotNil(t, l)
	require.Equal(t, "адреса нет", l.name)
}

// TestTimingInjectKnob_UnknownLaneIsRefused — ручка, назвавшая полосу, которой
// нет, — отказ словами: иначе инъекция молча не вносилась бы, и зелёное
// прочиталось бы как «критерий слеп».
func TestTimingInjectKnob_UnknownLaneIsRefused(t *testing.T) {
	lanes := []*timingLane{synthLane("A", 0)}
	l, err := timingInjectedLane(lanes, "нет такой")
	require.Error(t, err)
	require.Nil(t, l)
	require.True(t, strings.Contains(err.Error(), "нет такой") && strings.Contains(err.Error(), "A"),
		"отказ обязан назвать и ручку, и законные полосы: %v", err)
}

// timingFalseRedRate — доля прогонов, в которых критерий Ф1-48 красен на
// НЕРАЗЛИЧИМЫХ полосах: lanes полос по n обращений, каждое — равномерный
// остаток в пределах разрешения ожидания (timingWaitResolution). Критерий —
// тот же timingPairFailures, что судит живой прогон, а не его копия.
func timingFalseRedRate(n, lanes, trials int) float64 {
	rng := rand.New(rand.NewPCG(223, 1269))
	red := 0
	for range trials {
		ls := make([]*timingLane, lanes)
		for k := range ls {
			l := &timingLane{name: strconv.Itoa(k)}
			for range n {
				l.samples = append(l.samples, time.Duration(rng.Int64N(int64(timingWaitResolution))))
			}
			ls[k] = l
		}
		if failures, _ := timingPairFailures(synthRows(ls...)); len(failures) > 0 {
			red++
		}
	}
	return float64(red) / float64(trials)
}

// TestTimingCriterion_PositiveTwinHoldsAtTheDeclaredN — положительный близнец
// Ф1-48 устойчив при объявленном N (kaname#223): на неразличимых полосах в
// числе полос живой пробы критерий красен не чаще бюджета ложного красного.
// Без этого «без ручки — зелёная» держится жребием: при N=12 на 21 паре
// критерий красен на шуме разрешения ожидания в каждом шестом прогоне
// (измерено прогоном NA25 — 1 красный из 2, три пары на разностях ниже
// миллисекунды).
func TestTimingCriterion_PositiveTwinHoldsAtTheDeclaredN(t *testing.T) {
	rate := timingFalseRedRate(timingLaneN, timingLaneCount, timingFalseRedTrials)
	t.Logf("N=%d · полос %d · прогонов %d · доля ложного красного %.5f · бюджет %.5f",
		timingLaneN, timingLaneCount, timingFalseRedTrials, rate, timingFalseRedBudget)
	require.LessOrEqual(t, rate, timingFalseRedBudget,
		"при N=%d критерий Ф1-48 красен на неразличимых полосах в доле %.5f прогонов — выше бюджета %.5f: положительный контроль держится жребием",
		timingLaneN, rate, timingFalseRedBudget)
}

// TestTimingCriterion_StabilityCheckRedsOnTheUndersizedN — близнец с ОДНИМ
// изменённым фактом (N=12, прежнее значение): проверка устойчивости обязана
// покраснеть, иначе её зелёное при объявленном N ничего не утверждает.
func TestTimingCriterion_StabilityCheckRedsOnTheUndersizedN(t *testing.T) {
	const undersized = 12
	rate := timingFalseRedRate(undersized, timingLaneCount, timingFalseRedTrials)
	t.Logf("N=%d · доля ложного красного %.5f · бюджет %.5f", undersized, rate, timingFalseRedBudget)
	require.Greater(t, rate, timingFalseRedBudget,
		"при N=%d доля ложного красного %.5f не выше бюджета — проверка устойчивости слепа", undersized, rate)
}
