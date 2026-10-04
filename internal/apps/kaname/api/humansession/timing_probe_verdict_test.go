// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

import (
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
