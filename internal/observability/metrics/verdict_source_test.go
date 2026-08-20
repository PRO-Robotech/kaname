// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package metrics

// verdict_source_test.go — ИСТОЧНИК ВЕРДИКТА и НАПРАВЛЕНИЕ расхождения видны
// снаружи числом.
//
// Без источника «переключено» и «объявлено переключённым» неразличимы: рубильник
// может стоять в позиции «форма», а решения продолжать идти движком — например
// потому, что доставка настройки не перекатила под, и процесс живёт с прежним
// окружением. Наблюдаемого признака у такого состояния нет НИ ОДНОГО, кроме
// этих рядов: ответы вызывающим при этом правильные.
//
// Без направления P0 («форма разрешает там, где движок отказывал» — расширение
// доступа) и P1 («форма отказывает там, где движок разрешал» — отказ в
// обслуживании) различимы только чтением строки журнала, то есть человеком и
// постфактум. Оповещения на этом не построить.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Числа источника и направления доезжают наружу и различают состояния.
func TestVerdictSourceAndDirectionReachTheOutside(t *testing.T) {
	reg := NewRegistry()
	reg.NewShadowVerdictCollector(func() ShadowVerdictCounts {
		return ShadowVerdictCounts{
			Decisions: 10, Compared: 6, Diverged: 2, Unfinished: 3, Unaskable: 1,
			DivergedFormWider: 1, DivergedFormNarrower: 1,
			VerdictsForm: 4, VerdictsEngine: 6,
		}
	})

	for outcome, want := range map[string]float64{
		ShadowVerdictOutcomeVerdictsForm:         4,
		ShadowVerdictOutcomeVerdictsEngine:       6,
		ShadowVerdictOutcomeDivergedFormWider:    1,
		ShadowVerdictOutcomeDivergedFormNarrower: 1,
		ShadowVerdictOutcomeUnaskable:            1,
	} {
		v, ok := shadowSeries(t, reg, outcome)
		require.Truef(t, ok, "клетка %q не доехала наружу: состояние наблюдаемо только чтением логов", outcome)
		require.Equalf(t, want, v, "клетка %q", outcome)
	}
}

// Клетки источника ПОКРЫВАЮТ знаменатель: у решения ровно один источник.
//
// Проба утверждает арифметическое отношение, а не присутствие рядов: сумма,
// которая не сходится, означает решения, прошедшие мимо обоих источников, — то
// есть мимо всякого наблюдения.
func TestVerdictSourcesSumToDecisions(t *testing.T) {
	reg := NewRegistry()
	reg.NewShadowVerdictCollector(func() ShadowVerdictCounts {
		return ShadowVerdictCounts{Decisions: 10, VerdictsForm: 4, VerdictsEngine: 6}
	})

	form, _ := shadowSeries(t, reg, ShadowVerdictOutcomeVerdictsForm)
	engine, _ := shadowSeries(t, reg, ShadowVerdictOutcomeVerdictsEngine)
	decisions, _ := shadowSeries(t, reg, ShadowVerdictOutcomeDecisions)

	require.Equal(t, decisions, form+engine,
		"у решения обязан быть ровно один источник — иначе часть решений не видна ни одному ряду")
}

// Каждая объявленная клетка отдаётся до первого наблюдения — включая новые.
//
// Перечень и коллектор обязаны читать ОДНО множество: клетка, добавленная в
// счётчики и забытая в перечне, наружу не поедет и будет выглядеть нулём.
func TestNewCellsExistBeforeFirstUse(t *testing.T) {
	reg := NewRegistry()
	reg.NewShadowVerdictCollector(func() ShadowVerdictCounts { return ShadowVerdictCounts{} })

	for _, outcome := range ShadowVerdictOutcomes {
		v, ok := shadowSeries(t, reg, outcome)
		require.Truef(t, ok, "клетка %q отсутствует до первого наблюдения", outcome)
		require.Equalf(t, 0.0, v, "клетка %q до первого наблюдения обязана быть нулём", outcome)
	}
}
