// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// jwks_mirror_collector_test.go — «ноль отказов» обязано быть отличимо от «ни
// разу не спрашивали».
//
// Здесь стояла ссылка на счётчики ТЕНЕВОГО СРАВНЕНИЯ как на соседа по предмету.
// Соседа больше нет: сравнение двух источников вердикта снято вместе с внешним
// движком прав, а с ним и его пробы. Ссылка на снятое читается как указание на
// живой образец, поэтому предмет назван здесь прямо, а не через соседа.
//
// Зеркало ключей проверки отказывает закрыто: не ответил верхний хоп — вся
// плоскость данных отвергает токены. Пока наружу выходят только отказы, ноль в
// них означает сразу и «всё хорошо», и «сюда никто не приходил», а различие
// между этими двумя состояниями — это различие между «работает» и «не работает
// вообще» (security.md §Hardening-инвариант 8: «ноль отказов за всю жизнь
// контроля» обязано быть заметно).

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func jwksSeries(t *testing.T, r *Registry, outcome string) (value float64, present bool) {
	t.Helper()
	return labelledCounter(t, r, JWKSMirrorOutcomesMetric, map[string]string{"outcome": outcome})
}

// TestJWKSMirrorCollector_ZeroRefusalsIsDistinguishableFromZeroFetches — два
// состояния с нулём отказов обязаны давать РАЗНЫЙ наблюдаемый вывод.
func TestJWKSMirrorCollector_ZeroRefusalsIsDistinguishableFromZeroFetches(t *testing.T) {
	// Состояние A — зеркало не спрашивали ни разу.
	untouched := NewRegistry()
	untouched.NewJWKSMirrorCollector(func() JWKSMirrorCounts { return JWKSMirrorCounts{} })

	// Состояние B — зеркало отдало ключи 12 раз и не отказало ни разу.
	healthy := NewRegistry()
	healthy.NewJWKSMirrorCollector(func() JWKSMirrorCounts { return JWKSMirrorCounts{Served: 12} })

	refA, okA := jwksSeries(t, untouched, JWKSMirrorOutcomeUnavailable)
	refB, okB := jwksSeries(t, healthy, JWKSMirrorOutcomeUnavailable)
	require.True(t, okA)
	require.True(t, okB)
	require.Equal(t, refA, refB,
		"предпосылка пробы: по одним отказам эти два состояния НЕ различаются")

	srvA, okA := jwksSeries(t, untouched, JWKSMirrorOutcomeServed)
	srvB, okB := jwksSeries(t, healthy, JWKSMirrorOutcomeServed)
	require.True(t, okA, "ряд выданных отсутствует: «ноль отказов» тогда неотличимо от "+
		"«ни одного обращения», и мёртвое зеркало читается как здоровое")
	require.True(t, okB)
	require.NotEqual(t, srvA, srvB,
		"вывод не различает нетронутое зеркало (%v) и работающее без отказов (%v)", srvA, srvB)
	require.Equal(t, 0.0, srvA)
	require.Equal(t, 12.0, srvB)
}

// TestJWKSMirrorCollector_RefusalReasonsStayApart — «не ответил» и «по этому
// адресу не то» суть разные состояния: первое лечится временем, второе — только
// правкой настройки.
func TestJWKSMirrorCollector_RefusalReasonsStayApart(t *testing.T) {
	reg := NewRegistry()
	reg.NewJWKSMirrorCollector(func() JWKSMirrorCounts {
		return JWKSMirrorCounts{Served: 1, Unavailable: 2, Misconfigured: 3}
	})

	for outcome, want := range map[string]float64{
		JWKSMirrorOutcomeServed:        1,
		JWKSMirrorOutcomeUnavailable:   2,
		JWKSMirrorOutcomeMisconfigured: 3,
	} {
		v, ok := jwksSeries(t, reg, outcome)
		require.Truef(t, ok, "клетка %q отсутствует", outcome)
		require.Equalf(t, want, v, "клетка %q", outcome)
	}
}

// TestJWKSMirrorCollector_EveryOutcomeCellExistsBeforeFirstUse — отсутствие ряда
// отвечало бы сразу и «не случалось», и «не провязано».
func TestJWKSMirrorCollector_EveryOutcomeCellExistsBeforeFirstUse(t *testing.T) {
	reg := NewRegistry()
	reg.NewJWKSMirrorCollector(func() JWKSMirrorCounts { return JWKSMirrorCounts{} })
	for _, outcome := range JWKSMirrorOutcomes {
		v, ok := jwksSeries(t, reg, outcome)
		require.Truef(t, ok, "клетка %q отсутствует до первого наблюдения", outcome)
		require.Equalf(t, 0.0, v, "клетка %q", outcome)
	}
}

// TestJWKSMirrorCollector_RefusesASourcelessRegistration — вечный ноль без
// источника выглядит как работающее наблюдение и утверждает неправду.
func TestJWKSMirrorCollector_RefusesASourcelessRegistration(t *testing.T) {
	reg := NewRegistry()
	require.Panics(t, func() { reg.NewJWKSMirrorCollector(nil) },
		"коллектор без источника зарегистрировался: вечный ноль неотличим от нетронутого зеркала")
}
