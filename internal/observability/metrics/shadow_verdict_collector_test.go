// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package metrics

// shadow_verdict_collector_test.go — предмет проб здесь РАЗЛИЧЕНИЕ, а не наличие
// счётчика.
//
// # Почему «серия существует» — недостаточное утверждение
//
// Счётчик расхождений, показывающий ноль, отвечает сразу на два разных вопроса:
// «сравнения шли и разошлись ни разу» и «сравнений не было вовсе». Пока эти два
// состояния дают ОДИН И ТОТ ЖЕ наблюдаемый вывод, ноль в расхождениях не
// означает согласия — он означает тишину. Поэтому пробы ниже сравнивают ДВА
// состояния между собой и требуют, чтобы вывод их различал; проба «серия есть»
// осталась бы зелёной ровно на том выводе, который различать не умеет.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// shadowSeries — значение одной клетки закрытого набора исходов.
func shadowSeries(t *testing.T, r *Registry, outcome string) (value float64, present bool) {
	t.Helper()
	return labelledCounter(t, r, ShadowVerdictOutcomesMetric, map[string]string{"outcome": outcome})
}

// TestShadowVerdictCollector_ZeroComparisonsIsDistinguishableFromZeroDivergences —
// центральное утверждение: «сравнений не было» и «сравнения шли, расхождений нет»
// обязаны давать РАЗНЫЙ наблюдаемый вывод.
func TestShadowVerdictCollector_ZeroComparisonsIsDistinguishableFromZeroDivergences(t *testing.T) {
	// Состояние A — сравнитель не спрошен ни разу.
	silent := NewRegistry()
	silent.NewShadowVerdictCollector(func() ShadowVerdictCounts { return ShadowVerdictCounts{} })

	// Состояние B — сравнений семь, расхождений ноль.
	agreeing := NewRegistry()
	agreeing.NewShadowVerdictCollector(func() ShadowVerdictCounts {
		return ShadowVerdictCounts{Compared: 7}
	})

	divA, okA := shadowSeries(t, silent, ShadowVerdictOutcomeDiverged)
	divB, okB := shadowSeries(t, agreeing, ShadowVerdictOutcomeDiverged)
	require.True(t, okA)
	require.True(t, okB)
	require.Equal(t, divA, divB,
		"предпосылка пробы: по одному счётчику расхождений эти два состояния НЕ различаются — "+
			"ради этого и требуется второй ряд")

	cmpA, okA := shadowSeries(t, silent, ShadowVerdictOutcomeCompared)
	cmpB, okB := shadowSeries(t, agreeing, ShadowVerdictOutcomeCompared)
	require.True(t, okA, "клетка сравнений отсутствует: «ноль расхождений» тогда неотличимо от "+
		"«сравнений не было», и наблюдаемый вывод утверждает согласие, которого никто не проверял")
	require.True(t, okB, "клетка сравнений отсутствует у работающего сравнителя")
	require.NotEqual(t, cmpA, cmpB,
		"вывод не различает молчащий сравнитель (%v) и согласный (%v) — "+
			"это и есть форма проверки без содержания", cmpA, cmpB)
	require.Equal(t, 0.0, cmpA)
	require.Equal(t, 7.0, cmpB)
}

// TestShadowVerdictCollector_ComparedShareIsUnknowableWithoutItsDenominator —
// числа сравнений НЕДОСТАТОЧНО: «сравнили три» не отвечает на вопрос «из
// скольких».
//
// Знаменатель не выводится из остальных трёх клеток и потому обязан выходить
// наружу своим рядом. Решение, к которому теневой путь позван, попадает в
// `decisions` СРАЗУ, а его исход сводится позже — и может не свестись вовсе
// (сведение не позвали) либо не задаться вовсе (вопрос форме E непредставим,
// `Unaskable`). Тогда `decisions` строго больше суммы состоявшихся исходов, и
// этот зазор — доля решений, мимо которых сравнение прошло молча.
//
// Два состояния ниже совпадают по всем трём клеткам исходов и различаются только
// охватом: в первом сравнение видело каждое решение, во втором — три сотых. Без
// знаменателя они дают ОДИН наблюдаемый вывод, и мерой сходимости пользоваться
// нельзя — ровно то, что говорит о себе сам сравнитель.
func TestShadowVerdictCollector_ComparedShareIsUnknowableWithoutItsDenominator(t *testing.T) {
	// Состояние A — сравнение позвано шесть раз и свело исход каждого.
	full := NewRegistry()
	full.NewShadowVerdictCollector(func() ShadowVerdictCounts {
		return ShadowVerdictCounts{Decisions: 6, Compared: 3, Unfinished: 3}
	})

	// Состояние B — те же исходы, но позвано сравнение было сто раз: девяносто
	// четыре решения прошли мимо него, не оставив исхода вовсе.
	sparse := NewRegistry()
	sparse.NewShadowVerdictCollector(func() ShadowVerdictCounts {
		return ShadowVerdictCounts{Decisions: 100, Compared: 3, Unfinished: 3}
	})

	// Предпосылка пробы: по клеткам исходов эти состояния НЕ различаются. Упадёт
	// она — проба утверждает не то, ради чего написана.
	for _, outcome := range []string{
		ShadowVerdictOutcomeCompared, ShadowVerdictOutcomeDiverged, ShadowVerdictOutcomeUnfinished,
	} {
		a, okA := shadowSeries(t, full, outcome)
		b, okB := shadowSeries(t, sparse, outcome)
		require.True(t, okA)
		require.True(t, okB)
		require.Equalf(t, a, b, "предпосылка пробы: клетка %q обязана совпадать у обоих состояний", outcome)
	}

	decA, okA := shadowSeries(t, full, ShadowVerdictOutcomeDecisions)
	decB, okB := shadowSeries(t, sparse, ShadowVerdictOutcomeDecisions)
	require.True(t, okA, "клетка решений отсутствует: доля сравнённого не считается ни от чего, "+
		"и «сравнили три» одинаково верно для полного охвата и для трёх сотых")
	require.True(t, okB, "клетка решений отсутствует у сравнителя с редким охватом")
	require.NotEqual(t, decA, decB,
		"вывод не различает полный охват (%v) и три сотых (%v) — знаменатель остался внутри процесса", decA, decB)
	require.Equal(t, 6.0, decA)
	require.Equal(t, 100.0, decB)
}

// TestShadowVerdictCollector_EveryOutcomeCellExistsBeforeFirstUse — отсутствие
// серии отвечало бы сразу и «исхода не было», и «коллектор не провязан».
func TestShadowVerdictCollector_EveryOutcomeCellExistsBeforeFirstUse(t *testing.T) {
	reg := NewRegistry()
	reg.NewShadowVerdictCollector(func() ShadowVerdictCounts { return ShadowVerdictCounts{} })

	for _, outcome := range ShadowVerdictOutcomes {
		v, ok := shadowSeries(t, reg, outcome)
		require.Truef(t, ok, "клетка %q отсутствует до первого наблюдения: «не случалось» "+
			"неотличимо от «не провязано»", outcome)
		require.Equalf(t, 0.0, v, "клетка %q до первого наблюдения обязана быть нулём", outcome)
	}
}

// TestShadowVerdictCollector_ReadsTheLiveCountersNotACopy — коллектор читает те же
// счётчики, что растут на пути запроса, а не собственный слепок момента сборки.
//
// Копия сняла бы ровно ту проблему, ради которой заводится читатель: величина
// была бы наблюдаема и при этом навсегда нулевой.
func TestShadowVerdictCollector_ReadsTheLiveCountersNotACopy(t *testing.T) {
	live := ShadowVerdictCounts{}
	reg := NewRegistry()
	reg.NewShadowVerdictCollector(func() ShadowVerdictCounts { return live })

	if v, _ := shadowSeries(t, reg, ShadowVerdictOutcomeCompared); v != 0 {
		t.Fatalf("до сравнений клетка сравнений = %v, ожидался 0", v)
	}
	live = ShadowVerdictCounts{Compared: 3, Diverged: 1, Unfinished: 2}

	cmpV, _ := shadowSeries(t, reg, ShadowVerdictOutcomeCompared)
	divV, _ := shadowSeries(t, reg, ShadowVerdictOutcomeDiverged)
	unfV, _ := shadowSeries(t, reg, ShadowVerdictOutcomeUnfinished)
	require.Equal(t, 3.0, cmpV, "коллектор отдал слепок момента сборки, а не живой счётчик")
	require.Equal(t, 1.0, divV)
	require.Equal(t, 2.0, unfV,
		"«не выполнилось» обязано быть отдельным рядом: слитое со сравнениями, оно объявляет "+
			"сравнение состоявшимся там, где ответа не получено")
}

// TestShadowVerdictCollector_RefusesASourcelessRegistration — коллектор без
// источника величин не заводится.
//
// Молчаливая регистрация вечного нуля хуже отсутствия метрики: она выглядит как
// работающее наблюдение и утверждает «сравнений не было» о сравнителе, которого
// просто не спросили.
func TestShadowVerdictCollector_RefusesASourcelessRegistration(t *testing.T) {
	reg := NewRegistry()
	require.Panics(t, func() { reg.NewShadowVerdictCollector(nil) },
		"коллектор без источника зарегистрировался: вечный ноль неотличим от молчания сравнителя")
}
