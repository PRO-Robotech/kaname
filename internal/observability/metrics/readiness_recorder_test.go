// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// readiness_recorder_test.go — исход готовности ПРОИЗВОДИТ величину, и величина
// различает три состояния, а не два (задача продукта #2494).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Имена зависимостей готовности выходили наружу ТОЛЬКО в теле пробы. Дежурный
// видел один бит — «под не готов» — и, чтобы узнать, какая именно зависимость
// отказала, должен был пробросить порт на слушатель, поднятый по TLS, и
// спросить его в обход проверки сертификата. Ни один документ поставки этого не
// называет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ
//
//	Р1  ряды заведены НУЛЁМ при регистрации, а не при первой оценке: клетка,
//	    появляющаяся при первом попадании, неотличима от «ещё не случалось»;
//	Р2  величина ИЗМЕНИЛАСЬ при событии и НЕ ИЗМЕНИЛАСЬ без него — по каждой
//	    зависимости отдельно;
//	Р3  три состояния различимы ПО ИМЕНИ зависимости: «база недоступна» ·
//	    «образ не той версии, что схема» · «исполнитель ещё не поднялся»;
//	Р4  пустой набор зависимостей — ОТКАЗ, а не тихая регистрация без рядов.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/observability/health"
)

// readinessCell — значение ряда одной зависимости и одного исхода.
func readinessCell(t *testing.T, r *Registry, dependency, outcome string) (value float64, present bool) {
	t.Helper()
	return labelledCounter(t, r, ReadinessChecksMetric,
		map[string]string{"dependency": dependency, "outcome": outcome})
}

// TestReadinessRecorder_CellsExistBeforeTheFirstEvaluation — Р1.
func TestReadinessRecorder_CellsExistBeforeTheFirstEvaluation(t *testing.T) {
	reg := NewRegistry()
	reg.ReadinessRecorder([]string{"database", "schema-version", "lro-worker"})

	for _, dependency := range []string{"database", "schema-version", "lro-worker"} {
		for _, outcome := range ReadinessOutcomes {
			value, present := readinessCell(t, reg, dependency, outcome)
			require.Truef(t, present, "ряда %s{dependency=%q,outcome=%q} нет ДО первой оценки — "+
				"«зависимость ни разу не оценивали» тогда неотличимо от «оценивали и всё хорошо»",
				ReadinessChecksMetric, dependency, outcome)
			require.Zerof(t, value, "ряд %s{dependency=%q,outcome=%q} заведён не нулём",
				ReadinessChecksMetric, dependency, outcome)
		}
	}
}

// TestReadinessRecorder_MovesOnTheEventAndNotWithoutIt — Р2.
func TestReadinessRecorder_MovesOnTheEventAndNotWithoutIt(t *testing.T) {
	reg := NewRegistry()
	rec := reg.ReadinessRecorder([]string{"database", "lro-worker"})

	rec.Observe("database", false)

	down, ok := readinessCell(t, reg, "database", ReadinessOutcomeUnready)
	require.True(t, ok)
	require.Equal(t, 1.0, down, "исход зависимости наблюдён, а ряд не двинулся")

	up, ok := readinessCell(t, reg, "database", ReadinessOutcomeReady)
	require.True(t, ok)
	require.Zero(t, up, "ряд готовности вырос на событии НЕготовности")

	for _, outcome := range ReadinessOutcomes {
		value, ok := readinessCell(t, reg, "lro-worker", outcome)
		require.True(t, ok)
		require.Zerof(t, value, "ряд соседней зависимости двинулся без своего события (outcome=%q)", outcome)
	}

	rec.Observe("lro-worker", true)
	value, ok := readinessCell(t, reg, "lro-worker", ReadinessOutcomeReady)
	require.True(t, ok)
	require.Equal(t, 1.0, value)
}

// TestReadinessRecorder_NamesWhichDependencyRefused — Р3: три состояния,
// различимые БЕЗ чтения тела пробы.
//
// Проба идёт через НАСТОЯЩИЙ носитель готовности и его обработчик: провязка
// через объявленную опцию — то самое, чего не было, и утверждать её надо на
// живом пути, а не на прямом вызове приёмника.
func TestReadinessRecorder_NamesWhichDependencyRefused(t *testing.T) {
	reg := NewRegistry()
	rec := reg.ReadinessRecorder([]string{"database", "schema-version", "lro-worker"})

	agg := health.New([]health.Checker{
		{Name: "database", Check: func(context.Context) error { return nil }},
		// «Образ не той версии, что схема» — УСЛОВИЕ НЕ СОЗДАНО: накат не
		// прогнан либо откат поставил прежний образ на новую схему.
		{Name: "schema-version", Check: func(context.Context) error {
			return errors.New("схема ушла вперёд образа")
		}},
		// «Исполнитель ещё не поднялся» — носителя зависимости пока нет.
		{Name: "lro-worker", Check: func(context.Context) error {
			return health.ErrDependencyNotWired
		}},
	}, health.WithResultObserver(rec.Observe))

	rr := httptest.NewRecorder()
	agg.ReadyHandler()(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusServiceUnavailable, rr.Code, "предпосылка пробы: под обязан быть НЕ готов")

	ok0, present := readinessCell(t, reg, "database", ReadinessOutcomeReady)
	require.True(t, present)
	require.Equal(t, 1.0, ok0, "исправная зависимость не отражена — «не готов» тогда снова один бит")

	for _, dependency := range []string{"schema-version", "lro-worker"} {
		value, present := readinessCell(t, reg, dependency, ReadinessOutcomeUnready)
		require.True(t, present)
		require.Equalf(t, 1.0, value, "неготовая зависимость %q не названа ни одной величиной", dependency)
	}

	value, present := readinessCell(t, reg, "database", ReadinessOutcomeUnready)
	require.True(t, present)
	require.Zero(t, value, "исправная зависимость записана в неготовые")
}

// TestReadinessRecorder_EmptySetIsRefused — Р4: пустой вход не заводит ни одного
// ряда, и молчащая витрина была бы неотличима от исправной.
func TestReadinessRecorder_EmptySetIsRefused(t *testing.T) {
	reg := NewRegistry()
	require.Panics(t, func() { reg.ReadinessRecorder(nil) },
		"пустой набор зависимостей принят молча: рядов не будет ни одного, и витрина "+
			"будет выглядеть так же, как при исправной готовности")
}

// TestReadinessRecorder_SecondWiringDoesNotKillTheProcess — реестр один, а
// носитель готовности в прогоне собирается не единожды.
func TestReadinessRecorder_SecondWiringDoesNotKillTheProcess(t *testing.T) {
	reg := NewRegistry()
	first := reg.ReadinessRecorder([]string{"database"})
	second := reg.ReadinessRecorder([]string{"database", "schema-version"})
	require.Same(t, first, second, "второй вызов завёл ВТОРОГО приёмника — ряды разъехались бы по двум")

	value, present := readinessCell(t, reg, "schema-version", ReadinessOutcomeReady)
	require.True(t, present, "зависимость, добавленная вторым вызовом, рядов не получила")
	require.Zero(t, value)
}
