// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// relation_verdict_grounds_collector_test.go — основания, на которых форма
// отвечает о доступе, обязаны быть ВИДНЫ снаружи.
//
// Величины, которые здесь выходят наружу, копились с тех пор, когда их читало
// ТЕНЕВОЕ СРАВНЕНИЕ форм. Сравнения больше нет — оно снято вместе с внешним
// движком прав, — и читателя у величин не осталось ни одного. При этом сама
// форма из теневой стала ЕДИНСТВЕННЫМ источником вердикта, то есть считаются
// они теперь на живом пути решения о доступе, а не на наблюдаемом со стороны.
//
// Ненаблюдаемый счётчик отвечает на два разных вопроса одним молчанием:
// «события не было ни разу» и «код, который его считает, вообще не исполнялся»
// (security.md §Hardening-инвариант 8). Для этих двух величин вторым состоянием
// закрываются два тихих отказа:
//
//   - меточная ветвь перестала спрашиваться НА ОДНОЙ ИЗ ОСЕЙ — выдачи по меткам
//     на этой оси молча не действуют, а арендатор видит «прав не выдали»;
//   - отказы по основанию «типа нет в словаре модели» растут — значит кто-то
//     называет тип с опечаткой, доступ пропадает, и выглядит это так же.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func labelArmSeries(t *testing.T, r *Registry, axis string) (value float64, present bool) {
	t.Helper()
	return labelledCounter(t, r, RelationVerdictLabelArmGroundsMetric, map[string]string{"axis": axis})
}

// TestRelationVerdictGroundsCollector_EveryCellExistsBeforeFirstUse — отсутствие
// ряда отвечало бы сразу и «не случалось», и «не провязано».
func TestRelationVerdictGroundsCollector_EveryCellExistsBeforeFirstUse(t *testing.T) {
	reg := NewRegistry()
	reg.NewRelationVerdictGroundsCollector(func() RelationVerdictGrounds { return RelationVerdictGrounds{} })

	for _, axis := range RelationVerdictLabelAxes {
		v, ok := labelArmSeries(t, reg, axis)
		require.Truef(t, ok, "ось %q отсутствует до первого наблюдения: «ветвь молчала» "+
			"тогда неотличимо от «ось не провязана»", axis)
		require.Equalf(t, 0.0, v, "ось %q", axis)
	}
	for _, name := range []string{
		RelationVerdictEarlyStopsMetric,
		RelationVerdictUndeclaredTypeDenialsMetric,
	} {
		v, ok := labelledCounter(t, reg, name, map[string]string{})
		require.Truef(t, ok, "ряд %q отсутствует до первого наблюдения", name)
		require.Equalf(t, 0.0, v, "ряд %q", name)
	}
}

// TestRelationVerdictGroundsCollector_AxesStayApart — ось, переставшая
// спрашиваться, обязана быть видна ОТДЕЛЬНО.
//
// Ровно этот дефект и жил: меточная ветвь отвечала на одной оси и молчала на
// второй. Одно число на обе оси доказывает половину и молчит про другую —
// именно так дефект и дожил до находки.
func TestRelationVerdictGroundsCollector_AxesStayApart(t *testing.T) {
	// Ось зеркала работает, ось собственных таблиц iam молчит.
	half := NewRegistry()
	half.NewRelationVerdictGroundsCollector(func() RelationVerdictGrounds {
		return RelationVerdictGrounds{LabelArmMirror: 7}
	})
	// Обе оси работают.
	whole := NewRegistry()
	whole.NewRelationVerdictGroundsCollector(func() RelationVerdictGrounds {
		return RelationVerdictGrounds{LabelArmMirror: 7, LabelArmIAMDirect: 4}
	})

	mHalf, ok := labelArmSeries(t, half, RelationVerdictLabelAxisMirror)
	require.True(t, ok)
	mWhole, ok := labelArmSeries(t, whole, RelationVerdictLabelAxisMirror)
	require.True(t, ok)
	require.Equal(t, mHalf, mWhole,
		"предпосылка пробы: по оси зеркала эти два состояния НЕ различаются")

	dHalf, ok := labelArmSeries(t, half, RelationVerdictLabelAxisIAMDirect)
	require.True(t, ok, "ряд оси собственных таблиц отсутствует — молчащая ось невидима")
	dWhole, ok := labelArmSeries(t, whole, RelationVerdictLabelAxisIAMDirect)
	require.True(t, ok)
	require.NotEqual(t, dHalf, dWhole,
		"вывод не различает молчащую ось (%v) и работающую (%v)", dHalf, dWhole)
	require.Equal(t, 0.0, dHalf)
	require.Equal(t, 4.0, dWhole)
}

// TestRelationVerdictGroundsCollector_EarlyStopsAreReadableBesideTheArm —
// знаменатель выходит наружу РЯДОМ с оснóваниями, а не вместо них.
//
// Ранний выход прекращает чтение на первом безусловном основании, поэтому ноль
// оснований меточной ветви означает либо «ветвь молчала», либо «до неё не
// дочитали». Скрыть эту неопределённость было бы хуже, чем назвать её.
func TestRelationVerdictGroundsCollector_EarlyStopsAreReadableBesideTheArm(t *testing.T) {
	reg := NewRegistry()
	reg.NewRelationVerdictGroundsCollector(func() RelationVerdictGrounds {
		return RelationVerdictGrounds{EarlyStops: 41}
	})
	v, ok := labelledCounter(t, reg, RelationVerdictEarlyStopsMetric, map[string]string{})
	require.True(t, ok, "знаменатель не выходит наружу — ноль оснований ветви "+
		"неотличим от «до ветви не дочитали»")
	require.Equal(t, 41.0, v)
}

// TestRelationVerdictGroundsCollector_UndeclaredTypeDenialsAreObservable —
// растущий счётчик отказов по неизвестному типу обязан быть виден.
//
// Величина мала и обязана такой оставаться: её законный источник — вопрос про
// снятый тип. Рост означает опечатку в имени типа НАСТОЯЩЕГО ресурса, при
// которой доступ пропадает, а выглядит это как «прав не выдали».
func TestRelationVerdictGroundsCollector_UndeclaredTypeDenialsAreObservable(t *testing.T) {
	quiet := NewRegistry()
	quiet.NewRelationVerdictGroundsCollector(func() RelationVerdictGrounds { return RelationVerdictGrounds{} })
	noisy := NewRegistry()
	noisy.NewRelationVerdictGroundsCollector(func() RelationVerdictGrounds {
		return RelationVerdictGrounds{UndeclaredTypeDenials: 3}
	})

	q, ok := labelledCounter(t, quiet, RelationVerdictUndeclaredTypeDenialsMetric, map[string]string{})
	require.True(t, ok)
	n, ok := labelledCounter(t, noisy, RelationVerdictUndeclaredTypeDenialsMetric, map[string]string{})
	require.True(t, ok)
	require.Equal(t, 0.0, q)
	require.Equal(t, 3.0, n)
}

// TestRelationVerdictGroundsCollector_ReadsLiveValuesOnEverySweep — коллектор
// обязан спрашивать источник НА КАЖДОМ СБОРЕ, а не запоминать снимок.
//
// Запомненный снимок даёт неподвижный ряд при живом счётчике: наблюдение
// выглядит исправным и утверждает неправду о ветви, которая работает.
func TestRelationVerdictGroundsCollector_ReadsLiveValuesOnEverySweep(t *testing.T) {
	var live int64
	reg := NewRegistry()
	reg.NewRelationVerdictGroundsCollector(func() RelationVerdictGrounds {
		return RelationVerdictGrounds{UndeclaredTypeDenials: live}
	})

	first, ok := labelledCounter(t, reg, RelationVerdictUndeclaredTypeDenialsMetric, map[string]string{})
	require.True(t, ok)
	require.Equal(t, 0.0, first)

	live = 9
	second, ok := labelledCounter(t, reg, RelationVerdictUndeclaredTypeDenialsMetric, map[string]string{})
	require.True(t, ok)
	require.Equal(t, 9.0, second, "коллектор запомнил снимок: ряд неподвижен при живом счётчике")
}

// TestRelationVerdictGroundsCollector_RefusesASourcelessRegistration — вечный
// ноль без источника выглядит как работающее наблюдение и утверждает неправду.
func TestRelationVerdictGroundsCollector_RefusesASourcelessRegistration(t *testing.T) {
	reg := NewRegistry()
	require.Panics(t, func() { reg.NewRelationVerdictGroundsCollector(nil) },
		"коллектор без источника зарегистрировался: вечный ноль неотличим от "+
			"нетронутого разбора оснований")
}
