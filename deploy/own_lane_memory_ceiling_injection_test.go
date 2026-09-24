// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_lane_memory_ceiling_injection_test.go — способность меры упасть и
// смолчать доказывается ИНЪЕКЦИЕЙ, а не прочтением.
//
// Прогонов четыре, и первый — контроль:
//
//	контроль          — чарт цел: обе половины молчат;
//	снятый рендер     — блок `resources` убран из шаблона: Р1 краснеет, и страж
//	                    называет «предел не наложен» — тот же отказ, что дал
//	                    живой процесс до починки;
//	предел ниже нужды — профиль объявляет предел меньше бюджета: Р2 краснеет
//	                    отказом стража «превышает предел среды»;
//	законный близнец  — предел РОВНО равен бюджету: страж молчит. Без него
//	                    мера, требующая «больше», зеленела бы на профиле,
//	                    который стража не проходит по строгому неравенству,
//	                    и краснела бы на том, который проходит.
//
// Каждая инъекция меняет против контроля РОВНО ОДИН факт. Вердикт снимается с
// РЕНДЕРА копии чарта, а не с дерева.
package deploy_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// resourcesBlockInTemplate — исполняемая часть блока в шаблоне развёртывания,
// которую инъекция снимает. Копия текста намеренно ДОСЛОВНАЯ: изменится шаблон
// — инъекция не найдёт, что портить, и скажет об этом сама, а не пройдёт
// молча.
const resourcesBlockInTemplate = "          {{- with .Values.resources }}\n" +
	"          resources:\n" +
	"            {{- toYaml . | nindent 12 }}\n" +
	"          {{- end }}\n"

// TestInjection_ChartAsDeliveredCarriesTheOwnLaneMemoryLimit — КОНТРОЛЬ.
func TestInjection_ChartAsDeliveredCarriesTheOwnLaneMemoryLimit(t *testing.T) {
	dir := chartCopy(t)
	sets := withOwnPosture(minimalOperatorCoordinates...)
	rendered := renderChartAt2(t, dir, chartProfiles, sets...)
	limit, declared, raw := memoryLimitOfServiceContainer(t, rendered)
	census, err := judgeOwnLaneMemoryCeiling(loginLaneOfRender(t, rendered), limit, declared, raw)
	require.NoErrorf(t, err, "контроль инъекции красен — вердикты инъекций ниже недействительны: %s", census)
	t.Logf("контроль: %s", census)
}

// TestInjection_DroppingTheResourcesBlockIsFound — ДЕФЕКТ: шаблон не рендерит
// предел. Это состояние дерева ДО починки, снятое живым процессом.
func TestInjection_DroppingTheResourcesBlockIsFound(t *testing.T) {
	dir := chartCopy(t)
	patchInCopy(t, dir, "templates/deployment.yaml", resourcesBlockInTemplate, "")

	sets := withOwnPosture(minimalOperatorCoordinates...)
	rendered := renderChartAt2(t, dir, chartProfiles, sets...)
	limit, declared, raw := memoryLimitOfServiceContainer(t, rendered)
	require.Falsef(t, declared, "мера видит предел %q при снятом блоке — она смотрит НЕ ТУДА, "+
		"и её зелёный на настоящем чарте ничего не означает", raw)
	_, err := judgeOwnLaneMemoryCeiling(loginLaneOfRender(t, rendered), limit, declared, raw)
	require.Error(t, err, "страж смолчал на неналоженном пределе — мера зовёт не стража")
	require.Contains(t, err.Error(), "предел памяти средой не наложен",
		"отказ называет не тот предмет: читатель пошёл бы чинить не то")
}

// TestInjection_LimitBelowTheBudgetIsFound — ДЕФЕКТ второй оси: предел
// объявлен, но меньше бюджета полосы.
func TestInjection_LimitBelowTheBudgetIsFound(t *testing.T) {
	dir := chartCopy(t)
	sets := withOwnPosture(append([]string{"resources.limits.memory=512Mi"}, minimalOperatorCoordinates...)...)
	rendered := renderChartAt2(t, dir, chartProfiles, sets...)
	limit, declared, raw := memoryLimitOfServiceContainer(t, rendered)
	require.True(t, declared, "инъекция не объявила предел — она проверяла бы не ту ось")
	census, err := judgeOwnLaneMemoryCeiling(loginLaneOfRender(t, rendered), limit, declared, raw)
	require.Errorf(t, err, "страж принял предел ниже бюджета — мера проверяет НАЛИЧИЕ, а не величину: %s", census)
	require.Contains(t, err.Error(), "превышает предел среды",
		"отказ называет не тот предмет: читатель пошёл бы чинить не то")
}

// TestInjection_LimitEqualToTheBudgetIsLegal — ЗАКОННЫЙ БЛИЗНЕЦ: предел равен
// бюджету байт в байт. Величина ВЫЧИСЛЯЕТСЯ из рендера, а не выписывается:
// выписанная разошлась бы с бюджетом на первой смене ёмкости.
func TestInjection_LimitEqualToTheBudgetIsLegal(t *testing.T) {
	dir := chartCopy(t)
	// Бюджет читается ПОДПРОБОЙ: загрузчик настроек привязывает окружение
	// прогона, и второе чтение в той же пробе застало бы его занятым.
	var need uint64
	t.Run("бюджет", func(t *testing.T) {
		probe := renderChartAt2(t, dir, chartProfiles, withOwnPosture(minimalOperatorCoordinates...)...)
		census, _ := judgeOwnLaneMemoryCeiling(loginLaneOfRender(t, probe), 0, false, "")
		need = census.Need
	})
	require.NotZero(t, need, "бюджет полосы не прочитан — близнеца не из чего построить")

	sets := withOwnPosture(append([]string{fmt.Sprintf("resources.limits.memory=%d", need)}, minimalOperatorCoordinates...)...)
	rendered := renderChartAt2(t, dir, chartProfiles, sets...)
	limit, declared, raw := memoryLimitOfServiceContainer(t, rendered)
	require.True(t, declared)
	require.Equal(t, need, limit, "предел прочитан не тем числом, которым объявлен")
	twin, err := judgeOwnLaneMemoryCeiling(loginLaneOfRender(t, rendered), limit, declared, raw)
	require.NoErrorf(t, err, "страж отверг предел, РОВНО равный бюджету: мера строже стража — "+
		"она краснела бы на профиле, который процесс принимает: %s", twin)
}

// TestParseMemoryQuantity_KnowsTheFormsAndRefusesTheRest — распознаватель
// величины знает все формы количества, которыми профиль вправе её записать, и
// на незнакомой ОТКАЗЫВАЕТ, а не читает ноль.
func TestParseMemoryQuantity_KnowsTheFormsAndRefusesTheRest(t *testing.T) {
	for in, want := range map[string]uint64{
		"1280Mi": 1342177280, "1Gi": 1 << 30, "512Ki": 512 << 10, "2Ti": 2 << 40,
		"1342177280": 1342177280, "500M": 500_000_000, "1G": 1_000_000_000, "8k": 8000, "1T": 1_000_000_000_000,
	} {
		got, err := parseMemoryQuantity(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got, in)
	}
	for _, bad := range []string{"", "Mi", "1.5Gi", "1280MiB", "abc", "-1Mi"} {
		_, err := parseMemoryQuantity(bad)
		require.Errorf(t, err, "форма %q прочитана числом — незнакомая запись обязана быть отказом", bad)
	}
	t.Logf("перепись: законных форм 9 · отвергнутых 6 · %s", strings.Join([]string{"двоичные", "десятичные", "голые байты"}, " · "))
}
