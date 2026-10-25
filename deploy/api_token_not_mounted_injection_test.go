// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// api_token_not_mounted_injection_test.go — способность меры токена API упасть и
// смолчать доказывается ИНЪЕКЦИЕЙ, а не прочтением (задача kaname#997).
//
// Прогонов три, и третий обязателен:
//
//	контроль          — чарт цел: мера молчит;
//	снятое поле       — строка поля убрана из шаблона: краснеет;
//	обратная величина — литерал шаблона `true`: краснеет, называя величину.
//
// Каждая инъекция меняет против контроля РОВНО ОДИН факт. Вердикт снимается с
// РЕНДЕРА копии чарта, а не с дерева: правка дерева сделала бы вердикт свойством
// прогона и уронила бы соседние полосы, работающие в этой же копии.
package deploy_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var apiTokenInjectionChain = []string{"values.yaml", "values.prod.yaml"}

// TestProdProfile_RenderedTokenInjection_ChartAsDeliveredIsSilent — КОНТРОЛЬ.
//
// Стоит первым намеренно: инъекция, чей контроль не проверен, доказывает не
// способность меры упасть, а то, что она падает всегда.
func TestProdProfile_RenderedTokenInjection_ChartAsDeliveredIsSilent(t *testing.T) {
	m := apiTokenMountInRender(renderChartAt2(t, chartCopy(t), apiTokenInjectionChain, minimalOperatorCoordinates...))
	require.NotZero(t, m.Specs, "обход пуст: Deployment в рендере не найден — вердикт беспредметен")
	require.Equalf(t, m.Specs, m.SpecsOff, "поставляемый чарт токен монтирует (величины %#v): "+
		"контроль инъекции красен, и вердикты инъекций ниже недействительны", m.Values)
	t.Logf("контроль: spec пода %d · без токена %d", m.Specs, m.SpecsOff)
}

// TestProdProfile_RenderedTokenInjection_DroppedFieldIsFound — ДЕФЕКТ: поля нет,
// и кластер применит умолчание платформы — монтировать.
func TestProdProfile_RenderedTokenInjection_DroppedFieldIsFound(t *testing.T) {
	dir := chartCopy(t)
	dropLineInCopy(t, dir, "templates/deployment.yaml", apiTokenField+":")
	m := apiTokenMountInRender(renderChartAt2(t, dir, apiTokenInjectionChain, minimalOperatorCoordinates...))
	require.NotZero(t, m.Specs, "обход пуст: вердикт беспредметен")
	require.Zerof(t, m.SpecsOff, "выключение всё ещё видно при убранном поле: мера смотрит НЕ ТУДА "+
		"(spec пода %d, величины %#v)", m.Specs, m.Values)
}

// TestProdProfile_RenderedTokenInjection_OppositeLiteralIsFound — ДЕФЕКТ второй
// оси: поле на месте, литерал шаблона обратный. Мера, проверяющая лишь НАЛИЧИЕ
// поля, зеленела бы на включённом монтировании.
func TestProdProfile_RenderedTokenInjection_OppositeLiteralIsFound(t *testing.T) {
	dir := chartCopy(t)
	patchInCopy(t, dir, "templates/deployment.yaml", apiTokenField+": false", apiTokenField+": true")
	m := apiTokenMountInRender(renderChartAt2(t, dir, apiTokenInjectionChain, minimalOperatorCoordinates...))
	require.NotZero(t, m.Specs, "обход пуст: вердикт беспредметен")
	require.Zerof(t, m.SpecsOff, "мера сочла токен выключенным при величине %#v — она проверяет "+
		"НАЛИЧИЕ поля, а не его значение", m.Values)
}
