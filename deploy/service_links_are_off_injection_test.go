// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// service_links_are_off_injection_test.go — способность меры упасть и смолчать
// доказывается ИНЪЕКЦИЕЙ, а не прочтением.
//
// Прогонов три, и третий обязателен:
//
//	контроль         — чарт цел: мера молчит;
//	снятое гашение   — строка убрана: краснеет, называя цепочку профилей;
//	обратная величина — `true` вместо `false`: краснеет, называя величину.
//
// Каждая инъекция меняет против контроля РОВНО ОДИН факт — объявление в spec
// пода. Иначе неизвестно, какой из двух дал красное, и вердикт недействителен,
// хотя выглядит как обычный зелёный.
//
// Вердикт снимается с РЕНДЕРА копии чарта, а не с дерева: правка дерева сделала
// бы вердикт свойством прогона и уронила бы соседние полосы, работающие в этой
// же копии.
package deploy_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// serviceLinksOffInRender — объявлено ли гашение в рендере, и с какой величиной.
//
// Суждение отделено от дерева прогона намеренно: мера, чью способность падать
// нельзя предъявить иначе как поломкой настоящего чарта, доказательства не
// имеет.
func serviceLinksOffInRender(rendered string) (specs int, off int, values []any) {
	for _, doc := range strings.Split(rendered, "\n---") {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var obj map[string]any
		if yaml.Unmarshal([]byte(doc), &obj) != nil {
			continue
		}
		if kind, _ := obj["kind"].(string); kind != "Deployment" {
			continue
		}
		spec, _ := obj["spec"].(map[string]any)
		tmpl, _ := spec["template"].(map[string]any)
		ps, ok := tmpl["spec"].(map[string]any)
		if !ok {
			continue
		}
		specs++
		v, declared := ps["enableServiceLinks"]
		values = append(values, v)
		if b, isBool := v.(bool); declared && isBool && !b {
			off++
		}
	}
	return specs, off, values
}

// TestInjection_ChartAsDeliveredSilencesTheLinks — КОНТРОЛЬ.
//
// Стоит первым намеренно: инъекция, чей контроль не проверен, доказывает не
// способность меры упасть, а то, что она падает всегда.
func TestInjection_ChartAsDeliveredSilencesTheLinks(t *testing.T) {
	dir := chartCopy(t)
	specs, off, values := serviceLinksOffInRender(
		renderChartAt2(t, dir, []string{"values.yaml", "values.prod.yaml"}, minimalOperatorCoordinates...))
	require.NotZero(t, specs, "обход пуст: Deployment в рендере не найден — вердикт беспредметен")
	require.Equalf(t, specs, off, "поставляемый чарт гашения НЕ несёт (величины %#v): "+
		"контроль инъекции красен, и вердикты обеих инъекций ниже недействительны", values)
	t.Logf("контроль: spec пода %d · гашение объявлено в %d", specs, off)
}

// TestInjection_DroppingTheLineIsFound — ДЕФЕКТ: строка убрана.
func TestInjection_DroppingTheLineIsFound(t *testing.T) {
	dir := chartCopy(t)
	dropLineInCopy(t, dir, "templates/deployment.yaml", "enableServiceLinks:")

	specs, off, _ := serviceLinksOffInRender(
		renderChartAt2(t, dir, []string{"values.yaml", "values.prod.yaml"}, minimalOperatorCoordinates...))
	require.NotZero(t, specs, "обход пуст: вердикт беспредметен")
	require.Zerof(t, off, "гашение всё ещё объявлено при убранной строке: мера смотрит НЕ ТУДА, "+
		"и её зелёный на настоящем чарте ничего не означает (spec пода %d)", specs)
}

// TestInjection_TheOppositeValueIsFound — ДЕФЕКТ второй оси: строка на месте,
// величина обратная. Отличается от контроля РОВНО ОДНИМ фактом.
//
// Ось отдельная намеренно: мера, проверяющая лишь НАЛИЧИЕ ключа, зеленела бы на
// `enableServiceLinks: true` — то есть на включённой подстановке.
func TestInjection_TheOppositeValueIsFound(t *testing.T) {
	dir := chartCopy(t)
	patchInCopy(t, dir, "templates/deployment.yaml",
		"enableServiceLinks: false", "enableServiceLinks: true")

	specs, off, values := serviceLinksOffInRender(
		renderChartAt2(t, dir, []string{"values.yaml", "values.prod.yaml"}, minimalOperatorCoordinates...))
	require.NotZero(t, specs, "обход пуст: вердикт беспредметен")
	require.Zerof(t, off, "мера сочла подстановку погашенной при величине %#v — она проверяет "+
		"НАЛИЧИЕ ключа, а не его значение", values)
}
