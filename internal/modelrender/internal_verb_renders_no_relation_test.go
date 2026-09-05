// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// internal_verb_renders_no_relation_test.go — действие ВНУТРЕННЕЙ плоскости не
// порождает отношения модели, а действие тенантской — порождает.
//
// ПРЕДМЕТ. Раздел `resources` объявляет плоскость действия ключом `internal`, и
// плоскость эта сверяется с каталогом прав (roleexport/linkage.go). Но рендер
// блоков модели о плоскости не знал вовсе и выводил `define v_<действие>` из
// ВСЯКОГО объявленного действия — то есть объявить внутреннее действие было
// нельзя ни одним входом: побайтовая сверка канона отвергала порождённое сверх
// него отношение. Возможность была объявлена, покрыта типом, прочитана тремя
// местами — и неисполнима.
//
// ПОЧЕМУ ОТНОШЕНИЯ БЫТЬ НЕ ДОЛЖНО, А НЕ «ПОКА НЕ НУЖНО». Замер по каталогу
// (101 внутреннее действие шести модулей): гейт внутреннего действия спрашивает
// ЛИБО ярус области (`system_admin`/`system_viewer` на `cluster` — 58), ЛИБО
// отношение, которое уже порождает объявленное ТЕНАНТСКОЕ действие того же
// ресурса (`v_update`/`v_get` на `vpc_address` — 8), ЛИБО собственное отношение
// ресурса (`editor`, `realization_writer`, `announce_writer`, … ), ЛИБО не
// спрашивает ничего (18 освобождённых). Ни одно не спрашивает отношения, которое
// породило бы ТОЛЬКО внутреннее действие.
//
// Значит порождённое `v_internal…` было бы отношением, которого не спрашивает ни
// один гейт: право на него выдаётся, перечисляется в роли и не даёт ДОСТУПА НИ К
// ЧЕМУ. Отличить такую выдачу от неисполненной вызывающему нечем. Тот же довод
// уже записан в загрузчике у базовых ярусов (`validateResourceBaseRoles`).
//
// ОБЕ СТОРОНЫ. Односторонняя проба («внутреннего отношения нет») зеленела бы на
// рендере, который не порождает НИЧЕГО, поэтому тенантский близнец в том же
// блоке обязателен и утверждается тем же прогоном.
package modelrender_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
	"github.com/PRO-Robotech/kacho-iam/internal/modelrender"
)

const internalPlaneDoc = `apiVersion: iam/v1
module: vpc
resources:
  - name: network
    objectType: vpc_network
    parents: [project]
    producer: derived
    verbs:
      - get
      - {name: internalGetNetwork, class: get, internal: true}
`

func TestInternalVerbRendersNoRelationWhileTenantVerbDoes(t *testing.T) {
	m, err := manifest.Load([]byte(internalPlaneDoc))
	if err != nil {
		t.Fatalf("манифест с внутренним действием не прочитан: %v", err)
	}

	if len(m.Resources) != 1 {
		t.Fatalf("ресурсов прочитано %d, ожидался 1 — предмет пробы не тот", len(m.Resources))
	}
	body, err := modelrender.Render(m.Resources[0])
	if err != nil {
		t.Fatalf("рендер блока: %v", err)
	}
	text := string(body)
	if strings.TrimSpace(text) == "" {
		t.Fatal("блок пуст — предмет пуст, вердикт беспредметен")
	}

	tenant := manifest.VerbRelationName("get")
	internal := manifest.VerbRelationName("internalGetNetwork")

	// Положительный контроль: тенантское действие отношение ПОРОЖДАЕТ. Без него
	// отрицание ниже зеленело бы на пустом рендере.
	if !strings.Contains(text, "define "+tenant+":") {
		t.Errorf("тенантское действие не породило %q — рендер пуст по существу, "+
			"и отрицание ниже нечем отличить от вакуумного:\n%s", tenant, text)
	}

	if strings.Contains(text, "define "+internal+":") {
		t.Errorf("внутреннее действие породило отношение %q. Его не спрашивает ни один "+
			"гейт: право выдаётся, перечисляется в роли и не даёт доступа ни к чему. "+
			"Плюс побайтовая сверка канона отвергнет строку, которой в модели нет:\n%s",
			internal, text)
	}

	t.Logf("осмотрено: байт блока %d · тенантских отношений искали 1 · внутренних 1",
		len(text))
}
