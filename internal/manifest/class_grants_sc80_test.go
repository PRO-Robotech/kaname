// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// class_grants_sc80_test.go — SC-80: форма ключа оболочки S7
// `classGrantsOnlyOnContainers` на ЗАГРУЗКЕ доставки (задача PRO-Robotech/kaname#950).
//
// Приёмка docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md,
// редакция 17, отпечаток d44a9bbbdfef42e5f33d0ded13754ff103a4ae33f7ad6d7695be3865b65f9ae7.
// Сборочная половина (а) — `internal/modelcompose`, `TestCompose_SC80_…`.
//
// Порядок несущий: сначала фикстура — документ П6 (ключа нет) доставляется, —
// затем (а) документ П7 (ключ равен true) и (б) документ П7 со значением false.
// Отличие (б) от (а) — одно значение ключа (дельту сверяет фикстура).

import (
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// sc80Docs — документ П6 (контроль доставлен) и документ П7.
func sc80Docs(t *testing.T) (p6, p7 []byte) {
	t.Helper()
	p6, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	if _, err := manifest.LoadDelivered(deliveryDir(t, map[string]string{"registry/manifest.yaml": string(p6)})); err != nil {
		t.Fatalf("фикстура: документ П6 (ключа S7 нет) обязан доставляться: %v", err)
	}
	p7, err = publicreadfixture.WithClassGrantsKey(p6)
	if err != nil {
		t.Fatalf("фикстура: документ П7: %v", err)
	}
	return p6, p7
}

// TestLoadDelivered_SC80_a_KeyTrueIsDelivered — SC-80 (а), половина загрузки:
// документ П7 доставляется. Что ключ доезжает до каталога, утверждает
// разбор строк каталога (`modulecatalog`, `TestRowsOf_SC80_…`).
func TestLoadDelivered_SC80_a_KeyTrueIsDelivered(t *testing.T) {
	_, p7 := sc80Docs(t)
	rep, err := manifest.LoadDelivered(deliveryDir(t, map[string]string{"registry/manifest.yaml": string(p7)}))
	if err != nil {
		t.Fatalf("SC-80 (а): доставка документа П7 отвергнута (ключа %s у загрузчика нет — предмета S7 нет): %v",
			publicreadfixture.ClassGrantsKey, err)
	}
	if len(rep.Manifests) != 1 || rep.Manifests[0].Module != "registry" {
		t.Fatalf("SC-80 (а): доставка обязана дать один манифест registry, получено %d", len(rep.Manifests))
	}
}

// TestLoadDelivered_SC80_b_FalseIsAFindingOfTheLoad — SC-80 (б): значение false
// — находка загрузки в составе сегодняшнего отказа доставки, раньше сборки
// модели. Близнец — (а): одно значение ключа.
func TestLoadDelivered_SC80_b_FalseIsAFindingOfTheLoad(t *testing.T) {
	p6, p7 := sc80Docs(t)
	if _, err := manifest.LoadDelivered(deliveryDir(t, map[string]string{"registry/manifest.yaml": string(p7)})); err != nil {
		t.Fatalf("SC-80 (б) близнец (а): доставка документа П7 отвергнута (предмета S7 нет): %v", err)
	}
	falseDoc, err := publicreadfixture.WithClassGrantsKeyValue(p6, "false")
	if err != nil {
		t.Fatalf("фикстура: документ П7 со значением false: %v", err)
	}
	root := deliveryDir(t, map[string]string{"registry/manifest.yaml": string(falseDoc)})
	_, err = manifest.LoadDelivered(root)
	const finding = "classGrantsOnlyOnContainers: значение false не принимается — ключ либо отсутствует, либо равен true"
	head := fmt.Sprintf("каталог доставки %s: манифестов прочитано 1, находок 1", root)
	if err == nil || !strings.Contains(err.Error(), finding) || !strings.Contains(err.Error(), head) {
		t.Fatalf("SC-80 (б): отказ доставки обязан нести %q и находку %q, получено: %v", head, finding, err)
	}
}
