// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// public_read_sc70_test.go — SC-70 (в): третья форма манифеста registry,
// нарушающая правило ключа, отвергается на ЗАГРУЗКЕ, раньше сборки модели
// (задача PRO-Robotech/kaname#856).
//
// Приёмка docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md,
// редакция 10, отпечаток 198db838d0a75b7f5b5bdbd5564bacec23a79cc00550a26e8830f3c6be61aac9.
// Сборочная половина SC-70 — `internal/modelcompose`, `TestCompose_SC70_…`.
//
// Порядок несущий: фикстура (новая редакция без ключа доставляется), затем
// близнец (б) — новая редакция с ключом на `registries` доставляется, — затем
// предмет (в): тот же документ с ключом на `repositories`. Отличие (в) от (б) —
// одно поле: ресурс, на котором стоит ключ (дельту сверяет фикстура).

import (
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// TestLoadDelivered_SC70_c_KeyOnTheChildIsRefusedAtLoad — SC-70 (в).
func TestLoadDelivered_SC70_c_KeyOnTheChildIsRefusedAtLoad(t *testing.T) {
	doc, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	keyless, err := publicreadfixture.WithoutKey(doc)
	if err != nil {
		t.Fatalf("фикстура: близнец без ключа: %v", err)
	}
	if _, err := manifest.LoadDelivered(deliveryDir(t, map[string]string{"registry/manifest.yaml": string(keyless)})); err != nil {
		t.Fatalf("фикстура: новая редакция без ключа обязана доставляться: %v", err)
	}
	third, err := publicreadfixture.KeyMovedToRepositories(doc)
	if err != nil {
		t.Fatalf("фикстура: третья форма (в): %v", err)
	}

	if _, err := manifest.LoadDelivered(deliveryDir(t, map[string]string{"registry/manifest.yaml": string(doc)})); err != nil {
		t.Fatalf("SC-70 (в) близнец (б): доставка новой редакции отвергнута (предмета S5 нет): %v", err)
	}

	root := deliveryDir(t, map[string]string{"registry/manifest.yaml": string(third)})
	_, err = manifest.LoadDelivered(root)
	const finding = "resources[1].publicReadToChildren: на тип registry_repository не указывает ни один ресурс модуля registry — объявление без следствия"
	head := fmt.Sprintf("каталог доставки %s: манифестов прочитано 1, находок 1", root)
	if err == nil || !strings.Contains(err.Error(), finding) || !strings.Contains(err.Error(), head) {
		t.Fatalf("SC-70 (в): отказ доставки обязан нести %q и находку %q, получено: %v", head, finding, err)
	}
}
