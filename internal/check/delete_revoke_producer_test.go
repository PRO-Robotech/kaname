// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// delete_revoke_producer_test.go — гейт симметрии снятия (kacho#2055).
//
// Утверждает свойство ДЕРЕВА: у каждого пути снятия собственного объекта iam
// есть производитель отзыва — со-коммитнутое в ту же writer-tx событие
// реконсайла вида «delete» на СВОЙ тип. Воркер реконсайла на событие зовёт
// `ReconcileObject`, а тот на отсутствующем объекте получает ПУСТОЙ желаемый
// набор — что и есть отзыв (`reconcile.go`, ветка `objPresent == false`).
//
// Что гейт НЕ утверждает, и это сказано прямо: он судит НАЛИЧИЕ производителя, а
// не то, что отзыв доехал. Доезд — свойство прогона, его держит воркер и его
// собственные пробы; здесь бы утверждение о доезде было вакуумным.

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestDeletingAnOwnObjectHasARevokeProducer — гейт по дереву.
func TestDeletingAnOwnObjectHasARevokeProducer(t *testing.T) {
	apiDir := platformtree.RequirePath(t, "services/iam/internal/apps/kaname/api")

	census, findings, err := ScanDeleteRevokeProducers(apiDir)
	if err != nil {
		t.Fatalf("обход каталога use-case: %v", err)
	}
	t.Log(census.String())

	// Пустой обход — ОТКАЗ, а не молчание: «ноль находок» обязано быть отличимо
	// от «ноль прочитанного». Три величины проверяются порознь, потому что
	// обнулиться каждая может по своей причине.
	if census.Dirs == 0 {
		t.Fatalf("обход пуст: каталогов use-case под %s ноль — вердикт беспредметен", apiDir)
	}
	if census.Files == 0 {
		t.Fatalf("обход пуст: не-тестовых файлов Go прочитано ноль — вердикт беспредметен")
	}
	if census.Population == 0 {
		t.Fatalf("популяция пуста: ни у одного каталога не выведен свой тип вместе с путём " +
			"снятия — либо вывод типа разошёлся с деревом, либо признак эмиссии перестал " +
			"находиться; вердикт беспредметен")
	}

	for _, f := range findings {
		t.Errorf("снятие без производителя отзыва — %s", f)
	}
}
