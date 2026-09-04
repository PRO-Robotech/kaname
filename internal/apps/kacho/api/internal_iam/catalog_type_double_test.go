// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_iam

// catalog_type_double_test.go — дублёр читателя словаря каталога для проб,
// идущих на подставных портах (без базы).
//
// ─────────────────────────────────────────────────────────────────────────────
// ДУБЛЁР НЕ СНИСХОДИТЕЛЬНЕЕ ПРОДУКТА, И ЭТО ЕГО ГЛАВНОЕ СВОЙСТВО
//
// Он отвечает ровно на те имена, которые каталог несёт ПОСЕЯННЫМИ, — то есть
// стоит за состояние базы, на котором служба поднимается. Согласие посева со
// словарём сборки не допущение: его требует страж старта
// (`seed.AssertCatalogParity`) и он отказывает в пуске при расхождении, поэтому
// перечень посеянных пар здесь БЕРЁТСЯ у сборки, а не выписывается второй копией.
//
// Незнакомое имя даёт `ok=false` — ровно как настоящий читатель на типе, строки
// которого у платформы нет. Дублёр, отвечающий на всё, сделал бы невидимым
// именно тот дефект, ради которого порт заведён (kacho#1990).
//
// ЗАВЕДЁННОГО ПРИМЕНЕНИЕМ типа здесь нет и быть не может: его строку кладёт
// работающий процесс, а не сборка. Такой вход утверждает проба на живой базе
// (`register_resource_applied_type_integration_test.go`) — подставной читатель
// сказал бы о нём только то, что в него вписали.

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// seededCatalogTypes — читатель, стоящий за ПОСЕЯННЫЕ строки каталога.
type seededCatalogTypes struct{}

// DottedTypeTx — имя каталога у посеянной строки; `ok=false` у всего остального.
func (seededCatalogTypes) DottedTypeTx(_ context.Context, _ service.Tx, modelType string) (string, bool, error) {
	dotted, ok := authzmap.DottedType(modelType)
	return dotted, ok, nil
}
