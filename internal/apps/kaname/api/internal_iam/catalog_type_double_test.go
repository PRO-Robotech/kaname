// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// seededCatalogTypes — читатель, стоящий за ПОСЕЯННЫЕ строки каталога.
type seededCatalogTypes struct{}

// DottedTypeTx — имя каталога у посеянной строки; `ok=false` у всего остального.
func (seededCatalogTypes) DottedTypeTx(_ context.Context, _ service.Tx, modelType string) (string, bool, error) {
	dotted, ok := authzmap.DottedType(modelType)
	return dotted, ok, nil
}

// seededPolicies — политика записи ПОСЕВА (kaname#982, миграция
// 20261026090000): указатели посеянных строк, записей `writes` посев не несёт.
// Перечень — только типы, которые трогают пробы на подставных портах: дублёр
// политики не выводит (у сборки указателей нет), и тип вне перечня — отказ
// дублёра, а не «политики нет». Отвечающий на всё дублёр пропустил бы запись,
// которую продукт отвергает.
var seededPolicies = map[string]domain.WritePolicy{
	"vpc_network": {ObjectType: "vpc_network",
		Pointers: []domain.ParentPointer{{Name: "project", Type: "project"}}},
	"storage_volume": {ObjectType: "storage_volume",
		Pointers: []domain.ParentPointer{{Name: "project", Type: "project"}}},
	"registry_registry": {ObjectType: "registry_registry",
		Pointers: []domain.ParentPointer{{Name: "project", Type: "project"}}},
	"registry_repository": {ObjectType: "registry_repository",
		Pointers: []domain.ParentPointer{{Name: "parent", Type: "registry_registry"}}},
}

// WritePolicyTx — политика посеянной строки; `live=false` у имени, которого
// посев не несёт.
func (seededCatalogTypes) WritePolicyTx(_ context.Context, _ service.Tx, typeName string) (string, domain.WritePolicy, bool, error) {
	modelType := authzmap.ModelTypeName(typeName)
	dotted, known := authzmap.DottedType(modelType)
	if !known {
		return "", domain.WritePolicy{}, false, nil
	}
	policy, ok := seededPolicies[modelType]
	if !ok {
		return "", domain.WritePolicy{}, false, fmt.Errorf("дублёр каталога: политика посеянного типа %q не задана", modelType)
	}
	return dotted, policy, true, nil
}
