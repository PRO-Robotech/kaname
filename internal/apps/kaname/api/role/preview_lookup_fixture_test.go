// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// preview_lookup_fixture_test.go — набор глаголов типа для проб, гоняющих
// проекцию роли НАПРЯМУЮ.
//
// Проекция отвергает роль без набора (#1994): показ по словарю, порождённому
// сборкой, неотличим от честного превью, поэтому «нечем ответить» — отказ, а не
// тихий запасной путь. На пути продукта набор вешает чтение (`attachIntegrity`)
// и эхо мутации; проба, собравшая роль руками, обязана сделать то же.
//
// Каталог берётся у фикстуры, равной ПОСЕВУ МИГРАЦИИ, — то есть проба видит тот
// же каталог, что и служба на исправном стенде.

import (
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// withPreviewLookup вешает на роль набор глаголов типа по посеянному каталогу.
func withPreviewLookup(r domain.Role) domain.Role {
	r.TypeVerbs = catalogfixture.Facts().RolePreviewLookup()
	return r
}
