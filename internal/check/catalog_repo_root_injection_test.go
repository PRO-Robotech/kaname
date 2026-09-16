// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// catalog_repo_root_injection_test.go — доказательство того, что корень обхода
// гейтов этого пакета НЕ ВЫХОДИТ за границу судимого дерева.
//
// # Предмет
//
// Гейты пакета сверяют координаты ведомости с координатами обхода. Корень,
// взятый на уровень выше судимого дерева, добавляет к каждой координате лишнюю
// приставку — и тогда НЕ СОВПАДАЕТ НИ ОДИН ключ ведомости. Оба утверждения гейта
// переворачиваются разом: «отброшено вне ведомости» на всём и «нечего исключать»
// по каждой записи, — то есть гейт краснеет ДВАЖДЫ на исправном дереве и
// называет координаты, которые читаются как находка.
//
// Так и наблюдалось: рабочая копия, заведённая внутри другого checkout'а
// продукта, дала пять «находок» и три «нечего исключать» на нетронутом стволе
// (kacho#2429; из этого замера была заведена P0 kacho#2427, чья посылка оказалась
// неверна).
//
// # Что судит инъекция
//
// Каждая пара ниже отличается РОВНО ОДНИМ фактом — лежит ли модуль внутри
// каталога со своим `go.mod`. Всё прочее совпадает, поэтому покраснеть может
// только проверяемое свойство, а не сосед.

import (
	"os"
	"path/filepath"
	"testing"
)

// mkTreeModule — модуль (каталог с `go.mod`) по пути rel внутри base.
func mkTreeModule(t *testing.T, base, rel string) string {
	t.Helper()
	dir := filepath.Join(base, filepath.FromSlash(rel))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o600); err != nil {
		t.Fatalf("write go.mod в %s: %v", dir, err)
	}
	return dir
}

// foreignModuleAround — объемлющий каталог со СВОИМ `go.mod`: тот единственный
// факт, которым вложенная посадка отличается от обычной.
func foreignModuleAround(t *testing.T, base string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(base, "go.mod"),
		[]byte("module example.com/чужой\n"), 0o600); err != nil {
		t.Fatalf("объемлющий go.mod: %v", err)
	}
	inner := filepath.Join(base, "inner")
	if err := os.MkdirAll(inner, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", inner, err)
	}
	return inner
}

// TestCatalogRepoRoot_ModuleIsTheRoot — положительный близнец: модуль НЕ вложен
// в чужой каталог со своим `go.mod`. Без него утверждение ниже зеленело бы и на
// резолве, который всегда отдаёт что угодно.
func TestCatalogRepoRoot_ModuleIsTheRoot(t *testing.T) {
	base := t.TempDir()
	mod := mkTreeModule(t, base, "kaname-0.1.0")

	root, err := catalogRepoRootFrom(mod)
	if err != nil {
		t.Fatalf("корень обхода не установлен: %v", err)
	}
	if root != mod {
		t.Fatalf("корнем обхода назван %s, ожидался корень модуля %s", root, mod)
	}
}

// TestCatalogRepoRoot_HistoricPlatformLayoutStillNamesTheModule — посадка, под
// которую резолв писался прежде: модуль лежит в каталоге модулей платформы.
//
// Такой посадки в дереве больше нет, но резолв обязан оставаться ОДНОЗНАЧНЫМ и
// на ней: корнем обхода служит сам модуль, а не объемлющая платформа. Иначе
// координаты обхода получили бы приставку `services/iam/` и разошлись бы с
// координатами ведомости — молча, на всех ключах сразу.
func TestCatalogRepoRoot_HistoricPlatformLayoutStillNamesTheModule(t *testing.T) {
	base := t.TempDir()
	mod := mkTreeModule(t, base, "services/iam")

	root, err := catalogRepoRootFrom(mod)
	if err != nil {
		t.Fatalf("корень обхода не установлен: %v", err)
	}
	if root != mod {
		t.Fatalf("корнем обхода назван %s, ожидался корень модуля %s (объемлющий каталог — %s)",
			root, mod, base)
	}
}

// TestCatalogRepoRoot_NestedStandaloneCloneStaysTheRoot — вторая половина: в
// самостоятельном клоне корнем обхода служит сам модуль, и вложенность этого не
// меняет.
func TestCatalogRepoRoot_NestedStandaloneCloneStaysTheRoot(t *testing.T) {
	base := t.TempDir()
	inner := foreignModuleAround(t, base)
	mod := mkTreeModule(t, inner, "kaname-0.1.0")

	root, err := catalogRepoRootFrom(mod)
	if err != nil {
		t.Fatalf("корень обхода не установлен: %v", err)
	}
	if root != mod {
		t.Fatalf("корнем обхода назван %s, ожидался корень модуля %s "+
			"(объемлющий каталог — %s)", root, mod, base)
	}
}
