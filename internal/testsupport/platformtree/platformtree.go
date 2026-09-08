// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package platformtree даёт ПРОБЕ третий исход вместо красного там, где дерева
// платформы рядом с модулем нет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ И ЧЕГО ЗДЕСЬ НЕТ
//
// Здесь — только превращение исхода резолва в `t.Skipf` либо `t.Fatalf`. Сам
// резолв (лежит ли модуль в дереве платформы, как привести координату к посадке,
// от какого корня брать состав) живёт в `internal/treeposture` и НЕ ЗНАЕТ про
// `testing`.
//
// Разрез не косметический. Тот же вопрос задают приборы модуля — отпечаток сетки
// замера, писатель отчётов, — и они прод-код: пакет с `testing` в импорте они
// звать не вправе, иначе испытательная оснастка уезжает в поставляемый двоичный.
// Пока резолв жил здесь, приборы складывали координату литералом и в
// самостоятельном клоне читали несуществующий подкаталог.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПРОПУСК ЗДЕСЬ НЕ МАСКА
//
// Пропуск, который проба назначает себе сама, был бы ровно тем механизмом,
// который корпус запрещает: его нельзя отличить от «проба сломалась, и её
// заглушили». Здесь пропуск назначает НЕ проба, а ПРЕДПОСЫЛКА — свойство дерева,
// проверяемое на месте:
//
//	дерево платформы ЕСТЬ  → Require возвращает корень, проба идёт целиком;
//	дерева платформы НЕТ   → пропуск с НАЗВАННОЙ причиной и координатой.
//
// Отсюда несущее свойство: **в монорепо пропуск невозможен**. Не «его там не
// бывает», а невозможен — детектор отвечает «есть», и ветвь пропуска не
// достижима ни для одной пробы. Держит это гейт-сосед
// (`platformtree_gate_test.go`), а не обещание.
//
// Пометка ИСТЕКАЕТ САМА в обратную сторону: приедет каталог контрактов в
// поставку модуля — детектор в клоне ответит «есть», и помеченные пробы начнут
// исполняться там, где раньше пропускались.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО БРАТЬ — ТРИ ВХОДА, И ОНИ О РАЗНОМ
//
//	Require       — пробе нужно ДЕРЕВО ПЛАТФОРМЫ целиком (манифесты соседних
//	                модулей, каталог контрактов, зонтичный чарт). В клоне —
//	                пропуск: этого в поставку не входит by construction;
//	RequirePath   — пробе нужен ОДИН файл, записанный координатой от корня
//	                платформы. Лежит внутри модуля — резолвится в обеих посадках;
//	                лежит вне — пропуск;
//	RequireCorpus — проба ОБХОДИТ состав и судит его целиком. Возвращает корень
//	                обхода и приставку модуля в нём (пустую в клоне). Пропуска
//	                НЕТ: предмет таких проб — собственная композиция модуля, и она
//	                в поставку входит.
package platformtree

import (
	"errors"
	"os"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/treeposture"
)

// Признаки резолва — те же, что у него: два места об одном предмете разошлись бы
// молча, поэтому здесь они переобъявлены ссылкой, а не копией.
var (
	ErrNoPlatformTree    = treeposture.ErrNoPlatformTree
	ErrModuleRootUnknown = treeposture.ErrModuleRootUnknown
)

// ModuleRootFrom — см. treeposture.ModuleRootFrom.
func ModuleRootFrom(start string) (string, error) { return treeposture.ModuleRootFrom(start) }

// RootFrom — см. treeposture.RootFrom.
func RootFrom(start string) (string, error) { return treeposture.RootFrom(start) }

// ModuleDirIn — см. treeposture.ModuleDirIn.
func ModuleDirIn(root, moduleRoot string) (string, error) {
	return treeposture.ModuleDirIn(root, moduleRoot)
}

// PathOf — см. treeposture.PathOf.
func PathOf(start, rel string) (string, error) { return treeposture.PathOf(start, rel) }

// CorpusRoot — см. treeposture.CorpusRoot.
func CorpusRoot(start string) (root, prefix string, err error) { return treeposture.CorpusRoot(start) }

// Under — см. treeposture.Under.
func Under(prefix, rel string) string { return treeposture.Under(prefix, rel) }

// ModuleDirInPlatform — см. treeposture.ModuleDirInPlatform.
func ModuleDirInPlatform() string { return treeposture.ModuleDirInPlatform() }

// wd — рабочий каталог либо ОТКАЗ: не установлен — судить не о чем.
func wd(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	return dir
}

// third — единая точка превращения исхода резолва в исход пробы.
//
// Одна на все три входа намеренно: три копии этого ветвления разошлись бы на
// первой же правке текста, и разошлись бы молча — пропуск и отказ выглядят
// одинаково, пока не прочитать перепись.
func third(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, ErrNoPlatformTree) {
		t.Skipf("УСЛОВИЕ НЕ СОЗДАНО (не находка): %v", err)
	}
	t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
}

// Require — корень дерева платформы либо ПРОПУСК с названной предпосылкой.
func Require(t *testing.T) string {
	t.Helper()
	root, err := treeposture.RootFrom(wd(t))
	if err != nil {
		third(t, err)
	}
	return root
}

// RequirePath — координата, приведённая к посадке, либо ПРОПУСК.
func RequirePath(t *testing.T, rel string) string {
	t.Helper()
	p, err := treeposture.PathOf(wd(t), rel)
	if err != nil {
		third(t, err)
	}
	return p
}

// RequireCorpus — корень обхода и приставка модуля в нём.
//
// Пропуска НЕТ by construction: обе посадки дают ответ, и отказ здесь означает,
// что корня нет ни у одной, — то есть проба не может назвать дерево, о котором
// говорит.
func RequireCorpus(t *testing.T) (root, prefix string) {
	t.Helper()
	root, prefix, err := treeposture.CorpusRoot(wd(t))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	return root, prefix
}

// PathUnder — см. treeposture.PathUnder.
func PathUnder(root, rel string) (string, error) { return treeposture.PathUnder(root, rel) }

// PrefixUnder — см. treeposture.PrefixUnder.
func PrefixUnder(root string) string { return treeposture.PrefixUnder(root) }
