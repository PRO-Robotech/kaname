// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package platformtree даёт ПРОБЕ исход резолва координат дерева.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ И ЧЕГО ЗДЕСЬ НЕТ
//
// Здесь — только превращение исхода резолва в `t.Fatalf`. Сам резолв (какой
// корень судят пробы, как привести к нему координату, от какого корня брать
// состав) живёт в `internal/treeposture` и НЕ ЗНАЕТ про `testing`.
//
// Разрез не косметический. Тот же вопрос задают приборы модуля — отпечаток сетки
// замера, писатель отчётов, — и они прод-код: пакет с `testing` в импорте они
// звать не вправе, иначе испытательная оснастка уезжает в поставляемый двоичный.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРОПУСКА ЗДЕСЬ БОЛЬШЕ НЕТ — И ЭТО ГЛАВНОЕ, ЧТО СТОИТ ЗНАТЬ
//
// Пакет отдавал пробе третий исход — пропуск «дерева платформы рядом с модулем
// нет». Предпосылка была свойством КЛОНА ровно до выноса службы отдельным
// репозиторием; после него каталога `services/iam` нет НИ В ОДНОМ дереве, и
// пропуск стал безусловным. Замер на стволе `83ddd08a`: 58 пропусков, 54
// верхнеуровневые пробы, среди них гейт безопасности «у каждого публичного RPC
// есть пообъектный вопрос». Молчание такой пробы неотличимо от исправной работы.
//
// Поэтому ветви пропуска НЕТ. Её отсутствие держит компилятор — символа
// `ErrNoPlatformTree` не существует, — а не перепись и не обещание.
//
// Осталась одна причина отказать, и она ГРОМКАЯ: координата называет дерево,
// которого в этом репозитории нет (`treeposture.ErrForeignTree`). У такой пробы
// здесь нет предмета; её снимают вместе с предметом либо переносят туда, где
// предмет живёт. Тихо соглашаться с ней нельзя — именно так пропуск и переживает
// свою предпосылку.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО БРАТЬ — ТРИ ВХОДА, И ОНИ О РАЗНОМ
//
//	Require       — пробе нужен КОРЕНЬ дерева, которое она судит;
//	RequirePath   — пробе нужен ОДИН файл по координате дерева;
//	RequireCorpus — проба ОБХОДИТ состав и судит его целиком: возвращает корень
//	                обхода и приставку модуля в нём (пустую).
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
	ErrForeignTree       = treeposture.ErrForeignTree
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

// refuse — единая точка превращения исхода резолва в исход пробы.
//
// Одна на все входы намеренно: копии этого ветвления разошлись бы на первой же
// правке текста, и разошлись бы молча.
func refuse(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, ErrForeignTree) {
		t.Fatalf("У ЭТОЙ ПРОВЕРКИ ЗДЕСЬ НЕТ ПРЕДМЕТА (не пропуск): %v", err)
	}
	t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
}

// Require — корень дерева, которое судит проба.
func Require(t *testing.T) string {
	t.Helper()
	root, err := treeposture.RootFrom(wd(t))
	if err != nil {
		refuse(t, err)
	}
	return root
}

// RequirePath — координата, приведённая к дереву прогона.
func RequirePath(t *testing.T, rel string) string {
	t.Helper()
	p, err := treeposture.PathOf(wd(t), rel)
	if err != nil {
		refuse(t, err)
	}
	return p
}

// RequireCorpus — корень обхода и приставка модуля в нём.
func RequireCorpus(t *testing.T) (root, prefix string) {
	t.Helper()
	root, prefix, err := treeposture.CorpusRoot(wd(t))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	return root, prefix
}

// SiblingsDir — см. treeposture.SiblingsDir.
const SiblingsDir = treeposture.SiblingsDir

// PlatformTreeEnv — см. treeposture.PlatformTreeEnv.
const PlatformTreeEnv = treeposture.PlatformTreeEnv

// NamedPlatformRoot — см. treeposture.NamedPlatformRoot.
func NamedPlatformRoot() (string, string) { return treeposture.NamedPlatformRoot() }

// RequireNamedPlatformTree — корень дерева платформы, НАЗВАННЫЙ снаружи, либо
// пропуск с предпосылкой, у которой ЕСТЬ ПРОИЗВОДИТЕЛЬ.
//
// # Чем этот пропуск отличается от снятого
//
// Снятый пропуск («дерева платформы рядом с модулем нет») был БЕЗУСЛОВНЫМ: его
// предпосылка после выноса службы выполнялась всегда и ни в одной посадке не
// могла стать ложной. Проба, им помеченная, не исполнялась НИ РАЗУ, и отличить
// это от исправной работы было нечем.
//
// Здесь предпосылка — ручка, и её выставляет задание конвейера, выкладывающее
// манифесты соседних модулей. Значит пропуск наступает ровно там, где условие
// действительно не создано, и снимается СОЗДАНИЕМ УСЛОВИЯ, а не правкой пробы.
// Проба при этом исполняется в конвейере, а не только объявляет, что могла бы.
//
// Предмет таких проб — платформенный артефакт (таблица типов, порождённая из
// шести манифестов; побайтовая сверка канона модели с ними), и судить его по
// одному собственному манифесту нельзя: вердикт был бы о другом предмете.
func RequireNamedPlatformTree(t *testing.T) string {
	t.Helper()
	root, why := treeposture.NamedPlatformRoot()
	if why != "" {
		t.Skipf("УСЛОВИЕ НЕ СОЗДАНО (у предпосылки есть производитель): %s", why)
	}
	return root
}

// PathUnder — см. treeposture.PathUnder.
func PathUnder(root, rel string) (string, error) { return treeposture.PathUnder(root, rel) }

// PrefixUnder — см. treeposture.PrefixUnder.
func PrefixUnder(root string) string { return treeposture.PrefixUnder(root) }
