// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package treeroot отвечает на ОДИН вопрос: какое дерево судит этот каталог — и
// его ли это дерево.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Корень дерева выводили арифметикой пути: `"../../../.."` от каталога пакета.
// Такое выражение есть координата РАСКЛАДКИ монорепо, а не свойство модуля, и
// вне монорепо оно резолвится МОЛЧА — давая каталог, в который распаковали клон.
// Наблюдалось прямо: обход ушёл в исходники тулчейна Go, лежащие в домашнем
// каталоге оператора (kacho#2254), а гейт соглашения о вкладе читал ведомость по
// вычисленному пути (kacho#2239).
//
// Существенно не то, что проверка при этом падала. Существенно, что дерево, где
// по вычисленному пути лежит нечто годное, дало бы ЗЕЛЁНЫЙ — вердикт о ЧУЖОМ
// дереве, неотличимый от настоящего.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВА УТВЕРЖДЕНИЯ, И ВТОРОЕ НЕСУЩЕЕ
//
//  1. корень назван ИНДЕКСОМ (`rev-parse --show-toplevel`), а не числом уровней;
//  2. найденное дерево ОТСЛЕЖИВАЕТ каталог, из которого спрашивают.
//
// Без второго модуль, распакованный внутрь постороннего репозитория, получил бы
// корень того репозитория — и первое утверждение выполнялось бы при этом
// безупречно. Именно поэтому проверок две, а не одна.
//
// ─────────────────────────────────────────────────────────────────────────────
// ИСХОДОВ ДВА, ТРЕТЬЕГО НЕТ
//
// Предпосылка выполнена — корень назван; не выполнена — отказ, НАЗЫВАЮЩИЙ её
// словами. Молчаливое вычисление чужого пути исходом не является: «не знаю» не
// выдаётся ни за «нет находок», ни за «находка».
package treeroot

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
)

// ErrTreeNotResolved — дерево назвать нечем: проверка НЕ ИСПОЛНЯЛАСЬ.
//
// Отдельный признак, а не общий отказ: «дерева нет» и «в дереве находка» —
// разные исходы, и первый не вычитается из вердикта и не зачитывается в успех.
var ErrTreeNotResolved = errors.New("дерево под резолвом не установлено")

// ErrModuleRootUnknown — корень модуля не установлен подъёмом за маркером.
var ErrModuleRootUnknown = errors.New("корень модуля не установлен")

// Of — корень дерева, которому принадлежит start.
func Of(start string) (string, error) {
	out, err := gitenv.Command(start, "rev-parse", "--show-toplevel").Output()
	root := strings.TrimSpace(string(out))
	if err != nil || root == "" {
		return "", fmt.Errorf(
			"%w: каталог не принадлежит репозиторию\n  осмотрено:        %s\n"+
				"  ожидался признак: git отвечает на rev-parse --show-toplevel\n"+
				"  на распакованном архиве вердикта о дереве нет и быть не может — это\n"+
				"  «проверка НЕ ИСПОЛНЯЛАСЬ», а не находка",
			ErrTreeNotResolved, start)
	}

	// Предпосылка, несущая: найденное дерево содержит ТО МЕСТО, откуда
	// спрашивают, своим отслеживаемым составом.
	tracked, terr := gitenv.Command(start, "ls-files", "--", ".").Output()
	if terr != nil || len(bytes.TrimSpace(tracked)) == 0 {
		return "", fmt.Errorf(
			"%w: дерево %s не отслеживает каталог, из которого спрашивают\n"+
				"  осмотрено:        %s\n"+
				"  ожидался признак: непустой ответ git ls-files в этом каталоге\n"+
				"  его нет — значит каталог лежит внутри ПОСТОРОННЕГО репозитория и им не\n"+
				"  отслеживается; вердикт того дерева к этому коду отношения не имеет",
			ErrTreeNotResolved, root, start)
	}
	return root, nil
}

// ModuleRootFrom поднимается от start до БЛИЖАЙШЕГО каталога с `go.mod`.
//
// Маркер, а не число уровней и не имя каталога: имя у арендатора выбирает тот,
// кто клонировал, а число уровней верно ровно для одной посадки.
func ModuleRootFrom(start string) (string, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("%w: %s не приводится к абсолютному: %w", ErrModuleRootUnknown, start, err)
	}
	for {
		if st, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil && st.Mode().IsRegular() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("%w: маркер go.mod не найден подъёмом от %s", ErrModuleRootUnknown, start)
		}
		dir = parent
	}
}

// Placement — посадка модуля: дерево, которое его судит, и его путь в этом
// дереве.
//
// ModuleDir выводится, а не выписывается, и потому верен в ОБЕИХ посадках:
// `services/iam` внутри монорепо, `.` в самостоятельном клоне. Выписанная
// координата верна ровно в одной и молча неверна в другой.
type Placement struct {
	// RepoRoot — корень дерева, спрошенный у индекса; предпосылка проверена.
	RepoRoot string
	// ModuleRoot — корень модуля, найденный маркером go.mod.
	ModuleRoot string
	// ModuleDir — путь модуля ОТНОСИТЕЛЬНО RepoRoot.
	ModuleDir string
}

// Locate — посадка модуля, найденного от start.
func Locate(start string) (Placement, error) {
	moduleRoot, err := ModuleRootFrom(start)
	if err != nil {
		return Placement{}, err
	}
	root, err := Of(moduleRoot)
	if err != nil {
		return Placement{}, err
	}
	rel, rerr := filepath.Rel(root, moduleRoot)
	if rerr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return Placement{}, fmt.Errorf(
			"%w: модуль %s не сводится под корень %s — дерево найдено ЧУЖОЕ",
			ErrTreeNotResolved, moduleRoot, root)
	}
	return Placement{RepoRoot: root, ModuleRoot: moduleRoot, ModuleDir: filepath.ToSlash(rel)}, nil
}
