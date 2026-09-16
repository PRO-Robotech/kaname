// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// single_posture_gate_test.go — ПОСАДКА ОДНА, и координаты дерева обязаны
// разрешаться в ней все до одной.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Резолв писался под ДВЕ посадки: модуль внутри дерева платформы и модуль
// самостоятельным клоном. Первой не существует ни в одном дереве — каталога
// `services/iam` нет ни у платформы, ни здесь, — поэтому «дерева платформы рядом
// нет» перестало быть свойством КЛОНА и стало свойством ВСЕГО. Пробы, спросившие
// об этом дереве, пропускали себя ВСЕГДА, и молчание было неотличимо от работы.
//
// Отсюда несущее утверждение этого файла: дерево, которое судят пробы, есть
// дерево САМОГО МОДУЛЯ, и оно устанавливается в любом прогоне. Третьего исхода
// «платформы рядом нет» больше не существует — не «его не бывает», а его нет как
// ветви: снятие символа держит компилятор, а не обещание.
//
// Осталась одна законная причина отказать — координата, называющая ЧУЖОЕ дерево
// (маршрутизатор платформы, манифест соседнего модуля). Она НЕ пропуск: предмета
// у такой пробы в этом репозитории нет вовсе, и тихо соглашаться с ней нельзя.

package treeposture_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/treeposture"
)

// TestTheModuleJudgesItsOwnTree — несущее: корень суждения есть корень модуля, и
// он устанавливается в ЛЮБОЙ посадке.
func TestTheModuleJudgesItsOwnTree(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	module, err := treeposture.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не установлен: %v", err)
	}

	root, err := treeposture.RootFrom(wd)
	if err != nil {
		t.Fatalf("дерево, которое судят пробы, не установлено: %v", err)
	}
	if root != module {
		t.Fatalf("корнем суждения назван %s, а модуль лежит в %s — пробы судили бы чужое дерево", root, module)
	}

	corpusRoot, prefix := mustCorpus(t, wd)
	if corpusRoot != module {
		t.Fatalf("корень обхода %s разошёлся с корнем модуля %s", corpusRoot, module)
	}
	if prefix != "" {
		t.Fatalf("приставка обхода %q непуста: модуль сам себе дерево, и всякая приставка "+
			"промахивается мимо состава МОЛЧА", prefix)
	}
	t.Logf("посадка одна: корень суждения %s, приставка обхода пуста", root)
}

func mustCorpus(t *testing.T, wd string) (string, string) {
	t.Helper()
	root, prefix, err := treeposture.CorpusRoot(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень обхода не установлен: %v", err)
	}
	return root, prefix
}

// TestEveryTopLevelEntryOfThisModuleIsAResolvableCoordinate — перепись: всякая
// верхнеуровневая запись дерева модуля разрешается как координата.
//
// Единица счёта — верхнеуровневый каталог модуля, и он ВЫВОДИТСЯ обходом, а не
// выписан: выписанный перечень разошёлся бы с деревом на первом же новом
// каталоге, и разошёлся бы молча.
func TestEveryTopLevelEntryOfThisModuleIsAResolvableCoordinate(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	module, err := treeposture.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	entries, err := os.ReadDir(module)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: дерево модуля не читается: %v", err)
	}
	var dirs []string
	for _, e := range entries {
		if !e.IsDir() || e.Name() == ".git" || e.Name() == "." {
			continue
		}
		dirs = append(dirs, e.Name())
	}
	sort.Strings(dirs)
	if len(dirs) == 0 {
		t.Fatalf("обход пуст: верхнеуровневых каталогов модуля прочитано 0 — вердикта нет ни об одной координате")
	}

	resolved := 0
	for _, d := range dirs {
		got, perr := treeposture.PathOf(wd, d)
		if perr != nil {
			t.Errorf("координата %q ОТВЕРГНУТА, хотя каталог лежит в дереве модуля: %v", d, perr)
			continue
		}
		if got != filepath.Join(module, d) {
			t.Errorf("координата %q сведена в %s, а каталог лежит в %s", d, got, filepath.Join(module, d))
			continue
		}
		resolved++
	}
	t.Logf("перепись: верхнеуровневых каталогов модуля %d · разрешено координат %d", len(dirs), resolved)
}

// TestContractCoordinateResolvesInTheTreeThatShipsIt — контракт ЕДЕТ с модулем,
// и его координата обязана разрешаться.
//
// Прежний резолв отвергал её как «часть дерева платформы, у арендатора
// отсутствующую by construction» — посылка была ложной: каталог контрактов лежит
// в этом же репозитории и уезжает вместе с ним.
func TestContractCoordinateResolvesInTheTreeThatShipsIt(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	for _, rel := range []string{
		"proto/kaname/cloud/iam/v1/role.proto",
		"proto/kaname/cloud/iam/v1/fga_model.fga",
		"proto/corelib/operation/operation.proto",
	} {
		p, perr := treeposture.PathOf(wd, rel)
		if perr != nil {
			t.Errorf("%s: координата отвергнута: %v", rel, perr)
			continue
		}
		if _, serr := os.Stat(p); serr != nil {
			t.Errorf("%s: координата сведена в %s, а файла там нет: %v", rel, p, serr)
		}
	}
}

// TestHistoricCoordinateOfTheModuleStillResolves — историческая запись координат
// (`services/iam/...`) осталась в 347 файлах проб, и резолв обязан её знать.
//
// Распознаватель, знающий одну форму записи, оставляет всё записанное второй вне
// наблюдения — здесь это было бы половиной корпуса.
func TestHistoricCoordinateOfTheModuleStillResolves(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	module, err := treeposture.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	for _, c := range []struct{ rel, want string }{
		{"services/iam", module},
		{"services/iam/internal/migrations", filepath.Join(module, "internal", "migrations")},
		{"services/iam/cmd/kaname", filepath.Join(module, "cmd", "kaname")},
	} {
		got, perr := treeposture.PathOf(wd, c.rel)
		if perr != nil {
			t.Errorf("%s: историческая координата отвергнута: %v", c.rel, perr)
			continue
		}
		if got != c.want {
			t.Errorf("%s: сведена в %s, ожидалось %s", c.rel, got, c.want)
		}
	}
}
