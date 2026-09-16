// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package platformtree_test

// platformtree_gate_test.go — обёртка отдаёт пробе ИСХОД, и исходов у неё два.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ПРОВЕРЯЕТСЯ, А ЧТО ДЕРЖИТ КОМПИЛЯТОР
//
// Прежде здесь стояло утверждение «в монорепо ветвь пропуска недостижима»: из
// него следовало «пропущенных проб ноль» без переписи по каждой пробе. Оно было
// верно для своей посадки и пережило её — монорепо не несёт этого модуля ни
// одним файлом, поэтому ветвь пропуска стала достижимой ВСЕГДА.
//
// Пропуска больше нет как ветви, и держит это НЕ проба, а компилятор: символа
// `ErrNoPlatformTree` в дереве не существует, и вернуть его нечем. Здесь
// проверяется то, что компилятор не держит: что резолв даёт пробе ПУТЬ там, где
// файл действительно лежит в этом дереве, и ГРОМКИЙ отказ там, где координата
// называет чужое.
//
// Инъекция меняет ровно один факт против своего близнеца — существует ли
// названный первым сегментом каталог.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// mkModule — модуль (каталог с go.mod) по пути rel внутри base.
func mkModule(t *testing.T, base, rel string) string {
	t.Helper()
	dir := filepath.Join(base, filepath.FromSlash(rel))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestInThisTreeTheResolverNamesTheModuleItself — несущее утверждение о ДЕРЕВЕ
// ПРОГОНА: корень суждения установлен и совпадает с корнем модуля.
//
// Проба печатает, что именно она увидела: молчаливое «зелено» здесь означало бы,
// что корень мог оказаться каким угодно и никто этого не заметил.
func TestInThisTreeTheResolverNamesTheModuleItself(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	moduleRoot, err := platformtree.ModuleRootFrom(dir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не установлен: %v", err)
	}
	root, err := platformtree.RootFrom(dir)
	if err != nil {
		t.Fatalf("корень суждения не установлен: %v", err)
	}
	if root != moduleRoot {
		t.Fatalf("корнем суждения назван %s, а модуль лежит в %s", root, moduleRoot)
	}
	t.Logf("посадка одна: корень суждения %s", root)
}

// --- инъекция в резолв: обе стороны на синтетических деревьях ---------------

// TestResolver_CoordinateOfThisTreeResolves — положительный близнец: первый
// сегмент координаты есть запись дерева.
func TestResolver_CoordinateOfThisTreeResolves(t *testing.T) {
	base := t.TempDir()
	mod := mkModule(t, base, "kaname-0.1.0")
	if err := os.MkdirAll(filepath.Join(mod, "proto", "kaname"), 0o750); err != nil {
		t.Fatal(err)
	}

	got, err := platformtree.PathOf(mod, "proto/kaname/x.proto")
	if err != nil {
		t.Fatalf("координата собственного дерева отвергнута: %v", err)
	}
	if want := filepath.Join(mod, "proto", "kaname", "x.proto"); got != want {
		t.Fatalf("сведено в %s, ожидалось %s", got, want)
	}
}

// TestResolver_ForeignCoordinateIsALoudRefusal — инъекция. Отличается от
// близнеца выше РОВНО ОДНИМ фактом: каталога, названного первым сегментом, в
// дереве нет.
func TestResolver_ForeignCoordinateIsALoudRefusal(t *testing.T) {
	base := t.TempDir()
	mod := mkModule(t, base, "kaname-0.1.0")
	if err := os.MkdirAll(filepath.Join(mod, "proto", "kaname"), 0o750); err != nil {
		t.Fatal(err)
	}

	_, err := platformtree.PathOf(mod, "gateway/internal/middleware/embed/permission_catalog.json")
	if !errors.Is(err, platformtree.ErrForeignTree) {
		t.Fatalf("координата чужого дерева принята за свою: %v", err)
	}
	if !strings.Contains(err.Error(), "ожидался признак") ||
		!strings.Contains(err.Error(), "Предмета у такой проверки здесь НЕТ") {
		t.Fatalf("отказ не назвал предпосылку словами: %v", err)
	}
}

// TestResolver_HistoricCoordinateOfTheModuleStillResolves — вторая законная
// запись координаты. Распознаватель, знающий одну форму, оставил бы вне
// наблюдения сотни файлов корпуса — молча.
func TestResolver_HistoricCoordinateOfTheModuleStillResolves(t *testing.T) {
	base := t.TempDir()
	mod := mkModule(t, base, "kaname-0.1.0")

	got, err := platformtree.PathOf(mod, "services/iam/internal/migrations")
	if err != nil {
		t.Fatalf("историческая запись координаты отвергнута: %v", err)
	}
	if want := filepath.Join(mod, "internal", "migrations"); got != want {
		t.Fatalf("сведено в %s, ожидалось %s", got, want)
	}
	if got, err = platformtree.PathOf(mod, "services/iam"); err != nil || got != mod {
		t.Fatalf("сам модуль: получено %q (%v), ожидалось %q", got, err, mod)
	}
}

// TestResolver_NoModuleMarkerIsNotRun — третий исход представим отдельно:
// «корня модуля нет» не выдаётся ни за путь, ни за чужое дерево.
func TestResolver_NoModuleMarkerIsNotRun(t *testing.T) {
	deep := filepath.Join(t.TempDir(), "а", "б")
	if err := os.MkdirAll(deep, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := platformtree.RootFrom(deep); !errors.Is(err, platformtree.ErrModuleRootUnknown) {
		t.Fatalf("отсутствие корня модуля выдано за вердикт о дереве: %v", err)
	}
	if _, err := platformtree.PathOf(deep, "proto/x"); !errors.Is(err, platformtree.ErrModuleRootUnknown) {
		t.Fatalf("отсутствие корня модуля выдано за вердикт о координате: %v", err)
	}
}

// TestModuleDirIn_IsDerivedNotComposed — путь модуля в дереве выводится.
//
// Для корня, совпадающего с модулем, приставка ПУСТА, а не «.»: склейка «./x» не
// совпадает ни с одной записью состава, и промах был бы молчаливым.
func TestModuleDirIn_IsDerivedNotComposed(t *testing.T) {
	for _, c := range []struct{ root, mod, want string }{
		{"/д", "/д/services/iam", filepath.FromSlash("services/iam")},
		{"/д", "/д", ""},
	} {
		got, err := platformtree.ModuleDirIn(c.root, c.mod)
		if err != nil {
			t.Fatalf("%s → %s: %v", c.root, c.mod, err)
		}
		if got != c.want {
			t.Fatalf("%s в %s: получено %q, ожидалось %q", c.mod, c.root, got, c.want)
		}
	}
}

// TestCorpusRoot_TheModuleIsTheTreeItself — обход состава: корень есть корень
// модуля, приставка пуста.
func TestCorpusRoot_TheModuleIsTheTreeItself(t *testing.T) {
	base := t.TempDir()
	mod := mkModule(t, base, "kaname-0.1.0")

	root, prefix, err := platformtree.CorpusRoot(mod)
	if err != nil {
		t.Fatalf("корень обхода не установлен: %v", err)
	}
	if root != mod {
		t.Fatalf("корень обхода: получено %s, ожидалось %s", root, mod)
	}
	if prefix != "" {
		t.Fatalf("приставка: получено %q, ожидалась пустая", prefix)
	}
}

// TestCorpusRoot_NoModuleMarkerIsRefused — без маркера модуля судить не о чем.
func TestCorpusRoot_NoModuleMarkerIsRefused(t *testing.T) {
	bare := t.TempDir()
	if _, _, err := platformtree.CorpusRoot(bare); !errors.Is(err, platformtree.ErrModuleRootUnknown) {
		t.Fatalf("отсутствие корня модуля не названо своим признаком: %v", err)
	}
}

// TestUnder_EmptyPrefixDoesNotProduceALeadingSlash — склейка приставки.
func TestUnder_EmptyPrefixDoesNotProduceALeadingSlash(t *testing.T) {
	for _, c := range []struct{ prefix, rel, want string }{
		{"services/iam", "internal/x", "services/iam/internal/x"},
		{"", "internal/x", "internal/x"},
		{".", "internal/x", "internal/x"},
		{"", "./internal/x", "internal/x"},
	} {
		if got := platformtree.Under(c.prefix, c.rel); got != c.want {
			t.Fatalf("Under(%q, %q): получено %q, ожидалось %q", c.prefix, c.rel, got, c.want)
		}
	}
}

// TestPathUnder_NamedPlatformTreeKeepsTheCoordinateAsWritten — дерево платформы,
// названное СНАРУЖИ (ручкой задания `PLATFORM_TREE`), узнаётся по каталогу
// модулей, и координата берётся как записана.
//
// Это единственная посадка, где приставка модуля непуста, и она НЕ ищется
// подъёмом: модуль в таком дереве не лежит — его туда выкладывает задание.
func TestPathUnder_NamedPlatformTreeKeepsTheCoordinateAsWritten(t *testing.T) {
	platformBase := t.TempDir()
	if err := os.MkdirAll(filepath.Join(platformBase, "services", "iam"), 0o750); err != nil {
		t.Fatal(err)
	}

	got, err := platformtree.PathUnder(platformBase, "services/vpc/manifest.yaml")
	if err != nil {
		t.Fatalf("координата дерева платформы отвергнута: %v", err)
	}
	if want := filepath.Join(platformBase, "services", "vpc", "manifest.yaml"); got != want {
		t.Fatalf("сведено в %s, ожидалось %s", got, want)
	}
	if got := platformtree.PrefixUnder(platformBase); got != "services/iam" {
		t.Fatalf("приставка дерева платформы: получено %q", got)
	}

	// Законный близнец: тот же вызов по корню модуля даёт ПУСТУЮ приставку и
	// громкий отказ на координате соседнего модуля.
	mod := mkModule(t, t.TempDir(), "kaname-0.1.0")
	if got := platformtree.PrefixUnder(mod); got != "" {
		t.Fatalf("приставка дерева модуля: получено %q, ожидалась пустая", got)
	}
	if _, err := platformtree.PathUnder(mod, "services/vpc/manifest.yaml"); !errors.Is(err, platformtree.ErrForeignTree) {
		t.Fatalf("манифест соседнего модуля принят за свой: %v", err)
	}
}
