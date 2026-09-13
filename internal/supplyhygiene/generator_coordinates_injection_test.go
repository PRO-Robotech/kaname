// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// generator_coordinates_injection_test.go — доказательство, что гейт координат
// СПОСОБЕН упасть и способен СМОЛЧАТЬ.
//
// Инъекция подаёт вход, а не читает код. Каждый отрицательный случай меняет
// РОВНО ОДИН факт против своего положительного близнеца. Мир строится КОПИЕЙ
// настоящего дерева — тех его файлов, которые гейт читает, — а не выдумывается.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmapgen"
)

// generatorWorldFiles — что копируется в мир: два источника координат, сами
// каталоги-цели и признак корня модуля.
var generatorWorldFiles = []string{
	generatorDirectiveFile,
	authzmapgen.GeneratedRelPath,
	"go.mod",
}

// generatorWorldDirs — каталоги, чьё СУЩЕСТВОВАНИЕ судит гейт. Пустые: предмет
// оси — резолвится ли координата, а не что в каталоге лежит.
var generatorWorldDirs = []string{"cmd/authzmap-tables", "internal/authzmap"}

func generatorWorld(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range generatorWorldFiles {
		raw, err := os.ReadFile(filepath.Join(serviceRoot, rel))
		if err != nil {
			t.Fatalf("предпосылка инъекции не выполняется: %s не прочитан: %v", rel, err)
		}
		dst := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("каталог не заведён: %v", err)
		}
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			t.Fatalf("файл не записан: %v", err)
		}
	}
	for _, rel := range generatorWorldDirs {
		if err := os.MkdirAll(filepath.Join(root, rel), 0o755); err != nil {
			t.Fatalf("каталог не заведён: %v", err)
		}
	}
	return root
}

func generatorSubst(t *testing.T, root, rel, old, new string) {
	t.Helper()
	p := filepath.Join(root, rel)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("подготовка не удалась: %v", err)
	}
	s := string(raw)
	if strings.Count(s, old) != 1 {
		t.Fatalf("подготовка не удалась: образец встречается %d раз, а не единожды — "+
			"инъекция перестала быть одно-фактной:\n%s", strings.Count(s, old), old)
	}
	if err := os.WriteFile(p, []byte(strings.Replace(s, old, new, 1)), 0o644); err != nil {
		t.Fatalf("подготовка не удалась: %v", err)
	}
}

// generatorDirectiveLine — директива дерева ДОСЛОВНО. Подменяется целиком: тот
// же довод стоит рядом в прозе, объясняющей его, и подмена по короткому образцу
// перестала бы быть одно-фактной — страж одно-фактности это и показал.
const generatorDirectiveLine = "//go:generate go run github.com/PRO-Robotech/kaname/cmd/" +
	"authzmap-tables -root $KANAME_PLATFORM_TREE -module ../.."

// ── КОНТРОЛЬ ────────────────────────────────────────────────────────────────
func TestGeneratorCoordinatesInjectionControl_UntouchedWorldIsSilent(t *testing.T) {
	t.Parallel()
	census, coords, findings := scanGeneratorCoordinates(generatorWorld(t))
	if len(findings) != 0 {
		t.Fatalf("контроль не прошёл: нетронутая копия дала находки — красное ниже будет от копии, "+
			"а не от дефекта:\n%s", strings.Join(findings, "\n"))
	}
	if census.sourcesRead != 2 {
		t.Fatalf("контроль не прошёл: источников прочитано %d из 2", census.sourcesRead)
	}
	if len(coords) != 4 || census.resolved != 4 {
		t.Fatalf("контроль не прошёл: координат %d, резолвится %d, ожидалось 4/4",
			len(coords), census.resolved)
	}
}

// ── НАХОДКИ ─────────────────────────────────────────────────────────────────

// Дословное восстановление дефекта #61: довод, уводящий за пределы дерева.
// Существование каталога выше корня его НЕ оправдывает — в том и суть.
func TestGeneratorCoordinatesInjection_ModuleArgEscapingTheTreeIsFound(t *testing.T) {
	t.Parallel()
	root := generatorWorld(t)
	generatorSubst(t, root, generatorDirectiveFile, generatorDirectiveLine,
		strings.Replace(generatorDirectiveLine, "-module ../..", "-module ../../../..", 1))
	_, _, findings := scanGeneratorCoordinates(root)
	requireFindingMentions(t, findings, "уводит ЗА ПРЕДЕЛЫ дерева")
}

// Довод указывает в СУЩЕСТВУЮЩИЙ каталог, который корнем модуля не является.
// Без признака `go.mod` гейт был бы здесь зелен — и пропустил бы промах мимо цели.
func TestGeneratorCoordinatesInjection_ModuleArgPointingAtANonModuleIsFound(t *testing.T) {
	t.Parallel()
	root := generatorWorld(t)
	generatorSubst(t, root, generatorDirectiveFile, generatorDirectiveLine,
		strings.Replace(generatorDirectiveLine, "-module ../..", "-module .", 1))
	_, _, findings := scanGeneratorCoordinates(root)
	requireFindingMentions(t, findings, "go.mod")
}

// Директива без `-module`: продукт ляжет относительно каталога вызова.
func TestGeneratorCoordinatesInjection_DirectiveWithoutModuleArgIsFound(t *testing.T) {
	t.Parallel()
	root := generatorWorld(t)
	generatorSubst(t, root, generatorDirectiveFile, generatorDirectiveLine,
		strings.Replace(generatorDirectiveLine, " -module ../..", "", 1))
	_, _, findings := scanGeneratorCoordinates(root)
	requireFindingMentions(t, findings, "не называет `-module`")
}

// Директивы нет вовсе — перегенерация перестала быть объявленной.
func TestGeneratorCoordinatesInjection_MissingDirectiveIsFound(t *testing.T) {
	t.Parallel()
	root := generatorWorld(t)
	generatorSubst(t, root, generatorDirectiveFile, "//go:generate go run", "// go:generate go run")
	_, _, findings := scanGeneratorCoordinates(root)
	requireFindingMentions(t, findings, "директивы `go:generate` не найдено")
}

// Координата, уехавшая в САМ ПРОДУКТ: строка авторства. Именно её задача не
// застала — она смотрела на команду и на константу, а не на их продукт.
func TestGeneratorCoordinatesInjection_StaleAttributionInProductIsFound(t *testing.T) {
	t.Parallel()
	root := generatorWorld(t)
	generatorSubst(t, root, authzmapgen.GeneratedRelPath,
		"// Code generated by cmd/authzmap-tables.",
		"// Code generated by services/iam/cmd/authzmap-tables.")
	_, _, findings := scanGeneratorCoordinates(root)
	requireFindingMentions(t, findings, "services/iam/cmd/authzmap-tables")
	requireFindingMentions(t, findings, "НЕ РЕЗОЛВИТСЯ")
}

// Вторая координата продукта: подсказка перегенерации.
func TestGeneratorCoordinatesInjection_StaleRegenHintInProductIsFound(t *testing.T) {
	t.Parallel()
	root := generatorWorld(t)
	generatorSubst(t, root, authzmapgen.GeneratedRelPath,
		"go generate ./internal/authzmap/...",
		"go generate ./services/iam/internal/authzmap/...")
	_, _, findings := scanGeneratorCoordinates(root)
	requireFindingMentions(t, findings, "services/iam/internal/authzmap")
}

// Порождённого файла нет — обеих координат продукта не существует, и молчание
// означало бы «ноль прочитанного».
func TestGeneratorCoordinatesInjection_MissingProductIsFound(t *testing.T) {
	t.Parallel()
	root := generatorWorld(t)
	if err := os.Remove(filepath.Join(root, authzmapgen.GeneratedRelPath)); err != nil {
		t.Fatalf("подготовка не удалась: %v", err)
	}
	census, _, findings := scanGeneratorCoordinates(root)
	requireFindingMentions(t, findings, authzmapgen.GeneratedRelPath)
	if census.sourcesRead != 1 {
		t.Fatalf("источников прочитано %d, ожидался 1", census.sourcesRead)
	}
}

// ── ЗАКОННЫЕ БЛИЗНЕЦЫ ───────────────────────────────────────────────────────

// ФОРМА ИСТОЧНИКА МАНИФЕСТОВ — описание дерева ПЛАТФОРМЫ, а не координата
// этого. `services/*/manifest.yaml` здесь не резолвится и резолвиться не
// должен: манифесты лежат у платформы, и в самостоятельном клоне их нет by
// construction. Гейт по подстроке краснел бы тут и был бы снят.
func TestGeneratorCoordinatesInjection_PlatformManifestFormIsSilent(t *testing.T) {
	t.Parallel()
	root := generatorWorld(t)
	generatorSubst(t, root, authzmapgen.GeneratedRelPath,
		"// ИСТОЧНИК — МАНИФЕСТЫ МОДУЛЕЙ (services/*/manifest.yaml)",
		"// ИСТОЧНИК — МАНИФЕСТЫ МОДУЛЕЙ (services/*/manifest.yaml, дерево платформы)")
	_, _, findings := scanGeneratorCoordinates(root)
	if len(findings) != 0 {
		t.Fatalf("гейт краснеет на ЗАКОННОМ близнеце (форма источника у платформы):\n%s",
			strings.Join(findings, "\n"))
	}
}

// РАЗБОР ИСТОРИИ ПЕРЕЕЗДА в прозе. Он обязан называть прежнюю координату — иначе
// объяснение непонятно, — и гейт, краснеющий на собственном объяснении, есть тот
// самый класс, который корпус ловит.
func TestGeneratorCoordinatesInjection_ProseAboutTheMoveIsSilent(t *testing.T) {
	t.Parallel()
	root := generatorWorld(t)
	generatorSubst(t, root, generatorDirectiveFile, "//go:generate go run",
		"// Прежде довод звался `-root ../../../..` и отсчитывался от\n"+
			"// `services/iam/internal/authzmap`, которого в этом дереве нет.\n"+
			"//go:generate go run")
	_, _, findings := scanGeneratorCoordinates(root)
	if len(findings) != 0 {
		t.Fatalf("гейт краснеет на ЗАКОННОМ близнеце (проза о переезде):\n%s",
			strings.Join(findings, "\n"))
	}
}

// Довод `-root` называет ЧУЖОЕ дерево и в этом резолвиться не обязан: корня
// платформы рядом с самостоятельным клоном нет by construction, он приходит
// переменной окружения. Гейт судит `-module`, а не его.
func TestGeneratorCoordinatesInjection_PlatformRootArgIsSilent(t *testing.T) {
	t.Parallel()
	root := generatorWorld(t)
	generatorSubst(t, root, generatorDirectiveFile, "-root $KANAME_PLATFORM_TREE",
		"-root $SOME_OTHER_PLATFORM_TREE_VARIABLE")
	_, _, findings := scanGeneratorCoordinates(root)
	if len(findings) != 0 {
		t.Fatalf("гейт краснеет на ЗАКОННОМ близнеце (корень платформы из окружения):\n%s",
			strings.Join(findings, "\n"))
	}
}
