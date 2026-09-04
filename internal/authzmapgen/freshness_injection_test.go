// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzmapgen_test

// freshness_injection_test.go — ДОКАЗАТЕЛЬСТВО того, что гейт свежести способен
// упасть, и падает ТОЛЬКО на своём предмете.
//
// Вход синтетический: дерево собирается здесь целиком, поэтому доказательство не
// исчезнет вместе с починкой настоящего дерева и не покраснеет от чужой правки.
// Предикат при этом ТОТ ЖЕ (`authzmapgen.CheckFresh`) — второе сравнение рядом
// говорило бы о коде, которого гейт не исполняет.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmapgen"
)

// syntheticManifest — минимальный годный манифест модуля.
func syntheticManifest(module string, resources ...string) string {
	var sb strings.Builder
	sb.WriteString("apiVersion: iam/v1\nmodule: " + module + "\nresources:\n")
	for _, r := range resources {
		sb.WriteString("  - name: " + r + "\n")
		sb.WriteString("    objectType: " + module + "_" + r + "\n")
		sb.WriteString("    parents: [project]\n")
		sb.WriteString("    producer: derived\n")
		sb.WriteString("    verbs:\n      - get\n      - list\n")
	}
	return sb.String()
}

// syntheticRoot — дерево с манифестами и СВЕЖИМ порождённым файлом.
func syntheticRoot(t *testing.T, modules map[string][]string) string {
	t.Helper()
	root := t.TempDir()
	for module, resources := range modules {
		dir := filepath.Join(root, "services", module)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("каталог модуля %s: %v", module, err)
		}
		body := syntheticManifest(module, resources...)
		if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), []byte(body), 0o600); err != nil {
			t.Fatalf("манифест %s: %v", module, err)
		}
	}
	regenerate(t, root)
	return root
}

// regenerate приводит порождённый файл синтетического дерева к тому, что даёт
// производитель.
func regenerate(t *testing.T, root string) {
	t.Helper()
	tables, err := authzmapgen.Collect(root)
	if err != nil {
		t.Fatalf("Collect(%s): %v", root, err)
	}
	body, err := authzmapgen.Render(tables)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	target := filepath.Join(root, authzmapgen.GeneratedRelPath)
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		t.Fatalf("каталог продукта: %v", err)
	}
	if err := os.WriteFile(target, body, 0o600); err != nil {
		t.Fatalf("продукт не записан: %v", err)
	}
}

// TestFreshnessGateIsSilentOnASynthesizedFreshTree — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него всякая краснота ниже неотличима от предиката, отвергающего любое
// дерево.
func TestFreshnessGateIsSilentOnASynthesizedFreshTree(t *testing.T) {
	root := syntheticRoot(t, map[string][]string{"vpc": {"network"}, "iam": {"group"}})
	census, err := authzmapgen.CheckFresh(root)
	if err != nil {
		t.Fatalf("свежее дерево объявлено отставшим: %v (%s)", err, census.Summary())
	}
	if census.Resources != 2 {
		t.Fatalf("ресурсов осмотрено %d, ожидалось 2 (%s)", census.Resources, census.Summary())
	}
}

// TestFreshnessGateCatchesAHandEditOfTheProduct — правка ПРОДУКТА руками.
func TestFreshnessGateCatchesAHandEditOfTheProduct(t *testing.T) {
	root := syntheticRoot(t, map[string][]string{"vpc": {"network"}})
	target := filepath.Join(root, authzmapgen.GeneratedRelPath)
	// #nosec G304 -- путь собран из временного корня и константы пакета.
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("продукт не читается: %v", err)
	}
	edited := strings.Replace(string(body), `"v_get", "v_list"`,
		`"v_get", "v_list", "v_дописанное_руками"`, 1)
	if edited == string(body) {
		t.Fatal("инъекция не изменила продукт — доказательство было бы вакуумным")
	}
	if err := os.WriteFile(target, []byte(edited), 0o600); err != nil {
		t.Fatalf("инъекция не записана: %v", err)
	}

	_, err = authzmapgen.CheckFresh(root)
	if err == nil {
		t.Fatal("гейт молчит на продукте, правленном руками — «сгенерировано» стало бы " +
			"словом, за которым никто не следит")
	}
	if !strings.Contains(err.Error(), authzmapgen.GeneratedRelPath) ||
		!strings.Contains(err.Error(), "go generate") {
		t.Fatalf("находка не называет файл и способ починки: %v", err)
	}
}

// TestFreshnessGateCatchesAManifestThatMovedWithoutRegeneration — правка
// МАНИФЕСТА без перегенерации: ровно тот случай, ради которого вывод заводился.
func TestFreshnessGateCatchesAManifestThatMovedWithoutRegeneration(t *testing.T) {
	root := syntheticRoot(t, map[string][]string{"vpc": {"network"}})
	// Модуль объявил ВТОРОЙ ресурс, продукт остался прежним.
	body := syntheticManifest("vpc", "network", "subnet")
	if err := os.WriteFile(filepath.Join(root, "services", "vpc", "manifest.yaml"),
		[]byte(body), 0o600); err != nil {
		t.Fatalf("манифест не переписан: %v", err)
	}

	census, err := authzmapgen.CheckFresh(root)
	if err == nil {
		t.Fatal("новый ресурс манифеста не доехал до таблиц, и гейт промолчал — тип не " +
			"резолвился бы краем, а проверка выглядела бы пройденной")
	}
	if census.Resources != 2 {
		t.Fatalf("перепись не назвала осмотренного: %s", census.Summary())
	}

	// А после перегенерации — молчит. Без этой половины «краснеет» было бы
	// неотличимо от «краснеет всегда».
	regenerate(t, root)
	if _, err := authzmapgen.CheckFresh(root); err != nil {
		t.Fatalf("перегенерация не сняла находку: %v", err)
	}
}

// TestCollectRefusesAVoidSweep — беспредметный обход есть ОТКАЗ, а не пустая
// таблица.
//
// Пустой продукт снёс бы каталог типов целиком, и снаружи это выглядело бы как
// «платформа не объявляет ничего».
func TestCollectRefusesAVoidSweep(t *testing.T) {
	root := t.TempDir()
	if _, err := authzmapgen.Collect(root); err == nil {
		t.Fatal("обход без единого манифеста принят — таблица из пустоты выглядит целой")
	}
}

// TestCollectRefusesAFindingRatherThanDroppingATypeSilently — негодный манифест
// есть отказ, а не пропуск записи.
func TestCollectRefusesAFindingRatherThanDroppingATypeSilently(t *testing.T) {
	root := syntheticRoot(t, map[string][]string{"vpc": {"network"}})
	broken := filepath.Join(root, "services", "iam")
	if err := os.MkdirAll(broken, 0o750); err != nil {
		t.Fatalf("каталог модуля: %v", err)
	}
	if err := os.WriteFile(filepath.Join(broken, "manifest.yaml"),
		[]byte("apiVersion: iam/v1\nmodule: iam\nresources:\n  - name: group\n"), 0o600); err != nil {
		t.Fatalf("негодный манифест не записан: %v", err)
	}

	if _, err := authzmapgen.Collect(root); err == nil {
		t.Fatal("негодный манифест пропущен молча — таблица из части манифестов выглядит " +
			"целой и теряет тип")
	}
}
