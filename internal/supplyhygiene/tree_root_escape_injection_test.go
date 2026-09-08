// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// tree_root_escape_injection_test.go — способность меры упасть и смолчать
// доказывается ИНЪЕКЦИЕЙ, а не прочтением.
//
// Прогонов три, и третий обязателен:
//
//	контроль        — дерево цело: молчат обе меры;
//	новый дефект    — подъём на ОДНО звено длиннее: краснеет с координатой;
//	законный близнец — подъём РОВНО в корень: молчит.
//
// Каждая инъекция меняет против близнеца РОВНО ОДИН факт — длину цепочки. Иначе
// неизвестно, какой из двух дал красное, и вердикт недействителен, хотя выглядит
// как обычный зелёный.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// climb — цепочка из n звеньев подъёма, СОБРАННАЯ, а не выписанная.
//
// Собранная намеренно. Выписанный литерал `"../../.."` лежал бы в исходнике
// ЭТОГО файла, а мера обходит весь модуль и судит узлы строковых литералов — то
// есть краснела бы на фикстуре собственной инъекции. Тот самый класс, который
// корпус ловит: проверка, считающая своё объяснение предметом.
func climb(n int) string { return strings.TrimSuffix(strings.Repeat("../", n), "/") }

// synthTree — синтетический модуль: файл на заданной глубине с заданной
// цепочкой подъёма. Один факт различия задаётся параметром chain.
func synthTree(t *testing.T, dirRel, chain string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, filepath.FromSlash(dirRel))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("фикстура не собрана: %v", err)
	}
	body := "package p\n\nconst root = \"" + chain + "\"\n"
	if err := os.WriteFile(filepath.Join(dir, "probe_test.go"), []byte(body), 0o600); err != nil {
		t.Fatalf("фикстура не собрана: %v", err)
	}
	return root
}

// TestInjection_ChainLandingExactlyAtTheModuleRootIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ.
//
// `../..` из каталога глубины 2 приводит РОВНО в корень модуля — координата,
// верная в ОБЕИХ посадках, потому что корень модуля есть в обеих.
func TestInjection_ChainLandingExactlyAtTheModuleRootIsSilent(t *testing.T) {
	findings, census, err := judgeTreeRootEscapes(synthTree(t, "internal/errors", climb(2)))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if census.ChainsSeen != 1 {
		t.Fatalf("распознаватель не увидел цепочку: осмотрено %d — инъекция ниже была бы вакуумной", census.ChainsSeen)
	}
	if len(findings) != 0 {
		t.Fatalf("законная цепочка объявлена находкой: %v — мера ловит форму, а не существо", findings)
	}
}

// TestInjection_OneLinkLongerEscapesAndIsAFinding — ИНЪЕКЦИЯ.
//
// Против близнеца выше отличается РОВНО ОДНИМ фактом: цепочка на звено длиннее.
func TestInjection_OneLinkLongerEscapesAndIsAFinding(t *testing.T) {
	findings, census, err := judgeTreeRootEscapes(synthTree(t, "internal/errors", climb(3)))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if census.ChainsSeen != 1 {
		t.Fatalf("распознаватель не увидел цепочку: осмотрено %d", census.ChainsSeen)
	}
	if len(findings) != 1 {
		t.Fatalf("подъём ЗА корень модуля не найден: находок %d при переписи %+v — "+
			"мера потеряла способность падать", len(findings), census)
	}
	got := findings[0]
	if got.file != "internal/errors/probe_test.go" {
		t.Errorf("находка не называет координаты: %q — имя посылает читателя искать причину, "+
			"координата её называет", got.file)
	}
	if got.links != 3 || got.depth != 2 {
		t.Errorf("находка называет неверные величины: звеньев %d при глубине %d, ждали 3 при 2",
			got.links, got.depth)
	}
}

// TestInjection_DeeperPackageMakesTheSameChainLegitimate — вторая половина той же
// оси: цепочка ТА ЖЕ, изменена глубина каталога.
//
// Она доказывает, что мера судит ОТНОШЕНИЕ звеньев к глубине, а не длину
// цепочки: мера, ключующаяся на длину, покраснела бы и здесь.
func TestInjection_DeeperPackageMakesTheSameChainLegitimate(t *testing.T) {
	findings, census, err := judgeTreeRootEscapes(synthTree(t, "internal/apps/kaname/shared", climb(4)))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if census.ChainsSeen != 1 {
		t.Fatalf("распознаватель не увидел цепочку: осмотрено %d", census.ChainsSeen)
	}
	if len(findings) != 0 {
		t.Fatalf("цепочка, приводящая в корень модуля с глубины 4, объявлена находкой: %v", findings)
	}
}

// TestInjection_ChainInAStringThatIsNotAPathIsNotAChain — распознаватель судит
// ЦЕПОЧКУ, а не подстроку.
//
// Строка с именем между звеньями путём-подъёмом не является: её корень известен
// по имени. Без этого утверждения мера краснела бы на всяком относительном пути.
func TestInjection_ChainInAStringThatIsNotAPathIsNotAChain(t *testing.T) {
	findings, census, err := judgeTreeRootEscapes(synthTree(t, "internal/errors", climb(2)+"/pkg/.."))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if census.ChainsSeen != 0 {
		t.Fatalf("строка с именем между звеньями зачтена цепочкой: осмотрено %d", census.ChainsSeen)
	}
	if len(findings) != 0 {
		t.Fatalf("не-цепочка объявлена находкой: %v", findings)
	}
}

// TestInjection_EmptyTreeIsNotSilentlyGreen — пустой обход вердиктом не является.
func TestInjection_EmptyTreeIsNotSilentlyGreen(t *testing.T) {
	findings, census, err := judgeTreeRootEscapes(t.TempDir())
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if census.FilesRead != 0 || len(findings) != 0 {
		t.Fatalf("пустое дерево дало непустую перепись: %+v", census)
	}
	// Живая проба обязана на такой переписи ОТКАЗАТЬ, а не пройти: утверждение
	// об этом стоит в ней (`census.FilesRead == 0` → Fatalf). Здесь проверяется
	// лишь то, что величина, на которую она ключуется, действительно нулевая.
}
