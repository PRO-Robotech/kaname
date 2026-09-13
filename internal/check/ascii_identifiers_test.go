// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ascii_identifiers_test.go — ГЕЙТ КЛАССА: имя в коде Go обязано быть латинским
// (ban #17, задача #41).
//
// Норма, цена класса и довод «разбор, а не образец» — в шапке
// `ascii_identifiers.go`; здесь они не пересказываются, чтобы два места об одном
// предмете не разошлись.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// ascii_identifiers_injection_test.go: тот же разбор на синтетике, где каждый
// мир отличается от законного близнеца одним фактом.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// asciiIdentGoFloor — исходников Go, ниже которого обход беспредметен.
//
// Не «больше нуля»: ноль ловит только полностью сорванный обход, а обход,
// сузившийся до десятка файлов (сменилась раскладка, отсёкся суффикс), выглядел
// бы обычным зелёным. Величина взята НИЖЕ фактической с запасом — она признак
// беспредметности, а не перепись, и расти вместе с деревом ей не надо.
const asciiIdentGoFloor = 500

// TestIdentifiersAreASCII — в дереве службы нет нелатинских имён Go.
//
// Имя сохранено дословно с монорепо: шесть вхождений в приёмках службы называют
// держателем ban #17 именно его, и переименование сделало бы эти координаты
// ложными молча.
func TestIdentifiersAreASCII(t *testing.T) {
	t.Parallel()

	// Обход — по корню МОДУЛЯ службы. Дерево платформы этому модулю не
	// принадлежит: судить его отсюда значило бы краснеть на чужом, а в
	// самостоятельном клоне его нет вовсе.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}

	files, err := treecorpus.UnderWithSuffix(root, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева: %v — без переписи "+
			"«ноль находок» неотличимо от «ноль прочитанного»", err)
	}

	var (
		filesRead  int
		identsSeen int
		unparsed   []string
		findings   []check.NonASCIIIdent
	)
	for _, abs := range files {
		rel, rerr := filepath.Rel(root, abs)
		if rerr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git ЭТОГО дерева
		if rderr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: чтение %s: %v", rel, rderr)
		}
		seen, found, perr := check.ScanNonASCIIIdents(rel, src)
		if perr != nil {
			// Неразбираемый файл — не находка: он и собраться не может, об этом
			// скажет сборка. Но и молчать о нём нельзя, иначе перепись завысит
			// объём осмотренного.
			unparsed = append(unparsed, rel)
			continue
		}
		filesRead++
		identsSeen += seen
		findings = append(findings, found...)
	}

	t.Logf("перепись: исходников Go в индексе %d · разобрано %d · не разобралось %d %v · "+
		"имён осмотрено %d · находок %d",
		len(files), filesRead, len(unparsed), unparsed, identsSeen, len(findings))

	if filesRead < asciiIdentGoFloor {
		t.Fatalf("разобрано %d исходников Go при пороге %d — перепись беспредметна, "+
			"и «ноль находок» означало бы «ноль прочитанного»", filesRead, asciiIdentGoFloor)
	}
	if identsSeen == 0 {
		t.Fatal("осмотрено НОЛЬ имён при непустом обходе — разбор перестал доходить " +
			"до узлов-идентификаторов, и молчание гейта ничего не означает")
	}

	if len(findings) > 0 {
		lines := make([]string, 0, len(findings))
		for _, f := range findings {
			lines = append(lines, f.String())
		}
		t.Errorf("имя в коде обязано быть латинским — найдено %d:\n  %s\n\n"+
			"Кириллица даёт омоглифы: имя выглядит латинским и не находится ни поиском, "+
			"ни отбором по имени. Пробу с такой буквой нельзя выбрать через `-run`, и "+
			"«прогнал» молча означает «не прогнал».\n"+
			"Комментарии, строковые литералы и тексты сообщений правило НЕ ограничивает; "+
			"правьте имя ПО ПОЗИЦИИ разбора, а не текстовой заменой — замена попадает "+
			"внутрь строк.", len(findings), strings.Join(lines, "\n  "))
	}
}
