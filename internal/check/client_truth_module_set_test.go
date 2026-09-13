// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_truth_module_set_test.go — ГЕЙТ КЛАССА: перечень модулей, названный
// клиентской поверхностью, полон (задача #17, порт семейства
// `clienttruth_iam_moduleset`).
//
// Предмет, цена неполноты и границы распознавателя — в шапке
// `client_truth_module_set.go`; здесь они не пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// client_truth_module_set_injection_test.go.
package check_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestClientTruthIAMModuleSetEnumerationsAreComplete — имя сохранено ДОСЛОВНО с
// монорепо: семейство перенесено, а не заведено заново, и переименование
// сделало бы ссылки на него ложными молча.
func TestClientTruthIAMModuleSetEnumerationsAreComplete(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	tree, err := treecorpus.NewTree(root)
	if err != nil {
		t.Fatalf("состав дерева не установлен: %v — «ноль находок» здесь означало бы "+
			"«ноль прочитанного»", err)
	}

	// ── сторона объявления: набор выводится разбором пакета ──────────────────
	//
	// Обход и его отказ на пустоте держит ОДНА функция — `ModuleSetDeclCorpus`
	// (задача #17): прежде обход строился здесь, от корня своего модуля, и
	// подать ему пустое дерево было нечем.
	pkg, err := check.ModuleSetDeclCorpus(tree)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: пакет %s: %v", check.ModuleSetPkgRel, err)
	}

	modules, decl, err := check.ModuleSetFromDecl(pkg, check.ModuleSetVarName)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	// Премиса: прочитано то, что заведомо есть. Без неё «ноль находок»
	// достигалось бы пустым обходом.
	if len(modules) < 4 {
		t.Fatalf("модулей выведено %d — объявление набора не прочитано, судить перечни не по чему",
			len(modules))
	}
	// Премиса РАЗРЕШЕНИЯ: пакет прочитан не в один файл. Без неё «объявление
	// найдено» неотличимо от «повезло с первым же файлом».
	if decl.PkgFiles < 5 {
		t.Fatalf("файлов пакета %s осмотрено %d — обход пакета пуст или усечён",
			check.ModuleSetPkgRel, decl.PkgFiles)
	}
	if decl.TypeKeys < 20 {
		t.Fatalf("ключей типа прочитано %d — таблица прочитана не вся, набор мог выйти неполным",
			decl.TypeKeys)
	}

	// ── сторона поверхности ─────────────────────────────────────────────────
	surface, err := check.ModuleSetSurfaceCorpus(tree)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: клиентская поверхность (%s): %v",
			strings.Join(check.ModuleSetSurfaces, ", "), err)
	}

	var (
		surfaceFiles = len(surface)
		total        check.ModuleSetScan
		findings     []check.ModuleSetFinding
	)
	for _, rel := range surface.Rels() {
		f, scan := check.ScanModuleSetEnumerations(rel, surface[rel], modules)
		findings = append(findings, f...)
		total.Enumerations += scan.Enumerations
		total.PairSpans += scan.PairSpans
	}

	if surfaceFiles < 20 {
		t.Fatalf("файлов клиентской поверхности %d (%s) — обход пуст, вердикт беспредметен",
			surfaceFiles, strings.Join(check.ModuleSetSurfaces, ", "))
	}
	// Вердикт выносится ТОЛЬКО о перечнях. Ноль распознанных означал бы, что он
	// не вынесен ни разу, — и «находок ноль» получено даром.
	if total.Enumerations == 0 {
		t.Fatal("перечней распознано 0 — сверка не состоялась ни разу: либо код-форматирование " +
			"имён сменилось, либо перечни ушли с поверхности вовсе")
	}

	t.Logf("перепись: файлов пакета %s осмотрено %d · объявление в %s · ключей типа прочитано %d · "+
		"модулей выведено %d (%s) · файлов поверхности %d · перечней рассужено %d · "+
		"спанов из двух имён встречено %d (НЕ судятся — законная пара)",
		check.ModuleSetPkgRel, decl.PkgFiles, decl.DeclFile, decl.TypeKeys,
		len(modules), strings.Join(modules, ", "),
		surfaceFiles, total.Enumerations, total.PairSpans)

	for _, f := range findings {
		t.Errorf("%s", f)
	}
	if len(findings) > 0 {
		t.Log("Модуль — то, чем клиент выражает грант (`Rule.module`). Перечень, назвавший " +
			"меньше, чем принимает сервер, читается как «тонко выдать доступ к недостающему " +
			"домену нельзя», а единственный выход при таком чтении — системная роль на весь " +
			"уровень, то есть заведомое расширение доступа. Набор выводится из приставок " +
			"ключей `authzmap.objectTypes`; правьте ПЕРЕЧЕНЬ, а не набор.")
	}
}
