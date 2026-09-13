// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_truth_exclusion_form_test.go — ГЕЙТ КЛАССА: форма взаимоисключения,
// названная оператору, есть та, которой оно держится (задача #17, порт-ПОЛОВИНА
// семейства `clienttruth_kaname_exclusion_form`).
//
// Предмет, два утверждения, смена операнда премисы у второго и границы
// распознавателей — в шапке `client_truth_exclusion_form.go`; здесь они не
// пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// client_truth_exclusion_form_injection_test.go.
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

// TestClientTruthKanameExclusionFormMatchesTheTree — имя сохранено ДОСЛОВНО с
// монорепо: семейство перенесено, а не заведено заново.
func TestClientTruthKanameExclusionFormMatchesTheTree(t *testing.T) {
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
	read := func(rel string) string {
		b, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if readErr != nil {
			t.Fatalf("чтение %s: %v", rel, readErr)
		}
		return string(b)
	}

	in := check.ExclusionFormInput{
		GuideRel:    check.ExclusionGuideRel,
		ReaderFiles: map[string]string{},
		WrapFiles:   map[string]string{},
	}
	if !tree.HasFile(check.ExclusionGuideRel) {
		t.Fatalf("страницы установки %s нет в составе дерева — судить не о чем",
			check.ExclusionGuideRel)
	}
	in.GuideBody = read(check.ExclusionGuideRel)

	for _, rel := range tree.SortedFiles() {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		if strings.HasPrefix(rel, check.ExclusionReaderDirRel+"/") {
			in.ReaderFiles[rel] = read(rel)
		}
		// Обёртку ищем по ВСЕМУ не-тестовому дереву, а не в названном каталоге:
		// провязка уже переезжала между файлами, и привязка к имени файла дала
		// бы «построение мертво» вместо вердикта — то есть находку по причине,
		// к предмету отношения не имеющей.
		in.WrapFiles[rel] = read(rel)
	}

	findings, census, err := check.AuditExclusionForm(in)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	// ── премисы: «ноль находок» отличимо от «ноль прочитанного» ─────────────
	if census.GuideParagraphs == 0 {
		t.Fatal("абзацев страницы прочитано 0 — страница пуста или не найдена, " +
			"и вердикт о ней беспредметен")
	}
	if census.ReaderGoFiles == 0 {
		t.Fatalf("файлов читателя под %s разобрано 0 — обход стороны отказа пуст",
			check.ExclusionReaderDirRel)
	}
	if census.RefuseCalls == 0 {
		t.Fatalf("отказов у читателя встречено 0 — распознаватель отказов ослеп либо "+
			"читатель перестал отказывать вовсе; и то и другое означает, что "+
			"«производителя нет» получено даром (файлов разобрано %d)", census.ReaderGoFiles)
	}
	// Премиса ПРЕДМЕТА, а не обхода: гейт судит согласие страницы с ПОСТРОЕНИЕМ.
	// Построения нет — судить не с чем, и молчать об этом нельзя: зелёный на
	// мёртвом механизме неотличим от зелёного на исправном.
	if census.WrapCalls == 0 {
		t.Fatalf("обращений %s вне объявляющего файла — 0: построение, которым "+
			"взаимоисключение держится НА НАШЕЙ стороне, уехало из дерева. Гейт судит "+
			"согласие страницы с ним; без него он не выносит вердикта, а НЕ разрешает. "+
			"Вторая половина построения — снятие удостоверения у края — живёт в %s и "+
			"отсюда не судится вовсе",
			strings.Join(check.ExclusionWrapFuncs, "/"), check.ExclusionEdgeStripHome)
	}

	t.Logf("перепись страницы %s: абзацев прочитано %d, о предмете %d, объясняют отказом %d, "+
		"называют построение %d",
		check.ExclusionGuideRel, census.GuideParagraphs, census.SubjectParagraphs,
		census.ExplainByRefusal, census.ExplainByBuild)
	t.Logf("перепись дерева: файлов читателя разобрано %d, отказов %d, из них о сочетании форм %d; "+
		"не-тестовых файлов осмотрено на обёртку %d, обращений %d (%s)",
		census.ReaderGoFiles, census.RefuseCalls, census.CoPresenceRefusals,
		census.WrapGoFiles, census.WrapCalls, strings.Join(census.WrapSites, ", "))
	t.Logf("НЕ СУДИТСЯ ОТСЮДА: снятие удостоверения у края (%s) — вторая половина построения "+
		"лежит в другом репозитории, и читать её с диска значило бы сделать вердикт свойством "+
		"кеша машины прогона, а не коммита",
		check.ExclusionEdgeStripHome)

	for _, f := range findings {
		t.Errorf("%s", f)
	}
	if len(findings) > 0 {
		t.Log("Взаимоисключение двух форм личности держится ПОСТРОЕНИЕМ: читатель " +
			"предъявленного удостоверения накрывает пару звеньев переданной личности и решает " +
			"по её вердикту, а край перед пересылкой за себя снимает арендаторское " +
			"удостоверение. Страница обязана объяснять его построением — и не вправе обещать " +
			"оператору отказ, которого ни одна строка службы не производит.")
	}
}
