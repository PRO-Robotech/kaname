// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// module_manifest_check_wiring_test.go — ГЕЙТ КЛАССА: у единственного судьи
// ФОРМЫ МАНИФЕСТА обязан быть вызывающий (задача #17, порт семейства
// `modulemanifestcheckwiring`).
//
// Предмет, довод в пользу разобранного YAML и граница «исполняемое против
// объяснения» — в шапке `judge_target_wiring.go`; здесь они не пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// judge_target_wiring_injection_test.go (одна фикстура на оба семейства: они
// различаются ИМЕНЕМ ЦЕЛИ, а не механизмом, и второй копией доказательства это
// не чинилось бы — копии расходятся молча).
package check_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// ModuleManifestCheckTarget — цель, поднимающая единственного судью формы.
const ModuleManifestCheckTarget = "module-manifest-check"

// TestModuleManifestCheckTargetHasACaller — имя сохранено дословно с монорепо:
// семейство перенесено, а не заведено заново, и переименование сделало бы
// ссылки на него ложными молча.
func TestModuleManifestCheckTargetHasACaller(t *testing.T) {
	t.Parallel()
	assertJudgeTargetIsWired(t, ModuleManifestCheckTarget)
}

// assertJudgeTargetIsWired — общее тело обоих гейтов семейства.
//
// Различаются они ровно именем цели, поэтому тело одно: два тела об одном
// предмете разошлись бы на первой же правке — и разошлись бы молча, потому что
// оба остались бы зелёными.
func assertJudgeTargetIsWired(t *testing.T, target string) {
	t.Helper()

	root, prefix := platformtree.RequireCorpus(t)
	if prefix != "" {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень корпуса отдал приставку %q — "+
			"провязка судится в дереве МОДУЛЯ, и обход по чужой приставке смотрел бы не туда",
			prefix)
	}

	w, err := check.ReadJudgeTargetWiring(root, target)
	if err != nil {
		t.Fatalf("провязка не прочитана: %v — вердикт беспредметен", err)
	}

	// Предпосылки обхода: пустой обход обязан ронять прогон, иначе «находок
	// ноль» означало бы «прочитано ноль».
	if w.MakefilesRead == 0 {
		t.Fatal("корневой рецепт не прочитан — гейт смотрит не туда, его вердикт беспредметен")
	}
	if w.WorkflowsRead == 0 {
		t.Fatalf("в %s не прочитано ни одного файла задания — гейт смотрит не туда",
			check.WorkflowsDirRel)
	}
	if w.RunStepsRead == 0 {
		t.Fatal("ни в одном задании не найдено шага с телом `run:` — разбор сломан, " +
			"и «вызова нет» означало бы «не прочитано ничего»")
	}

	t.Log(w.Census())

	for _, f := range check.JudgeTargetWiringFaults(w) {
		t.Errorf("%s", f)
	}
}
