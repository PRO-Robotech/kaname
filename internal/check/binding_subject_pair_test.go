// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// binding_subject_pair_test.go — kaname#917: доступ к одиночной паре субъекта
// выдачи вне закрытого перечня — находка. Способность упасть доказана
// binding_subject_pair_injection_test.go.
package check_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// bindingPairOnDisk — непроверочные файлы Go радиуса по индексу git.
func bindingPairOnDisk(t *testing.T, root string) []string {
	t.Helper()
	args := append([]string{"-C", root, "ls-files", "--"}, check.BindingPairDirs...)
	out, err := exec.Command("git", args...).Output() // #nosec G204 -- аргументы — константы гейта
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав радиуса не прочитан: %v", err)
	}
	var files []string
	for _, ln := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasSuffix(ln, ".go") && !strings.HasSuffix(ln, "_test.go") {
			files = append(files, ln)
		}
	}
	if len(files) == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: в радиусе %v индекс не назвал ни одного файла", check.BindingPairDirs)
	}
	return files
}

// collectLiveBindingPair — перепись по живому дереву.
func collectLiveBindingPair(t *testing.T) check.BindingPairCensus {
	t.Helper()
	root := ceremonyModuleRoot(t)
	census, err := check.CollectBindingSubjectPair(t.Context(), check.BindingPairSpec{
		ModuleRoot:  root,
		RootPackage: ceremonyModulePath(t, root) + "/" + ceremonyRootDir,
		OnDisk:      bindingPairOnDisk(t, root),
	})
	if err != nil {
		t.Fatalf("гейт НЕ ИСПОЛНИЛСЯ — это не зелёное и не находка: %v", err)
	}
	return census
}

// TestBindingSubjectPairIsReadOnlyInListedPlaces — живой прогон: каждый
// доступ к паре стоит в перечисленном месте с точным числом.
func TestBindingSubjectPairIsReadOnlyInListedPlaces(t *testing.T) {
	census := collectLiveBindingPair(t)
	t.Logf("перепись: %s", census.Summary())
	if len(census.Accesses) == 0 {
		t.Fatalf("доступов к паре 0 — предмета у гейта нет либо распознаватель ослеп: %s", census.Summary())
	}
	for _, f := range check.JudgeBindingSubjectPair(census, check.BindingSubjectPairLedger) {
		t.Error(f)
	}
}
