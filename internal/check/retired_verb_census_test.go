// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_verb_census_test.go — перепись следов снятого глагола по живому дереву
// службы (AWI-09, kaname#929). Норма и закрытый перечень исключений — в шапке
// retired_verb_census.go; способность упасть и смолчать — в
// retired_verb_census_injection_test.go.
package check_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestAWI09_RetiredVerbLeavesNoTraceInTheTree — снятый глагол не назван ни
// контрактом, ни проводкой, ни каталогом прав, ни манифестом, ни документацией.
func TestAWI09_RetiredVerbLeavesNoTraceInTheTree(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	tracked, err := check.TrackedPathsOfTree(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	files := make(map[string]string, len(tracked))
	for _, rel := range tracked {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			// Отслеживаемый, но снятый в рабочей копии путь судить не о чем; молча
			// его не пропускаем — число прочитанного печатается ниже.
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: чтение %s: %v", rel, err)
		}
		files[rel] = string(b)
	}

	for _, verb := range check.RetiredVerbs() {
		c := check.JudgeRetiredVerb(files, verb)
		t.Log(c.String())
		if msg := c.Refusal(); msg != "" {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ (%s): %s", verb.Refs, msg)
		}
		for _, f := range c.Findings {
			t.Errorf("%s: файл называет снятый глагол %s (%s) — след снятия: контракт, проводка, "+
				"каталог прав, манифест, политика вызывающих либо документ утверждают о глаголе, "+
				"которого служба не объявляет", f, verb.Name, verb.Refs)
		}
	}
}
