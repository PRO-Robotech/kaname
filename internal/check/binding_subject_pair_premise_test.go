// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// binding_subject_pair_premise_test.go — предпосылка гейта пары субъекта
// выдачи (kaname#917): снятая пара — «предмет гейта снят», а не зелёное.

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"
)

// bindingPairCheckDomain — синтетический пакет домена из исходника.
func bindingPairCheckDomain(t *testing.T, src string) *types.Package {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "domain.go", src, 0)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	conf := types.Config{Importer: importer.Default()}
	pkg, err := conf.Check("example/internal/domain", fset, []*ast.File{f}, nil)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	return pkg
}

// TestBindingSubjectPairRemovedPairIsNotGreen — у выдачи без пары (и без
// типа выдачи) гейт не исполняется: ему нечего судить, и сказать «доступов
// ноль» значило бы промолчать о том, что гейт пора снимать.
func TestBindingSubjectPairRemovedPairIsNotGreen(t *testing.T) {
	cases := map[string]string{
		"пары нет":        "package domain\ntype AccessBinding struct{ ID string; Subjects []string }\n",
		"половины пары":   "package domain\ntype AccessBinding struct{ SubjectType string }\n",
		"типа выдачи нет": "package domain\ntype Other struct{ SubjectType, SubjectID string }\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := bindingPairFieldObjects(bindingPairCheckDomain(t, src))
			if err == nil || !strings.Contains(err.Error(), "предмет гейта снят") {
				t.Fatalf("снятая пара не названа снятым предметом: %v", err)
			}
		})
	}
	// Близнец: пара на месте — оба поля найдены.
	fields, err := bindingPairFieldObjects(bindingPairCheckDomain(t,
		"package domain\ntype AccessBinding struct{ SubjectType, SubjectID string }\n"))
	if err != nil || len(fields) != 2 {
		t.Fatalf("пара на месте не найдена: %d полей, %v", len(fields), err)
	}
}
