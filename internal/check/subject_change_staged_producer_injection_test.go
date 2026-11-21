// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// Проба использует текущий полный корпус обоих guards. Объявление двух
// staged callbacks не разрешает третьего producer, перенос или исчезновение.
// Это census-контроль, не доказательство transaction/flush семантики.
func TestStagedSubjectChangeProducerRoster_InjectionBothWays(t *testing.T) {
	t.Parallel()
	const stagedRel = "internal/apps/kaname/api/access_binding/staged_withdrawal.go"
	const movedRel = "internal/apps/kaname/api/access_binding/staged_withdrawal_moved.go"
	const addedRel = "internal/apps/kaname/api/access_binding/subject_change_added.go"
	const selector = "w.AccessBindingsW().EmitSubjectChangeEvent"
	tree, err := treecorpus.NewTree(peopleAddressRoot(t))
	if err != nil {
		t.Fatalf("состав дерева не установлен: %v", err)
	}
	corpus, err := check.SubjectChangeProducerCorpus(tree)
	if err != nil {
		t.Fatalf("корпус производителей не прочитан: %v", err)
	}
	source, ok := corpus[stagedRel]
	if !ok || strings.Count(source, selector) != 2 {
		t.Fatalf("инъекция не выполнена: %s должен нести ровно два якоря, найдено %d", stagedRel, strings.Count(source, selector))
	}
	for _, receiver := range []string{"DeleteAccessBindingUseCase", "RevokeAccessBindingUseCase"} {
		if strings.Count(source, "func (u *"+receiver+") withdrawStaged(") != 1 {
			t.Fatalf("инъекция не выполнена: actual staged method %s не найден однозначно", receiver)
		}
	}
	if subjectChangeProducerRoster[stagedRel] != 2 {
		t.Fatalf("staged entry должна объявлять ровно два обращения, объявлено %d", subjectChangeProducerRoster[stagedRel])
	}
	for _, rel := range []string{movedRel, addedRel} {
		if _, exists := corpus[rel]; exists {
			t.Fatalf("инъекция не выполнена: destination уже занят: %s", rel)
		}
	}
	first := strings.Index(source, selector)
	last := strings.LastIndex(source, selector)
	replaceAt := func(offset int) string {
		return source[:offset] + "w.AccessBindingsW().EmitSomethingElse" + source[offset+len(selector):]
	}
	// Вставляем третье обращение именно в первый existing after callback,
	// сохраняя обе исходные ссылки и весь остальной реальный source.
	callbackAnchor := "\t\tif err := emitSubjectChangeFor(ctx, " + selector
	if strings.Count(source, callbackAnchor) != 2 {
		t.Fatalf("инъекция не выполнена: два actual after callbacks не найдены")
	}
	third := strings.Replace(source, callbackAnchor, "\t\t_ = "+selector+"\n"+callbackAnchor, 1)
	for _, tc := range []struct {
		name              string
		change            func(check.TreeCorpus, map[string]int)
		stagedCount       int
		undeclared, stale string
		parseError        bool
	}{
		{name: "actual two staged callbacks", stagedCount: 2},
		{name: "roster entry removed", stagedCount: 2, undeclared: stagedRel,
			change: func(_ check.TreeCorpus, roster map[string]int) { delete(roster, stagedRel) }},
		{name: "one callback declared", stagedCount: 2, undeclared: stagedRel,
			change: func(_ check.TreeCorpus, roster map[string]int) { roster[stagedRel] = 1 }},
		{name: "third callback predeclared", stagedCount: 2, stale: stagedRel,
			change: func(_ check.TreeCorpus, roster map[string]int) { roster[stagedRel] = 3 }},
		{name: "delete callback producer removed", stagedCount: 1, stale: stagedRel,
			change: func(c check.TreeCorpus, _ map[string]int) { c[stagedRel] = replaceAt(first) }},
		{name: "revoke callback producer removed", stagedCount: 1, stale: stagedRel,
			change: func(c check.TreeCorpus, _ map[string]int) { c[stagedRel] = replaceAt(last) }},
		{name: "both producers removed", stagedCount: 0, stale: stagedRel,
			change: func(c check.TreeCorpus, _ map[string]int) {
				c[stagedRel] = strings.ReplaceAll(source, selector, "w.AccessBindingsW().EmitSomethingElse")
			}},
		{name: "extra producer in actual callback", stagedCount: 3, undeclared: stagedRel,
			change: func(c check.TreeCorpus, _ map[string]int) { c[stagedRel] = third }},
		{name: "new producer file", stagedCount: 2, undeclared: addedRel,
			change: func(c check.TreeCorpus, _ map[string]int) {
				c[addedRel] = "package access_binding\nfunc extra(w Writer) { _ = " + selector + " }\n"
			}},
		{name: "moved producers expire old coordinate", stagedCount: 0, undeclared: movedRel, stale: stagedRel,
			change: func(c check.TreeCorpus, _ map[string]int) { delete(c, stagedRel); c[movedRel] = source }},
		{name: "selector words in prose are silent", stagedCount: 2,
			change: func(c check.TreeCorpus, _ map[string]int) {
				c[stagedRel] = source + "\n// " + selector + "\nconst stagedProducerDescription = \"" + selector + "\"\n"
			}},
		{name: "broken source is not a quiet census", parseError: true,
			change: func(c check.TreeCorpus, _ map[string]int) { c[stagedRel] = source + "\nfunc broken(\n" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := check.TreeCorpus{}
			for rel, src := range corpus {
				input[rel] = src
			}
			roster := map[string]int{}
			for rel, count := range subjectChangeProducerRoster {
				roster[rel] = count
			}
			if tc.change != nil {
				tc.change(input, roster)
			}
			var producers []check.SubjectChangeProducer
			stagedCount := 0
			for _, rel := range input.Rels() {
				found, parseErr := check.SubjectChangeProducersIn(rel, input[rel])
				if parseErr != nil {
					if tc.parseError && rel == stagedRel {
						return
					}
					t.Fatalf("неожиданный отказ разбора %s: %v", rel, parseErr)
				}
				producers = append(producers, found...)
				if rel == stagedRel {
					stagedCount = len(found)
				}
			}
			if tc.parseError {
				t.Fatal("повреждённый source молча принят")
			}
			if stagedCount != tc.stagedCount {
				t.Fatalf("actual staged producers: %d, ожидалось %d", stagedCount, tc.stagedCount)
			}
			diff := check.CompareSubjectChangeRoster(producers, roster)
			assertSide := func(label string, actual []string, coordinate string) {
				t.Helper()
				if coordinate == "" {
					if len(actual) != 0 {
						t.Fatalf("%s: неожиданные находки %v", label, actual)
					}
					return
				}
				if len(actual) != 1 || !strings.Contains(actual[0], coordinate) {
					t.Fatalf("%s: нужна одна находка на %s, получено %v", label, coordinate, actual)
				}
			}
			assertSide("undeclared", diff.Undeclared, tc.undeclared)
			assertSide("stale", diff.Stale, tc.stale)
		})
	}
}
