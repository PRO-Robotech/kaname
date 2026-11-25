// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"fmt"
	"go/types"
	"slices"
	"strings"
	"testing"
)

func TestCallerIdentityFieldQueryCandidateWorkBound(t *testing.T) {
	const activeSources, duplicateQueries = 64, 8
	var body strings.Builder
	for i := 0; i < activeSources; i++ {
		fmt.Fprintf(&body, "box%d:=&Box{reader:Benign{}};_=box%d;", i, i)
	}
	p := callerSoundnessProgram(t, "", body.String(), `&Handler{}`)
	g, refs := newCallerGraph(p), callerOwnershipSources(p)
	field := p.root.types.Scope().Lookup("Box").Type().Underlying().(*types.Struct).Field(0)
	fields := []*types.Var{field}
	var last valueSrc
	for i := 0; i < activeSources; i++ {
		src := refs[fmt.Sprintf("box%d", i)]
		if src.pkg == nil || src.expr == nil || callerVariable(src.pkg, src.expr) == nil {
			t.Fatal("fixture lost a typed distinct source")
		}
		index, entered := g.enterCallerFieldQuery(src, fields)
		if !entered || index != i {
			t.Fatal("distinct typed source did not create its own active frame")
		}
		last = src
	}
	snapshot := []valueSrc{refs["box0"], refs["box1"]}
	g.fieldQueries[activeSources-1].refs = snapshot
	g.fieldQueries[activeSources-1].unknown = true
	candidates, cuts := g.work.FieldQueryCandidates, g.resolveCuts
	epoch, skips, completed := g.bindingEpoch, g.initialSkips, g.completedInitialSkips
	for i := 0; i < duplicateQueries; i++ {
		index, entered := g.enterCallerFieldQuery(last, fields)
		if entered || index != activeSources-1 {
			t.Fatal("duplicate query lost the exact active frame")
		}
		active := g.fieldQueries[index]
		if !active.unknown || !slices.Equal(active.refs, snapshot) {
			t.Fatal("duplicate query changed the exact current snapshot or UNKNOWN")
		}
	}
	if len(g.fieldQueries) != activeSources || g.resolveCuts-cuts != duplicateQueries || g.bindingEpoch != epoch || g.initialSkips != skips || g.completedInitialSkips != completed || len(g.resolveMemo) != 0 || len(g.initialResolveMemo) != 0 || len(g.objectMemo) != 0 || len(g.initialObjectMemo) != 0 || g.work.ObjectRetained != 0 || g.work.ResolveMemoEntries != 0 {
		t.Fatal("snapshot cuts changed active state, published an answer, or received completion credit")
	}
	// Измеряется только восемь повторных запросов, без стоимости подготовки фикстуры.
	if visits := g.work.FieldQueryCandidates - candidates; visits > activeSources {
		t.Fatalf("field-query candidate work exceeded bound: got %d, maximum %d", visits, activeSources)
	}
}
