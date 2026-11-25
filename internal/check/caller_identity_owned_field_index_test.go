// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"maps"
	"testing"
)

func TestCallerIdentityOwnedFieldIndexPreservesScopeProof(t *testing.T) {
	p := callerCanonicalScopeProgram(t)
	reference, _, _, _ := callerCanonicalScopeGraph(t, p)
	g := callerGraphFor(p, nil)
	g.ctx = context.Background()
	g.claimCallerFieldQueryIndex()
	if g.fieldQueryIndexOwner != g {
		t.Fatal("новый граф не получил владение пустым индексом")
	}
	for i, frame := range reference.fieldQueries {
		index, entered := g.enterCallerFieldQuery(frame.source.source, frame.fields)
		if !entered || index != i {
			t.Fatalf("отклонён корректный кадр %d", i)
		}
		g.fieldQueries[index].refs, g.fieldQueries[index].unknown = frame.refs, frame.unknown
	}
	before := g.work.ObjectScopeTrackedFrameVisits
	exact := reference.callerExecutionSnapshot()
	if !exact.matches(g) || g.work.ObjectScopeTrackedFrameVisits != before {
		t.Fatal("корректный закрытый индекс требует повторного обхода кадров")
	}

	// Быстрый путь проверяет лишь структуру индекса. Изменение содержимого
	// того же кадра должно по-прежнему отвергать повторное использование ответа.
	frame := &g.fieldQueries[0]
	frame.unknown = !frame.unknown
	if exact.matches(g) {
		t.Fatal("снимок приняли после изменения UNKNOWN")
	}
	frame.unknown = !frame.unknown
	if !exact.matches(g) {
		t.Fatal("восстановленный снимок должен совпасть")
	}

	// У копии этого же графа нет права пропустить проверку.
	clone := *g
	clone.fieldQueryHeads = maps.Clone(g.fieldQueryHeads)
	clone.fieldQueryHeads[g.fieldQueries[0].source] = 0
	if exact.matches(&clone) || !exact.matches(g) {
		t.Fatal("повреждение посторонней копии должно отклонить только её")
	}

	g.leaveCallerFieldQuery(1)
	if g.fieldQueryIndexOwner != nil || g.callerExecutionScopeTracked() {
		t.Fatal("снятие кадра не по порядку должно отозвать владение индексом")
	}
	g.leaveCallerFieldQuery(0)
	if g.fieldQueryIndexOwner != nil || !g.callerExecutionScopeTracked() {
		t.Fatal("опустевший индекс должен проверяться обычным путём")
	}
}

func TestCallerIdentityOwnedFieldIndexDeclinesOpaqueContext(t *testing.T) {
	g := callerGraphFor(callerCanonicalScopeProgram(t), nil)
	g.ctx = &callerExecutionResetContext{Context: context.Background(), checkpoint: func() {}}
	g.claimCallerFieldQueryIndex()
	if g.fieldQueryIndexOwner != nil {
		t.Fatal("граф с внешним обработчиком контекста получил быстрый путь")
	}
}
