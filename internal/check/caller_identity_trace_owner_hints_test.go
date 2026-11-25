// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"testing"
)

func TestCallerIdentityTraceOwnerHintsPreserveStack(t *testing.T) {
	p := callerTraceTypedProgram(t, callerTraceDiamondBody(4))
	g, _, _ := callerTraceTypedGraph(t, p, "x4")
	g.ctx = context.Background()
	seen := make(map[callerObjectSourceID]bool)
	chain := g.beginCallerTrace(seen)
	if chain == nil {
		t.Fatal("не удалось начать учтённую трассировку")
	}
	defer g.endCallerTrace(chain)
	chain.executing = true

	// Те же парные push/seen и delete/pop, что в закрытом рабочем обходе.
	push := func(source callerObjectSourceID) *callerTraceFrame {
		t.Helper()
		frame := g.callerTracePush(chain, source)
		if frame == nil {
			t.Fatal("не удалось войти в учтённый кадр")
		}
		seen[source] = true
		return frame
	}
	pop := func(frame *callerTraceFrame) {
		t.Helper()
		delete(seen, frame.source)
		g.callerTracePop(chain, frame)
	}
	for source := callerObjectSourceID(1); source <= 12; source++ {
		frame := push(source)
		defer pop(frame)
	}
	for _, source := range []callerObjectSourceID{1, 2} {
		if depth := g.callerTraceOwnerDepth(chain, source); depth != int(source) {
			t.Fatalf("начальный поиск: источник %d, глубина %d", source, depth)
		}
	}
	checkRepeated := func() int {
		t.Helper()
		before := g.work.ObjectTraceDependencySteps
		for range 8 {
			for _, source := range []callerObjectSourceID{1, 2} {
				if depth := g.callerTraceOwnerDepth(chain, source); depth != int(source) {
					t.Fatalf("повторный поиск: источник %d, глубина %d", source, depth)
				}
			}
		}
		return g.work.ObjectTraceDependencySteps - before
	}
	closed := checkRepeated()
	callerAssertExecutionRetention(t, g.objectExecutions, nil)
	chain.executing = false
	open := checkRepeated()
	chain.executing = true
	executions := g.objectExecutions
	g.objectExecutions = nil
	detached := checkRepeated()
	g.objectExecutions = executions
	if closed != 16 || open != 8*(12+11) || detached != open {
		t.Fatalf("число просмотров живых кадров: закрытая цепь %d, открытая %d, без владельца %d", closed, open, detached)
	}

	child := push(13)
	for _, source := range []callerObjectSourceID{3, 1, 13} {
		if depth := g.callerTraceOwnerDepth(chain, source); depth != int(source) {
			t.Fatalf("совпадение номера ячейки: источник %d, глубина %d", source, depth)
		}
	}
	pop(child)
	if child.ownerHints != ([2]*callerTraceFrame{}) {
		t.Fatal("снятый кадр удержал ссылку на предка")
	}
	if depth := g.callerTraceOwnerDepth(chain, 13); depth != 0 {
		t.Fatalf("снятый источник всё ещё имеет владельца на глубине %d", depth)
	}
	if count := checkRepeated(); count != closed {
		t.Fatalf("возврат к родительскому кадру изменил число просмотров: %d", count)
	}
}
