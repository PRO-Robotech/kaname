// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"hash/maphash"
	"testing"
)

func TestCallerIdentityScopeBooleanHashesKeepPrimitiveValues(t *testing.T) {
	for range 2 {
		seed := maphash.MakeSeed()
		hashes := callerExecutionBoolHashes{}
		// Эталон — прежний примитив стандартной библиотеки, без копии
		// производственного обхода scope. Оба значения повторяются и чередуются.
		for _, value := range []bool{false, false, true, true, false, true} {
			if got, want := hashes.sum(seed, value), maphash.Comparable(seed, value); got != want {
				t.Fatalf("хеш bool изменился: значение=%v получено=%x ожидалось=%x", value, got, want)
			}
		}
	}
	// Пустое содержимое сохраняет исходную нулевую корзину и не читает seed:
	// прежний чистый расчёт здесь не обращался даже к nil receiver.
	var empty *callerObjectExecutions
	if got := empty.scopeHash(&callerGraph{}); got != 0 {
		t.Fatalf("пустой scope изменил корзину: %x", got)
	}
}

func TestCallerIdentityScopeProofSurvivesStandardContextChecks(t *testing.T) {
	g, _, _, _ := callerCanonicalScopeGraph(t, callerCanonicalScopeProgram(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.ctx = ctx
	if !callerFreshReplayContext(ctx) {
		t.Fatal("закреплённый контекст должен допускать чистую проверку отмены")
	}
	c := g.objectExecutions
	before := g.work.ObjectScopeTrackedFrameVisits
	marks := callerReuseMarks(g)
	entries, units := c.entries, c.weight
	scope := c.scope(g)
	if scope == nil {
		t.Fatal("не получен снимок типизированного стека")
	}
	visits := g.work.ObjectScopeTrackedFrameVisits - before
	if !scope.snapshot.matches(g) || marks != callerReuseMarks(g) {
		t.Fatal("полученный снимок или семантические отметки изменились")
	}
	c.releaseTicket(g, scope)
	if c.entries != entries || c.weight != units || c.active != 0 {
		t.Fatal("после освобождения снимка остались удерживаемые данные")
	}
	if want := len(g.fieldQueries); visits != want {
		t.Fatalf("повторная проверка кадров после чистого Err: обходов %d, ожидается %d", visits, want)
	}
}

func TestCallerIdentityScopePointerReadsStayWithinCheckpoint(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trigger int
		changed bool
	}{
		{"before_copy/equal", 1, false},
		{"before_copy/changed", 1, true},
		{"after_copy/equal", 2, false},
		{"after_copy/changed", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, _, _, _ := callerCanonicalScopeGraph(t, callerCanonicalScopeProgram(t))
			c := g.objectExecutions
			full := g.captureCallerContainerObjectScope()
			for _, head := range c.scopes {
				for node := head; node != nil; node = node.next {
					if node.snapshot.matches(g) {
						t.Fatal("фикстура уже удерживает точный scope до проверяемого acquire")
					}
				}
			}
			if full.queries[0].source == full.queries[1].source || len(full.queries[0].refs) == 0 {
				t.Fatal("typed фикстура не различает источники или не содержит реальные refs")
			}
			defer func() {
				g.ctx = nil
				g.fieldQueries = full.queries
			}()
			entries, units, active := c.entries, c.weight, c.active
			marks, epoch := callerReuseMarks(g), g.bindingEpoch
			checks, replacements := 0, 0
			g.ctx = &callerExecutionResetContext{Context: context.Background(), checkpoint: func() {
				checks++
				if checks != tc.trigger {
					return
				}
				replacements++
				retired := g.fieldQueries
				replacement := callerExecutionSlice(retired)
				for i := range replacement {
					replacement[i].fields = callerExecutionSlice(replacement[i].fields)
					replacement[i].refs = callerExecutionSlice(replacement[i].refs)
				}
				g.fieldQueries = replacement
				// Указатель из завершившегося чистого чтения не должен пережить
				// Err: старый массив теперь намеренно содержит неверный source.
				retired[0].source = full.queries[1].source
				if tc.changed {
					// Единственная дельта к законному близнецу — тот же дефект
					// внесён ещё и в новый живой массив, при прежних heads/depth.
					g.fieldQueries[0].source = full.queries[1].source
				}
			}}
			acquired := c.scope(g)
			defer func() {
				if acquired != nil {
					c.releaseTicket(g, acquired)
				}
			}()
			g.ctx = nil
			expectedChecks := 2
			if tc.changed {
				expectedChecks = tc.trigger
			}
			if checks != expectedChecks || replacements != 1 || g.bindingEpoch != epoch || callerReuseMarks(g) != marks {
				t.Fatal("подмена массива изменила checkpoint, эпоху или семантические отметки")
			}
			if tc.changed {
				if acquired != nil {
					t.Fatal("изменённый живой source принят по старому указателю")
				}
				if g.callerExecutionScopeTracked() || full.matches(g) {
					t.Fatal("неверный живой source прошёл точное доказательство")
				}
			} else {
				if acquired == nil {
					t.Fatal("равное typed содержимое в новом массиве отвергнуто по старому указателю")
				}
				if c.active != active+1 || c.entries != entries+1 || c.weight != units+acquired.weight || !acquired.snapshot.matches(g) || !full.matches(g) {
					t.Fatal("равный новый массив изменил payload, ticket или физический учёт")
				}
				callerAssertExecutionRetention(t, c, acquired)
				c.releaseTicket(g, acquired)
				acquired = nil
			}
			if c.active != active || c.entries != entries || c.weight != units {
				t.Fatal("проверка замены массива оставила удерживаемое владение")
			}
			callerAssertExecutionRetention(t, c, nil)
		})
	}
}
