// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"maps"
	"testing"
)

// Измеряем один настоящий прогретый execution hit. Достаточно одного структурного
// обхода перед сравнением снимка: до hit стек не меняется.
// Прежний алгоритм обходил N кадров дважды. Счётчик считает
// реальные чтения кадров, а semantic assertions выполняются до work assertion.
func TestCallerIdentityTrackedAcquisitionSingleProofWork(t *testing.T) {
	p := callerCanonicalScopeProgram(t)
	fast, root, _, _ := callerCanonicalScopeGraph(t, p)
	reference, otherRoot, _, _ := callerCanonicalScopeGraph(t, p)
	reference.objectExecutions = nil
	n := len(fast.fieldQueries)
	if n != 3 || len(fast.fieldQueryHeads) != 2 || len(reference.fieldQueries) != n {
		t.Fatal("typed scope lacks its nonempty repeated-source chain")
	}
	// Калибровка отдельного реального обхода до измеряемого execution.
	beforeProof := fast.work.ObjectScopeTrackedFrameVisits
	if !fast.callerExecutionScopeTracked() || fast.work.ObjectScopeTrackedFrameVisits-beforeProof != n {
		t.Fatal("tracked frame counter did not observe every typed frame exactly once")
	}
	escaped := callerPrimeObjectExecution(t, fast, root)
	immutable := maps.Clone(escaped)
	for range 3 {
		reference.callerObjects(otherRoot, map[callerObjectSourceID]bool{})
	}
	c := fast.objectExecutions
	pin := c.freshScope(fast)
	if pin == nil || !pin.snapshot.matches(fast) {
		t.Fatal("warm execution lacks a real pinned exact scope")
	}
	defer c.releaseTicket(fast, pin)
	state, epoch := fast.callerObjectExecutionState(), fast.bindingEpoch
	fm, rm := callerReuseMarks(fast), callerReuseMarks(reference)
	fr, rr := fast.work.ObjectRawEvaluations, reference.work.ObjectRawEvaluations
	hits, stores := fast.work.ObjectExecutionHits, fast.work.ObjectExecutionStores
	visits := fast.work.ObjectScopeTrackedFrameVisits
	got, unknown := fast.callerObjects(root, map[callerObjectSourceID]bool{})
	// Снять delta до любых дополнительных scope guards самой проверки.
	actual := fast.work.ObjectScopeTrackedFrameVisits - visits
	want, referenceUnknown := reference.callerObjects(otherRoot, map[callerObjectSourceID]bool{})
	if unknown || referenceUnknown || len(got) == 0 || !maps.Equal(got, want) || !maps.Equal(escaped, immutable) || !maps.Equal(got, immutable) {
		t.Fatal("warm replay changed typed objects, UNKNOWN or an escaped immutable map")
	}
	if callerReuseDelta(fast, fm) != callerReuseDelta(reference, rm) || callerReuseDelta(fast, fm)[0] <= callerReuseDelta(fast, fm)[1] || callerReuseDelta(fast, fm)[2] != 0 {
		t.Fatal("warm replay changed four semantic marks or invented completion credit")
	}
	if fast.work.ObjectExecutionHits != hits+1 || fast.work.ObjectRawEvaluations != fr || reference.work.ObjectRawEvaluations <= rr || fast.work.ObjectExecutionStores != stores {
		t.Fatal("measurement lacks one real warm execution hit and an uncached raw witness")
	}
	if fast.callerObjectExecutionState() != state || fast.bindingEpoch != epoch || !pin.snapshot.matches(fast) {
		t.Fatal("warm replay changed exact scope, epoch or durable state")
	}
	callerAssertExecutionRetention(t, c, pin)
	t.Logf("semantic checks passed: frames=%d visits=%d hits=%d fastRaw=%d referenceRaw=%d marks=%v", n, actual, fast.work.ObjectExecutionHits-hits, fast.work.ObjectRawEvaluations-fr, reference.work.ObjectRawEvaluations-rr, callerReuseDelta(fast, fm))
	if actual != n {
		t.Fatalf("redundant tracked acquisition work: frameVisits=%d want=%d; old entry + hit guard visits %d frames", actual, n, 2*n)
	}
}
