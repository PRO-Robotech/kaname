// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"testing"
)

// Тот же typed call-return сравнивается с исходным обходом без execution
// cache; обычный memo reference сохраняется. Между direct и call-return
// равенство объектов не предполагается. Сроки и скорость не измеряются.
func TestCallerIdentityReturnChildTracePreservesColdAndWarmSemantics(t *testing.T) {
	for _, depth := range []int{4, 6, 8} {
		t.Run(fmt.Sprintf("depth-%d", depth), func(t *testing.T) {
			name := fmt.Sprintf("x%d", depth)
			body := strings.Replace(callerTraceDiamondBody(depth), "x0:=holder.items;",
				"x0:=holder.items;x0=append(x0,Box{});x0=append(x0,Box{});", 1)
			body += "id:=func(v []Box)[]Box{return v};result:=id(" + name + ");_=result"
			p := callerTraceTypedProgram(t, body)
			fast, _, refs := callerTraceTypedGraph(t, p, name)
			reference, _, otherRefs := callerTraceTypedGraph(t, p, name)
			fast.ctx, reference.ctx = context.Background(), context.Background()
			reference.objectExecutions = nil
			root := refs["result"]
			callRefs := fast.assignments[callerVariable(root.pkg, root.expr).Origin()]
			if len(callRefs) != 1 {
				t.Fatal("у результата вызова должен быть один источник")
			}
			seen, otherSeen := map[callerObjectSourceID]bool{}, map[callerObjectSourceID]bool{}
			seenBefore, otherSeenBefore := maps.Clone(seen), maps.Clone(otherSeen)
			epoch := fast.bindingEpoch
			var cold, coldReference, frozenCold, frozenReference map[callerObjectKey]bool
			for _, phase := range []string{"cold", "warm"} {
				before := fast.work
				marks, referenceMarks := callerReuseMarks(fast), callerReuseMarks(reference)
				got, unknown, _ := fast.callerObjectsOwned(refs["result"], seen)
				want, otherUnknown, _ := reference.callerObjectsOwned(otherRefs["result"], otherSeen)
				if !maps.Equal(seen, seenBefore) || !maps.Equal(otherSeen, otherSeenBefore) {
					t.Fatalf("%s: исходные visited sets не восстановлены", phase)
				}
				delta, referenceDelta := callerReuseDelta(fast, marks), callerReuseDelta(reference, referenceMarks)
				if fast.semanticOverflow || reference.semanticOverflow || unknown != otherUnknown ||
					!maps.Equal(got, want) || len(got) == 0 || delta != referenceDelta {
					t.Fatalf("%s: изменились typed objects, UNKNOWN или семантические счётчики", phase)
				}
				if delta[3] == 0 {
					t.Fatalf("%s: self-append cycle не исполнен", phase)
				}
				// До diamond расположен effectful bind. Старый bad parent не
				// сохраняет этот хвост; положительный hit требует child reuse.
				if fast.work.ObjectTraceHits <= before.ObjectTraceHits {
					t.Fatalf("%s: дочерняя трасса не использована", phase)
				}
				if phase == "cold" {
					if fast.bindingEpoch <= epoch || fast.work.ObjectTraceStores <= before.ObjectTraceStores {
						t.Fatal("cold: нет штатного bind или новых trace records")
					}
					cold, coldReference = got, want
					frozenCold, frozenReference = maps.Clone(got), maps.Clone(want)
				} else if !maps.Equal(cold, frozenCold) || !maps.Equal(coldReference, frozenReference) {
					t.Fatal("warm: изменена ранее возвращённая карта объектов")
				}
				if reference.objectExecutions != nil {
					t.Fatal("reference получил execution cache")
				}
				callID := fast.objectSourceIDs[callerResolveKeyFor(callRefs[0], true)]
				if callID == 0 {
					t.Fatalf("%s: обход не дошёл до вызова", phase)
				}
				for _, record := range callerUnlinkRecords(t, fast.objectExecutions) {
					if record.source == callID {
						t.Fatalf("%s: сам вызов сохранён в кэше", phase)
					}
				}
				callerAssertExecutionRetention(t, fast.objectExecutions, nil)
				if fast.objectExecutions.active != 0 || fast.objectExecutions.traceChains != nil || fast.objectExecutions.traceFrames != nil {
					t.Fatalf("%s: после возврата остались живые цепи или кадры", phase)
				}
			}
		})
	}
}
