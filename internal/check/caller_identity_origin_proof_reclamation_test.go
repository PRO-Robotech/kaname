// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import "testing"

func TestCallerIdentityOriginTransferProofKeepsPushedGuard(t *testing.T) {
	p, root, _, _ := callerOriginTransferProgram(t, 4)
	g, original := callerOriginTransferPair(t, p, root)
	c := g.objectExecutions
	seen := map[callerResolveKey]bool{}
	owner := g.beginCallerOrigin(seen)
	if owner == nil {
		t.Fatal("не допущен настоящий owner")
	}
	defer func() {
		if owner.live {
			g.endCallerOrigin(owner)
		}
	}()
	key := callerResolveKeyFor(root, false)
	outer := g.beginCallerOriginFrame(owner, key)
	if outer == nil {
		t.Fatal("не допущен внешний frame")
	}
	defer func() {
		if outer.live {
			g.endCallerOriginFrame(owner, outer, nil, true)
		}
	}()
	key.source.tuple += 1000
	frame := g.beginCallerOriginFrame(owner, key)
	if frame == nil {
		t.Fatal("не допущен pushed frame")
	}
	defer func() {
		if frame.live {
			g.endCallerOriginFrame(owner, frame, nil, true)
		}
	}()
	frame.pushed, seen[key] = true, true
	defer delete(seen, key)
	for index := 0; !frame.bad && index <= callerOriginDependencyLimit; index++ {
		other := key
		other.source.tuple += index + 1
		g.addCallerOriginDependency(owner, frame, other, false)
	}
	if !frame.bad || frame.callerOriginProof != nil || frame.units != callerOriginGuardUnits ||
		frame.dependencies != nil || frame.count != 0 || frame.parent != outer || frame.owner != owner ||
		frame.key != key || !frame.pushed || !seen[key] || owner.top != frame || owner.bad {
		t.Fatal("отказ proof уничтожил live guard или оставил неоплаченное доказательство")
	}
	callerOriginAccount(t, c)
	entries, units, count := c.entries, c.weight, outer.count
	// Даже без proof свой pushed key останавливает передачу внешнему frame.
	g.callerOriginRead(owner, key, true)
	if outer.bad || outer.count != count || c.entries != entries || c.weight != units {
		t.Fatal("удаление proof позволило чтению пересечь сохранённую pushed-границу")
	}
	if c.rejectCallerOriginFrame(frame) != 0 || c.entries != entries || c.weight != units {
		t.Fatal("повторный отказ списал физическую память второй раз")
	}
	delete(seen, key)
	g.endCallerOriginFrame(owner, frame, nil, true)
	g.endCallerOriginFrame(owner, outer, nil, true)
	g.endCallerOrigin(owner)
	callerOriginAccount(t, c)
	callerOriginSame(t, callerOriginObserve(g, root, map[callerResolveKey]bool{}),
		callerOriginObserve(original, root, map[callerResolveKey]bool{}))
}

func TestCallerIdentityOriginTransferProofReclaimsForChild(t *testing.T) {
	p, root, _, _ := callerOriginTransferProgram(t, 4)
	g, original := callerOriginTransferPair(t, p, root)
	c := g.objectExecutions
	owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
	if owner == nil {
		t.Fatal("не допущен настоящий owner")
	}
	key := callerResolveKeyFor(root, false)
	first := g.beginCallerOriginFrame(owner, key)
	if first == nil {
		t.Fatal("не допущен первый frame")
	}
	key.source.tuple++
	second := g.beginCallerOriginFrame(owner, key)
	if second == nil {
		t.Fatal("не допущен второй frame")
	}
	_, drain := callerOriginAdmissionPressure(t, g)
	var child *callerOriginRecord
	cleanup := func() {
		if child != nil && child.live {
			g.endCallerOriginFrame(owner, child, nil, true)
		}
		if second.live {
			g.endCallerOriginFrame(owner, second, nil, true)
		}
		if first.live {
			g.endCallerOriginFrame(owner, first, nil, true)
		}
		drain()
		if owner.live {
			g.endCallerOrigin(owner)
		}
	}
	defer cleanup()
	need := callerOriginRecordUnits + callerOriginDependencyUnits
	// Два seed сами по себе не освобождают места для дочернего полного frame.
	if first.count != 1 || second.count != 1 || c.traceRoom(2, need) ||
		callerObjectExecutionValues-c.weight+2*callerOriginDependencyUnits >= need {
		t.Fatal("давление не отделяет освобождение proof от прежнего удаления seed")
	}
	entries, units, active := c.entries, c.weight, c.active
	key.source.tuple++
	child = g.beginCallerOriginFrame(owner, key)
	if child == nil || child.bad || child.parent != second || child.count != 1 ||
		!first.bad || !second.bad || first.callerOriginProof != nil || second.callerOriginProof != nil ||
		first.units != callerOriginGuardUnits || second.units != callerOriginGuardUnits ||
		owner.bad || owner.capacityBoundary != second {
		t.Fatal("освобождение двух proof не сохранило guards и независимый дочерний сертификат")
	}
	if c.entries != entries || c.weight != units-2*callerOriginProofUnits+need || c.active != active+1 {
		t.Fatal("учёт не соответствует двум удалённым proof и новому guard с seed")
	}
	callerOriginAccount(t, c)
	cleanup()
	callerOriginAccount(t, c)
	callerOriginSame(t, callerOriginObserve(g, root, map[callerResolveKey]bool{}),
		callerOriginObserve(original, root, map[callerResolveKey]bool{}))
}

func TestCallerIdentityOriginTransferProofRetiredAccount(t *testing.T) {
	p, root, _, _ := callerOriginTransferProgram(t, 4)
	g, _ := callerOriginTransferPair(t, p, root)
	c := g.objectExecutions
	owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
	if owner == nil {
		t.Fatal("не допущен настоящий owner")
	}
	frame := g.beginCallerOriginFrame(owner, callerResolveKeyFor(root, false))
	if frame == nil {
		t.Fatal("не допущен настоящий frame")
	}
	entries, units, proof := c.entries, c.weight, frame.callerOriginProof
	g.resetCallerObjectExecutions()
	if c.graph != nil || g.objectExecutions != c || c.active == 0 {
		t.Fatal("reset не сохранил активный B1 namespace")
	}
	if c.rejectCallerOriginFrame(frame) != 0 || frame.callerOriginProof != proof ||
		c.entries != entries || c.weight != units {
		t.Fatal("отказ в retired namespace преждевременно освободил proof или его учёт")
	}
	callerOriginAccount(t, c)
	g.endCallerOriginFrame(owner, frame, nil, true)
	g.endCallerOrigin(owner)
	if c.active != 0 || c.entries != entries || c.weight != units || frame.callerOriginProof != proof {
		t.Fatal("B1 unwind изменил удержанный физический account")
	}
	callerOriginAccount(t, c)
	g.resetCallerObjectExecutions()
	if g.objectExecutions == c || g.objectExecutions.entries != 0 || g.objectExecutions.weight != 0 {
		t.Fatal("idle reset не отделил новый пустой namespace")
	}
}

func TestCallerIdentityOriginTransferProofAllocationBudget(t *testing.T) {
	p, root, _, _ := callerOriginTransferProgram(t, 4)
	g, _ := callerOriginTransferPair(t, p, root)
	owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
	if owner == nil {
		t.Fatal("не допущен настоящий owner")
	}
	defer func() {
		if owner.live {
			g.endCallerOrigin(owner)
		}
	}()
	key := callerResolveKeyFor(root, false)
	allocations := testing.AllocsPerRun(20, func() {
		frame := g.beginCallerOriginFrame(owner, key)
		if frame == nil {
			panic("не допущен frame без давления")
		}
		g.endCallerOriginFrame(owner, frame, nil, false)
	})
	if allocations > 2 {
		t.Fatalf("guard и proof со встроенным seed выделили лишние объекты: %v", allocations)
	}
	callerOriginAccount(t, g.objectExecutions)
}
