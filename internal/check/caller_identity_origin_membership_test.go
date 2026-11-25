// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"math/bits"
	"testing"
	"unsafe"
)

func TestCallerIdentityOriginMembershipCollisions(t *testing.T) {
	p, root, _, _ := callerOriginTransferProgram(t, 4)
	g, _ := callerOriginTransferPair(t, p, root)
	c := g.objectExecutions
	owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
	if owner == nil {
		t.Fatal("owner admission failed")
	}
	defer g.endCallerOrigin(owner)
	node := &ast.Ident{Name: "membership", NamePos: 1}
	key := callerResolveKeyFor(root, false)
	key.source.expr, key.source.tuple = node, 0
	empty := key
	empty.source.expr = nil
	empty.source.tuple = 3
	if c.originDependencySlot(empty) != 4 {
		t.Fatal("nil expression must use only the tuple")
	}
	frame := g.beginCallerOriginFrame(owner, key)
	if frame == nil {
		t.Fatal("frame admission failed")
	}
	defer g.endCallerOriginFrame(owner, frame, nil, false)
	collision := key
	collision.source.tuple = bits.UintSize
	sameSlot := collision
	sameSlot.receiver = true
	other := key
	other.source.tuple++
	first := c.originDependencySlot(key)
	if first != c.originDependencySlot(collision) || first != c.originDependencySlot(sameSlot) ||
		first == c.originDependencySlot(other) || frame.dependencyMask != first.mask() {
		t.Fatal("fixture did not exercise collision and definite absence")
	}
	a := g.addCallerOriginDependency(owner, frame, collision, true)
	b := g.addCallerOriginDependency(owner, frame, sameSlot, false)
	d := g.addCallerOriginDependency(owner, frame, other, true)
	if a == nil || b == nil || d == nil || frame.dependencies != d ||
		d.next != b || b.next != a || a.next != &frame.seed || a == b ||
		frame.dependencyMask != first.mask()|c.originDependencySlot(other).mask() {
		t.Fatal("colliding keys changed insertion order, signs or membership")
	}
	node.Name, node.NamePos = "renamed", 999
	if g.addCallerOriginDependency(owner, frame, key, false) != &frame.seed ||
		g.addCallerOriginDependency(owner, frame, collision, true) != a ||
		g.addCallerOriginDependency(owner, frame, sameSlot, false) != b || frame.count != 4 {
		t.Fatal("exact duplicate missed after AST content mutation")
	}
	callerOriginAccount(t, c)
	if g.addCallerOriginDependency(owner, frame, collision, false) != nil ||
		!frame.bad || frame.count != 0 || frame.dependencyMask != 0 || frame.dependencies != nil || owner.bad {
		t.Fatal("opposite signed read of exact colliding key did not reject this proof")
	}
	callerOriginAccount(t, c)
}

func TestCallerIdentityOriginMembershipReplayAndScope(t *testing.T) {
	p, root, cycle, field := callerOriginTransferProgram(t, 4)
	g, _ := callerOriginTransferPair(t, p, root)
	c := g.objectExecutions
	owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
	if owner == nil {
		t.Fatal("owner admission failed")
	}
	sourceKey := callerResolveKeyFor(cycle, false)
	source := g.beginCallerOriginFrame(owner, sourceKey)
	if source == nil {
		t.Fatal("source admission failed")
	}
	a := callerResolveKeyFor(field, false)
	b := a
	b.source.tuple += bits.UintSize
	if g.addCallerOriginDependency(owner, source, a, false) == nil ||
		g.addCallerOriginDependency(owner, source, b, false) == nil {
		t.Fatal("source dependency admission failed")
	}
	g.resolveCuts++
	g.endCallerOriginFrame(owner, source, nil, true)
	if !source.retained {
		t.Fatal("source was not published")
	}
	targetKey := callerResolveKeyFor(root, false)
	target := g.beginCallerOriginFrame(owner, targetKey)
	if target == nil {
		t.Fatal("target admission failed")
	}
	owner.seen[b] = true
	if _, ok := g.callerOriginHit(owner, sourceKey); ok || target.count != 1 || source.pins != 0 {
		t.Fatal("retained source ignored exact seen validation for a colliding key")
	}
	delete(owner.seen, b)
	reads, hits := g.work.OriginTransferReads, g.work.OriginTransferHits
	answer, ok := g.callerOriginHit(owner, sourceKey)
	if !ok || !answer.unknown || source.pins != 0 || g.work.OriginTransferReads != reads+source.count ||
		g.work.OriginTransferHits != hits+1 || target.count != 4 {
		t.Fatal("cached fingerprints changed the transfer")
	}
	dep := target.dependencies
	for _, key := range []callerResolveKey{sourceKey, a, b} {
		if dep == nil || dep.key != key || dep.want || !dep.propagated || dep.slot != c.originDependencySlot(key) {
			t.Fatal("replay did not preserve ordered exact dependencies")
		}
		dep = dep.next
	}
	if dep != &target.seed || dep.next != nil {
		t.Fatal("replay disturbed the destination seed")
	}
	callerOriginAccount(t, c)
	g.bindingEpoch++
	if _, ok := g.callerOriginHit(owner, sourceKey); ok || source.pins != 0 {
		t.Fatal("old source admitted after binding epoch changed")
	}
	mask, entries, units := target.dependencyMask, c.entries, c.weight
	g.resetCallerObjectExecutions()
	if c.graph != nil || c.rejectCallerOriginFrame(target) != 0 || target.dependencyMask != mask ||
		c.entries != entries || c.weight != units {
		t.Fatal("retired namespace lost its charged dependencies before drain")
	}
	callerOriginAccount(t, c)
	g.endCallerOriginFrame(owner, target, nil, true)
	g.endCallerOrigin(owner)
	g.resetCallerObjectExecutions()
	fresh := g.beginCallerOrigin(map[callerResolveKey]bool{})
	if fresh == nil || fresh.cache == c {
		t.Fatal("new namespace was not admitted")
	}
	defer g.endCallerOrigin(fresh)
	if _, ok := g.callerOriginHit(fresh, sourceKey); ok {
		t.Fatal("new owner used the retired namespace")
	}
	f := g.beginCallerOriginFrame(fresh, targetKey)
	if f == nil {
		t.Fatal("new frame admission failed")
	}
	defer g.endCallerOriginFrame(fresh, f, nil, false)
	if f.count != 1 || f.dependencyMask != fresh.cache.originDependencySlot(targetKey).mask() {
		t.Fatal("new frame inherited stale membership")
	}
	callerOriginAccount(t, fresh.cache)
}

func TestCallerIdentityOriginMembershipPhysicalSize(t *testing.T) {
	aligned := func(n, alignment uintptr) uintptr { return (n + alignment - 1) &^ (alignment - 1) }
	var r callerOriginRecord
	var d callerOriginDependency
	// The preceding layout ended with an int bucket and six bools; the
	// dependency ended with two flags, pointer alignment and one next pointer.
	oldRecord := aligned(unsafe.Offsetof(r.dependencyMask)+unsafe.Sizeof(int(0))+6*unsafe.Sizeof(false), unsafe.Alignof(r))
	oldNext := aligned(unsafe.Offsetof(d.want)+2*unsafe.Sizeof(false), unsafe.Alignof(d.next))
	if unsafe.Sizeof(r) != oldRecord || unsafe.Offsetof(d.next) != oldNext || unsafe.Sizeof(d) != oldNext+unsafe.Sizeof(d.next) {
		t.Fatal("membership changed guard or dependency physical charge", unsafe.Sizeof(r), oldRecord, unsafe.Sizeof(d), oldNext)
	}
}
