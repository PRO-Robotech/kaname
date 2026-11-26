// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"maps"
	"slices"
	"testing"
)

// Обычный reader служит независимым oracle для второго entry-read. Сравниваются
// порядок точных predicates, propagated, отказ и полный физический accounting.
func TestCallerIdentityOriginTransferPreparedRawEntryRead(t *testing.T) {
	for _, mode := range []string{"prepared", "standalone", "refusal", "contradiction", "different_key", "pushed_ancestor", "matching_seed", "rejected_ancestor"} {
		t.Run(mode, func(t *testing.T) {
			p, root, _, _ := callerOriginTransferProgram(t, 4)
			type dependency struct {
				key              callerResolveKey
				want, propagated bool
			}
			type observation struct {
				entries, units, active, reads int
				parentBad, childBad           bool
				parentPushed                  bool
				seen                          map[callerResolveKey]bool
				parent, child                 []dependency
				marks                         [4]uint64
			}
			var got [2]observation
			for side := range got {
				g, original := callerOriginTransferPair(t, p, root)
				c := g.objectExecutions
				seen := map[callerResolveKey]bool{}
				owner := g.beginCallerOrigin(seen)
				if owner == nil {
					t.Fatal("exact owner admission failed")
				}
				key := callerResolveKeyFor(root, false)
				parentKey := key
				if mode != "matching_seed" {
					parentKey.source.tuple += 1000
				}
				parent := g.beginCallerOriginFrame(owner, parentKey)
				if parent == nil {
					t.Fatal("parent admission failed")
				}
				parentSeed := parent.dependencies
				if parentSeed == nil || parentSeed.propagated {
					t.Fatal("parent seed unexpectedly propagated before its first read")
				}
				if mode == "pushed_ancestor" {
					parent.pushed = true
					seen[parentKey] = true
				}
				prepared := false
				if mode != "standalone" {
					prepared = g.callerOriginRead(owner, key, false)
					if !prepared {
						t.Fatal("first exact read was not recorded")
					}
				}
				if mode == "matching_seed" && (parent.dependencies != parentSeed || !parentSeed.propagated || parent.count != 1) {
					t.Fatal("first read failed to propagate the existing exact parent seed")
				}
				if mode == "rejected_ancestor" {
					c.rejectCallerOriginFrame(parent)
				}
				drain := func() {}
				if mode == "refusal" {
					_, drain = callerOriginAdmissionPressure(t, g)
				}
				child := g.beginCallerOriginFrame(owner, key)
				cleanup := func() {
					drain()
					if child != nil && child.live {
						g.endCallerOriginFrame(owner, child, nil, true)
					}
					if parent.live {
						if parent.pushed {
							delete(seen, parentKey)
						}
						g.endCallerOriginFrame(owner, parent, nil, true)
					}
					if owner.live {
						g.endCallerOrigin(owner)
					}
				}
				defer cleanup()
				if mode == "refusal" {
					if child != nil || !parent.bad || owner.capacityBoundary != parent {
						t.Fatal("real pressure did not establish the refused-child boundary")
					}
				} else if child == nil || child.count != 1 || child.dependencies.propagated {
					t.Fatal("standalone begin prematurely claimed seed propagation")
				}
				want := mode == "contradiction"
				if mode == "different_key" {
					key.source.tuple++
				}
				beforeSeen := maps.Clone(seen)
				reads, marks := g.work.OriginTransferReads, callerReuseMarks(g)
				if side == 0 {
					g.callerOriginRead(owner, key, want)
				} else {
					g.callerOriginRawEntryRead(owner, child, key, want, prepared)
				}
				callerOriginAccount(t, c)
				capture := func(frame *callerOriginRecord) []dependency {
					var result []dependency
					if frame != nil {
						for dep := frame.dependencies; dep != nil; dep = dep.next {
							result = append(result, dependency{dep.key, dep.want, dep.propagated})
						}
					}
					return result
				}
				got[side] = observation{c.entries, c.weight, c.active, g.work.OriginTransferReads - reads,
					parent.bad, child != nil && child.bad, parent.pushed, maps.Clone(seen), capture(parent), capture(child), callerReuseDelta(g, marks)}
				if got[side].reads != 1 || got[side].marks != [4]uint64{} || owner.bad || !maps.Equal(seen, beforeSeen) {
					t.Fatal("entry-read changed logical counts, effects or owner validity")
				}
				if mode == "prepared" || mode == "standalone" || mode == "pushed_ancestor" {
					if parent.count != 2 || child.count != 1 || !child.dependencies.propagated || parent.bad || child.bad {
						t.Fatal("entry-read did not establish the complete negative witness")
					}
				}
				if mode == "matching_seed" && (parent.count != 1 || child.count != 1 || !parentSeed.propagated || !child.dependencies.propagated || parent.bad || child.bad) {
					t.Fatal("matching seeds lost the completed first-read witness")
				}
				if mode == "rejected_ancestor" && (!parent.bad || parent.count != 0 || parent.dependencies != nil || child.bad || child.count != 1 || !child.dependencies.propagated) {
					t.Fatal("fresh child resurrected the rejected ancestor or lost its own witness")
				}
				if mode == "pushed_ancestor" && (!parent.pushed || !seen[parentKey] || len(seen) != 1) {
					t.Fatal("entry-read changed the independent pushed ancestor")
				}
				cleanup()
				if len(seen) != 0 {
					t.Fatal("normal unwind left caller seen entries")
				}
				callerOriginAccount(t, c)
				// Настоящий resolver дополнительно проверяет origins/order/UNKNOWN
				// и все marks после unwind обеих независимых owner-сессий.
				callerOriginSame(t, callerOriginObserve(g, root, map[callerResolveKey]bool{}),
					callerOriginObserve(original, root, map[callerResolveKey]bool{}))
			}
			a, b := got[0], got[1]
			if a.entries != b.entries || a.units != b.units || a.active != b.active || a.reads != b.reads ||
				a.parentBad != b.parentBad || a.childBad != b.childBad || a.parentPushed != b.parentPushed ||
				!maps.Equal(a.seen, b.seen) || a.marks != b.marks ||
				!slices.Equal(a.parent, b.parent) || !slices.Equal(a.child, b.child) {
				t.Fatalf("prepared entry differs from ordinary read: %+v / %+v", a, b)
			}
		})
	}
}
