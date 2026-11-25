// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/types"
)

const (
	callerContainerInactiveEntries   = 8
	callerContainerInactivePositions = 2048
)

// Статический индекс разделяется графами. Этот фильтр принадлежит одному
// экземпляру графа и одному корню. Его срезы содержат позиции в неизменяемом
// списке кандидатов, а не ответы об объектах или алиасах.
type callerContainerInactiveVersion struct {
	graph *callerGraph
	index *callerLifetimeWriteIndex
	epoch int
	ctx   context.Context
}

type callerContainerInactiveMemo struct {
	*callerContainerInactiveVersion
	entries   map[types.Type]int
	positions [callerContainerInactiveEntries][]int
	weight    int
}

func (m *callerContainerInactiveMemo) current(g *callerGraph) bool {
	return m != nil && m == g.containerInactive && m.graph == g &&
		m.index == g.lifetimeWriteIndex && m.epoch == g.bindingEpoch && m.ctx == g.ctx
}

func (g *callerGraph) callerContainerActiveScan(ctx context.Context, typ types.Type, candidates []int) callerContainerScan {
	if !callerFreshSameContext(ctx, g.ctx) {
		g.containerInactive = nil
		return callerContainerScan{}
	}
	if len(candidates) < 2 || len(candidates) > callerContainerInactivePositions {
		return callerContainerScan{}
	}
	memo := g.containerInactive
	if !memo.current(g) {
		memo = &callerContainerInactiveMemo{
			callerContainerInactiveVersion: &callerContainerInactiveVersion{
				graph: g, index: g.lifetimeWriteIndex, epoch: g.bindingEpoch, ctx: ctx,
			},
			entries: make(map[types.Type]int),
		}
		g.containerInactive = memo
	}
	slot, found := memo.entries[typ]
	if found {
		g.work.ContainerInactiveCacheHits++
	} else {
		// Предел относится только к дополнительному фильтру. Полный
		// исходный список остаётся доступен при любом отказе.
		if len(memo.entries) >= callerContainerInactiveEntries || len(candidates) > callerContainerInactivePositions-memo.weight {
			return callerContainerScan{}
		}
		positions := make([]int, 0, len(candidates))
		for pos, ordinal := range candidates {
			owner := g.lifetimeWrites[ordinal].owner.fk.fn
			g.work.ContainerInactiveCandidateChecks++
			if owner != nil && !g.called[callerNode{fn: owner}] {
				continue
			}
			positions = append(positions, pos)
		}
		if len(positions) == len(candidates) {
			positions = nil
		} else {
			// Учитываем выделенный буфер целиком, включая запас.
			memo.weight += cap(positions)
		}
		slot = len(memo.entries)
		memo.entries[typ], memo.positions[slot] = slot, positions
		g.work.ContainerInactiveCacheBuilds++
	}
	if memo.positions[slot] == nil {
		return callerContainerScan{}
	}
	return callerContainerScan{version: memo.callerContainerInactiveVersion, slot: slot}
}

// После каждого потенциально эффектного шага проверяем эпоху до выбора
// следующей записи. При изменении продолжаем исходный суффикс: старые
// пропуски сделаны в том же порядке, что и при полном проходе.
type callerContainerScan struct {
	// Паузирующий обход не удерживает позиции из прежней эпохи.
	version    *callerContainerInactiveVersion
	slot       int
	next       int
	nextActive int
}

func (s *callerContainerScan) take(g *callerGraph, total int) (int, bool) {
	if s.version != nil {
		memo := g.containerInactive
		if !memo.current(g) || memo.callerContainerInactiveVersion != s.version {
			g.work.ContainerInactiveEpochFallbacks++
			s.version = nil
		} else if s.nextActive == len(memo.positions[s.slot]) {
			g.work.ContainerInactiveSkippedWrites += total - s.next
			return 0, false
		} else {
			position := memo.positions[s.slot][s.nextActive]
			s.nextActive++
			g.work.ContainerInactiveSkippedWrites += position - s.next
			s.next = position + 1
			return position, true
		}
	}
	if s.next == total {
		return 0, false
	}
	position := s.next
	s.next++
	return position, true
}
