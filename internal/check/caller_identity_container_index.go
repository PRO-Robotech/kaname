// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/types"
	"sync"
)

type callerLifetimeWriteMetadata struct {
	ordinal   int
	whole     bool
	ownerType types.Type
	param     bool
}

// Записи и опубликованные срезы кандидатов неизменяемы. Копии графа разделяют только
// этот указатель: мьютекс защищает ограниченный кеш, а не состояние решения.
type callerLifetimeWriteIndex struct {
	entries []callerLifetimeWriteMetadata
	mu      sync.Mutex
	queries map[types.Type][]int
	weight  int
}

const (
	callerContainerCandidateEntries = 256
	callerContainerCandidateValues  = 262144
)

func (g *callerGraph) indexCallerLifetimeWrites() {
	index := &callerLifetimeWriteIndex{entries: make([]callerLifetimeWriteMetadata, len(g.lifetimeWrites)), queries: map[types.Type][]int{}}
	for ordinal, write := range g.lifetimeWrites {
		entry := callerLifetimeWriteMetadata{ordinal: ordinal, whole: write.whole}
		if !write.whole && write.owner.pkg != nil && write.owner.expr != nil {
			entry.ownerType = callerContainerType(write.owner.pkg.info.TypeOf(write.owner.expr))
			if entry.ownerType != nil {
				entry.param = g.hasCallerTypeParam(entry.ownerType)
			}
		}
		index.entries[ordinal] = entry
	}
	g.lifetimeWriteIndex = index
}

// Кешируется только существующий статический предикат совместимости. В частности,
// неизвестные типы владельцев и обобщённые владельцы или запросы остаются кандидатами.
// Вызывающая сторона по-прежнему разрешает эффекты, выделения, алиасы и поля каждого запроса.
// Если полный список кандидатов нельзя сохранить, используется исходный полный обход;
// эти границы ограничивают память и не превращают доказательство в частичный ответ.
func (g *callerGraph) callerContainerWriteCandidates(typ types.Type) ([]int, bool) {
	index := g.lifetimeWriteIndex
	if index == nil || typ == nil || len(index.entries) != len(g.lifetimeWrites) {
		return nil, false
	}
	switch typ.Underlying().(type) {
	case *types.Slice, *types.Array, *types.Map:
	default:
		return nil, false
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	if candidates, ok := index.queries[typ]; ok {
		g.work.ContainerCandidateHits++
		return candidates, true
	}
	if len(index.queries) >= callerContainerCandidateEntries {
		return nil, false
	}
	param := g.hasCallerTypeParam(typ)
	var candidates []int
	for _, entry := range index.entries {
		if entry.whole || entry.ownerType != nil && !types.Identical(entry.ownerType.Underlying(), typ.Underlying()) && !entry.param && !param {
			continue
		}
		if len(candidates) >= callerContainerCandidateValues-index.weight {
			return nil, false
		}
		candidates = append(candidates, entry.ordinal)
	}
	// Не сохраняем запас ёмкости сверх ограниченного числа порядковых номеров.
	candidates = append([]int(nil), candidates...)
	index.queries[typ] = candidates
	index.weight += len(candidates)
	g.work.ContainerCandidateBuilds++
	return candidates, true
}
