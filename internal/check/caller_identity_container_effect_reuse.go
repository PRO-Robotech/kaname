// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"maps"
	"slices"
)

// Запись принадлежит одному вызову callerContainerSources и сбрасывается перед
// обходом значения совпавшей записи. Она не переживает этот вызов, сброс корня,
// полный lifetime-барьер или следующую фазу remember внешнего владельца поля.
// Набор уже посещённых объектов всегда новый; поля и набор посещённых полей
// вызывающего принадлежат той же области. Снимки создаются только для повторного
// источника; уникальные владельцы их не выделяют.
type callerContainerObjectReuse struct {
	graph   *callerGraph
	key     callerResolveKey
	ready   bool
	answer  callerObjectAnswer
	state   callerContainerObjectState
	scope   callerContainerObjectScope
	effects callerInitialObjectEffects
	weight  int
}

// Начальный обход не выполняет полное lifetime-доказательство и не расходует
// callerLifetimeProbe.steps. Его границы остаются непокрытыми (дельта D == 0).
// Повторное использование создаёт новые обязательства в текущем внешнем барьере;
// зачесть их может только прежний предикат штатного завершения этого барьера.
// Циклы объектов учитываются отдельно: их событие читают и внешние обходы.
type callerInitialObjectEffects struct {
	cuts, skips, cycles uint64
}

// В этой синхронной области live/called/emptyVariadic только растут через записи,
// увеличивающие epoch. Кэши object/resolve добавляют лишь неизменяемые записи;
// их сброс меняет epoch или признак nil. Идентификаторы источников и identityFree
// только растут. Поэтому равные счётчики здесь означают равное содержимое карт.
// Сертификат нельзя переносить через сброс корня или произвольную правку карты.
// Кэши статических типов и кандидатов не входят в сертификат: промах и запасной
// путь вычисляют тот же полный неизменяемый ответ при любой их заполненности.
type callerContainerObjectState struct {
	bindingEpoch, effectEpoch, objectEpoch, resolveEpoch int
	objectEntries, initialObjectEntries, objectWeight    int
	resolveEntries, initialResolveEntries                int
	resolveWeight, initialResolveWeight                  int
	resolveEntryCap, resolveValueCap                     int
	sourceIDs, identityFree, indexedDepth                int
	objectSet, initialObjectSet                          bool
	resolveSet, initialResolveSet                        bool
	lifetime, effectScanning, effectIncomplete           bool
}

func (g *callerGraph) callerContainerObjectState() callerContainerObjectState {
	return callerContainerObjectState{
		bindingEpoch: g.bindingEpoch, effectEpoch: g.effectEpoch,
		objectEpoch: g.objectMemoEpoch, resolveEpoch: g.resolveMemoEpoch,
		objectEntries: len(g.objectMemo), initialObjectEntries: len(g.initialObjectMemo), objectWeight: g.objectMemoWeight,
		resolveEntries: len(g.resolveMemo), initialResolveEntries: len(g.initialResolveMemo),
		resolveWeight: g.resolveWeight, initialResolveWeight: g.initialResolveWeight,
		resolveEntryCap: g.resolveEntryCap, resolveValueCap: g.resolveValueCap,
		sourceIDs: len(g.objectSourceIDs), identityFree: len(g.identityFree), indexedDepth: g.fieldQueryIndexedDepth,
		objectSet: g.objectMemo != nil, initialObjectSet: g.initialObjectMemo != nil,
		resolveSet: g.resolveMemo != nil, initialResolveSet: g.initialResolveMemo != nil,
		lifetime: g.lifetimeScanning, effectScanning: g.effectScanning, effectIncomplete: g.effectIncomplete,
	}
}

// У значений снимков и стражей обхода нет binding epoch. Копируем их содержимое,
// включая порядок и точные идентичности источников и полей; изменяемые заголовки
// срезов не сохраняем, хеши не используем. Вложенные запросы добавляют и снимают
// только свои кадры, не меняя запомненные ссылки приостановленного внешнего кадра.
type callerContainerObjectScope struct {
	queries    []callerFieldQuery
	heads      map[callerResolveKey]int
	containers map[callerResolveKey]bool
	mutations  map[callerFieldKey]bool
}

func (s callerContainerObjectScope) matches(g *callerGraph) bool {
	if len(s.queries) != len(g.fieldQueries) || !maps.Equal(s.heads, g.fieldQueryHeads) || !maps.Equal(s.containers, g.containerScanning) || !maps.Equal(s.mutations, g.mutationScanning) {
		return false
	}
	for i := range s.queries {
		before, after := &s.queries[i], &g.fieldQueries[i]
		if before.source != after.source || before.unknown != after.unknown || before.previousSourceQuery != after.previousSourceQuery || !slices.Equal(before.fields, after.fields) || !slices.Equal(before.refs, after.refs) {
			return false
		}
	}
	return true
}

func (g *callerGraph) callerContainerObjectScopeWeight() int {
	weight := len(g.fieldQueries) + len(g.fieldQueryHeads) + len(g.containerScanning) + len(g.mutationScanning)
	for i := range g.fieldQueries {
		weight += len(g.fieldQueries[i].fields) + len(g.fieldQueries[i].refs)
	}
	return weight
}

func (g *callerGraph) captureCallerContainerObjectScope() callerContainerObjectScope {
	scope := callerContainerObjectScope{
		queries: slices.Clone(g.fieldQueries), heads: maps.Clone(g.fieldQueryHeads),
		containers: maps.Clone(g.containerScanning), mutations: maps.Clone(g.mutationScanning),
	}
	for i := range scope.queries {
		scope.queries[i].fields = slices.Clone(scope.queries[i].fields)
		scope.queries[i].refs = slices.Clone(scope.queries[i].refs)
	}
	return scope
}

func (g *callerGraph) callerObjectMemoHasCapacity(weight int) bool {
	return len(g.objectMemo)+len(g.initialObjectMemo) < 4096 && g.objectMemoWeight+weight <= callerLifetimeStepLimit
}

// Возвращаемые карты доступны только для чтения, включая неопубликованные карты,
// сохранённые локально. Владение вызывающему не передаётся. При отказе сертификата
// выполняется полный прежний обход; новый UNKNOWN не добавляется.
func (c *callerContainerObjectReuse) objects(g *callerGraph, src valueSrc) (map[callerObjectKey]bool, bool) {
	return c.writeObjects(g, src, false)
}

func (c *callerContainerObjectReuse) writeObjects(g *callerGraph, src valueSrc, sampleOwner bool) (map[callerObjectKey]bool, bool) {
	if !g.lifetimeScanning || g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		*c = callerContainerObjectReuse{}
		return g.callerObjects(src, map[callerObjectSourceID]bool{})
	}
	key := callerResolveKeyFor(src, true)
	if c.graph != g || c.key != key {
		if c.ready {
			*c = callerContainerObjectReuse{}
		}
		c.graph, c.key = g, key
		if sampleOwner {
			return g.callerContainerObjects(src, key, callerWriteOwner)
		}
		return g.callerObjects(src, map[callerObjectSourceID]bool{})
	}
	state := g.callerContainerObjectState()
	if c.ready && c.state == state && g.callerObjectMemoHasCapacity(c.weight) && c.scope.matches(g) {
		if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
			*c = callerContainerObjectReuse{}
			return nil, true
		}
		if !g.addCallerSemantic(c.effects.cuts, c.effects.skips, c.effects.cycles, 0) {
			return nil, true
		}
		// Счётчики работы не добавляем: подтверждённый дочерний обход не выполнялся.
		return c.answer.objects, c.answer.unknown
	}
	if c.ready {
		*c = callerContainerObjectReuse{graph: g, key: key}
	}
	cuts, skips, completed, cycles := g.resolveCuts, g.initialSkips, g.completedInitialSkips, g.objectCuts
	objects, unknown := g.callerObjects(src, map[callerObjectSourceID]bool{})
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		*c = callerContainerObjectReuse{}
		return nil, true
	}
	// Прогревающий обход сам не проходит проверку стабильности. Повторный обход
	// должен увидеть одинаковое содержимое кэшей на входе и выходе, прежде чем
	// сохранять точные эффекты. Завершённые ответы уже использует обычный object memo.
	effects := callerInitialObjectEffects{g.resolveCuts - cuts, g.initialSkips - skips, g.objectCuts - cycles}
	if state != g.callerContainerObjectState() || completed != g.completedInitialSkips || effects.cuts == effects.skips {
		return objects, unknown
	}
	weight := len(objects) + g.callerContainerObjectScopeWeight()
	if !g.callerObjectMemoHasCapacity(weight) {
		return objects, unknown
	}
	scope := g.captureCallerContainerObjectScope()
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		*c = callerContainerObjectReuse{}
		return nil, true
	}
	c.ready, c.answer, c.state = true, callerObjectAnswer{objects, unknown}, state
	c.scope, c.effects, c.weight = scope, effects, weight
	return objects, unknown
}

// Три дешёвых промаха одного источника разрешают восемь обычных обходов без
// внешнего execution-снимка. В таблице нет ответов и семантических отметок.
// Коллизия, смена эпохи или новый namespace начинают измерение заново.
type callerContainerAdmission struct {
	source            callerObjectSourceID
	epoch             int
	misses, remaining uint8
}

// Начальное чтение и владелец записи в одном сканировании могут запрашивать
// тот же источник. Попадания одного входа не характеризуют другой.
type callerContainerObjectUse uint8

const (
	callerContainerInput callerContainerObjectUse = iota
	callerWriteOwner
)

func (g *callerGraph) callerContainerObjects(src valueSrc, key callerResolveKey, use callerContainerObjectUse) (map[callerObjectKey]bool, bool) {
	seen := map[callerObjectSourceID]bool{}
	c := g.objectExecutions
	id := g.objectSourceIDs[key]
	if !g.lifetimeScanning || g.semanticOverflow || c == nil || c.graph != g || id == 0 || !callerFreshReplayContext(g.ctx) || g.objectMemoEpoch != g.bindingEpoch || g.initialObjectMemo == nil {
		return g.callerObjects(src, seen)
	}
	if answer, complete := g.initialObjectMemo[id]; complete {
		if g.objectMemo == nil || key != callerResolveKeyFor(src, true) {
			return g.callerObjects(src, seen)
		}
		g.taintCallerTraces()
		if g.ctx != nil && g.ctx.Err() != nil {
			return nil, true
		}
		return g.callerInitialObjectExecutionHit(answer, seen)
	}
	if g.ctx != nil && g.ctx.Err() != nil {
		return g.callerObjects(src, seen)
	}
	table := &c.containerOwners
	bypasses := &g.work.ContainerOwnerAdmissionBypasses
	if use == callerContainerInput {
		table = &c.containerInputs
		bypasses = &g.work.ContainerInputAdmissionBypasses
	}
	slot := &table[uint64(id)%uint64(len(table))]
	if slot.source != id || slot.epoch != g.bindingEpoch {
		*slot = callerContainerAdmission{source: id, epoch: g.bindingEpoch}
	}
	raw := g.work.ObjectRawEvaluations
	if slot.remaining > 0 {
		slot.remaining--
		*bypasses++
		g.work.ObjectExecutionFallbacks++
		// Как у внешнего входа, закрываем suspended traces и списываем прошлые
		// поколения. Внутренний обход сохраняет собственные tickets, обычный
		// memo, полный seen, начальные границы, UNKNOWN и связывание вызовов.
		g.taintCallerTraces()
		c.advance(g)
		objects, unknown, _ := g.callerObjectsOwned(src, seen)
		if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
			return nil, true
		}
		if g.work.ObjectRawEvaluations-raw > 3 && slot.source == id && slot.epoch == g.bindingEpoch {
			slot.remaining = 0
		}
		return objects, unknown
	}
	before := *slot
	queries, hits := g.work.ObjectExecutionQueries, g.work.ObjectExecutionHits
	objects, unknown := g.callerObjects(src, seen)
	if *slot != before || c != g.objectExecutions || c.graph != g || g.bindingEpoch != before.epoch {
		return objects, unknown
	}
	if g.work.ObjectExecutionQueries-queries == 1 && g.work.ObjectExecutionHits == hits && g.work.ObjectRawEvaluations-raw <= 3 {
		slot.misses++
		if slot.misses == 3 {
			slot.misses, slot.remaining = 0, 8
		}
	} else {
		slot.misses = 0
	}
	return objects, unknown
}
