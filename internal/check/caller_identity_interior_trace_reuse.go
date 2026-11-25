// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"go/ast"
	"go/types"
	"maps"
	"reflect"
	"runtime"
	"unsafe"
)

// Допуск Err привязан к побайтово одинаковому context.go Go 1.26.10/1.26.11.
// SHA256: 765f99f7cc0710b0117ffa183e432524f429c21496fcbad9b63fb9886fdbaac7.
// Проверка сборки подтверждает закреплённый stdlib source; иные версии закрыты.
// Здесь не вызываются методы произвольного Context и не читается его parent.
func callerTraceContext(ctx context.Context) bool {
	return callerTraceContextVersion(ctx, runtime.Version())
}

// Четыре точных dynamic type из закреплённой stdlib вместо повторного
// декодирования Kind/Name/PkgPath на каждом checkpoint. Таблица после init
// не меняется и не удерживает Context, parent, graph, ответы или tickets.
// Оба производных контекста немедленно закрыты; нулевой timeout не оставляет
// живого таймера. Произвольный вызывающий Context здесь не используется.
var callerTraceContextTypes = func() [4]reflect.Type {
	background, todo := context.Background(), context.TODO()
	cancelled, cancel := context.WithCancel(background)
	cancelType := reflect.TypeOf(cancelled)
	cancel()
	timed, stop := context.WithTimeout(background, 0)
	timerType := reflect.TypeOf(timed)
	stop()
	types := [4]reflect.Type{reflect.TypeOf(background), reflect.TypeOf(todo), cancelType, timerType}
	// Constructor drift закрывает допуск, а не расширяет прежний whitelist.
	for i, name := range [4]string{"backgroundCtx", "todoCtx", "cancelCtx", "timerCtx"} {
		typ := types[i]
		if i >= 2 {
			if typ.Kind() != reflect.Pointer {
				return [4]reflect.Type{}
			}
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || typ.PkgPath() != "context" || typ.Name() != name {
			return [4]reflect.Type{}
		}
	}
	return types
}()

func callerTraceContextVersion(ctx context.Context, version string) bool {
	if (version != "go1.26.10" && version != "go1.26.11") || ctx == nil {
		return false
	}
	switch reflect.TypeOf(ctx) {
	case callerTraceContextTypes[0], callerTraceContextTypes[1]:
		return true
	case callerTraceContextTypes[2], callerTraceContextTypes[3]:
		return !reflect.ValueOf(ctx).IsNil()
	default:
		return false
	}
}

func callerTraceSameContext(a, b context.Context) bool {
	// После допуска тип a сравним. Равенство интерфейсов уже требует
	// того же типа и значения b, поэтому повторно проверять b не нужно.
	return callerTraceContext(a) && a == b
}

// Старый fresh слой допускает nil: у него вообще нет пропускаемых Err.
// Interior требует конкретный контекст и отдельное происхождение seen.
func callerFreshReplayContext(ctx context.Context) bool {
	return ctx == nil || callerTraceContext(ctx)
}

func callerFreshSameContext(a, b context.Context) bool {
	return callerFreshReplayContext(a) && a == b
}

const (
	callerTraceDependencies    = 64
	callerTraceRecordUnits     = 21
	callerTraceDependencyUnits = 2
	callerTraceLiveRecordUnits = callerTraceRecordUnits + callerTraceDependencies*callerTraceDependencyUnits
	callerTraceGuardUnits      = 24
	callerTraceFrameUnits      = 8
	callerTraceChainUnits      = 9
	callerTraceBucketCount     = 16
	callerTraceHeaderUnits     = 5 + callerTraceBucketCount
	callerTraceLive            = 1
	callerTraceRetained        = 2
	callerTraceDead            = 3
)

type callerTraceDependency struct {
	source callerObjectSourceID
	want   uint64
}

type callerTraceGuard struct {
	state callerObjectExecutionState
	marks [4]uint64
}

type callerTraceRecord struct {
	// Live владеет geometric backing по числу predicates; retained — точным prefix.
	// Заголовок slice входит в record, весь backing оплачивается отдельно.
	dependencies []callerTraceDependency
	next, parent *callerTraceRecord
	// У головы previous хранит хвост; у остальных — предыдущую запись.
	// Прямой next остаётся конечным списком в обратном порядке выделения.
	previous *callerTraceRecord
	// Корзина содержит подпоследовательность global allocation order, включая
	// живые записи. Completion не переставляет родителей после их детей.
	bucketNext, bucketPrevious                       *callerTraceRecord
	scope                                            *callerObjectExecutionScope
	guard                                            *callerTraceGuard
	entry                                            *callerTraceFrame
	chain                                            *callerTraceChain
	ctx                                              context.Context
	objects                                          map[callerObjectKey]bool
	pending                                          map[callerObjectKey]bool
	effects                                          callerInitialObjectEffects
	source                                           callerObjectSourceID
	count, phase                                     uint8
	bad, holdsScope, resultReserved, unknown, ticket bool
	// По умолчанию доказательства нет; только новый исполненный кадр начинает его.
	scopeIndependent bool
}

type callerTraceFrame struct {
	next, parent *callerTraceFrame
	chain        *callerTraceChain
	source       callerObjectSourceID
	depth        int
	live         bool
	// Подсказки относятся к вершине с её неизменными предками и занимают
	// уже зарезервированную память кадра.
	ownerHints [2]*callerTraceFrame
}

type callerTraceChain struct {
	next      *callerTraceChain
	owner     *callerObjectExecutions
	head      *callerTraceFrame
	record    *callerTraceRecord
	seen      map[callerObjectSourceID]bool
	ctx       context.Context
	bad, live bool
	// Только закрытое тело callerObjectsOwned; сам begin не выдаёт этот признак.
	executing bool
	// Однократный borrow, оплаченный полем chain; ticket остаётся у fresh caller.
	entryScope *callerObjectExecutionScope
}

// Проверки layout не исполняют unsafe-код. Slice header оплачен в record,
// backing и полный guard оплачиваются отдельно до allocation.
var (
	_ [callerTraceRecordUnits*8 - int(unsafe.Sizeof(callerTraceRecord{}))]byte
	_ [callerTraceDependencyUnits*8 - int(unsafe.Sizeof(callerTraceDependency{}))]byte
	_ [callerTraceGuardUnits*8 - int(unsafe.Sizeof(callerTraceGuard{}))]byte
	_ [callerTraceFrameUnits*8 - int(unsafe.Sizeof(callerTraceFrame{}))]byte
	_ [callerTraceChainUnits*8 - int(unsafe.Sizeof(callerTraceChain{}))]byte
	_ [callerTraceBucketCount*8 - int(unsafe.Sizeof([callerTraceBucketCount]*callerTraceRecord{}))]byte
)

// Новый backing не удерживает capacity live-буфера и не разделяет его память.
// Вызывающий до входа оплачивает оба backing одновременно.
func callerTraceDependencyPrefix(dependencies []callerTraceDependency, count int) []callerTraceDependency {
	prefix := make([]callerTraceDependency, count)
	copy(prefix, dependencies[:count])
	return prefix
}

func (c *callerObjectExecutions) traceRoom(entries, units int) bool {
	return entries <= callerObjectExecutionEntries-c.entries && units <= callerObjectExecutionValues-c.weight
}

func (c *callerObjectExecutions) traceHeader(g *callerGraph) bool {
	if c.traceAccount {
		return true
	}
	if !c.admit(g, 1, callerTraceHeaderUnits, false) {
		return false
	}
	c.traceAccount = true
	c.retained(g, callerTraceHeaderUnits)
	// Пять полей владельца и весь фиксированный массив оплачены до allocation.
	c.traceBuckets = new([callerTraceBucketCount]*callerTraceRecord)
	return true
}

func (c *callerObjectExecutions) traceReleaseHeader() {
	if c.graph != nil && c.traceAccount && c.traceChains == nil && c.traceFrames == nil && c.traceRecords == nil {
		c.traceBuckets = nil
		c.traceAccount = false
		c.entries--
		c.weight -= callerTraceHeaderUnits
	}
}

// Непокрытая операция запрещает перенос scope всем живым предкам. Это
// отдельное доказательство: старый exact replay не выключается этим флагом.
func callerTraceScopeDependent(chain *callerTraceChain) {
	if chain == nil {
		return
	}
	// Первая false-запись уже означает false у всех живых предков.
	// За U вызовов и R созданных записей суммарный обход занимает O(U+R).
	for record := chain.record; record != nil && record.scopeIndependent; record = record.parent {
		record.scopeIndependent = false
	}
}

func (g *callerGraph) taintCallerTraces() {
	if c := g.objectExecutions; c != nil {
		for chain := c.traceChains; chain != nil; chain = chain.next {
			if chain.live {
				callerTraceScopeDependent(chain)
				chain.bad = true
			}
		}
	}
}

// Подготовка сохраняет внешнюю границу и retirement даже тогда, когда обычный
// memo уже доказал, что raw и его trace-кадры не понадобятся.
func (g *callerGraph) prepareCallerTrace(seen map[callerObjectSourceID]bool) *callerObjectExecutions {
	// Внешний вход не выдаётся за прямое продолжение suspended chain.
	g.taintCallerTraces()
	c := g.objectExecutions
	if len(seen) != 0 || seen == nil || !g.lifetimeScanning || g.semanticOverflow || !callerTraceContext(g.ctx) || c == nil || c.graph != g {
		return nil
	}
	c.advance(g)
	return c
}

func (g *callerGraph) beginCallerTrace(seen map[callerObjectSourceID]bool) *callerTraceChain {
	c := g.prepareCallerTrace(seen)
	if c == nil {
		return nil
	}
	if !c.admit(g, 1, callerTraceChainUnits, true) {
		g.work.ObjectTraceCapacityFallbacks++
		return nil
	}
	c.traceHeader(g)
	c.retained(g, callerTraceChainUnits)
	chain := &callerTraceChain{next: c.traceChains, owner: c, seen: seen, ctx: g.ctx, live: true}
	c.traceChains = chain
	c.active++
	return chain
}

func (g *callerGraph) endCallerTrace(chain *callerTraceChain) {
	if chain == nil {
		return
	}
	c := chain.owner
	// Borrow не переживает тело и снимается даже при B1 quarantine, до выхода
	// внешнего fresh ticket. Собственного references/active у него никогда нет.
	chain.entryScope = nil
	chain.executing, chain.live = false, false
	c.active--
	if c.graph == nil {
		return
	}
	link := &c.traceChains
	for *link != chain {
		link = &(*link).next
	}
	*link = chain.next
	// Завершённая локальная цепочка не удерживает удалённые узлы кеша и списка.
	chain.next, chain.head, chain.record, chain.seen, chain.ctx = nil, nil, nil, nil, nil
	c.entries--
	c.weight -= callerTraceChainUnits
	c.traceReleaseHeader()
}

// Это поиск известного pinned узла, не memo валидности scope. Открытый
// прямому вызову helper сохраняет полное structural и content доказательство.
func (c *callerObjectExecutions) callerTraceEntryScope(g *callerGraph, chain *callerTraceChain) *callerObjectExecutionScope {
	scope := c.callerTraceTakeEntryScope(g, chain)
	if scope == nil || !scope.snapshot.matches(g) {
		return nil
	}
	g.work.ObjectScopeHandoffs++
	return scope
}

// Только сразу после полного callerExecutionScopeTracked и до любого Err,
// callback или изменения scope. Чистые advance и проверка membership ниже
// сохраняют это локальное доказательство; полное content equality обязательно.
func (c *callerObjectExecutions) callerTraceEntryTrackedScope(g *callerGraph, chain *callerTraceChain) *callerObjectExecutionScope {
	scope := c.callerTraceTakeEntryScope(g, chain)
	if scope == nil || !scope.snapshot.matchesTrackedContent(g) {
		return nil
	}
	g.work.ObjectScopeHandoffs++
	return scope
}

// Только после полного tracked-доказательства и до Err или изменения scope.
// Проверяем голову корзины, чтобы промах не дублировал последующий поиск
// записи. Её ответ здесь не используется. До выдачи ticket scope удерживает
// сама retained-запись.
func (c *callerObjectExecutions) callerTraceRetainedTrackedScope(g *callerGraph, chain *callerTraceChain, source callerObjectSourceID) *callerObjectExecutionScope {
	if chain == nil || !chain.executing || chain.bad || !chain.live || chain.owner != c ||
		g.objectExecutions != c || c.graph != g || !g.lifetimeScanning || g.semanticOverflow ||
		!callerTraceSameContext(chain.ctx, g.ctx) || c.traceBuckets == nil {
		return nil
	}
	record := c.traceBuckets[source%callerTraceBucketCount]
	if record == nil || record.phase != callerTraceRetained || record.source != source ||
		record.guard == nil || record.guard.state != g.callerObjectExecutionState() ||
		!callerTraceSameContext(record.ctx, g.ctx) || !record.holdsScope ||
		record.scope == nil || record.scope.references <= 0 {
		return nil
	}
	scope := record.scope
	for node := c.scopes[scope.hash]; node != nil; node = node.next {
		if node == scope && scope.snapshot.matchesTrackedContent(g) {
			return scope
		}
	}
	return nil
}

// Снимает одноразовый borrow и проверяет владельца, жизнь и membership.
// Сам по себе возвращённый узел ещё не доказывает ни structure, ни content.
// Чужой/снятый узел и открытая цепь не могут выдать заимствованную ссылку.
func (c *callerObjectExecutions) callerTraceTakeEntryScope(g *callerGraph, chain *callerTraceChain) *callerObjectExecutionScope {
	scope := chain.entryScope
	chain.entryScope = nil
	if scope == nil || !chain.executing || chain.bad || !chain.live || chain.owner != c || g.objectExecutions != c || c.graph != g || !g.lifetimeScanning || g.semanticOverflow || !callerTraceSameContext(chain.ctx, g.ctx) || scope.references <= 0 {
		return nil
	}
	for node := c.scopes[scope.hash]; node != nil; node = node.next {
		if node == scope {
			return scope
		}
	}
	return nil
}

func (g *callerGraph) callerTraceValid(chain *callerTraceChain) bool {
	if chain == nil || chain.bad || !chain.live {
		return false
	}
	if g.semanticOverflow || g.objectExecutions != chain.owner || chain.owner.graph != g || !callerTraceSameContext(chain.ctx, g.ctx) {
		chain.bad = true
		return false
	}
	depth := 0
	for frame := chain.head; frame != nil; frame = frame.parent {
		g.work.ObjectTraceValidationSteps++
		if !frame.live || frame.chain != chain || !chain.seen[frame.source] {
			chain.bad = true
			return false
		}
		depth++
	}
	if len(chain.seen) != depth {
		chain.bad = true
		return false
	}
	return true
}

// Закрытый владелец начинает с пустого seen. Только raw push/set и парный
// defer delete/pop меняют его стек; до внешнего входа цепь становится bad.
// Поэтому неизменные предки доказаны индукцией, а здесь проверяется текущая
// граница. executing не хранит результат проверки и не выдаётся ручной цепи.
// Прямой callerTraceValid всегда проверяет и изменённые извне предки.
func (g *callerGraph) callerTraceExecutionValid(chain *callerTraceChain) bool {
	if chain == nil || !chain.executing {
		return g.callerTraceValid(chain)
	}
	if chain.bad || !chain.live {
		return false
	}
	if g.semanticOverflow || g.objectExecutions != chain.owner || chain.owner.graph != g || !callerTraceSameContext(chain.ctx, g.ctx) {
		chain.bad = true
		return false
	}
	depth := 0
	if frame := chain.head; frame != nil {
		g.work.ObjectTraceValidationSteps++
		if !frame.live || frame.chain != chain || !chain.seen[frame.source] {
			chain.bad = true
			return false
		}
		depth = frame.depth
	}
	if len(chain.seen) != depth {
		chain.bad = true
		return false
	}
	return true
}

// Порядок — только представление точного множества predicates. Он не меняет
// порядок records/FIFO, а поиск не вызывает Err и не получает внешних callbacks.
func (g *callerGraph) callerTraceDependencyPosition(record *callerTraceRecord, source callerObjectSourceID) (int, bool) {
	low, high := 0, int(record.count)
	if high == 0 {
		return 0, false
	}
	steps := 0
	for low < high {
		middle := low + (high-low)/2
		steps++
		current := record.dependencies[middle].source
		if current < source {
			low = middle + 1
		} else if current > source {
			high = middle
		} else {
			g.work.ObjectTraceDependencySteps += steps
			return middle, true
		}
	}
	g.work.ObjectTraceDependencySteps += steps
	return low, false
}

// Рост не вытесняет: вызывающий hit ещё может читать retained source record.
// Старый и полный новый backing оплачены одновременно до allocation. Здесь
// нет Err/callback; после copy/rebind старый backing больше не имеет владельца.
func (c *callerObjectExecutions) growCallerTraceDependencies(g *callerGraph, record *callerTraceRecord) bool {
	if c == nil || c.graph != g || g.objectExecutions != c || record.phase != callerTraceLive || record.chain == nil || record.chain.owner != c || !record.chain.live || !record.ticket || !record.holdsScope {
		return false
	}
	oldCapacity := cap(record.dependencies)
	if int(record.count) != len(record.dependencies) || len(record.dependencies) != oldCapacity || oldCapacity >= callerTraceDependencies {
		return false
	}
	capacity := 1
	if oldCapacity != 0 {
		capacity = 2 * oldCapacity
	}
	if capacity > callerTraceDependencies {
		return false
	}
	units := capacity * callerTraceDependencyUnits
	if !c.traceRoom(0, units) {
		return false
	}
	c.weight += units
	g.work.ObjectExecutionPeakValues = max(g.work.ObjectExecutionPeakValues, c.weight)
	dependencies := make([]callerTraceDependency, capacity)
	copy(dependencies, record.dependencies[:int(record.count)])
	record.dependencies = dependencies
	c.weight -= oldCapacity * callerTraceDependencyUnits
	return true
}

// Положительный predicate ищет ближайший кадр. В закрытом обходе текущая
// вершина и её предки не меняются до снятия вершины. Новый дочерний кадр
// начинает со своих пустых подсказок; открытая цепь всегда идёт по стеку.
func (g *callerGraph) callerTraceOwnerDepth(chain *callerTraceChain, source callerObjectSourceID) int {
	head := chain.head
	var hint **callerTraceFrame
	if chain.executing && !chain.bad && chain.live && chain.owner != nil &&
		g.objectExecutions == chain.owner && chain.owner.graph == g &&
		head != nil && head.live && head.chain == chain {
		hint = &head.ownerHints[source%2]
		if owner := *hint; owner != nil && owner.live && owner.chain == chain && owner.source == source {
			g.work.ObjectTraceDependencySteps++
			return owner.depth
		}
	}
	steps := 0
	for frame := head; frame != nil; frame = frame.parent {
		steps++
		if frame.source == source {
			if hint != nil {
				*hint = frame
			}
			g.work.ObjectTraceDependencySteps += steps
			return frame.depth
		}
	}
	if steps != 0 {
		g.work.ObjectTraceDependencySteps += steps
	}
	return 0
}

func (g *callerGraph) callerTraceDependency(chain *callerTraceChain, dependency callerTraceDependency) {
	if chain == nil || chain.bad {
		return
	}
	// При true текущий владелец push ищется один раз для всех родителей.
	// При false полного expected-stack validation достаточно: local push нет.
	ownerDepth := 0
	if dependency.want == 1 {
		ownerDepth = g.callerTraceOwnerDepth(chain, dependency.source)
		if ownerDepth == 0 {
			chain.bad = true
			return
		}
	}
	for record := chain.record; record != nil; record = record.parent {
		if record.bad {
			continue
		}
		entryDepth := 0
		if record.entry != nil {
			entryDepth = record.entry.depth
		}
		if ownerDepth > entryDepth {
			continue
		}
		index, found := g.callerTraceDependencyPosition(record, dependency.source)
		if found {
			record.bad = record.dependencies[index].want != dependency.want
			// В закрытом живом теле первая вставка уже прошла всех допустимых
			// предков. Их parent/entry не меняются до выхода этого record; внешний
			// вход заранее делает chain bad. Равный повтор не добавляет обязательств.
			// Противоречие обязано продолжить обход и пометить остальных предков.
			if !record.bad && chain.executing && chain.live && record.phase == callerTraceLive && record.chain == chain && record.ticket && record.holdsScope {
				return
			}
			continue
		}
		if int(record.count) == callerTraceDependencies {
			record.bad = true
			continue
		}
		if int(record.count) == len(record.dependencies) && !chain.owner.growCallerTraceDependencies(g, record) {
			record.bad = true
			g.work.ObjectTraceCapacityFallbacks++
			continue
		}
		// Сдвигаются только уже оплаченные пары source/want. Ни один predicate
		// не теряется; на переполнении весь record по-прежнему становится bad.
		copy(record.dependencies[index+1:int(record.count)+1], record.dependencies[index:int(record.count)])
		record.dependencies[index] = dependency
		record.count++
	}
}

func (g *callerGraph) callerTraceRead(chain *callerTraceChain, source callerObjectSourceID, present bool) {
	if !g.callerTraceExecutionValid(chain) {
		return
	}
	g.work.ObjectTraceSeenReads++
	dependency := callerTraceDependency{source: source}
	if present {
		dependency.want = 1
	}
	g.callerTraceDependency(chain, dependency)
}

func (g *callerGraph) callerTracePush(chain *callerTraceChain, source callerObjectSourceID) *callerTraceFrame {
	if !g.callerTraceExecutionValid(chain) {
		return nil
	}
	c := chain.owner
	if !c.admit(g, 1, callerTraceFrameUnits, false) {
		chain.bad = true
		g.work.ObjectTraceCapacityFallbacks++
		return nil
	}
	c.retained(g, callerTraceFrameUnits)
	depth := 1
	if chain.head != nil {
		depth += chain.head.depth
	}
	frame := &callerTraceFrame{next: c.traceFrames, parent: chain.head, chain: chain, source: source, depth: depth, live: true}
	c.traceFrames, chain.head = frame, frame
	return frame
}

func (g *callerGraph) callerTracePop(chain *callerTraceChain, frame *callerTraceFrame) {
	if frame == nil {
		return
	}
	c := chain.owner
	chain.head = frame.parent
	clear(frame.ownerHints[:])
	frame.live = false
	if c.graph == nil {
		return
	}
	link := &c.traceFrames
	for *link != frame {
		link = &(*link).next
	}
	*link = frame.next
	frame.next, frame.parent, frame.chain = nil, nil, nil
	c.entries--
	c.weight -= callerTraceFrameUnits
}

// Первый допустимый узел с хвоста — та же FIFO-жертва, которую полный
// прямой обход выбирал последней. Живые и ещё ticket-owned узлы пропускаются;
// завершение родителя не переставляет его после уже завершённых детей.
func (c *callerObjectExecutions) oldestCallerTrace() *callerTraceRecord {
	if c.traceRecords == nil {
		return nil
	}
	for record := c.traceRecords.previous; ; record = record.previous {
		if record.phase == callerTraceRetained && !record.ticket && record.holdsScope && record.resultReserved && record.pending == nil && record.parent == nil && record.entry == nil && record.chain == nil {
			return record
		}
		if record == c.traceRecords {
			return nil
		}
	}
}

func (c *callerObjectExecutions) releaseCallerTrace(g *callerGraph, record *callerTraceRecord) {
	if record.holdsScope {
		record.holdsScope = false
		c.releaseScope(g, record.scope)
	}
	if c.graph == nil {
		record.phase = callerTraceDead
		return
	}
	// В quarantine обе структуры остаются под прежним полным account. Здесь
	// действующий владелец снимает ровно эту запись из её source-корзины.
	if record.bucketPrevious == nil {
		c.traceBuckets[record.source%callerTraceBucketCount] = record.bucketNext
	} else {
		record.bucketPrevious.bucketNext = record.bucketNext
	}
	if record.bucketNext != nil {
		record.bucketNext.bucketPrevious = record.bucketPrevious
	}
	if record == c.traceRecords {
		c.traceRecords = record.next
		if record.next != nil {
			record.next.previous = record.previous
		}
	} else {
		record.previous.next = record.next
		if record.next != nil {
			record.next.previous = record.previous
		} else {
			c.traceRecords.previous = record.previous
		}
	}
	c.entries--
	c.weight -= callerTraceRecordUnits + callerTraceGuardUnits + cap(record.dependencies)*callerTraceDependencyUnits
	if record.resultReserved {
		c.weight -= 1 + len(record.objects)
	}
	// Не меняем ранее возвращённые карты ответов. Обнуляем собственные ссылки:
	// даже локальный указатель больше не удерживает соседей, страж или данные.
	*record = callerTraceRecord{}
	c.traceReleaseHeader()
}

func (c *callerObjectExecutions) retireCallerTraces(g *callerGraph, version callerObjectExecutionVersion) {
	for record := c.traceRecords; record != nil; {
		next := record.next
		if record.phase == callerTraceRetained {
			state := record.guard.state
			old := callerObjectExecutionVersion{state.bindingEpoch, state.effectEpoch, state.sourceIDs, state.identityFree, state.objectGeneration, state.resolveGeneration}
			if old != version {
				c.releaseCallerTrace(g, record)
			}
		}
		record = next
	}
}

// Только exact duplicate frame может сделать selector терминальной границей.
// Общий selector включает remember/lifetime/events и не допускается в trace.
func (g *callerGraph) callerTraceSelector(src valueSrc, selection *types.Selection) bool {
	if selection == nil || selection.Kind() != types.FieldVal || !g.callerExecutionScopeTracked() {
		return false
	}
	fields := fieldPath(selection)
	if len(fields) != 1 {
		return false
	}
	src.expr = ast.Unparen(src.expr).(*ast.SelectorExpr).X
	key := callerResolveKeyFor(src, true)
	for head := g.fieldQueryHeads[key]; head > 0; {
		query := g.fieldQueries[head-1]
		if len(query.fields) == 1 && query.fields[0].Origin() == fields[0].Origin() {
			return true
		}
		head = query.previousSourceQuery
	}
	return false
}

// Конструктор начинает с пустой памятью зависимостей; рост оплачивается при вставке.
// Допуск заголовка записи и guard остаются у вызывающего кода.
func (c *callerObjectExecutions) newCallerTraceLiveRecord(g *callerGraph, chain *callerTraceChain, scope *callerObjectExecutionScope, source callerObjectSourceID) *callerTraceRecord {
	return &callerTraceRecord{next: c.traceRecords, parent: chain.record, scope: scope, entry: chain.head, chain: chain, ctx: g.ctx, source: source, phase: callerTraceLive, holdsScope: true, ticket: true, scopeIndependent: true}
}

func (g *callerGraph) callerInteriorRaw(src valueSrc, seen map[callerObjectSourceID]bool, source callerObjectSourceID, chain *callerTraceChain) (map[callerObjectKey]bool, bool, bool) {
	original := func() (map[callerObjectKey]bool, bool, bool) {
		return g.callerObjectsRaw(src, seen, source, chain)
	}
	if len(seen) == 0 || !g.lifetimeScanning || !g.callerTraceExecutionValid(chain) {
		return original()
	}
	// При нехватке текущего места не допускаем новый сертификат ради
	// терминального цикла. При свободном месте прежний lookup/capture сохранён.
	// Исходный raw сохраняет Err, seen-read живых родителей и cuts/cycles;
	// после Err он заново читает seen. Это только выбор admission policy.
	if seen[source] && !chain.owner.traceRoom(1, callerTraceLiveRecordUnits+callerTraceGuardUnits+1) {
		g.work.ObjectTraceCycleBypasses++
		return original()
	}
	// Живой родитель уже доказал точный scope и удерживает его своим ticket.
	// До вложенного входа valid-цепочка не меняет queries/refs/heads и карты:
	// общий call закрывает её до resolve; selector допускает лишь duplicate
	// query без remember; внешний вход закрывает все suspended chains.
	// Это заимствование внутри непрерывного тела, не кеш эпохи или хеша.
	var scope *callerObjectExecutionScope
	if parent := chain.record; parent != nil && parent.phase == callerTraceLive && parent.chain == chain && parent.holdsScope && parent.ticket {
		scope = parent.scope
	}
	if scope == nil && !g.callerExecutionScopeTracked() {
		return original()
	}
	g.work.ObjectTraceQueries++
	c := chain.owner
	c.advance(g)
	// При nil scope полный structural proof выполнен выше. Между ним и
	// обоими входами лишь счётчик, advance и чистые проверки ticket/content:
	// здесь нет Err, callback или записи в queries/heads/refs и карты scope.
	if scope == nil {
		scope = c.callerTraceEntryTrackedScope(g, chain)
	}
	if scope == nil {
		scope = c.callerTraceRetainedTrackedScope(g, chain, source)
	}
	if scope == nil {
		scope = c.acquireTrackedScope(g, true)
	} else {
		// advance снимает только завершённые записи; внешний fresh ticket,
		// живой родитель либо проверенная retained-запись сохраняет pin.
		// Новый ticket совпадает с existing-scope acquire:
		// та не вызывает Err, допуск или вытеснение. Полные exit/hit guards ниже.
		scope.references++
		c.active++
	}
	if scope == nil {
		return original()
	}
	// Scope полностью проверен acquire, взят у живого родителя с ticket либо
	// найден через fresh/retained после exact matches и проверки membership.
	// В закрытом owned-теле до bad нет записи в полный
	// queries/heads/refs/unknown/container/mutation scope: общий call и новый
	// selector закрывают цепь заранее, duplicate query возвращается до remember.
	// Поэтому hit/exit ниже проверяют неизменность владения/контекста/состояния,
	// а повторный полный content scan нужен лишь открытой ручной цепи. Сам
	// executing не доказывает произвольный snapshot; здесь proof относится только
	// к этому scope и непрерывному телу после его точного допуска.
	var recording *callerTraceRecord
	defer func() {
		if recording != nil {
			recording.ticket = false
		}
		c.releaseTicket(g, scope)
	}()
	state := g.callerObjectExecutionState()
	// Другие корзины заведомо не содержат этот source. Внутри сохраняются
	// прежний порядок и все predicates: коллизия не даёт нового допуска.
	for record := c.traceBuckets[source%callerTraceBucketCount]; record != nil; record = record.bucketNext {
		g.work.ObjectTraceValidationSteps++
		if record.phase != callerTraceRetained || record.source != source || record.guard.state != state || !callerTraceSameContext(record.ctx, g.ctx) {
			continue
		}
		// Старый exact путь сохраняется. Доказанный прозрачный путь не читает
		// ни содержимое, ни глубину field scope: selector и общий call снимают
		// scopeIndependent до чтения, включая всех живых родителей. Поэтому
		// иной depth допустим только с этим доказательством. Полный текущий
		// scope уже допущен выше; state/context/seen и exit guards остаются ниже.
		if record.scope != scope && !record.scopeIndependent {
			continue
		}
		matches := true
		for i := 0; i < int(record.count); i++ {
			g.work.ObjectTraceValidationSteps++
			dependency := record.dependencies[i]
			if seen[dependency.source] != (dependency.want == 1) {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		if g.ctx.Err() != nil || !g.callerTraceExecutionValid(chain) || state != g.callerObjectExecutionState() || !chain.executing && !scope.snapshot.matches(g) {
			return original()
		}
		// Exact hit без доказательства не превращает предков в прозрачные.
		// Снимаем доказательство до переноса зависимостей и semantic replay.
		if !record.scopeIndependent {
			callerTraceScopeDependent(chain)
		}
		for i := 0; i < int(record.count); i++ {
			g.callerTraceDependency(chain, record.dependencies[i])
		}
		if !g.addCallerSemantic(record.effects.cuts, record.effects.skips, record.effects.cycles, 0) {
			return nil, true, false
		}
		g.work.ObjectTraceHits++
		return record.objects, record.unknown, false
	}
	if !c.admit(g, 1, callerTraceRecordUnits+callerTraceGuardUnits, false) {
		g.work.ObjectTraceCapacityFallbacks++
		return original()
	}
	c.retained(g, callerTraceRecordUnits+callerTraceGuardUnits)
	record := c.newCallerTraceLiveRecord(g, chain, scope, source)
	recording = record
	record.guard = &callerTraceGuard{state: state, marks: [4]uint64{g.resolveCuts, g.initialSkips, g.completedInitialSkips, g.objectCuts}}
	scope.references++
	if record.next != nil {
		record.previous = record.next.previous
		record.next.previous = record
	} else {
		record.previous = record
	}
	c.traceRecords, chain.record = record, record
	bucket := source % callerTraceBucketCount
	record.bucketNext = c.traceBuckets[bucket]
	if record.bucketNext != nil {
		record.bucketNext.bucketPrevious = record
	}
	c.traceBuckets[bucket] = record
	objects, unknown, owned := original()
	chain.record = record.parent
	// После сырого обхода запись уже не часть стека, даже если страж откажет.
	record.parent, record.entry, record.chain = nil, nil, nil
	if g.ctx == nil || !callerTraceSameContext(record.ctx, g.ctx) || g.ctx.Err() != nil || !g.callerTraceExecutionValid(chain) || record.bad || state != g.callerObjectExecutionState() || !chain.executing && !scope.snapshot.matches(g) || g.completedInitialSkips != record.guard.marks[2] {
		c.releaseCallerTrace(g, record)
		return objects, unknown, owned
	}
	marks := record.guard.marks
	effects := callerInitialObjectEffects{g.resolveCuts - marks[0], g.initialSkips - marks[1], g.objectCuts - marks[3]}
	// В admission одновременно помещаются live backing, новый prefix и result.
	// Ни один из старых slots не вычитается до allocation/copy/rebind.
	prefixUnits := int(record.count) * callerTraceDependencyUnits
	if effects.cuts <= effects.skips || !c.admit(g, 0, 1+len(objects)+prefixUnits, false) {
		c.releaseCallerTrace(g, record)
		return objects, unknown, owned
	}
	// В закрытом Owned-теле seen восстановлен после raw. Старое совпадение
	// было бы entry hit; новый same-source потомок видит наш активный source
	// и сохраняет want=true, несовместимый с нашим выходом. Если source уже
	// был true на входе, raw сразу вернул cycle и не создал потомков вообще.
	// Все taint/state/context guards выше обязательны. Ручной открытый span
	// такого доказательства не получает и сохраняет прежний полный dedup.
	if !chain.executing && c.callerTraceDuplicate(g, record, seen) {
		c.releaseCallerTrace(g, record)
		return objects, unknown, owned
	}
	// Последний checkpoint уже выполнен. Резервирование предшествует clone;
	// pending удерживает только фактический исходный readonly результат.
	record.pending, record.resultReserved = objects, true
	c.weight += 1 + len(objects) + prefixUnits
	g.work.ObjectExecutionPeakValues = max(g.work.ObjectExecutionPeakValues, c.weight)
	oldUnits := cap(record.dependencies) * callerTraceDependencyUnits
	record.dependencies = callerTraceDependencyPrefix(record.dependencies, int(record.count))
	// Единственный владелец старого backing уже переведён на новый prefix.
	// Заимствованных slice aliases у live writer/reader нет.
	c.weight -= oldUnits
	record.objects = maps.Clone(objects)
	record.pending = nil
	record.unknown, record.effects, record.phase = unknown, effects, callerTraceRetained
	record.parent, record.entry, record.chain = nil, nil, nil
	g.work.ObjectTraceStores++
	return objects, unknown, owned
}

// Открытый путь ищет только exact duplicate и не меняет найденную карту.
// Вызов стоит после прежних exit guards и result-capacity admission.
func (c *callerObjectExecutions) callerTraceDuplicate(g *callerGraph, record *callerTraceRecord, seen map[callerObjectSourceID]bool) bool {
	for old := c.traceRecords; old != nil; old = old.next {
		if old.phase != callerTraceRetained || old.source != record.source || old.scope != record.scope || old.scopeIndependent != record.scopeIndependent || old.guard.state != record.guard.state || !callerTraceSameContext(old.ctx, g.ctx) {
			continue
		}
		matches := true
		for i := 0; i < int(old.count); i++ {
			g.work.ObjectTraceValidationSteps++
			dependency := old.dependencies[i]
			matches = matches && seen[dependency.source] == (dependency.want == 1)
		}
		if matches {
			return true
		}
	}
	return false
}
