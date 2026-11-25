// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"hash/maphash"
	"maps"
	"slices"
)

// Слой хранит завершённое исполнение в точном начальном контексте, а не
// доказательство полноты происхождения. Его ответы никогда не входят в object memo.
// Предел общий для записей исполнения и неизменяемых узлов контекста.
const (
	callerObjectExecutionEntries = 4096
	callerObjectExecutionValues  = 16384
)

type callerObjectExecutionState struct {
	callerContainerObjectState
	objectGeneration, resolveGeneration uint64
}

type callerObjectExecutionScope struct {
	snapshot   callerExecutionScopeSnapshot
	next       *callerObjectExecutionScope
	hash       uint64
	weight     int
	references int // Живые tickets и ключи удерживаемых answers; metadata входит в единицу node.
}

type callerObjectExecutionKey struct {
	source callerResolveKey
	scope  *callerObjectExecutionScope
	state  callerObjectExecutionState
}

type callerObjectExecutionAnswer struct {
	answer  callerObjectAnswer
	effects callerInitialObjectEffects
}

type callerObjectExecutionVersion struct {
	binding, effect, sources, reports int
	objects, resolve                  uint64
}

type callerObjectExecutions struct {
	graph           *callerGraph
	seed            maphash.Seed
	entries, weight int
	active          int
	version         callerObjectExecutionVersion
	scopes          map[uint64]*callerObjectExecutionScope
	answers         map[callerObjectExecutionKey]callerObjectExecutionAnswer
	traceRecords    *callerTraceRecord
	traceFrames     *callerTraceFrame
	traceChains     *callerTraceChain
	traceAccount    bool
	traceBuckets    *[callerTraceBucketCount]*callerTraceRecord
	originOwners    *callerOriginOwner
	originRecords   *callerOriginRecord
	originAccount   bool
	originIndex     *callerOriginIndex
	containerOwners [32]callerContainerAdmission
	containerInputs [32]callerContainerAdmission
}

// В execution-снимке heads не удерживается: при полном tracked-доказательстве
// каждая цепочка строго убывает, разные source не имеют общих кадров, covered
// покрывает весь стек. Поэтому head — последняя позиция source в queries.
// Отдельный тип сохраняет прежний полный снимок локального container reuse.
type callerExecutionScopeSnapshot callerContainerObjectScope

func (s callerExecutionScopeSnapshot) matches(g *callerGraph) bool {
	// Проверка обязательна и после Err: одинаковая глубина не исключает прямую
	// замену heads/previous. Нельзя заменить этот предикат эпохой или хешем.
	return g.callerExecutionScopeTracked() && s.matchesTrackedContent(g)
}

// Вызывается только сразу после полного tracked-доказательства, без callback
// или изменения графа между доказательством и точным сравнением содержимого.
func (s callerExecutionScopeSnapshot) matchesTrackedContent(g *callerGraph) bool {
	if len(s.queries) != len(g.fieldQueries) || !maps.Equal(s.containers, g.containerScanning) || !maps.Equal(s.mutations, g.mutationScanning) {
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

// Удалена только физически отсутствующая копия производной карты heads.
// Полные refs/fields и обе непроизводные карты оплачиваются как прежде.
func (g *callerGraph) callerExecutionScopeWeight() int {
	return g.callerContainerObjectScopeWeight() - len(g.fieldQueryHeads)
}

// Ёмкость каждого удерживаемого среза точно равна его длине. Пустой nil
// сохраняется; запас ёмкости исходного аккумулятора не принадлежит слою.
func callerExecutionSlice[T any](src []T) []T {
	if src == nil {
		return nil
	}
	out := make([]T, len(src))
	copy(out, src)
	return out
}

func (g *callerGraph) callerExecutionSnapshot() callerExecutionScopeSnapshot {
	scope := callerExecutionScopeSnapshot{
		queries:    callerExecutionSlice(g.fieldQueries),
		containers: maps.Clone(g.containerScanning), mutations: maps.Clone(g.mutationScanning),
	}
	for i := range scope.queries {
		scope.queries[i].fields = callerExecutionSlice(scope.queries[i].fields)
		scope.queries[i].refs = callerExecutionSlice(scope.queries[i].refs)
	}
	return scope
}

// Одной глубины недостаточно: прямой синтетический стек мог оставить старые
// heads. Проверяем все цепочки и число покрытых кадров без выделения новой карты.
func (g *callerGraph) callerExecutionScopeTracked() bool {
	if g.fieldQueryIndexedDepth != len(g.fieldQueries) {
		return false
	}
	covered := 0
	for source, head := range g.fieldQueryHeads {
		if head <= 0 || head > len(g.fieldQueries) {
			g.work.ObjectScopeTrackedFrameVisits += covered
			return false
		}
		for head > 0 {
			query := &g.fieldQueries[head-1]
			if query.source != source || query.previousSourceQuery < 0 || query.previousSourceQuery >= head {
				// Этот кадр уже прочитан, хотя structural-проверка его отвергла.
				g.work.ObjectScopeTrackedFrameVisits += covered + 1
				return false
			}
			covered++
			head = query.previousSourceQuery
		}
	}
	// work — значение в graph. Один aggregate update на выходе, без новой
	// записи/ветки внутри успешной итерации и без callback или allocation.
	g.work.ObjectScopeTrackedFrameVisits += covered
	return covered == len(g.fieldQueries)
}

// Фабрика запуска и граница RPC создают отдельное пространство. Копия графа
// с чужим указателем владельца остаётся на исходном пути, даже при равной эпохе.
func (g *callerGraph) resetCallerObjectExecutions() {
	g.objectMemoGeneration++
	g.resolveMemoGeneration++
	if g.objectExecutions != nil && g.objectExecutions.active != 0 {
		// Живые кадры сохраняют единственный store и весь его учёт даже после
		// повторных сбросов. Снятый владелец запрещает новые входы; поколения
		// запрещают публикацию старых билетов. Новый namespace возможен после drain.
		g.objectExecutions.graph = nil
		return
	}
	g.objectExecutions = &callerObjectExecutions{graph: g, seed: maphash.MakeSeed()}
}

// Старые монотонные поколения недостижимы даже внутри живого внешнего
// обхода. Удаляем только их answers; scope остаётся, пока его держит ticket
// или другой answer. Снимок и его identity никогда не меняются на месте.
func (c *callerObjectExecutions) advance(g *callerGraph) {
	version := callerObjectExecutionVersion{g.bindingEpoch, g.effectEpoch, len(g.objectSourceIDs), len(g.identityFree), g.objectMemoGeneration, g.resolveMemoGeneration}
	if c.version == version {
		return
	}
	if c.entries != 0 {
		g.work.ObjectExecutionInvalidations++
	}
	for key := range c.answers {
		state := key.state
		retainedVersion := callerObjectExecutionVersion{state.bindingEpoch, state.effectEpoch, state.sourceIDs, state.identityFree, state.objectGeneration, state.resolveGeneration}
		if retainedVersion == version {
			continue
		}
		c.releaseAnswer(g, key)
		g.work.ObjectExecutionRetiredAnswers++
	}
	c.retireCallerTraces(g, version)
	c.retireCallerOrigins(g)
	c.version = version
}

// Удаляется только собственное владение необязательным ответом. Ранее выданная
// неизменяемая карта не очищается; scope освобождается лишь с последней ссылкой.
// Вызывающие проверяют действующего владельца до изменения учёта, без callback.
func (c *callerObjectExecutions) releaseAnswer(g *callerGraph, key callerObjectExecutionKey) int {
	answer, exists := c.answers[key]
	if !exists {
		return 0
	}
	units := 1 + len(answer.answer.objects)
	delete(c.answers, key)
	c.entries--
	c.weight -= units
	c.releaseScope(g, key.scope)
	return units
}

// Последняя ссылка снимается только после выхода ticket или удаления answer.
// B1 namespace со снятым владельцем сохраняет весь учёт до штатного idle reset.
func (c *callerObjectExecutions) releaseScope(g *callerGraph, node *callerObjectExecutionScope) {
	node.references--
	if node.references != 0 || c.graph == nil {
		return
	}
	link := c.scopes[node.hash]
	if link == node {
		if node.next == nil {
			delete(c.scopes, node.hash)
		} else {
			c.scopes[node.hash] = node.next
		}
	} else {
		for link.next != node {
			link = link.next
		}
		link.next = node.next
	}
	node.next = nil
	c.entries--
	c.weight -= node.weight
	g.work.ObjectExecutionReleasedScopes++
}

// Освобождение настоящего ticket общее для обоих replay-слоёв и lifecycle-проверок.
func (c *callerObjectExecutions) releaseTicket(g *callerGraph, scope *callerObjectExecutionScope) {
	c.active--
	c.releaseScope(g, scope)
}

func (c *callerObjectExecutions) retained(g *callerGraph, weight int) {
	c.entries++
	c.weight += weight
	g.work.ObjectExecutionPeakEntries = max(g.work.ObjectExecutionPeakEntries, c.entries)
	g.work.ObjectExecutionPeakValues = max(g.work.ObjectExecutionPeakValues, c.weight)
}

func (g *callerGraph) callerObjectExecutionState() callerObjectExecutionState {
	state := g.callerContainerObjectState()
	// Глубина входит в точный снимок стека; push/pop не инвалидируют другие
	// восстановимые контексты той же долговечной эпохи.
	state.indexedDepth = 0
	return callerObjectExecutionState{state, g.objectMemoGeneration, g.resolveMemoGeneration}
}

func (c *callerObjectExecutions) room(weight int) bool {
	return c.entries < callerObjectExecutionEntries && weight <= callerObjectExecutionValues-c.weight
}

// Сначала допуск освобождает законченные trace-сертификаты в прежнем FIFO
// порядке выделения. Затем удаляет произвольный собственный fresh answer:
// порядок необязательного кеша не задаёт семантику, отдельного списка жертв нет.
// Каждый неуспешный шаг удаляет одну из не более 4096 учтённых записей.
// Живые tickets, кадры и ссылки других владельцев никогда не снимаются.
// withHeader нужен begin: удаление последней записи может снять старый заголовок,
// поэтому его стоимость пересчитывается после каждого реального удаления.
func (c *callerObjectExecutions) admit(g *callerGraph, entries, units int, withHeader bool) bool {
	if c.graph != g || g.objectExecutions != c || entries < 0 || units < 0 || entries > callerObjectExecutionEntries || units > callerObjectExecutionValues {
		return false
	}
	// Заголовок обязателен для всего trace-запроса, даже если уже удерживается.
	if withHeader && (entries > callerObjectExecutionEntries-1 || units > callerObjectExecutionValues-callerTraceHeaderUnits) {
		return false
	}
	for {
		needEntries, needUnits := entries, units
		if withHeader && !c.traceAccount {
			needEntries++
			needUnits += callerTraceHeaderUnits
		}
		if c.traceRoom(needEntries, needUnits) {
			return true
		}
		victim := c.oldestCallerTrace()
		if victim == nil {
			removed := false
			for key := range c.answers {
				g.work.ObjectExecutionEvictedValues += c.releaseAnswer(g, key)
				g.work.ObjectExecutionEvictions++
				removed = true
				break
			}
			if !removed {
				if c.evictCallerOrigin(g) {
					continue
				}
				return false
			}
			continue
		}
		// Счётчик включает только снятое владение кеша, не ранее возвращённые
		// ответы вызывающих. Их карты остаются неизменными, как при advance.
		values := callerTraceRecordUnits + callerTraceGuardUnits + cap(victim.dependencies)*callerTraceDependencyUnits
		if victim.resultReserved {
			values += 1 + len(victim.objects)
		}
		c.releaseCallerTrace(g, victim)
		g.work.ObjectTraceEvictions++
		g.work.ObjectTraceEvictedValues += values
	}
}

// Два возможных bool-хеша вычисляются лениво внутри одного scopeHash.
// Все обращения имеют один seed. Нулевой хеш допустим: готовность хранится
// отдельно. Значения не переживают вызов и не добавляют состояние namespace.
type callerExecutionBoolHashes struct {
	values [2]uint64
	ready  [2]bool
}

func (h *callerExecutionBoolHashes) sum(seed maphash.Seed, value bool) uint64 {
	index := 0
	if value {
		index = 1
	}
	if !h.ready[index] {
		h.values[index] = maphash.Comparable(seed, value)
		h.ready[index] = true
	}
	return h.values[index]
}

// Хеш выбирает только корзину. Решение о равенстве всегда принимает matches
// по полным queries и картам стражей. Производный heads доказан tracked-проверкой;
// порядок refs, поля и все значения непроизводных карт сравниваются точно.
// XOR для карт не зависит от порядка их обхода; коллизия не даёт попадания.
func (c *callerObjectExecutions) scopeHash(g *callerGraph) uint64 {
	hash := uint64(0)
	booleans := callerExecutionBoolHashes{}
	for i := range g.fieldQueries {
		query := &g.fieldQueries[i]
		hash = hash*1099511628211 + maphash.Comparable(c.seed, query.source)
		hash = hash*1099511628211 + booleans.sum(c.seed, query.unknown)
		hash = hash*1099511628211 + maphash.Comparable(c.seed, query.previousSourceQuery)
		for _, field := range query.fields {
			hash = hash*1099511628211 + maphash.Comparable(c.seed, field)
		}
		for _, ref := range query.refs {
			hash = hash*1099511628211 + maphash.Comparable(c.seed, ref)
		}
	}
	for key, value := range g.containerScanning {
		hash ^= maphash.Comparable(c.seed, key) + booleans.sum(c.seed, value)
	}
	for key, value := range g.mutationScanning {
		hash ^= maphash.Comparable(c.seed, key) + booleans.sum(c.seed, value)
	}
	return hash
}

// Trace и прямые lifecycle-примитивы сохраняют прежний допускающий вытеснение путь.
func (c *callerObjectExecutions) scope(g *callerGraph) *callerObjectExecutionScope {
	return c.acquireScope(g, true)
}

// Fresh lookup не вытесняет summaries ради создания ещё неизвестного ключа.
// Уже существующий exact scope получает тот же настоящий ticket без allocation.
func (c *callerObjectExecutions) freshScope(g *callerGraph) *callerObjectExecutionScope {
	return c.acquireScope(g, false)
}

// Проверка свободного места не изменяет ни владение, ни семантические отметки.
func (c *callerObjectExecutions) freshRoom(g *callerGraph, weight int) bool {
	return c.graph == g && g.objectExecutions == c && weight >= 0 && c.room(weight)
}

func (c *callerObjectExecutions) scopeRoom(g *callerGraph, weight int, reclaim bool) bool {
	if reclaim {
		return c.admit(g, 1, weight, false)
	}
	return c.freshRoom(g, weight)
}

// Обе цели используют один протокол snapshot-before-body, checkpoints и pins.
func (c *callerObjectExecutions) acquireScope(g *callerGraph, reclaim bool) *callerObjectExecutionScope {
	if !g.callerExecutionScopeTracked() {
		return nil
	}
	return c.acquireTrackedScope(g, reclaim)
}

// Вход требует только что выполненного полного structural-доказательства.
// Между ним и входом запрещены Err, callback и запись в queries/heads/refs или
// карты scope. Допустим advance: он снимает только владение кеша и его учёт.
// Это локальная предпосылка вызова, не сохранённый флаг или сертификат эпохи.
// После Err без доказанной прозрачности проверки выполняются заново.
func (c *callerObjectExecutions) acquireTrackedScope(g *callerGraph, reclaim bool) *callerObjectExecutionScope {
	hash := c.scopeHash(g)
	for node := c.scopes[hash]; node != nil; node = node.next {
		// Хеширование и чтение корзины не меняют граф после полного доказательства.
		if node.snapshot.matchesTrackedContent(g) {
			node.references++
			c.active++
			return node
		}
	}
	weight := 1 + g.callerExecutionScopeWeight()
	if !c.scopeRoom(g, weight, reclaim) {
		g.work.ObjectExecutionCapacityFallbacks++
		return nil
	}
	// Err стандартных контекстов из закреплённой библиотеки читает отмену
	// и не вызывает пользовательский код. Доказательство стека остаётся
	// действительным: учёт и вытеснение меняют только хранилище снимков.
	recheckScope := !callerFreshReplayContext(g.ctx)
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		return nil
	}
	if g.objectExecutions != c || c.graph != g {
		return nil
	}
	if recheckScope {
		// Произвольный Err может изменить содержимое или вложенным вызовом
		// поместить точный снимок в ту же корзину.
		if !g.callerExecutionScopeTracked() || hash != c.scopeHash(g) || weight != 1+g.callerExecutionScopeWeight() {
			return nil
		}
		for existing := c.scopes[hash]; existing != nil; existing = existing.next {
			if existing.snapshot.matchesTrackedContent(g) {
				existing.references++
				c.active++
				return existing
			}
		}
	}
	if !c.scopeRoom(g, weight, reclaim) {
		g.work.ObjectExecutionCapacityFallbacks++
		return nil
	}
	node := &callerObjectExecutionScope{snapshot: g.callerExecutionSnapshot(), hash: hash, weight: weight, references: 1}
	if c.scopes == nil {
		c.scopes = map[uint64]*callerObjectExecutionScope{}
	}
	// Между копированием и публикацией нет callback. Вторая контрольная
	// точка видит уже учтённый и pinned node, который prune не может освободить.
	node.next = c.scopes[hash]
	c.scopes[hash] = node
	c.retained(g, weight)
	c.active++
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil || g.objectExecutions != c || c.graph != g || recheckScope && !node.snapshot.matches(g) {
		c.releaseTicket(g, node)
		return nil
	}
	return node
}

func (g *callerGraph) callerObjectExecution(src valueSrc, seen map[callerObjectSourceID]bool) (map[callerObjectKey]bool, bool) {
	entryContext := g.ctx
	var entryScope *callerObjectExecutionScope
	original := func() (map[callerObjectKey]bool, bool) {
		g.work.ObjectExecutionFallbacks++
		objects, unknown, _ := g.callerObjectsOwnedScope(src, seen, entryScope)
		return objects, unknown
	}
	// Непрозрачный Err получает ровно исходную последовательность checkpoint.
	// Даже acquire scope до этого отказа уже мог бы вызвать лишний callback.
	if !callerFreshReplayContext(entryContext) {
		return original()
	}
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		return nil, true
	}
	if g.objectExecutions == nil || g.objectExecutions.graph != g {
		return original()
	}
	// Холодная эпоха, неинтернированный источник и завершённый memo идут прежним
	// путём. Новый слой не меняет публикацию или начальные marks обычного memo.
	source := callerResolveKeyFor(src, true)
	id := g.objectSourceIDs[source]
	if id == 0 || g.objectMemo == nil || g.objectMemoEpoch != g.bindingEpoch || g.initialObjectMemo == nil {
		return original()
	}
	if _, complete := g.initialObjectMemo[id]; complete {
		// Точный обычный memo уже существует. Допущенный Err не вызывает код
		// пользователя, а prepare не меняет memo: Tracked либо отменится на
		// прежнем checkpoint, либо вернёт тот же hit с одной initial boundary.
		// Сохраняем taint/retirement, но не резервируем неиспользуемый trace.
		g.work.ObjectExecutionFallbacks++
		g.prepareCallerTrace(seen)
		objects, unknown, _ := g.callerObjectsTracked(src, seen, nil)
		return objects, unknown
	}
	if !g.callerExecutionScopeTracked() {
		return original()
	}
	g.work.ObjectExecutionQueries++
	state := g.callerObjectExecutionState()
	c := g.objectExecutions
	c.advance(g)
	// Полное tracked-доказательство выше остаётся действительным: чтение state
	// и advance не вызывают Err/callback и не меняют содержимое scope. Повторно
	// проверяем только hash/content здесь; состояние и контекст hit сверяются ниже.
	scope := c.acquireTrackedScope(g, false)
	if scope == nil {
		return original()
	}
	defer c.releaseTicket(g, scope)
	if g.objectExecutions != c || c.graph != g {
		return original()
	}
	key := callerObjectExecutionKey{source, scope, state}
	if answer, ok := c.answers[key]; ok {
		if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
			return nil, true
		}
		// acquireTrackedScope уже сравнил точный снимок. До hit были только
		// чтения состояния и чистая проверка отмены допущенного контекста.
		if g.objectExecutions != c || c.graph != g || state != g.callerObjectExecutionState() || !callerFreshSameContext(entryContext, g.ctx) {
			return original()
		}
		if !g.addCallerSemantic(answer.effects.cuts, answer.effects.skips, answer.effects.cycles, 0) {
			return nil, true
		}
		g.work.ObjectExecutionHits++
		return answer.answer.objects, answer.answer.unknown
	}
	cuts, skips, completed, cycles := g.resolveCuts, g.initialSkips, g.completedInitialSkips, g.objectCuts
	// Только настоящий miss передаёт уже удерживаемый ticket закрытому телу.
	// Остальные original-ветви сохраняют nil; borrowed ссылка не владеет ticket.
	entryScope = scope
	objects, unknown := original()
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		return nil, true
	}
	if g.objectExecutions != c || state != g.callerObjectExecutionState() || completed != g.completedInitialSkips || !scope.snapshot.matches(g) || !callerFreshSameContext(entryContext, g.ctx) {
		return objects, unknown
	}
	if _, retained := c.answers[key]; retained {
		return objects, unknown
	}
	weight := 1 + len(objects)
	if !c.freshRoom(g, weight) {
		g.work.ObjectExecutionCapacityFallbacks++
		return objects, unknown
	}
	// Даже неопубликованный owned-ответ принадлежит исходному вызывающему.
	// Слой удерживает только собственную карту и никогда не возвращает owned=true.
	if g.semanticOverflow || g.ctx != nil && g.ctx.Err() != nil {
		return nil, true
	}
	// После проверки снимка, выполненной за original, были только чтения и
	// чистый Err того же контекста. Снимок остаётся точным до публикации.
	if g.objectExecutions != c || c.graph != g || state != g.callerObjectExecutionState() || !callerFreshSameContext(entryContext, g.ctx) {
		return objects, unknown
	}
	if !c.freshRoom(g, weight) {
		g.work.ObjectExecutionCapacityFallbacks++
		return objects, unknown
	}
	if _, retained := c.answers[key]; retained {
		return objects, unknown
	}
	copyObjects := maps.Clone(objects)
	if c.answers == nil {
		c.answers = map[callerObjectExecutionKey]callerObjectExecutionAnswer{}
	}
	c.answers[key] = callerObjectExecutionAnswer{
		answer:  callerObjectAnswer{copyObjects, unknown},
		effects: callerInitialObjectEffects{g.resolveCuts - cuts, g.initialSkips - skips, g.objectCuts - cycles},
	}
	scope.references++
	c.retained(g, weight)
	g.work.ObjectExecutionStores++
	return objects, unknown
}

// Replay может представлять экспоненциальное число семантических границ. Все
// четыре отметки меняются атомарно: ни wrap, ни насыщение не превращают cut
// в нулевую дельту. Отказ живёт весь запуск и запрещает последующие доказательства.
func (g *callerGraph) addCallerSemantic(cuts, skips, cycles, completed uint64) bool {
	if g.semanticOverflow {
		return false
	}
	limit := ^uint64(0)
	if cuts > limit-g.resolveCuts || skips > limit-g.initialSkips || cycles > limit-g.objectCuts || completed > limit-g.completedInitialSkips {
		g.semanticOverflow = true
		g.work.ObjectSemanticOverflows++
		return false
	}
	g.resolveCuts += cuts
	g.initialSkips += skips
	g.objectCuts += cycles
	g.completedInitialSkips += completed
	return true
}

// Финализатор вызывается после любого выхода judge, включая ранние возвраты.
// Существующий отказ сохраняется; сброс namespace очередного RPC флаг не очищает.
func (g *callerGraph) refuseCallerSemanticOverflow(report *CallerIdentityReport) {
	if !g.semanticOverflow {
		return
	}
	if report.Invalid == "" {
		report.Invalid = "переполнение семантических границ caller identity; доказательство недействительно"
	}
	report.Work = g.work
}
