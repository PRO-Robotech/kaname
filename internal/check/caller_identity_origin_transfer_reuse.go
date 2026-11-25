// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"hash/maphash"
	"math/bits"
	"unsafe"
)

// Размеры оплачивают физические поля, включая указатели, padding и заголовки
// срезов. Узлы зависимостей не имеют скрытого запаса; результат имеет cap == len.
const (
	callerOriginBuckets           = 256
	_                       uint8 = callerOriginBuckets - 1 // Номер retained-корзины помещается в один байт.
	callerOriginHeaderUnits       = 4 + int((unsafe.Sizeof(callerOriginIndex{})+7)/8)
	callerOriginOwnerUnits        = int((unsafe.Sizeof(callerOriginOwner{}) + 7) / 8)
	callerOriginGuardUnits        = int((unsafe.Sizeof(callerOriginRecord{}) + 7) / 8)
	callerOriginProofUnits        = int((unsafe.Sizeof(callerOriginProof{}) + 7) / 8)
	// Полный frame без логической seed: её физические bytes уже входят в proof.
	callerOriginRecordUnits     = callerOriginGuardUnits + callerOriginProofUnits - callerOriginDependencyUnits
	callerOriginDependencyUnits = int((unsafe.Sizeof(callerOriginDependency{}) + 7) / 8)
	callerOriginValueUnits      = int((unsafe.Sizeof(callerOrigin{}) + 7) / 8)
	callerOriginDependencyLimit = 64
)

// Фиксированный оплаченный индекс содержит только retained записи. Hash выбирает
// корзину, а исходник, scope, revision и admitted context сравниваются точно.
// Корзины не растут и не содержат заимствованных live-frame ссылок.
// Хвост общего списка может принадлежать ещё открытому кадру.
type callerOriginIndex struct {
	buckets        [callerOriginBuckets]*callerOriginRecord
	oldest         *callerOriginRecord
	replaySequence uint64 // ID не повторяются, пока живёт этот оплаченный индекс.
}
type callerOriginIndexKey struct {
	source callerResolveKey
	scope  *callerObjectExecutionScope
	state  callerObjectExecutionState
	ctx    context.Context
}

func (c *callerObjectExecutions) callerOriginBucket(key callerResolveKey, scope *callerObjectExecutionScope, state callerObjectExecutionState, ctx context.Context) uint8 {
	return uint8(maphash.Comparable(c.seed, callerOriginIndexKey{key, scope, state, ctx}) % callerOriginBuckets)
}

type callerOriginOwner struct {
	next             *callerOriginOwner
	cache            *callerObjectExecutions
	seen             map[callerResolveKey]bool
	scope            *callerObjectExecutionScope
	top              *callerOriginRecord
	capacityBoundary *callerOriginRecord
	ctx              context.Context
	live, bad        bool
}

// Ноль обозначает ещё не вычисленный номер. Seed namespace неизменен до
// завершения всех его owners. Хешируем identity expr, включая nil; не
// разыменовываем AST и не читаем его изменяемые поля. Tuple различает
// результаты одного выражения. Коллизия требует исходного точного сравнения.
type callerOriginDependencySlot uint8

func (c *callerObjectExecutions) originDependencySlot(key callerResolveKey) callerOriginDependencySlot {
	hash := uint(key.source.tuple)
	if key.source.expr != nil {
		hash ^= uint(maphash.Comparable(c.seed, key.source.expr))
	}
	return 1 + callerOriginDependencySlot(hash&(bits.UintSize-1))
}

func (s callerOriginDependencySlot) mask() uint {
	return uint(1) << (s - 1)
}

type callerOriginDependency struct {
	key              callerResolveKey
	want, propagated bool
	slot             callerOriginDependencySlot // Занимает byte прежнего выравнивания перед next.
	next             *callerOriginDependency
}

// Seed входит в отдельный физический proof: успешный begin по-прежнему
// выделяет два объекта (guard и proof с seed), а не третий узел зависимости.
// После отказа proof вместе со всей цепочкой можно отпустить до unwind guard.
type callerOriginProof struct {
	state   callerObjectExecutionState
	marks   [4]uint64
	effects callerInitialObjectEffects
	seed    callerOriginDependency
}

// Guard остаётся оплаченным после отказа: key/parent/pushed ещё ограничивают
// передачу чтений. Отдельный proof не может быть частью этой же allocation.
type callerOriginRecord struct {
	*callerOriginProof
	next, previous, parent, bucketNext *callerOriginRecord
	owner                              *callerOriginOwner
	key                                callerResolveKey
	scope                              *callerObjectExecutionScope
	ctx                                context.Context
	dependencies                       *callerOriginDependency
	values                             []callerOrigin
	// У live frame это свидетель перевода, у retained — собственный ID.
	replayIdentity     uint64
	units, count, pins int
	// Одно слово вместо прежнего int bucket; bucket занимает свободный byte
	// рядом с bool. Биты описывают только наличие в собственном списке.
	dependencyMask                                   uint
	bucket                                           uint8
	live, bad, pushed, retained, holdsScope, unknown bool
}

// Origin не вытесняет trace/fresh summaries ради ещё не доказанного resolve.
// В общем прежнем бюджете он может снять только собственные завершённые записи;
// их pins, scope references и заголовок освобождает прежний единый путь eviction.
func (c *callerObjectExecutions) admitCallerOrigin(g *callerGraph, entries, units int) bool {
	if c.graph != g || g.objectExecutions != c || entries < 0 || units < 0 || entries > callerObjectExecutionEntries || units > callerObjectExecutionValues {
		return false
	}
	for !c.traceRoom(entries, units) {
		if !c.evictCallerOrigin(g) {
			return false
		}
	}
	return true
}

// Внешний wrapper владеет переданной картой только на время синхронного вызова.
// Ложные записи допускаются исходным движком, но удаление такой записи нельзя
// пропустить при replay. Поэтому весь этот owner остаётся исходным исполнением.
// Независимые fresh-map descendants могут открыть собственный допустимый owner.
func (g *callerGraph) beginCallerOrigin(seen map[callerResolveKey]bool) *callerOriginOwner {
	c := g.objectExecutions
	if !g.lifetimeScanning || g.semanticOverflow || !callerFreshReplayContext(g.ctx) || seen == nil || c == nil || c.graph != g {
		return nil
	}
	for _, value := range seen {
		if !value {
			return nil
		}
	}
	if g.ctx != nil && g.ctx.Err() != nil {
		return nil
	}
	if c.graph != g || g.objectExecutions != c {
		return nil
	}
	c.advance(g)
	for {
		header := !c.originAccount
		entries, units := 1, callerOriginOwnerUnits
		if header {
			entries++
			units += callerOriginHeaderUnits
		}
		if !c.admitCallerOrigin(g, entries, units) {
			g.work.OriginTransferCapacityFallbacks++
			return nil
		}
		// Последняя вытесненная origin-запись могла освободить прежний индекс.
		// До allocation повторяем допуск с фактически требуемым заголовком.
		if !header && !c.originAccount {
			continue
		}
		break
	}
	// До первого выделения и любого checkpoint живой owner входит в B1 active.
	c.active++
	if !c.originAccount {
		c.retained(g, callerOriginHeaderUnits)
		c.originAccount = true
		c.originIndex = &callerOriginIndex{}
	}
	c.retained(g, callerOriginOwnerUnits)
	owner := &callerOriginOwner{next: c.originOwners, cache: c, seen: seen, ctx: g.ctx, live: true}
	c.originOwners = owner
	// Exact существующий scope получает обычный ticket. Новый snapshot, как
	// и fresh lookup, не освобождает чужие summaries для неизвестного ключа.
	owner.scope = c.freshScope(g)
	if owner.scope == nil || c.graph != g || g.objectExecutions != c || !callerFreshSameContext(owner.ctx, g.ctx) {
		g.endCallerOrigin(owner)
		return nil
	}
	g.work.OriginTransferOwners++
	return owner
}

func (g *callerGraph) endCallerOrigin(owner *callerOriginOwner) {
	if owner == nil {
		return
	}
	c := owner.cache
	owner.live = false
	c.active--
	if owner.scope != nil {
		c.releaseTicket(g, owner.scope)
	}
	owner.scope, owner.seen, owner.top, owner.capacityBoundary, owner.ctx = nil, nil, nil, nil, nil
	if c.graph == nil {
		return
	}
	link := &c.originOwners
	for *link != owner {
		link = &(*link).next
	}
	*link = owner.next
	owner.next = nil
	c.entries--
	c.weight -= callerOriginOwnerUnits
	c.releaseCallerOriginHeader()
}

func (c *callerObjectExecutions) releaseCallerOriginHeader() {
	if c.graph != nil && c.originAccount && c.originOwners == nil && c.originRecords == nil {
		c.originAccount = false
		c.originIndex = nil
		c.entries--
		c.weight -= callerOriginHeaderUnits
	}
}

// Запись field-owner меняет только собственный pushed query. После его leave
// проверяется полное восстановление внешнего scope, включая false extra guards.
// Внутренние same-owner resolve между такими границами scope не меняют.
func (g *callerGraph) restoreCallerOriginScope(owner *callerOriginOwner) {
	if owner != nil {
		g.work.OriginTransferFieldRestores++
	}
	if owner != nil && !owner.bad && (owner.scope == nil || !owner.scope.snapshot.matches(g)) {
		owner.bad = true
	}
}

// Неаудированный наблюдаемый writer запрещает публикацию затронутых родителей,
// но не запрещает будущим независимым fresh owners начать собственное доказательство.
func (g *callerGraph) taintCallerOrigins() {
	if c := g.objectExecutions; c != nil {
		for owner := c.originOwners; owner != nil; owner = owner.next {
			c.rejectCallerOriginAncestors(owner)
		}
	}
}

// Отвергнутый живой сертификат отпускает отдельный proof с seed и dependencies.
// Минимальный guard, его pushed-граница и ticket оплачены до unwind. При B1
// снятый namespace сохраняет весь physical account до завершения drain.
func (c *callerObjectExecutions) rejectCallerOriginFrame(frame *callerOriginRecord) int {
	frame.replayIdentity = 0
	frame.bad = true
	if c.graph == nil || frame.callerOriginProof == nil {
		return 0
	}
	units := callerOriginProofUnits + (frame.count-1)*callerOriginDependencyUnits
	c.entries -= frame.count
	c.weight -= units
	frame.units -= units
	frame.dependencies, frame.count, frame.dependencyMask = nil, 0, 0
	frame.callerOriginProof = nil
	return units
}

// После неучтённого push старые родители не публикуются, но новые независимые
// потомки могут доказать собственные зависимости. Граница движется вместе с
// unwind: каждый открытый frame посещается здесь не более одного раза.
// Повторный отказ без нового frame имеет O(1), а не O(depth), ancestor walk.
func (c *callerObjectExecutions) rejectCallerOriginAncestors(owner *callerOriginOwner) int {
	units := 0
	for frame := owner.top; frame != owner.capacityBoundary; frame = frame.parent {
		units += c.rejectCallerOriginFrame(frame)
	}
	owner.capacityBoundary = owner.top
	return units
}

func (g *callerGraph) callerOriginOwnerValid(owner *callerOriginOwner) bool {
	// beginCallerOrigin возвращает owner только после callerFreshSameContext.
	// До endCallerOrigin его ctx неизменен и сравним (включая nil). Равенство
	// отклонит другой dynamic type, даже если новый g.ctx несравним.
	return owner != nil && owner.live && !owner.bad && owner.cache == g.objectExecutions && owner.cache.graph == g && g.lifetimeScanning && !g.semanticOverflow && owner.ctx == g.ctx
}

// Чтение передаётся каждому живому предку до первого собственного push этого
// ключа. Выше такого push положительный ответ объясняется локальным стеком,
// а не внешней seen-картой. Fresh wrapper имеет отдельный owner и отдельный top.
func (g *callerGraph) callerOriginRead(owner *callerOriginOwner, key callerResolveKey, want bool) bool {
	return g.callerOriginEntryRead(owner, key, want, false)
}

func (g *callerGraph) callerOriginEntryRead(owner *callerOriginOwner, key callerResolveKey, want, skipSiblings bool) bool {
	if !g.callerOriginOwnerValid(owner) {
		return false
	}
	g.recordCallerOriginRead(owner, key, want, skipSiblings, 0)
	return true
}

// prepared принадлежит только непосредственному вызову resolveOwned: тот же
// owner, source и seen уже передали отрицательное чтение прежним предкам.
// Между чтениями нет resolver/callback; admission может лишь отвергнуть их.
// Самостоятельный begin не устанавливает propagated и остаётся обычным путём.
func (g *callerGraph) callerOriginRawEntryRead(owner *callerOriginOwner, frame *callerOriginRecord, key callerResolveKey, want, prepared bool) {
	if !prepared || want || !g.callerOriginOwnerValid(owner) {
		g.callerOriginRead(owner, key, want)
		return
	}
	if frame == nil {
		if owner.top != owner.capacityBoundary {
			g.callerOriginRead(owner, key, want)
			return
		}
	} else {
		dep := frame.dependencies
		if owner.top != frame || frame.owner != owner || !frame.live || frame.bad || frame.pushed ||
			frame.key != key || frame.count != 1 || dep == nil || dep.key != key || dep.want || dep.propagated {
			g.callerOriginRead(owner, key, want)
			return
		}
		// Новый seed уже объясняет это чтение; прежние предки получили его
		// до открытия frame. Сохраняем логическое чтение без нового поиска.
		dep.propagated = true
	}
	g.work.OriginTransferReads++
}

// Вызывается с уже проверенным живым owner. Запись зависимости и допуск памяти
// не вызывают Err и не меняют владельца, контекст или режим анализа.
func (g *callerGraph) recordCallerOriginRead(owner *callerOriginOwner, key callerResolveKey, want, skipSiblings bool, slot callerOriginDependencySlot) {
	g.work.OriginTransferReads++
	// За capacityBoundary все сертификаты уже отвергнуты. Чтения нижних
	// новых frames записаны до этой границы; сканировать старый стек незачем.
	for frame := owner.top; frame != owner.capacityBoundary; frame = frame.parent {
		if frame.pushed && frame.key.source.expr == key.source.expr &&
			frame.key.receiver == key.receiver && frame.key == key {
			break
		}
		dep := g.addCallerOriginDependencyForRead(owner, frame, key, want, skipSiblings, &slot)
		skipSiblings = false
		if dep == nil {
			continue
		}
		if dep.propagated {
			break
		}
		// У живого кадра цепочка родителей неизменна. Синхронный обход
		// запишет зависимость до ближайшей границы и не вызовет повторный вход.
		dep.propagated = true
	}
}

func (g *callerGraph) addCallerOriginDependency(owner *callerOriginOwner, frame *callerOriginRecord, key callerResolveKey, want bool) *callerOriginDependency {
	var slot callerOriginDependencySlot
	return g.addCallerOriginDependencyForRead(owner, frame, key, want, false, &slot)
}

func (g *callerGraph) addCallerOriginDependencyForRead(owner *callerOriginOwner, frame *callerOriginRecord, key callerResolveKey, want, skipSiblings bool, slot *callerOriginDependencySlot) *callerOriginDependency {
	if frame.bad {
		return nil
	}
	if *slot == 0 {
		*slot = owner.cache.originDependencySlot(key)
	}
	mask := slot.mask()
	first := frame.dependencies
	if frame.dependencyMask&mask == 0 {
		// Каждый добавленный узел, включая seed, установил свой бит. Один
		// отсутствующий бит исключает точный ключ во всём этом кадре.
		first = nil
	} else if skipSiblings {
		// Предыдущие siblings различны с key. Seed проверяем точно, как и
		// весь список каждого предка. Вставка по-прежнему идёт в начало.
		first = &frame.seed
	}
	for dep := first; dep != nil; dep = dep.next {
		// Разные узлы AST различают ключи. Для одного узла всё равно нужны
		// полное сравнение tuple, владельца и режима источника.
		if dep.slot != *slot || dep.key.source.expr != key.source.expr || dep.key.receiver != key.receiver {
			continue
		}
		if dep.key == key {
			if dep.want != want {
				owner.cache.rejectCallerOriginFrame(frame)
				return nil
			}
			return dep
		}
	}
	c := owner.cache
	if frame.count == callerOriginDependencyLimit || !c.admitCallerOrigin(g, 1, callerOriginDependencyUnits) {
		c.rejectCallerOriginFrame(frame)
		g.work.OriginTransferCapacityFallbacks++
		return nil
	}
	// Frame уже удерживает active. Резерв предшествует выделению узла.
	c.retained(g, callerOriginDependencyUnits)
	frame.dependencies = &callerOriginDependency{key: key, want: want, slot: *slot, next: frame.dependencies}
	frame.dependencyMask |= mask
	frame.count++
	frame.units += callerOriginDependencyUnits
	return frame.dependencies
}

// Ноль запрещает сокращение replay. Счётчик живёт внутри оплаченного индекса
// и никогда не оборачивается. Его освобождение требует отсутствия всех owners
// и records: ни один прежний свидетель или ID не переживает этот namespace.
func (c *callerObjectExecutions) nextCallerOriginReplayIdentity() uint64 {
	if c.originIndex.replaySequence == ^uint64(0) {
		return 0
	}
	c.originIndex.replaySequence++
	return c.originIndex.replaySequence
}

func (g *callerGraph) callerOriginHit(owner *callerOriginOwner, key callerResolveKey) (callerResolveAnswer, bool) {
	return g.callerOriginHitWithEntryRead(owner, key, false)
}

// Отрицательное чтение может передать resolveOwned: он уже проверил тот же
// ключ в seen этого owner и при положительном ответе вышел по циклу.
func (g *callerGraph) callerOriginHitWithEntryRead(owner *callerOriginOwner, key callerResolveKey, negativeEntryRead bool) (callerResolveAnswer, bool) {
	if !g.callerOriginOwnerValid(owner) {
		return callerResolveAnswer{}, false
	}
	c, state := owner.cache, g.callerObjectExecutionState()
	bucket := c.callerOriginBucket(key, owner.scope, state, g.ctx)
	for record := c.originIndex.buckets[bucket]; record != nil; record = record.bucketNext {
		g.work.OriginTransferCandidates++
		if !record.retained || record.key.source.expr != key.source.expr ||
			record.key.receiver != key.receiver || record.key != key ||
			record.scope != owner.scope || record.state != state || !callerFreshSameContext(record.ctx, g.ctx) {
			continue
		}
		var stop *callerOriginDependency
		if negativeEntryRead {
			// После точного совпадения record.key его отрицательная seed уже
			// проверена. Все прочие зависимости добавлены перед ней.
			stop = &record.seed
		}
		match := true
		for dep := record.dependencies; dep != stop; dep = dep.next {
			if owner.seen[dep.key] != dep.want {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		if g.ctx != nil && g.ctx.Err() != nil {
			return callerResolveAnswer{nil, true}, true
		}
		if !g.callerOriginOwnerValid(owner) || state != g.callerObjectExecutionState() {
			return callerResolveAnswer{}, false
		}
		// Перевод child-hit dependencies может потребовать допуска памяти родителей.
		// Жертва, которую мы сейчас читаем, pinned до завершения перевода и replay.
		record.pins++
		// Новый replay не выдаёт пропущенные fresh-object события за продолжение
		// чужой object-seen цепочки. Её необязательный сертификат остаётся на fallback.
		g.taintCallerTraces()
		top := owner.top
		// Свидетель принадлежит ровно этому живому получателю. Источник уже
		// полностью проверен по seen/context/state и pinned до конца replay.
		witnessable := top != nil && top.live && !top.bad && top.owner == owner &&
			record.retained && !record.live && record.pins > 0 && record.replayIdentity != 0
		if owner.top == owner.capacityBoundary {
			// Получателей нет. Сохраняем число логических чтений без второго
			// обхода уже проверенных зависимостей.
			g.work.OriginTransferReads += record.count
		} else if witnessable && top.replayIdentity == record.replayIdentity {
			// Первый полный перевод оставил каждый ключ в top с propagated либо
			// остановил его на собственном push. Повторный обычный перевод уже
			// остановился бы здесь для каждого ключа, даже если предок отвергнут.
			g.work.OriginTransferReads += record.count
			g.work.OriginTransferRepeatReplays++
		} else {
			for dep := record.dependencies; dep != nil; dep = dep.next {
				g.recordCallerOriginRead(owner, dep.key, dep.want, false, dep.slot)
			}
			// Перевод синхронен, без callback. Отказ получателя уничтожает
			// dependencies и запрещает свидетель, даже если источник ещё pinned.
			if witnessable && owner.top == top && !top.bad {
				top.replayIdentity = record.replayIdentity
			}
		}
		answer := callerResolveAnswer{record.values, record.unknown}
		if !g.addCallerSemantic(record.effects.cuts, record.effects.skips, record.effects.cycles, 0) {
			answer = callerResolveAnswer{nil, true}
		}
		record.pins--
		g.work.OriginTransferHits++
		return answer, true
	}
	return callerResolveAnswer{}, false
}

func (g *callerGraph) beginCallerOriginFrame(owner *callerOriginOwner, key callerResolveKey) *callerOriginRecord {
	if !g.callerOriginOwnerValid(owner) {
		return nil
	}
	c := owner.cache
	// Новый frame не вытесняет готовые сертификаты ради ещё не доказанного
	// ответа. До allocation проверяем место и для обязательной первой зависимости.
	units := callerOriginRecordUnits + callerOriginDependencyUnits
	if !c.traceRoom(2, units) {
		g.work.OriginTransferCapacityFallbacks++
		// Только сертификаты текущих родителей теряют достоверность, а не
		// scope всего owner. Освободив их proof и dependencies, пробуем один
		// раз; без освобождения повторный admission заведомо бесполезен.
		if c.rejectCallerOriginAncestors(owner) == 0 || !c.traceRoom(2, units) {
			return nil
		}
	}
	c.active++
	// Два физических объекта оплачены до allocation. Seed — первая dependency
	// того же proof, поэтому число entries остаётся прежним: guard + seed.
	c.retained(g, callerOriginGuardUnits)
	c.retained(g, callerOriginProofUnits)
	slot := c.originDependencySlot(key)
	frame := &callerOriginRecord{
		dependencyMask: slot.mask(),
		callerOriginProof: &callerOriginProof{
			state: g.callerObjectExecutionState(),
			marks: [4]uint64{g.resolveCuts, g.initialSkips, g.objectCuts, g.completedInitialSkips},
			seed:  callerOriginDependency{key: key, slot: slot},
		},
		next: c.originRecords, parent: owner.top, owner: owner, key: key,
		scope: owner.scope, ctx: g.ctx, units: units, count: 1, live: true,
	}
	frame.dependencies = &frame.seed
	if frame.next == nil {
		c.originIndex.oldest = frame
	} else {
		frame.next.previous = frame
	}
	c.originRecords, owner.top = frame, frame
	return frame
}

func (g *callerGraph) endCallerOriginFrame(owner *callerOriginOwner, frame *callerOriginRecord, values []callerOrigin, unknown bool) {
	if frame == nil {
		return
	}
	c := owner.cache
	owner.top = frame.parent
	if owner.capacityBoundary == frame {
		owner.capacityBoundary = frame.parent
	}
	frame.live, frame.parent, frame.owner = false, nil, nil
	frame.replayIdentity = 0
	c.active--
	stable := g.callerOriginOwnerValid(owner) && !frame.bad && frame.state == g.callerObjectExecutionState() && frame.marks[3] == g.completedInitialSkips && (g.ctx == nil || g.ctx.Err() == nil)
	if stable {
		frame.effects = callerInitialObjectEffects{g.resolveCuts - frame.marks[0], g.initialSkips - frame.marks[1], g.objectCuts - frame.marks[2]}
		// Полные ответы по-прежнему принадлежат обычному memo. Здесь только partial,
		// без completed credits и без подмены реально невыполненных work counters.
		stable = frame.effects.cuts != frame.effects.skips
	}
	if stable && len(values) <= (callerObjectExecutionValues-frame.units)/callerOriginValueUnits {
		units := len(values) * callerOriginValueUnits
		// Публикуемый frame пока не является жертвой, а scope удерживается owner.
		if c.admitCallerOrigin(g, 0, units) {
			c.weight += units
			g.work.ObjectExecutionPeakValues = max(g.work.ObjectExecutionPeakValues, c.weight)
			frame.units += units
			frame.values = callerExecutionSlice(values)
			frame.unknown, frame.retained, frame.holdsScope = unknown, true, true
			frame.replayIdentity = c.nextCallerOriginReplayIdentity()
			frame.scope.references++
			frame.bucket = c.callerOriginBucket(frame.key, frame.scope, frame.state, frame.ctx)
			frame.bucketNext = c.originIndex.buckets[frame.bucket]
			c.originIndex.buckets[frame.bucket] = frame
			g.work.OriginTransferStores++
			return
		}
		g.work.OriginTransferCapacityFallbacks++
	}
	g.work.OriginTransferRejected++
	if c.graph == nil {
		// B1 сохраняет весь старый physical account до idle reset. Не оставляем
		// ссылок на завершившийся стек или mutable seen, но узлы остаются учтёнными.
		frame.scope, frame.ctx = nil, nil
		return
	}
	c.releaseCallerOrigin(g, frame)
}

func (c *callerObjectExecutions) releaseCallerOrigin(g *callerGraph, frame *callerOriginRecord) {
	if frame.previous == nil {
		c.originRecords = frame.next
	} else {
		frame.previous.next = frame.next
	}
	if frame.next == nil {
		c.originIndex.oldest = frame.previous
	} else {
		frame.next.previous = frame.previous
	}
	if frame.retained {
		slot := &c.originIndex.buckets[frame.bucket]
		for *slot != frame {
			slot = &(*slot).bucketNext
		}
		*slot = frame.bucketNext
		frame.bucketNext = nil
	}
	if frame.holdsScope {
		c.releaseScope(g, frame.scope)
	}
	c.entries -= 1 + frame.count
	c.weight -= frame.units
	// Выданный immutable result не очищается. Удаляем только ссылки кеша.
	frame.next, frame.previous, frame.scope, frame.dependencies, frame.values, frame.ctx = nil, nil, nil, nil, nil, nil
	frame.replayIdentity, frame.dependencyMask = 0, 0
	frame.callerOriginProof = nil
	c.releaseCallerOriginHeader()
}

func (c *callerObjectExecutions) evictCallerOrigin(g *callerGraph) bool {
	if c.originIndex == nil {
		return false
	}
	// Как и раньше, вытесняется самый старый допустимый кадр по порядку
	// создания, даже если вложенный кадр завершился раньше родителя.
	for record := c.originIndex.oldest; record != nil; record = record.previous {
		if record.retained && !record.live && record.pins == 0 && record.owner == nil && record.parent == nil {
			c.releaseCallerOrigin(g, record)
			g.work.OriginTransferEvictions++
			return true
		}
	}
	return false
}

func (c *callerObjectExecutions) retireCallerOrigins(g *callerGraph) {
	for record := c.originRecords; record != nil; {
		next := record.next
		if record.retained && record.pins == 0 && record.state != g.callerObjectExecutionState() {
			c.releaseCallerOrigin(g, record)
		}
		record = next
	}
}
