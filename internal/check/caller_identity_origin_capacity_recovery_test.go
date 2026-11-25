// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"slices"
	"testing"
)

func TestCallerIdentityOriginTransferCapacityRecovery(t *testing.T) {
	p, root, _, _ := callerOriginTransferProgram(t, 4)
	g, original := callerOriginTransferPair(t, p, root)
	c := g.objectExecutions
	owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
	if owner == nil {
		t.Fatal("real owner admission failed")
	}
	parent := g.beginCallerOriginFrame(owner, callerResolveKeyFor(root, false))
	if parent == nil {
		t.Fatal("real parent admission failed")
	}
	var pressure []*callerOriginOwner
	defer func() {
		for i := len(pressure) - 1; i >= 0; i-- {
			if pressure[i].live {
				g.endCallerOrigin(pressure[i])
			}
		}
		if parent.live {
			c.rejectCallerOriginFrame(parent)
			g.endCallerOriginFrame(owner, parent, nil, true)
		}
		if owner.live {
			g.endCallerOrigin(owner)
		}
	}()
	for {
		next := g.beginCallerOrigin(map[callerResolveKey]bool{})
		if next == nil {
			break
		}
		pressure = append(pressure, next)
	}
	observe := func() callerOriginObservation {
		marks, raw := callerReuseMarks(g), g.work.ResolveEvaluations
		values, unknown := g.resolveOwned(root, false, owner.seen, owner)
		return callerOriginObservation{slices.Clone(values), unknown, callerReuseDelta(g, marks), g.work.ResolveEvaluations - raw}
	}
	want := callerOriginObserve(original, root, map[callerResolveKey]bool{})
	blocked := observe()
	callerOriginSame(t, blocked, want)
	if blocked.raw != want.raw || blocked.raw == 0 || owner.bad || !parent.bad || parent.pushed || owner.capacityBoundary != parent {
		t.Fatal("capacity refusal changed raw traversal or permanently disabled its owner")
	}
	callerOriginAccount(t, c)
	entries, units := c.entries, c.weight
	for range 32 {
		if c.rejectCallerOriginAncestors(owner) != 0 || c.entries != entries || c.weight != units || owner.capacityBoundary != parent {
			t.Fatal("repeated refusal reclaimed paid storage twice")
		}
	}
	for i := len(pressure) - 1; i >= 0; i-- {
		g.endCallerOrigin(pressure[i])
	}
	stores, hits := g.work.OriginTransferStores, g.work.OriginTransferHits
	recovered := observe()
	callerOriginSame(t, recovered, want)
	if recovered.raw >= want.raw || g.work.OriginTransferStores <= stores || g.work.OriginTransferHits <= hits || owner.bad || owner.capacityBoundary != parent {
		t.Fatal("independent child certificates did not recover after pressure drained")
	}
	callerOriginAccount(t, c)
	hits = g.work.OriginTransferHits
	sibling := observe()
	callerOriginSame(t, sibling, want)
	if sibling.raw >= want.raw || g.work.OriginTransferHits <= hits {
		t.Fatal("later sibling did not reuse its paid exact certificate")
	}
	// Даже когда собственные потомки уже публикуются, старый родитель не
	// получает сертификат задним числом после реально неучтённого push.
	stores = g.work.OriginTransferStores
	g.endCallerOriginFrame(owner, parent, recovered.values, recovered.unknown)
	if parent.retained || g.work.OriginTransferStores != stores || owner.capacityBoundary != nil || owner.top != nil {
		t.Fatal("untracked child push became a published parent")
	}
	g.endCallerOrigin(owner)
	callerOriginAccount(t, c)
	for c.evictCallerOrigin(g) {
		callerOriginAccount(t, c)
	}
	if c.originOwners != nil || c.originRecords != nil || c.originAccount || c.active != 0 {
		t.Fatal("dependency release, unwind and eviction did not drain origin ownership")
	}
	g.resetCallerObjectExecutions()
	if g.objectExecutions == c || g.objectExecutions.entries != 0 || g.objectExecutions.weight != 0 {
		t.Fatal("idle reset retained an old physical account")
	}
}

func TestCallerIdentityOriginTransferRejectedDependencies(t *testing.T) {
	p, root, _, _ := callerOriginTransferProgram(t, 4)
	g, _ := callerOriginTransferPair(t, p, root)
	c := g.objectExecutions
	owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
	if owner == nil {
		t.Fatal("real owner admission failed")
	}
	defer g.endCallerOrigin(owner)
	frame := g.beginCallerOriginFrame(owner, callerResolveKeyFor(root, false))
	if frame == nil {
		t.Fatal("real frame admission failed")
	}
	defer g.endCallerOriginFrame(owner, frame, nil, true)
	key := callerResolveKeyFor(root, false)
	for i := 0; !frame.bad && i <= callerOriginDependencyLimit; i++ {
		key.source.tuple = i
		g.addCallerOriginDependency(owner, frame, key, false)
	}
	if !frame.bad || frame.dependencies != nil || frame.count != 0 || frame.units != callerOriginGuardUnits || frame.callerOriginProof != nil || owner.bad {
		t.Fatal("rejected certificate retained unusable dependencies or disabled owner")
	}
	callerOriginAccount(t, c)
	entries, units := c.entries, c.weight
	c.rejectCallerOriginFrame(frame)
	g.taintCallerOrigins()
	if c.entries != entries || c.weight != units {
		t.Fatal("double taint released dependencies twice")
	}
	callerOriginAccount(t, c)
}

func TestCallerIdentityOriginTransferRepeatedReadThroughLiveFrames(t *testing.T) {
	p, root, cycle, _ := callerOriginTransferProgram(t, 4)
	g, _ := callerOriginTransferPair(t, p, root)
	c := g.objectExecutions
	owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
	if owner == nil {
		t.Fatal("real owner admission failed")
	}
	defer g.endCallerOrigin(owner)
	parent := g.beginCallerOriginFrame(owner, callerResolveKeyFor(cycle, false))
	if parent == nil {
		t.Fatal("real parent admission failed")
	}
	defer g.endCallerOriginFrame(owner, parent, nil, true)
	key := callerResolveKeyFor(root, false)
	child := g.beginCallerOriginFrame(owner, key)
	if child == nil {
		t.Fatal("real child admission failed")
	}
	defer g.endCallerOriginFrame(owner, child, nil, true)
	self := child.dependencies
	if self == nil || self.propagated || parent.count != 1 {
		t.Fatal("seeding the child incorrectly propagated a dependency")
	}

	g.callerOriginRead(owner, key, false)
	ancestor := parent.dependencies
	if child.dependencies != self || !self.propagated || parent.count != 2 || ancestor == nil ||
		ancestor.key != key || ancestor.want || !ancestor.propagated {
		t.Fatal("the first observed read did not reach the parent exactly once")
	}
	entries, units := c.entries, c.weight
	reads := g.work.OriginTransferReads
	for range 8 {
		g.callerOriginRead(owner, key, false)
	}
	if child.dependencies != self || parent.dependencies != ancestor || c.entries != entries || c.weight != units ||
		g.work.OriginTransferReads != reads+8 {
		t.Fatal("repeated reads changed dependencies or their storage account")
	}
	callerOriginAccount(t, c)

	// Та же AST identity и receiver, но другой tuple: противоположный want
	// принадлежит другой зависимости и не отвергает исходный сертификат.
	twin := key
	twin.source.tuple++
	g.callerOriginRead(owner, twin, true)
	childTwin, parentTwin := child.dependencies, parent.dependencies
	if child.bad || parent.bad || child.count != 2 || parent.count != 3 ||
		childTwin == nil || childTwin.key != twin || !childTwin.want || childTwin.next != self ||
		parentTwin == nil || parentTwin.key != twin || !parentTwin.want || parentTwin.next != ancestor ||
		c.entries != entries+2 || c.weight != units+2*callerOriginDependencyUnits {
		t.Fatal("same-expression tuple twin merged dependencies or changed their order/account")
	}
	g.callerOriginRead(owner, twin, true)
	if child.dependencies != childTwin || parent.dependencies != parentTwin ||
		c.entries != entries+2 || c.weight != units+2*callerOriginDependencyUnits {
		t.Fatal("exact tuple twin duplicate changed dependencies or their storage account")
	}
	callerOriginAccount(t, c)

	g.callerOriginRead(owner, key, true)
	if !child.bad || !parent.bad || owner.bad || child.dependencies != nil || parent.dependencies != nil {
		t.Fatal("a contradictory read did not invalidate both frame certificates")
	}
	callerOriginAccount(t, c)
}

func TestCallerIdentityOriginTransferFrameReclaimsOnlyAncestors(t *testing.T) {
	p, root, _, _ := callerOriginTransferProgram(t, 4)
	g, _ := callerOriginTransferPair(t, p, root)
	c := g.objectExecutions
	owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
	if owner == nil {
		t.Fatal("real owner admission failed")
	}
	defer g.endCallerOrigin(owner)
	parent := g.beginCallerOriginFrame(owner, callerResolveKeyFor(root, false))
	if parent == nil {
		t.Fatal("real parent admission failed")
	}
	defer g.endCallerOriginFrame(owner, parent, nil, true)
	key := callerResolveKeyFor(root, false)
	for i := 0; i < callerOriginDependencyLimit-2; i++ {
		key.source.tuple = i
		g.addCallerOriginDependency(owner, parent, key, false)
	}
	if parent.bad || parent.count < callerOriginDependencyLimit-2 {
		t.Fatal("live parent did not reserve its real dependency payload")
	}
	var pressure []*callerOriginOwner
	defer func() {
		for i := len(pressure) - 1; i >= 0; i-- {
			g.endCallerOrigin(pressure[i])
		}
	}()
	for {
		next := g.beginCallerOrigin(map[callerResolveKey]bool{})
		if next == nil {
			break
		}
		pressure = append(pressure, next)
	}
	if c.traceRoom(1, callerOriginRecordUnits) {
		t.Fatal("live pressure did not force frame admission refusal")
	}
	entries, units, dependencies, active := c.entries, c.weight, parent.count, c.active
	child := g.beginCallerOriginFrame(owner, key)
	if child == nil {
		t.Fatal("bounded retry did not admit child after dropping ancestor dependencies")
	}
	defer g.endCallerOriginFrame(owner, child, nil, true)
	if owner.bad || !parent.bad || parent.count != 0 || parent.dependencies != nil || parent.units != callerOriginGuardUnits || parent.callerOriginProof != nil || owner.capacityBoundary != parent || child.bad || child.parent != parent || child.count != 1 {
		t.Fatal("retry discarded paid frames or failed to record independent child dependencies")
	}
	if c.entries != entries-dependencies+2 || c.weight != units-(callerOriginProofUnits+(dependencies-1)*callerOriginDependencyUnits)+callerOriginRecordUnits+callerOriginDependencyUnits || c.active != active+1 {
		t.Fatal("повторный допуск изменил память за пределами proof предков и нового child")
	}
	callerOriginAccount(t, c)
}

func TestCallerIdentityOriginTransferScopeMismatchRemainsTerminal(t *testing.T) {
	p, root, cycle, _ := callerOriginTransferProgram(t, 4)
	g, original := callerOriginTransferPair(t, p, root)
	owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
	if owner == nil {
		t.Fatal("real owner admission failed")
	}
	defer g.endCallerOrigin(owner)
	key := callerResolveKeyFor(cycle, true)
	before := g.containerScanning
	g.containerScanning = map[callerResolveKey]bool{key: false}
	g.restoreCallerOriginScope(owner)
	g.containerScanning = before
	g.restoreCallerOriginScope(owner)
	if !owner.bad {
		t.Fatal("scope mismatch healed after content was restored")
	}
	if g.beginCallerOriginFrame(owner, callerResolveKeyFor(root, false)) != nil {
		t.Fatal("terminal owner admitted a new certificate")
	}
	if _, hit := g.callerOriginHit(owner, callerResolveKeyFor(root, false)); hit {
		t.Fatal("terminal owner reused a certificate")
	}
	marks, raw := callerReuseMarks(g), g.work.ResolveEvaluations
	values, unknown := g.resolveOwned(root, false, owner.seen, owner)
	got := callerOriginObservation{slices.Clone(values), unknown, callerReuseDelta(g, marks), g.work.ResolveEvaluations - raw}
	want := callerOriginObserve(original, root, map[callerResolveKey]bool{})
	callerOriginSame(t, got, want)
	if !owner.bad {
		t.Fatal("independent nested work restored a terminal owner")
	}
	callerOriginAccount(t, g.objectExecutions)
}

// Источники проходят настоящий допуск, publication и pin/replay; тест не
// подменяет immutable certificate или зависимости уже опубликованной записи.
func TestCallerIdentityOriginTransferRepeatReplayWitness(t *testing.T) {
	p, root, cycle, field := callerOriginTransferProgram(t, 4)
	g, _ := callerOriginTransferPair(t, p, root)
	c := g.objectExecutions
	owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
	if owner == nil {
		t.Fatal("real owner admission failed")
	}
	defer g.endCallerOrigin(owner)
	extra := callerResolveKeyFor(field, false)
	publish := func(key callerResolveKey) *callerOriginRecord {
		t.Helper()
		r := g.beginCallerOriginFrame(owner, key)
		if r == nil {
			t.Fatal("real certificate admission failed")
		}
		g.addCallerOriginDependency(owner, r, extra, false)
		g.resolveCuts++
		g.endCallerOriginFrame(owner, r, nil, true)
		if !r.retained || r.replayIdentity == 0 {
			t.Fatal("real incomplete certificate publication failed")
		}
		return r
	}
	a := publish(callerResolveKeyFor(root, false))
	b := publish(callerResolveKeyFor(cycle, false))
	if a.replayIdentity == b.replayIdentity {
		t.Fatal("distinct certificates reused an identity")
	}
	owner.seen[a.key] = true
	if _, ok := g.callerOriginHit(owner, a.key); ok {
		t.Fatal("standalone lookup skipped the positive entry in seen")
	}
	cuts, hits := g.work.ResolveCycleCuts, g.work.OriginTransferHits
	if values, unknown := g.resolveOwned(root, false, owner.seen, owner); len(values) != 0 || unknown ||
		g.work.ResolveCycleCuts != cuts+1 || g.work.OriginTransferHits != hits {
		t.Fatal("resolver reused a certificate across a positive entry in seen")
	}
	delete(owner.seen, a.key)
	key := a.key
	key.source.tuple += 100
	parent := g.beginCallerOriginFrame(owner, key)
	if parent == nil {
		t.Fatal("real parent admission failed")
	}
	defer g.endCallerOriginFrame(owner, parent, nil, true)
	key.source.tuple++
	top := g.beginCallerOriginFrame(owner, key)
	if top == nil {
		t.Fatal("real receiver admission failed")
	}
	defer g.endCallerOriginFrame(owner, top, nil, true)
	hit := func(r *callerOriginRecord) {
		t.Helper()
		cuts, reads, hits := g.resolveCuts, g.work.OriginTransferReads, g.work.OriginTransferHits
		if owner.seen[r.key] {
			t.Fatal("fixture expected a negative entry in seen")
		}
		answer, ok := g.callerOriginHitWithEntryRead(owner, r.key, true)
		if !ok || !answer.unknown || len(answer.values) != 0 || r.pins != 0 ||
			g.resolveCuts != cuts+r.effects.cuts || g.work.OriginTransferReads != reads+r.count ||
			g.work.OriginTransferHits != hits+1 {
			t.Fatal("replay changed answer, pin, semantic effects or logical work")
		}
	}
	saved := g.work.OriginTransferRepeatReplays
	hit(a)
	if top.replayIdentity != a.replayIdentity || g.work.OriginTransferRepeatReplays != saved {
		t.Fatal("first transfer did not establish the exact witness")
	}
	dependencies, count, entries, units := top.dependencies, top.count, c.entries, c.weight
	hit(a)
	if g.work.OriginTransferRepeatReplays != saved+1 || top.dependencies != dependencies ||
		top.count != count || c.entries != entries || c.weight != units {
		t.Fatal("repeat did not save exactly one transfer or changed canonical storage")
	}
	// Свидетель не заменяет новое чтение внешнего seen.
	owner.seen[extra] = true
	if _, ok := g.callerOriginHitWithEntryRead(owner, a.key, true); ok || g.work.OriginTransferRepeatReplays != saved+1 {
		t.Fatal("witness bypassed current dependency validation")
	}
	delete(owner.seen, extra)
	hit(b)
	if top.replayIdentity != b.replayIdentity || g.work.OriginTransferRepeatReplays != saved+1 {
		t.Fatal("distinct certificate reused the previous witness")
	}
	hit(b)
	if g.work.OriginTransferRepeatReplays != saved+2 {
		t.Fatal("distinct certificate did not establish its own witness")
	}
	// Даже тот же полный ключ не заменяет identity конкретной публикации.
	replacement := publish(b.key)
	if replacement.replayIdentity == b.replayIdentity {
		t.Fatal("same-key publication reused the previous identity")
	}
	hit(replacement)
	if top.replayIdentity != replacement.replayIdentity || g.work.OriginTransferRepeatReplays != saved+2 {
		t.Fatal("same-key replacement reused the previous certificate witness")
	}
	b = replacement
	// Предок необратимо отвергнут. Обычный повтор уже остановился бы на
	// propagated зависимостях good top и тоже не вернул бы предку сертификат.
	c.rejectCallerOriginFrame(parent)
	hit(b)
	if !parent.bad || parent.count != 0 || g.work.OriginTransferRepeatReplays != saved+3 {
		t.Fatal("rejected ancestor changed established top propagation")
	}
	c.rejectCallerOriginFrame(top)
	if top.replayIdentity != 0 {
		t.Fatal("rejected receiver retained a replay witness")
	}
	hit(b)
	if g.work.OriginTransferRepeatReplays != saved+3 || top.count != 0 {
		t.Fatal("rejected receiver used a replay witness")
	}
	callerOriginAccount(t, c)
}

func TestCallerIdentityOriginTransferReplayIdentityExhaustion(t *testing.T) {
	p, root, _, _ := callerOriginTransferProgram(t, 4)
	g, _ := callerOriginTransferPair(t, p, root)
	c := g.objectExecutions
	owner := g.beginCallerOrigin(map[callerResolveKey]bool{})
	if owner == nil {
		t.Fatal("real owner admission failed")
	}
	c.originIndex.replaySequence = ^uint64(0) - 1
	if c.nextCallerOriginReplayIdentity() != ^uint64(0) ||
		c.nextCallerOriginReplayIdentity() != 0 || c.nextCallerOriginReplayIdentity() != 0 ||
		c.originIndex.replaySequence != ^uint64(0) {
		t.Fatal("exhausted replay identity wrapped or reused a value")
	}
	r := g.beginCallerOriginFrame(owner, callerResolveKeyFor(root, false))
	if r == nil {
		t.Fatal("real certificate admission failed")
	}
	g.resolveCuts++
	g.endCallerOriginFrame(owner, r, nil, true)
	if !r.retained || r.replayIdentity != 0 || c.originIndex.replaySequence != ^uint64(0) {
		t.Fatal("identity exhaustion changed publication or reset the live index sequence")
	}
	key := r.key
	key.source.tuple++
	top := g.beginCallerOriginFrame(owner, key)
	if top == nil {
		t.Fatal("real receiver admission failed")
	}
	saved := g.work.OriginTransferRepeatReplays
	for range 2 {
		if _, ok := g.callerOriginHit(owner, r.key); !ok {
			t.Fatal("exhaustion disabled the ordinary certificate replay")
		}
	}
	if top.replayIdentity != 0 || g.work.OriginTransferRepeatReplays != saved {
		t.Fatal("zero identity authorized replay omission")
	}
	callerOriginAccount(t, c)
	c.rejectCallerOriginFrame(top)
	g.endCallerOriginFrame(owner, top, nil, true)
	g.endCallerOrigin(owner)
	if !c.originAccount || c.originIndex == nil || c.originIndex.replaySequence != ^uint64(0) {
		t.Fatal("retained certificate lost its paid identity namespace")
	}
	for c.evictCallerOrigin(g) {
		callerOriginAccount(t, c)
	}
	if c.originAccount || c.originIndex != nil || c.originOwners != nil || c.originRecords != nil ||
		top.live || top.replayIdentity != 0 || r.replayIdentity != 0 {
		t.Fatal("identity namespace drained with a usable old witness or certificate")
	}
	// Новый namespace допустим только после полного исчезновения старых
	// owners и records. Повтор числового ID больше не может дать совпадение.
	owner = g.beginCallerOrigin(map[callerResolveKey]bool{})
	if owner == nil {
		t.Fatal("real owner readmission failed")
	}
	defer g.endCallerOrigin(owner)
	if c.originIndex.replaySequence != 0 {
		t.Fatal("fresh paid index inherited an exhausted namespace")
	}
	if _, ok := g.callerOriginHit(owner, r.key); ok {
		t.Fatal("fresh namespace found a certificate from the released index")
	}
	fresh := g.beginCallerOriginFrame(owner, r.key)
	if fresh == nil {
		t.Fatal("fresh certificate admission failed")
	}
	g.resolveCuts++
	g.endCallerOriginFrame(owner, fresh, nil, true)
	if !fresh.retained || fresh.replayIdentity != 1 {
		t.Fatal("fresh index did not start an independent identity sequence")
	}
	callerOriginAccount(t, c)
}
