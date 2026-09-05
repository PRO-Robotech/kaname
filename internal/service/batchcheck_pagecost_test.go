// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

import (
	"context"
	"sync"
	"testing"
	"time"
)

// latencyRelations — дверь решения, которая ТРАТИТ ВРЕМЯ на каждый вопрос и
// помнит, сколько вопросов было в полёте одновременно.
//
// Второе число — предмет этого файла, и счётчик вызовов его не видит: проход,
// разобранный последовательно, и проход, разобранный параллельно, задают ОДНО И
// ТО ЖЕ число вопросов и различаются лишь тем, сколько ждёт вызывающий.
//
// Полосы считаются РАЗДЕЛЬНО — пообъектная и пакетная, — потому что они отвечают
// на разные вопросы. Общая величина не отличила бы «однородная партия отвечена
// одним вопросом» от «партия не спросила вовсе», а именно это различие здесь и
// стало предметом: единица работы сменилась с пункта на ПРОГОН.
type latencyRelations struct {
	perCheck time.Duration

	mu        sync.Mutex
	perObject int
	batched   int
	inFlight  int
	maxInFly  int
}

// wait — одна задержка хранилища. Один вопрос — одна задержка, независимо от
// того, о скольких объектах он спрашивает: в этом и состоит разница полос.
func (m *latencyRelations) wait(ctx context.Context) {
	if m.perCheck <= 0 {
		return
	}
	select {
	case <-time.After(m.perCheck):
	case <-ctx.Done():
	}
}

func (m *latencyRelations) enter() {
	m.mu.Lock()
	m.inFlight++
	if m.inFlight > m.maxInFly {
		m.maxInFly = m.inFlight
	}
	m.mu.Unlock()
}

func (m *latencyRelations) leave() {
	m.mu.Lock()
	m.inFlight--
	m.mu.Unlock()
}

func (m *latencyRelations) CheckWithContext(ctx context.Context, _, _, _ string,
	_ map[string]any) (bool, error) {
	m.mu.Lock()
	m.perObject++
	m.mu.Unlock()
	m.enter()
	m.wait(ctx)
	m.leave()
	return false, nil // every per-object resolve denies: the worst case, and the shape a page filter hits
}

// BatchCheckWithContext — ПАКЕТНАЯ ДВЕРЬ К ТОМУ ЖЕ ОРАКУЛУ: отказ каждому.
//
// Задержка платится ОДИН раз на вопрос, а не на объект: в этом и состоит
// измеряемая разница. Дублёр, спавший бы по разу на объект, показал бы, что
// партия ничего не сберегла, — и был бы дублёром другого хранилища, не нашего.
func (m *latencyRelations) BatchCheckWithContext(ctx context.Context, _, _ string,
	objects []string, _ map[string]any) ([]bool, error) {
	m.mu.Lock()
	m.batched++
	m.mu.Unlock()
	m.enter()
	m.wait(ctx)
	m.leave()
	return make([]bool, len(objects)), nil
}

func (m *latencyRelations) ListSubjects(ctx context.Context, objectType, objectID, relation string, pageSize int, pageToken string) ([]string, string, error) {
	return nil, "", nil
}

func (m *latencyRelations) Sources(ctx context.Context, objectType, objectID, relation string) ([]string, error) {
	return nil, nil
}

// DirectRelations — диагностика хвоста текста отказа. Она НЕ учитывается
// счётчиками выше, и это осознанно: предмет файла — сколько вопросов о ВЕРДИКТЕ
// пачка задаёт одновременно, а не сколько всего обращений к хранилищу делает
// ответ. Считать её здесь значило бы смешать две величины и получить число,
// которого никто не измерял.
func (m *latencyRelations) DirectRelations(context.Context, string, string, string, int) ([]string, error) {
	return nil, nil
}

// DirectRelationsMany — та же диагностика о странице, и так же вне счёта.
func (m *latencyRelations) DirectRelationsMany(context.Context, string, string, []string, int) (
	map[string][]string, error) {
	return nil, nil
}

// snapshot — сколько вопросов о вердикте задано ВСЕГО и сколько их было в полёте
// одновременно. Полосы отдельно отдаёт `lanes`.
func (m *latencyRelations) snapshot() (calls, maxInFly int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.perObject + m.batched, m.maxInFly
}

func (m *latencyRelations) lanes() (perObject, batched int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.perObject, m.batched
}

// batchOfSameSubject builds the shape a sibling's page filter actually sends: one
// subject, one relation, many distinct objects — a slice of ONE page.
func batchOfSameSubject(n int) []CheckRequest {
	reqs := make([]CheckRequest, n)
	for i := range reqs {
		reqs[i] = CheckRequest{
			Subject:          "user:usr_tenant",
			Resource:         ResourceRef{Type: "vpc_network", ID: "net_" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26))},
			Action:           "vpc.networks.get",
			RequiredRelation: "v_get",
		}
	}
	return reqs
}

// TestBatchCheck_AUniformSliceIsOneQuestion — партия, какой её присылает фильтр
// списка соседа, стоит ОДИН вопрос хранилищу.
//
// Здесь стояло обратное утверждение — «один вопрос на пункт присущ предикату,
// и это НЕ то, что изменилось», — и рядом с ним арифметика ожидания, выведенная
// из той же посылки. Посылка была неверна: предикат пообъектен, а обращение к
// хранилищу пообъектным быть не обязано. Однородная партия (один субъект, одно
// отношение, один тип — форма страницы by construction) отвечается одним
// вопросом, и стенное время партии перестаёт зависеть от её длины.
//
// Арифметика печатается, а не утверждается как время: время зависит от машины, а
// предмет здесь — ЧИСЛО ВОПРОСОВ.
func TestBatchCheck_AUniformSliceIsOneQuestion(t *testing.T) {
	const (
		slice        = 100                     // the published cap siblings partition against
		perCheck     = 5 * time.Millisecond    // a deliberately OPTIMISTIC store latency
		callerBudget = 1000 * time.Millisecond // authzfilter.DefaultConfig().Timeout in vpc/compute/nlb/storage
	)

	// Предпосылка. Арифметика выведена из ОДНОГО числа, которое этому пакету не
	// принадлежит: контрактного предела партии, по которому режут соседи. Ввозить
	// его импортом нельзя (сервис не импортирует соседа), поэтому он
	// восстанавливается против самой проверки ниже — сменится предел, и разбор
	// придётся переделать, а не унаследовать молча.
	if _, err := (&AuthorizeService{}).BatchCheck(context.Background(), make([]CheckRequest, slice+1)); err == nil {
		t.Fatalf("предпосылка нарушена: партия из %d больше не отвергается, значит %d не тот "+
			"предел, по которому режут соседи, и арифметика этой пробы описывает не ту партию",
			slice+1, slice)
	}

	store := &latencyRelations{perCheck: perCheck}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store})

	start := time.Now()
	results, err := svc.BatchCheck(context.Background(), batchOfSameSubject(slice))
	wall := time.Since(start)
	if err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}
	if len(results) != slice {
		t.Fatalf("results: got %d want %d", len(results), slice)
	}

	perObject, batched := store.lanes()
	t.Logf("партия=%d | вопросов пообъектных=%d, пакетных=%d | задержка хранилища=%v | "+
		"стенное время=%v | бюджет вызывающего=%v",
		slice, perObject, batched, perCheck, wall.Round(time.Millisecond), callerBudget)
	t.Logf("пообъектная полоса стоила бы %v на партию и %v на страницу договора "+
		"(1000 идентификаторов = 10 партий)",
		time.Duration(slice)*perCheck, time.Duration(slice*10)*perCheck)

	// Объём осмотренного: проход, не дошедший до хранилища, удовлетворил бы любое
	// «не больше» тождественно.
	if batched+perObject == 0 {
		t.Fatalf("хранилище не спрошено ни разу: предмета замера нет")
	}
	if perObject != 0 {
		t.Fatalf("однородная партия задала %d ПООБЪЕКТНЫХ вопросов: партия существует по форме "+
			"и отсутствует по существу — каждый идентификатор уезжает отдельным вопросом",
			perObject)
	}
	if batched != 1 {
		t.Fatalf("однородная партия из %d задала %d пакетных вопросов вместо одного: набор "+
			"однороден by construction (один субъект, тип, отношение), и делить его не на чем",
			slice, batched)
	}
}

// batchOfRunsFromDistinctSubjects — партия, дающая МНОГО прогонов.
//
// Прогон — однородная часть партии, и разные субъекты дают разные прогоны. Это
// не гипотетическая форма: метод поддерживает смешанную партию явно, и ровно на
// ней предел одновременности имеет предмет.
func batchOfRunsFromDistinctSubjects(n int) []CheckRequest {
	return batchOfDistinctSubjects(n)
}

// TestBatchCheck_ResolvesItsRunsConcurrently — прогоны одного прохода не ждут
// друг друга.
//
// Единица сменилась (прогон вместо пункта), а довод — нет: бюджет вызывающего
// принадлежит ЗАПРОСУ. Смешанная партия даёт столько прогонов, сколько субъектов,
// и последовательный проход по ним стоил бы прогоны × время ответа хранилища —
// то самое ожидание, которое роняло ПОЛОЖИТЕЛЬНЫЙ список вызывающего в
// UNAVAILABLE.
//
// Свойство выражено наблюдаемой одновременностью, а не временем: время — величина
// машины, и утверждать её значило бы завести дрожащую пробу.
func TestBatchCheck_ResolvesItsRunsConcurrently(t *testing.T) {
	const (
		slice    = 100
		perCheck = 5 * time.Millisecond
	)
	if batchCheckParallelism <= 1 {
		t.Fatalf("предпосылка нарушена: batchCheckParallelism=%d одновременности не выражает",
			batchCheckParallelism)
	}

	store := &latencyRelations{perCheck: perCheck}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store})

	start := time.Now()
	if _, err := svc.BatchCheck(context.Background(), batchOfRunsFromDistinctSubjects(slice)); err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}
	wall := time.Since(start)

	calls, maxInFly := store.snapshot()
	perObject, batched := store.lanes()
	t.Logf("партия=%d различных субъектов | вопросов всего=%d (пообъектных %d, пакетных %d) | "+
		"в полёте одновременно=%d | стенное время=%v",
		slice, calls, perObject, batched, maxInFly, wall.Round(time.Millisecond))

	// Объём осмотренного: проход, не дошедший до хранилища, одновременности тоже
	// не покажет, и всё ниже выполнялось бы тождественно.
	if calls < 2 {
		t.Fatalf("хранилище спрошено %d раз(а) на %d различных субъектов — прогонов, чью "+
			"одновременность можно наблюдать, нет вовсе", calls, slice)
	}
	if maxInFly <= 1 {
		t.Fatalf("прогоны разбираются ПОСЛЕДОВАТЕЛЬНО (в полёте одновременно=%d): стенное время "+
			"прохода равно прогоны × задержка хранилища (%v здесь), а бюджет вызывающего на всю "+
			"партию — одна секунда. Партия не должна быть очередью.",
			maxInFly, wall.Round(time.Millisecond))
	}
}

// TestBatchCheck_RunConcurrencyIsBounded — ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к
// утверждению выше, и причина, по которой то утверждение нельзя удовлетворить
// неверной правкой.
//
// «Не очередь» не должно стать «горутина на прогон»: неограниченный веер выложил
// бы на хранилище всю страницу разом, а одновременные списки других вызывающих
// умножились бы друг на друга.
//
// Без этой пары соседнее утверждение читается как «чем больше одновременности,
// тем лучше» — и именно так ограниченный веер снимает следующий, кто захочет
// ускорить страницу.
func TestBatchCheck_RunConcurrencyIsBounded(t *testing.T) {
	const slice = 100

	store := &latencyRelations{perCheck: 2 * time.Millisecond}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: store})

	if _, err := svc.BatchCheck(context.Background(), batchOfRunsFromDistinctSubjects(slice)); err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}

	_, maxInFly := store.snapshot()
	t.Logf("партия=%d | в полёте одновременно=%d | объявленный предел=%d",
		slice, maxInFly, batchCheckParallelism)

	if maxInFly > batchCheckParallelism {
		t.Fatalf("BatchCheck выложил на хранилище %d вопросов разом при объявленном пределе %d. "+
			"Проход с горутиной на прогон отдаёт всю страницу одним всплеском, и одновременные "+
			"списки умножаются на него.", maxInFly, batchCheckParallelism)
	}
	if maxInFly <= 1 {
		t.Fatalf("в полёте одновременно=%d — предел ненаблюдаем, потому что одновременно ничего "+
			"не шло; этот контроль пуст, пока не держится соседнее свойство", maxInFly)
	}
}

// TestBatchCheck_ClusterAdminMemoStaysDedupedUnderConcurrency — the memo that makes
// a cluster-admin batch cost ONE super-gate question instead of one per item is
// shared mutable state across the pass. Resolving the pass concurrently is exactly
// what turns that sharing into a data race, so the property it encodes is re-asserted
// here under the concurrent path (and this file is run with -race).
//
// This is the "did the fix keep the earlier fix" check: the dedup was itself a
// measured improvement (TestAuthorize_BatchCheck_ClusterAdmin_SingleShortCircuit),
// and a concurrency change that silently restored one super-gate question per item
// would leave that test green while undoing its point.
func TestBatchCheck_ClusterAdminMemoStaysDedupedUnderConcurrency(t *testing.T) {
	const slice = 100

	store := &latencyRelations{perCheck: time.Millisecond}
	cl := &scClusterChecker{admins: map[string]bool{"user:usr_tenant": true}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations:           store,
		ClusterAdminChecker: cl,
	})

	results, err := svc.BatchCheck(context.Background(), batchOfSameSubject(slice))
	if err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}
	for i, r := range results {
		if !r.Allowed {
			t.Fatalf("item %d: cluster-admin must resolve via the super-gate; deny=%v", i, r.DenyReasons)
		}
	}
	storeCalls, _ := store.snapshot()
	t.Logf("партия=%d | вопросов о вердикте=%d | вопросов надзора=%d (мемоизирован: один на "+
		"СУБЪЕКТА, а не на пункт)", slice, storeCalls, cl.calls)
	// Объём осмотренного: надзор достижим ТОЛЬКО после отказа по объекту, поэтому
	// проход, не спросивший хранилище, не дошёл бы и до него — и «≤1» держалось бы
	// по неверной причине.
	//
	// Здесь стояло `storeCalls != slice`: величина была верна, пока однородная
	// партия стоила вопрос на пункт. Теперь она стоит ОДИН вопрос, и требование
	// ста сделало бы предпосылку невыполнимой — то есть проба падала бы на
	// достижении собственной цели.
	if storeCalls < 1 {
		t.Fatalf("хранилище не спрошено ни разу на партию из %d: надзор достижим только после "+
			"отказа по объекту, поэтому замер ниже был бы пуст", slice)
	}
	if cl.calls < 1 {
		t.Fatalf("super-gate was never asked (%d): the memo cannot be shown to dedupe a question "+
			"that was not asked", cl.calls)
	}
	if cl.calls > 1 {
		t.Fatalf("super-gate asked %d times for ONE subject; the per-pass memo must dedupe it to 1 "+
			"even when the pass is resolved concurrently", cl.calls)
	}
}

// latencyClusterChecker — a cluster-admin checker that TAKES TIME and records
// how many of its questions were ever in flight at once.
//
// The existing double counts calls only, which cannot see the property below: a
// memo that serialises every subject and a memo that resolves subjects in
// parallel issue the SAME number of super-gate questions and differ only in how
// long the pass takes.
type latencyClusterChecker struct {
	perCheck time.Duration
	admins   map[string]bool

	mu       sync.Mutex
	calls    int
	bySubj   map[string]int
	inFlight int
	maxInFly int
}

func (c *latencyClusterChecker) Check(_ context.Context, subject, _, _ string) (bool, error) {
	c.mu.Lock()
	c.calls++
	if c.bySubj == nil {
		c.bySubj = map[string]int{}
	}
	c.bySubj[subject]++
	c.inFlight++
	if c.inFlight > c.maxInFly {
		c.maxInFly = c.inFlight
	}
	c.mu.Unlock()

	if c.perCheck > 0 {
		time.Sleep(c.perCheck)
	}

	c.mu.Lock()
	c.inFlight--
	allowed := c.admins[subject]
	c.mu.Unlock()
	return allowed, nil
}

func (c *latencyClusterChecker) snapshot() (calls, maxInFly, maxPerSubject int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, n := range c.bySubj {
		if n > maxPerSubject {
			maxPerSubject = n
		}
	}
	return c.calls, c.maxInFly, maxPerSubject
}

// batchOfDistinctSubjects — a slice whose items name DIFFERENT subjects. The
// method supports this shape explicitly (its own comment says a mixed-subject
// batch stays correct), so it is not a hypothetical.
func batchOfDistinctSubjects(n int) []CheckRequest {
	reqs := make([]CheckRequest, n)
	for i := range reqs {
		reqs[i] = CheckRequest{
			Subject:          "user:usr_" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)),
			Resource:         ResourceRef{Type: "vpc_network", ID: "net_shared"},
			Action:           "vpc.networks.get",
			RequiredRelation: "v_get",
		}
	}
	return reqs
}

// TestBatchCheck_SuperGateDoesNotSerialiseDistinctSubjects — the pool survives a
// slice whose items name different subjects.
//
// The memo exists to ask the cluster-admin super-gate at most once per SUBJECT,
// and to do that it must hold its guard across the question — otherwise every
// worker that arrives before the first answer misses and asks again. Held as ONE
// guard for the whole pass, that correct requirement had a consequence its
// comment denied: on a mixed-subject slice the single lock was taken across a
// network call for every item in turn, so the bounded pool this method was given
// was defeated completely and the pass ran at parallelism one — the very failure
// the pool was added to remove, reintroduced one layer in.
//
// Two things are asserted together, because either alone is satisfiable by a
// broken implementation: the super-gate is still asked AT MOST ONCE PER SUBJECT
// (drop the memo and this fails), and questions for DIFFERENT subjects overlap
// (serialise the memo and this fails).
func TestBatchCheck_SuperGateDoesNotSerialiseDistinctSubjects(t *testing.T) {
	const slice = 100

	store := &latencyRelations{}
	cl := &latencyClusterChecker{perCheck: 5 * time.Millisecond, admins: map[string]bool{}}
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations:           store,
		ClusterAdminChecker: cl,
	})

	start := time.Now()
	if _, err := svc.BatchCheck(context.Background(), batchOfDistinctSubjects(slice)); err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}
	wall := time.Since(start)

	calls, maxInFly, maxPerSubject := cl.snapshot()
	storeCalls, _ := store.snapshot()
	t.Logf("slice=%d distinct subjects | store round-trips=%d | super-gate questions=%d "+
		"| max in flight=%d | max per subject=%d | wall=%s",
		slice, storeCalls, calls, maxInFly, maxPerSubject, wall.Round(time.Millisecond))

	// Volume examined: the super-gate is reached only after a per-object deny, so
	// a pass that asked nothing would satisfy every bound below for the wrong
	// reason.
	if storeCalls != slice {
		t.Fatalf("probe asked the store %d times for a %d-item slice — the measurement below "+
			"would be vacuous", storeCalls, slice)
	}
	if calls == 0 {
		t.Fatalf("super-gate was never asked: nothing about its concurrency can be shown")
	}
	if maxPerSubject > 1 {
		t.Errorf("super-gate asked %d times for ONE subject — the per-subject memo is gone, and "+
			"a same-subject slice would pay one super-gate question per item", maxPerSubject)
	}
	if maxInFly < 2 {
		t.Errorf("super-gate questions for %d DIFFERENT subjects never overlapped (max in flight=%d).\n"+
			"  The memo is serialising the whole pass across a network call, so the bounded pool "+
			"given to this method is defeated and the slice resolves at parallelism one — exactly "+
			"the wall-time failure the pool was added to remove.\n"+
			"  Guard per SUBJECT, not per pass: the dedup is a property of one subject's question.",
			slice, maxInFly)
	}
}
