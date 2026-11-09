// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// register_resource_redelivery_test.go — контракт цены производителя для
// RegisterResource при ДУБЛИРУЮЩЕЙ доставке каждого потребителя.
//
// ДУБЛИРОВАНИЕ. Каждое создание ресурса в vpc/compute/nlb/storage/registry выпускает
// намерение регистрации в собственный fga_register_outbox сервиса ВНУТРИ транзакции записи и,
// после фиксации, ТАКЖЕ синхронно вызывает iam.RegisterResource с тем же намерением.
// Асинхронный обработчик регистраций затем доставляет и постоянную строку. Поэтому iam получает
// каждую регистрацию ДВАЖДЫ и до этой проверки выполнял ПОЛНУЮ материализацию
// оба раза: UPSERT зеркала, постановку кортежа владельца и события сведения, а также
// синхронный прямой проход по всем совпавшим выдачам. На стенде измерены
// два побайтово одинаковых пакета fga_outbox по 27 строк с интервалом 6,7 мс для одной созданной
// сети; 2,21 строки outbox на различный кортеж по всей таблице.
//
// КООРДИНАЦИЯ. Два пути уже несут различитель — монотонный
// source_version. Синхронный регистратор ставит time.Now() ПОСЛЕ фиксации; обработчик
// воспроизводит версию, поставленную БД ВНУТРИ транзакции записи, то есть строго раньше.
// UPSERT зеркала уже защищён условием `WHERE resource_mirror.source_version <
// EXCLUDED.source_version`, поэтому повтор обработчика обновляет НОЛЬ строк: это уже
// обнаруженное отсутствие изменения, чей результат сценарий отбрасывал. Чтение этого результата
// и пропуск последующей работы устраняют дефект.
//
// ПОЧЕМУ ТАК, А НЕ УСТРАНЕНИЕМ ПОВТОРОВ ОЧЕРЕДИ. Схлопывание неотправленных строк outbox по (тип события, данные)
// молча теряет повторную выдачу: выдача → отзыв → выдача превращается в выдача → отзыв,
// теряя выдачу. Проверка опирается на ПРИМЕНЁННОЕ СОСТОЯНИЕ и МОНОТОННУЮ версию, а не содержимое
// очереди, поэтому более поздняя регистрация всегда несёт новую версию (отзыв же
// удаляет строку зеркала целиком) и никогда не проглатывается — закреплено ниже.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
)

// ── Двойники, моделирующие монотонное зеркало ────────────────────────────────

// versionedMirror моделирует монотонную защиту UPSERT kaname.resource_mirror: строка
// пишется, лишь когда входящий source_version СТРОГО новее сохранённого,
// а механизм выпуска сообщает, изменилось ли что-нибудь.
type versionedMirror struct {
	noDescendants
	mu       sync.Mutex
	stored   map[string]time.Time
	upserts  int // Вызовы UpsertTx.
	deletes  int // Вызовы DeleteTx.
	mutated  int // Вызовы, действительно изменившие строку.
	labelsOf map[string]map[string]string
}

func newVersionedMirror() *versionedMirror {
	return &versionedMirror{stored: map[string]time.Time{}, labelsOf: map[string]map[string]string{}}
}

func (m *versionedMirror) UpsertTx(_ context.Context, _ service.Tx, row service.ResourceMirrorRow) (bool, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upserts++
	key := row.ObjectType + ":" + row.ObjectID
	prev, exists := m.stored[key]
	if exists && !row.SourceVersion.After(prev) {
		return false, false, nil // Устаревший/равный повтор — обновлено 0 строк.
	}
	// projectionUnchanged: запись продвинула лишь версию. Эти случаи меняют только метки,
	// поэтому двойник сравнивает их (SQL-оператор также сравнивает
	// родительскую область — см. resource_mirror.UpsertTx).
	unchanged := exists && sameStringMap(m.labelsOf[key], row.Labels)
	m.stored[key] = row.SourceVersion
	m.labelsOf[key] = row.Labels
	m.mutated++
	return true, unchanged, nil
}

// sameStringMap — равенство двух карт меток как множеств.
func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

func (m *versionedMirror) DeleteTx(_ context.Context, _ service.Tx, ot, oid string, tombstone time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes++
	key := ot + ":" + oid
	if prev, exists := m.stored[key]; exists && !prev.After(tombstone) {
		delete(m.stored, key)
		delete(m.labelsOf, key)
		m.mutated++
		return true, nil
	}
	return false, nil
}

// countingEmitter считает строки кортежей владельца, поставленные в fga_outbox.
type countingEmitter struct {
	mu      sync.Mutex
	writes  int
	deletes int
}

func (e *countingEmitter) EmitOrderedWriteTx(_ context.Context, _ service.Tx, ts []service.RelationTuple, _ time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.writes += len(ts)
	return nil
}

func (e *countingEmitter) EmitOrderedDeleteTx(_ context.Context, _ service.Tx, ts []service.RelationTuple, _ time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.deletes += len(ts)
	return nil
}

// countingReconcileEvents считает постановки в resource_reconcile_outbox.
type countingReconcileEvents struct {
	mu     sync.Mutex
	events []string // eventType
}

func (r *countingReconcileEvents) EmitTx(_ context.Context, _ service.Tx, eventType, _, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, eventType)
	return nil
}

func (r *countingReconcileEvents) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

// versionedReq — registerInput с явными source_version и метками.
type versionedReq struct {
	subject, relation, object string
	labels                    map[string]string
	version                   time.Time
}

func (r *versionedReq) GetSubjectId() string { return r.subject }
func (r *versionedReq) GetRelation() string  { return r.relation }
func (r *versionedReq) GetObject() string    { return r.object }
func (r *versionedReq) GetSourceVersion() *timestamppb.Timestamp {
	return timestamppb.New(r.version)
}
func (r *versionedReq) GetLabels() map[string]string { return r.labels }
func (r *versionedReq) GetParentProjectId() string   { return "prj-1" }
func (r *versionedReq) GetParentAccountId() string   { return "acc-1" }
func (r *versionedReq) GetParentChain() []string     { return nil }

type redeliveryRig struct {
	uc      *RegisterResourceUseCase
	mirror  *versionedMirror
	emitter *countingEmitter
	events  *countingReconcileEvents
	recon   *smObjectReconciler
}

func newRedeliveryRig() *redeliveryRig {
	m := newVersionedMirror()
	e := &countingEmitter{}
	ev := &countingReconcileEvents{}
	rec := &smObjectReconciler{}
	uc := NewRegisterResourceUseCase(e, m, &smTxBeginner{}, seededCatalogTypes{}, &recordingPublisher{}, &recordingWithdrawal{}, noAudit{}, unitScopes()).WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "vpc"}).
		WithReconcile(ev).
		WithObjectReconciler(rec, nil)
	return &redeliveryRig{uc: uc, mirror: m, emitter: e, events: ev, recon: rec}
}

// TestRegisterResource_DrainerReplay_DoesNoDuplicateWork — основной контракт. Синхронный
// регистратор доставляет первым с версией часов после фиксации; обработчик повторяет
// ту же регистрацию с версией БД, поставленной внутри транзакции записи (строго
// раньше). Повтор должен распознаваться как отсутствие изменения: ни строки кортежа владельца,
// ни события сведения, ни веера прямого прохода.
//
// До проверки КРАСНО: сценарий отбрасывал результат UPSERT зеркала и повторял
// всю материализацию — 2 строки кортежей, 2 события сведения, 2 прямых прохода.
func TestRegisterResource_DrainerReplay_DoesNoDuplicateWork(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()

	inTx := time.Now()                           // Поставлена БД внутри транзакции записи производителя.
	postCommit := inTx.Add(3 * time.Millisecond) // Поставлена синхронным регистратором после фиксации.

	// (1) Доставка синхронного регистратора — она выполняет работу.
	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "gold"}, version: postCommit,
	}))
	require.Equal(t, 1, rig.emitter.writes, "the first delivery enqueues the owner tuple")
	require.Equal(t, 1, rig.events.count(), "the first delivery enqueues the reconcile event")
	require.Len(t, rig.recon.snapshot(), 1, "the first delivery drives the forward reconcile")

	// (2) Повтор обработчиком ТОЙ ЖЕ регистрации с более ранней
	// версией из транзакции записи. Ресурс никак не изменился.
	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "gold"}, version: inTx,
	}))

	assert.Equal(t, 1, rig.emitter.writes,
		"a replay that changed no mirror row must not enqueue the owner tuple again")
	assert.Equal(t, 1, rig.events.count(),
		"a replay that changed no mirror row must not enqueue another reconcile event")
	assert.Len(t, rig.recon.snapshot(), 1,
		"a replay that changed no mirror row must not re-run the forward reconcile fan-out")
	assert.Equal(t, 1, rig.mirror.mutated, "exactly one delivery mutated the mirror")
}

// TestRegisterResource_IdenticalReplay_DoesNoDuplicateWork — тот же контракт для
// точно равной версии (повторная доставка той же строки хотя бы один раз, например
// повтор обработчика после временной ошибки): равная не новее, значит изменения нет.
func TestRegisterResource_IdenticalReplay_DoesNoDuplicateWork(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()
	v := time.Now()

	req := func() *versionedReq {
		return &versionedReq{
			subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
			labels: map[string]string{"tier": "gold"}, version: v,
		}
	}
	require.NoError(t, rig.uc.Register(ctx, req()))
	require.NoError(t, rig.uc.Register(ctx, req()))
	require.NoError(t, rig.uc.Register(ctx, req()))

	assert.Equal(t, 1, rig.emitter.writes, "three identical deliveries do the work once")
	assert.Equal(t, 1, rig.events.count(), "three identical deliveries enqueue one reconcile event")
	assert.Len(t, rig.recon.snapshot(), 1, "three identical deliveries drive one forward reconcile")
}

// TestRegisterResource_NewerVersion_StillMaterializes — проверка не должна проглатывать настоящее
// изменение. UPDATE меток повторно регистрирует объект с НОВЕЙШЕЙ версией; путь повторной
// материализации (закрытый дефект отзыва) должен срабатывать целиком.
func TestRegisterResource_NewerVersion_StillMaterializes(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()
	v1 := time.Now()

	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "gold"}, version: v1,
	}))
	// UPDATE меток — метка совпадения выдачи снята. Это ОБЯЗАНО вызвать повторную материализацию,
	// чтобы запущенный проход сведения отозвал больше не совпадающую выдачу.
	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "bronze"}, version: v1.Add(time.Second),
	}))

	assert.Equal(t, 2, rig.emitter.writes, "a newer version re-enqueues the owner tuple")
	assert.Equal(t, 2, rig.events.count(), "a newer version enqueues another reconcile event")
	assert.Len(t, rig.recon.snapshot(), 2, "a newer version re-runs the forward reconcile")
}

// TestRegisterResource_GrantRevokeGrant_NotCollapsed — проверка против ловушки на
// границе производителя. Ловушка очевидного устранения повторов — схлопнуть
// выдача → отзыв → выдача в выдача → отзыв. Здесь ключ — МОНОТОННАЯ
// версия (а снятие регистрации удаляет строку зеркала целиком), а не равенство данных,
// поэтому вторая выдача всегда материализуется.
func TestRegisterResource_GrantRevokeGrant_NotCollapsed(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()
	base := time.Now()

	// ВЫДАЧА.
	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "gold"}, version: base,
	}))
	// ОТЗЫВ (снятие регистрации — ресурс удалён).
	require.NoError(t, rig.uc.Unregister(ctx, &unregReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		version: base.Add(time.Second),
	}))
	require.Equal(t, 1, rig.emitter.deletes, "the unregister enqueues the tuple delete")

	// ПОВТОРНАЯ ВЫДАЧА — заново созданный ресурс с теми же координатами идентичности.
	// Устранение повторов производителя НЕ должно проглотить её.
	require.NoError(t, rig.uc.Register(ctx, &versionedReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		labels: map[string]string{"tier": "gold"}, version: base.Add(2 * time.Second),
	}))

	assert.Equal(t, 2, rig.emitter.writes,
		"the re-grant after a revoke must be re-emitted — never collapsed into grant → revoke")
	// Три прохода, по одному на шаг: обе выдачи И промежуточный отзыв выполняют
	// материализацию в процессе. Проход отзыва выводит снятие из
	// критического пути очереди сведения (см. unregister_resource_sync_revoke_test.go);
	// прежде последовательность давала два прохода, а удаление среднего шага ждало
	// обработчика.
	assert.Len(t, rig.recon.snapshot(), 3,
		"grant, revoke and re-grant each drive their own post-commit pass")
}

// TestRegisterResource_UnregisterAlwaysMaterializes — отзывы никогда не отсекаются. Снятие
// регистрации всегда ставит удаление кортежа и событие сведения, даже если
// строка зеркала уже исчезла: проглоченный отзыв — избыточная выдача, асимметрия
// намеренна (отказ по умолчанию — цена сокращается только на пути выдачи).
func TestRegisterResource_UnregisterAlwaysMaterializes(t *testing.T) {
	rig := newRedeliveryRig()
	ctx := context.Background()
	v := time.Now()

	require.NoError(t, rig.uc.Unregister(ctx, &unregReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1", version: v,
	}))
	require.NoError(t, rig.uc.Unregister(ctx, &unregReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1", version: v,
	}))

	assert.Equal(t, 2, rig.emitter.deletes, "every unregister enqueues the tuple delete")
	assert.Equal(t, 2, rig.events.count(), "every unregister enqueues the reconcile event")
}

// unregReq удовлетворяет unregisterInput.
type unregReq struct {
	subject, relation, object string
	version                   time.Time
}

func (r *unregReq) GetSubjectId() string { return r.subject }
func (r *unregReq) GetRelation() string  { return r.relation }
func (r *unregReq) GetObject() string    { return r.object }
func (r *unregReq) GetSourceVersion() *timestamppb.Timestamp {
	return timestamppb.New(r.version)
}

// TestRegisterResource_UnversionedProducer_IsNeverGated — проверка требует положительного
// доказательства повторной доставки, которого производитель без версии не предоставляет.
//
// Отсутствующий source_version отображается в '-infinity', проигрывающий КАЖДОЕ монотонное
// сравнение, поэтому после первой записи регистрации сообщают `changed = false`
// по причине, не связанной с повторной доставкой. Отсечение здесь подавило бы настоящую
// материализацию и отправило вызывающего в асинхронную очередь, расширяя окно чтения собственных
// записей вместо какой-либо экономии.
//
// Это наблюдалось: синхронный регистратор registry не передаёт source_version, и
// его отсечение остановило набор registry-redesign на живом стенде (6,8с → >10мин повторов)
// до добавления этой защиты.
func TestRegisterResource_UnversionedProducer_IsNeverGated(t *testing.T) {
	rig := newRedeliveryRig()
	rig.uc.WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "registry"})
	ctx := context.Background()

	// Производитель без версии: source_version — нулевое время ⇒ '-infinity'.
	unversioned := func() *versionedReq {
		return &versionedReq{
			subject: "project:prj-1", relation: "project", object: "registry_registry:rep-1",
			labels: map[string]string{"tier": "gold"}, version: time.Time{},
		}
	}
	for i := 0; i < 3; i++ {
		require.NoError(t, rig.uc.Register(ctx, unversioned()))
	}

	assert.Equal(t, 3, rig.emitter.writes,
		"an unversioned register must always enqueue the owner tuple — '-infinity' is not proof of redelivery")
	assert.Equal(t, 3, rig.events.count(),
		"an unversioned register must always enqueue the reconcile event")
	assert.Len(t, rig.recon.snapshot(), 3,
		"an unversioned register must always drive the forward reconcile (its sync fast path)")
}
