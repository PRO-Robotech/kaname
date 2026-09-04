// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_iam

// register_resource_forward_route_test.go — КАКОЙ вход материализации выбирает
// кросс-сервисный путь регистрации, и почему это решает окно видимости.
//
// ПРЕДМЕТ. Каждая регистрация доезжает до iam ДВАЖДЫ: синхронный регистратор
// владельца штампует source_version временем ПОСЛЕ коммита, а at-least-once дренаж
// переигрывает версию, которую БД проставила ВНУТРИ writer-TX, то есть строго
// раньше. Порядок прибытия при этом ничем не закреплён. Когда первым приходит
// дренаж, вторая доставка несёт БОЛЕЕ НОВУЮ версию — монотонная стража зеркала её
// принимает, и прежний гейт повторной доставки (он смотрел только «изменилась ли
// строка») её не узнаёт. Дальше вторая доставка попадает в ОХРАНЯЕМЫЙ форвард,
// его страж видит уже материализованных членов (их записала первая доставка) и
// уводит объект в ПОЛНЫЙ пересчёт под EXCLUSIVE advisory-lock, общий для всех
// ресурсов аккаунта.
//
// ЧТО РАЗЛИЧАЕТ ЭТОТ НАБОР. Не «пришла ли регистрация повторно» (этого iam знать
// неоткуда), а «заменила ли она СОБОЙ ДРУГУЮ проекцию». Устаревшим член может стать
// только если у объекта изменилось то, по чему селекторы его выбирают — метки и
// родительская область. Байт-идентичная проекция ничего устареть не заставляет,
// значит удаляющий проход не нужен; изменившаяся — заставляет, значит нужен.
// Оба утверждения проверяются здесь, и второе — тот самый класс «аддитивный путь
// на правке = НЕПРИМЕНЁННЫЙ ОТЗЫВ ПРАВ», который проект уже ловил.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ── зеркало с монотонной стражей И сравнением проекции ──────────────────────

// projectionMirror моделирует kacho_iam.resource_mirror так, как его видит
// use-case: строка пишется, только если входящая source_version строго новее
// хранимой, и отдельно сообщается, что запись НЕ заменила проекцию — то есть
// продвинула версию, оставив parent-область и метки байт-в-байт прежними.
type projectionMirror struct {
	mu     sync.Mutex
	stored map[string]projectionRow
}

type projectionRow struct {
	version time.Time
	project string
	account string
	labels  map[string]string
}

func newProjectionMirror() *projectionMirror {
	return &projectionMirror{stored: map[string]projectionRow{}}
}

func sameLabels(a, b map[string]string) bool {
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

func (m *projectionMirror) UpsertTx(_ context.Context, _ service.Tx, row service.ResourceMirrorRow) (bool, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := row.ObjectType + ":" + row.ObjectID
	next := projectionRow{version: row.SourceVersion, project: row.ParentProjectID,
		account: row.ParentAccountID, labels: row.Labels}
	prev, exists := m.stored[key]
	if exists && !row.SourceVersion.After(prev.version) {
		return false, false, nil // не новее — строка не тронута
	}
	unchanged := exists && prev.project == next.project && prev.account == next.account &&
		sameLabels(prev.labels, next.labels)
	m.stored[key] = next
	return true, unchanged, nil
}

func (m *projectionMirror) DeleteTx(_ context.Context, _ service.Tx, ot, oid string, tombstone time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := ot + ":" + oid
	if prev, ok := m.stored[key]; ok && !prev.version.After(tombstone) {
		delete(m.stored, key)
	}
	return nil
}

// ── реконсайлер, воспроизводящий страж устаревших членов ────────────────────

// guardedReconciler моделирует ровно то, что делает reconcile.Reconciler:
// охраняемый вход читает уже материализованных членов объекта и, найдя их,
// уходит в ПОЛНЫЙ пересчёт под EXCLUSIVE-локом; вход «устареть нечему» этой
// проверки не делает и остаётся аддитивным.
type guardedReconciler struct {
	mu      sync.Mutex
	passes  []string // "additive" | "full-exclusive"
	members map[string]bool
}

func newGuardedReconciler() *guardedReconciler {
	return &guardedReconciler{members: map[string]bool{}}
}

func (r *guardedReconciler) ReconcileObjectForward(_ context.Context, ot, oid string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.members[ot+":"+oid] {
		r.passes = append(r.passes, "full-exclusive")
		return nil
	}
	r.members[ot+":"+oid] = true
	r.passes = append(r.passes, "additive")
	return nil
}

func (r *guardedReconciler) ReconcileObjectForwardNoStale(_ context.Context, ot, oid string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.members[ot+":"+oid] = true
	r.passes = append(r.passes, "additive")
	return nil
}

func (r *guardedReconciler) snapshotPasses() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.passes))
	copy(out, r.passes)
	return out
}

func newRouteRig() (*RegisterResourceUseCase, *guardedReconciler) {
	rec := newGuardedReconciler()
	uc := NewRegisterResourceUseCase(&countingEmitter{}, newProjectionMirror(), &smTxBeginner{}, seededCatalogTypes{}).
		WithReconcile(&countingReconcileEvents{}).
		WithObjectReconciler(rec, nil)
	return uc, rec
}

// routeReq — registerInput с явной версией, метками и родительской областью.
type routeReq struct {
	object  string
	project string
	account string
	labels  map[string]string
	version time.Time
}

func (r *routeReq) GetSubjectId() string { return "project:" + r.project }
func (r *routeReq) GetRelation() string  { return "project" }
func (r *routeReq) GetObject() string    { return r.object }
func (r *routeReq) GetSourceVersion() *timestamppb.Timestamp {
	return timestamppb.New(r.version)
}
func (r *routeReq) GetLabels() map[string]string { return r.labels }
func (r *routeReq) GetParentProjectId() string   { return r.project }
func (r *routeReq) GetParentAccountId() string   { return r.account }
func (r *routeReq) GetParentChain() []string     { return nil }

// TestRegisterResource_DrainerWonTheRace_StaysOnAdditivePath — ГОНКА, из-за которой
// окно материализации выходило за клиентский бюджет чтения-своих-записей.
//
// Дренаж доставил первым (версия из writer-TX), синхронный регистратор — вторым, с
// более новой версией и БАЙТ-ИДЕНТИЧНОЙ проекцией. Вторая доставка обязана остаться
// на аддитивном пути: заменять она ничего не заменила, устареть нечему.
//
// КРАСНЫЙ до правки: use-case звал охраняемый вход, тот видел членов, записанных
// первой доставкой, и уводил объект в полный пересчёт под EXCLUSIVE-локом, общим
// для всех ресурсов аккаунта.
func TestRegisterResource_DrainerWonTheRace_StaysOnAdditivePath(t *testing.T) {
	uc, rec := newRouteRig()
	ctx := context.Background()
	inTx := time.Now()

	base := func(v time.Time) *routeReq {
		return &routeReq{object: "vpc_network:net-1", project: "prj-1", account: "acc-1",
			labels: map[string]string{"tier": "gold"}, version: v}
	}

	// (1) дренаж — версия, штампованная ВНУТРИ writer-TX.
	require.NoError(t, uc.Register(ctx, base(inTx)))
	require.Equal(t, []string{"additive"}, rec.snapshotPasses(),
		"первая доставка материализует объект аддитивно")

	// (2) синхронный регистратор — версия ПОСЛЕ коммита, строго новее, проекция та же.
	require.NoError(t, uc.Register(ctx, base(inTx.Add(3*time.Millisecond))))

	assert.Equal(t, []string{"additive", "additive"}, rec.snapshotPasses(),
		"доставка, не заменившая проекцию, обязана остаться на аддитивном пути: "+
			"полный пересчёт берёт EXCLUSIVE-лок, общий для всех ресурсов аккаунта, "+
			"и именно он растягивает окно видимости за клиентский бюджет")
}

// TestRegisterResource_LabelUpdate_KeepsDeleteStalePath — ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ
// КОНТРОЛЬ и одновременно защита от класса «аддитивный путь на правке =
// НЕПРИМЕНЁННЫЙ ОТЗЫВ ПРАВ».
//
// Правка меток МЕНЯЕТ проекцию: грант, выданный по прежней метке, перестаёт
// совпадать и обязан быть снят. Снять его умеет только полный проход, поэтому
// послабление предыдущего теста не имеет права распространиться сюда.
func TestRegisterResource_LabelUpdate_KeepsDeleteStalePath(t *testing.T) {
	uc, rec := newRouteRig()
	ctx := context.Background()
	v1 := time.Now()

	require.NoError(t, uc.Register(ctx, &routeReq{object: "vpc_network:net-1",
		project: "prj-1", account: "acc-1",
		labels: map[string]string{"tier": "gold"}, version: v1}))
	require.Equal(t, []string{"additive"}, rec.snapshotPasses())

	// Метка, по которой выдан грант, снята — проекция ЗАМЕНЕНА другой.
	require.NoError(t, uc.Register(ctx, &routeReq{object: "vpc_network:net-1",
		project: "prj-1", account: "acc-1",
		labels: map[string]string{"tier": "bronze"}, version: v1.Add(time.Second)}))

	assert.Equal(t, []string{"additive", "full-exclusive"}, rec.snapshotPasses(),
		"правка, заменившая проекцию, обязана идти удаляющим проходом — иначе "+
			"переставший совпадать грант остаётся стоять, то есть отзыв прав не применён")
}

// TestRegisterResource_ParentScopeMove_KeepsDeleteStalePath — та же граница по ВТОРОЙ
// оси проекции. Селекторы выбирают объект и по вложенности, поэтому смена
// родительского проекта делает прежние гранты устаревшими ровно так же, как смена
// метки, и обязана идти удаляющим проходом.
func TestRegisterResource_ParentScopeMove_KeepsDeleteStalePath(t *testing.T) {
	uc, rec := newRouteRig()
	ctx := context.Background()
	v1 := time.Now()

	require.NoError(t, uc.Register(ctx, &routeReq{object: "vpc_network:net-1",
		project: "prj-1", account: "acc-1",
		labels: map[string]string{"tier": "gold"}, version: v1}))
	require.NoError(t, uc.Register(ctx, &routeReq{object: "vpc_network:net-1",
		project: "prj-2", account: "acc-2",
		labels: map[string]string{"tier": "gold"}, version: v1.Add(time.Second)}))

	assert.Equal(t, []string{"additive", "full-exclusive"}, rec.snapshotPasses(),
		"смена родительской области — тоже замена проекции: гранты прежней области "+
			"обязаны сниматься удаляющим проходом")
}

// TestRegisterResource_Unregister_AlwaysKeepsDeleteStalePath — снятие регистрации
// материализуется ТЕМ ЖЕ удаляющим проходом и никогда не получает послабления:
// именно он выводит объект в пустое желаемое множество и снимает его кортежи.
func TestRegisterResource_Unregister_AlwaysKeepsDeleteStalePath(t *testing.T) {
	uc, rec := newRouteRig()
	ctx := context.Background()
	v1 := time.Now()

	require.NoError(t, uc.Register(ctx, &routeReq{object: "vpc_network:net-1",
		project: "prj-1", account: "acc-1",
		labels: map[string]string{"tier": "gold"}, version: v1}))
	require.NoError(t, uc.Unregister(ctx, &unregReq{
		subject: "project:prj-1", relation: "project", object: "vpc_network:net-1",
		version: v1.Add(time.Second)}))

	assert.Equal(t, []string{"additive", "full-exclusive"}, rec.snapshotPasses(),
		"снятие регистрации обязано идти удаляющим проходом — он и есть отзыв")
}

// ── наблюдаемость пост-коммитных ускорителей ────────────────────────────────

// recordingMetrics — фейковый приёмник счётчика.
type recordingMetrics struct {
	mu   sync.Mutex
	seen []string // "<step>/<outcome>"
}

func (m *recordingMetrics) ObserveRegisterPostCommit(step, outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen = append(m.seen, step+"/"+outcome)
}

func (m *recordingMetrics) snapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.seen))
	copy(out, m.seen)
	return out
}

// failingReconciler — оба входа отказывают, чтобы отличить «ни разу не отказал» от
// «ни разу не исполнялся».
type failingReconciler struct{ err error }

func (r *failingReconciler) ReconcileObjectForward(context.Context, string, string) error {
	return r.err
}
func (r *failingReconciler) ReconcileObjectForwardNoStale(context.Context, string, string) error {
	return r.err
}

// TestRegisterResource_PostCommitSteps_AreCounted_RunsAndFailures — пост-коммитные
// ускорители по построению не роняют Register: они стоят перед durable-очередью,
// поэтому их отказ стоит задержки, а не изменения. Ровно это и делает сломанный
// ускоритель невидимым — один WARN и продукт, который работает медленнее, всегда.
// Счётчик обязан фиксировать И запуск, И исход: иначе «ни разу не отказал»
// неотличимо от «ни разу не исполнялся» (security.md, инвариант 8).
//
// Здесь же проверяется, что метка шага называет ВЫБРАННЫЙ путь материализации —
// иначе регресс, загоняющий каждую регистрацию обратно на EXCLUSIVE-пересчёт,
// виден только как задержка, которую надо заметить.
func TestRegisterResource_PostCommitSteps_AreCounted_RunsAndFailures(t *testing.T) {
	inTx := time.Now()
	base := func(v time.Time) *routeReq {
		return &routeReq{object: "vpc_network:net-1", project: "prj-1", account: "acc-1",
			labels: map[string]string{"tier": "gold"}, version: v}
	}

	t.Run("успешные запуски посчитаны, и метка называет выбранный путь", func(t *testing.T) {
		rec := newGuardedReconciler()
		met := &recordingMetrics{}
		uc := NewRegisterResourceUseCase(&countingEmitter{}, newProjectionMirror(), &smTxBeginner{}, seededCatalogTypes{}).
			WithReconcile(&countingReconcileEvents{}).
			WithObjectReconciler(rec, nil).
			WithMetrics(met)
		ctx := context.Background()

		require.NoError(t, uc.Register(ctx, base(inTx)))                           // создание
		require.NoError(t, uc.Register(ctx, base(inTx.Add(3*time.Millisecond))))   // повторная доставка
		require.NoError(t, uc.Register(ctx, &routeReq{object: "vpc_network:net-1", // правка меток
			project: "prj-1", account: "acc-1",
			labels: map[string]string{"tier": "bronze"}, version: inTx.Add(time.Second)}))

		assert.Equal(t, []string{
			"forward_guarded/ok",  // создание: доказательства нет, страж на месте
			"forward_additive/ok", // повторная доставка: проекция не заменена
			"forward_guarded/ok",  // правка: проекция заменена, нужен удаляющий проход
		}, met.snapshot(),
			"счётчик обязан фиксировать УСПЕШНЫЕ запуски и называть выбранный путь")
	})

	t.Run("отказ ускорителя посчитан, а не только залогирован", func(t *testing.T) {
		met := &recordingMetrics{}
		uc := NewRegisterResourceUseCase(&countingEmitter{}, newProjectionMirror(), &smTxBeginner{}, seededCatalogTypes{}).
			WithReconcile(&countingReconcileEvents{}).
			WithObjectReconciler(&failingReconciler{err: assertAnError}, nil).
			WithMetrics(met)

		require.NoError(t, uc.Register(context.Background(), base(inTx)),
			"отказ ускорителя не проваливает регистрацию — ресурс уже durable")
		assert.Equal(t, []string{"forward_guarded/error"}, met.snapshot(),
			"отказ обязан быть посчитан: один WARN не делает мёртвый ускоритель заметным")
	})
}

// assertAnError — маркерная ошибка для отрицательной ветки выше.
var assertAnError = errForTest("post-commit forward failed")

type errForTest string

func (e errForTest) Error() string { return string(e) }
