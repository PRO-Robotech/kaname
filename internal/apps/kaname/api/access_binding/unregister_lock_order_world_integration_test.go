// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// unregister_lock_order_world_integration_test.go — порядок замков снятия
// регистрации против писателей, которые держат свою транзакцию ОТКРЫТОЙ
// (kaname#963, ревью @5c0f8f13d):
//
//   - F1 (security-auditor): проход материализации после создания выдачи
//     прочитал выдачу ACTIVE, а пишет член, реестр выпущенного и факт уже после
//     зафиксированного отзыва по снятию. Отзыв снимает только то, что успело
//     попасть в реестр, — остаток на ключе пережил бы снятие и повторную
//     регистрацию ключа другим владельцем.
//   - второй порядок гонки Р8 (db-architect-reviewer, заказ 1): писатель выдачи
//     или роли взял замок строки регистрации (`FOR KEY SHARE`) и ещё не
//     зафиксировался — снятие обязано ЖДАТЬ его, а не проходить мимо.
//
// Удержание у обеих проб стоит ВНУТРИ транзакции писателя, после того как она
// прочитала (или заперла) то, о чём спор, — иначе проба проверяла бы только
// первый порядок (писатель стартует после снятия), который держат URG-24/26.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	rolerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// ── удержание ────────────────────────────────────────────────────────────────

// pause — одна точка удержания: заряжается `arm`, срабатывает один раз.
type pause struct {
	mu      sync.Mutex
	gate    chan struct{}
	reached chan struct{}
}

func (p *pause) arm() (reached <-chan struct{}, release func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.gate = make(chan struct{})
	p.reached = make(chan struct{})
	gate := p.gate
	return p.reached, func() { close(gate) }
}

// hit — точка удержания: при заряде сообщает и ждёт отпускания.
func (p *pause) hit() {
	p.mu.Lock()
	gate, reached := p.gate, p.reached
	p.gate, p.reached = nil, nil
	p.mu.Unlock()
	if gate != nil {
		close(reached)
		<-gate
	}
}

// forwardHold — исполнитель транзакций реконсайлера, держащий проход
// материализации на первой записи (UpsertMembers): выдача уже прочитана,
// желаемые члены вычислены, ничего ещё не записано.
type forwardHold struct {
	reconcile.TxRunner
	p        pause
	mu       sync.Mutex
	finished chan struct{}
}

func (h *forwardHold) arm() (reached, finished <-chan struct{}, release func()) {
	h.mu.Lock()
	h.finished = make(chan struct{})
	finished = h.finished
	h.mu.Unlock()
	reached, release = h.p.arm()
	return reached, finished, release
}

func (h *forwardHold) WithTx(ctx context.Context, fn func(ctx context.Context, s reconcile.ReconcileStore) error) error {
	h.mu.Lock()
	finished := h.finished
	h.finished = nil
	h.mu.Unlock()
	if finished == nil {
		return h.TxRunner.WithTx(ctx, fn)
	}
	err := h.TxRunner.WithTx(ctx, func(ctx context.Context, s reconcile.ReconcileStore) error {
		return fn(ctx, &heldWriteStore{ReconcileStore: s, p: &h.p})
	})
	close(finished)
	return err
}

type heldWriteStore struct {
	reconcile.ReconcileStore
	p *pause
}

func (s *heldWriteStore) UpsertMembers(ctx context.Context, members []domain.TargetMember) error {
	s.p.hit()
	return s.ReconcileStore.UpsertMembers(ctx, members)
}

// lockHoldRepo — порт `Repo`, чей писатель держит транзакцию записи ПОСЛЕ
// записи выдачи или роли (замок строки регистрации уже взят, фиксации нет).
type lockHoldRepo struct {
	kanamerepo.Repository
	p pause
}

func (h *lockHoldRepo) Writer(ctx context.Context) (kanamerepo.Writer, error) {
	w, err := h.Repository.Writer(ctx)
	if err != nil {
		return nil, err
	}
	return &lockHoldWriter{Writer: w, p: &h.p}, nil
}

type lockHoldWriter struct {
	kanamerepo.Writer
	p *pause
}

func (w *lockHoldWriter) AccessBindingsW() abrepo.WriterIface {
	return &lockHoldAB{WriterIface: w.Writer.AccessBindingsW(), p: w.p}
}

func (w *lockHoldWriter) RolesW() rolerepo.WriterIface {
	return &lockHoldRole{WriterIface: w.Writer.RolesW(), p: w.p}
}

type lockHoldAB struct {
	abrepo.WriterIface
	p *pause
}

func (a *lockHoldAB) Insert(ctx context.Context, b domain.AccessBinding) (domain.AccessBinding, error) {
	out, err := a.WriterIface.Insert(ctx, b)
	if err == nil {
		a.p.hit()
	}
	return out, err
}

type lockHoldRole struct {
	rolerepo.WriterIface
	p *pause
}

func (r *lockHoldRole) Insert(ctx context.Context, role domain.Role) (domain.Role, error) {
	out, err := r.WriterIface.Insert(ctx, role)
	if err == nil {
		r.p.hit()
	}
	return out, err
}

// awaitBlockedOrDone — ждёт, пока снятие либо встанет на замке (в базе мира есть
// обслуживающий процесс, которого держит другой: `pg_blocking_pids`), либо
// закончится. blocked=true — встало и ещё идёт.
func awaitBlockedOrDone(t *testing.T, ctx context.Context, pool *pgxpool.Pool, done <-chan error) (blocked bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			require.NoError(t, err, "снятие регистрации")
			return false
		default:
		}
		var n int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_stat_activity
			  WHERE datname = current_database() AND wait_event_type = 'Lock'
			    AND cardinality(pg_blocking_pids(pid)) > 0`).Scan(&n))
		if n > 0 {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("снятие ни встало на замке, ни закончилось за 20 с")
	return false
}

// factsOf — прямые факты субъекта на объекте (то, что решение читает ветвью фактов).
func (w *urxWorld) factsOf(subject, objectType, objectID string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.relation_fact WHERE object_type = $1 AND object_id = $2 AND subject = $3`,
		objectType, objectID, subject).Scan(&n))
	return n
}

// ── F1: проход материализации против снятия ─────────────────────────────────

// forwardCreate — обработчик выдач, чей проход материализации держит `hold`.
func (w *urxWorld) forwardCreate(hold *forwardHold) *accessbindingapp.Handler {
	create := accessbindingapp.NewCreateAccessBindingUseCase(w.repo, w.ops, pcrFacts{w.pcrWorld}).
		WithRelationStore(w.door, nil).
		WithReconciler(reconcile.New(hold, nil, catalog.Fixed{F: w.facts})).
		WithRegisteredKeys(kanamepg.NewRegisteredKeys(w.pool))
	get := accessbindingapp.NewGetAccessBindingUseCase(w.repo).WithRelationStore(w.door, nil).WithRelationQueries(w.door)
	return accessbindingapp.NewHandler(create, nil, get, nil, nil, nil, nil)
}

// F1 · проход материализации, прочитавший выдачу до снятия, не оставляет факта
// на ключе после снятия и повторной регистрации ключа другим владельцем.
func TestUnregisterVsCreateForward_HeldForwardLeavesNoFactOnKey(t *testing.T) {
	w := newURXWorld(t)
	hold := &forwardHold{TxRunner: kanamepg.NewReconcileAdapter(w.pool, catalog.Fixed{F: w.facts})}
	h := w.forwardCreate(hold)
	reached, finished, release := hold.arm()

	op, err := h.Create(asUser(w.ctx, w.usrA), w.grantRequest(userSubject(w.usrD), w.rolRegGet, urTarget(pcrX)))
	require.NoError(t, err, "F1: приём выдачи на X")
	var md iamv1.CreateAccessBindingMetadata
	require.NoError(t, op.GetMetadata().UnmarshalTo(&md))
	require.Nil(t, awaitOp(t, w.ctx, w.ops, op.GetId()).Error, "F1: создание выдачи")
	select {
	case <-reached:
	case <-time.After(30 * time.Second):
		t.Fatal("F1: проход материализации не дошёл до записи")
	}

	done := make(chan error, 1)
	go func() { done <- w.withdrawErr(w.ctx, pcrX) }()
	blocked := awaitBlockedOrDone(t, w.ctx, w.pool, done)
	release()
	if blocked {
		require.NoError(t, <-done, "F1: снятие после отпускания прохода")
	}
	<-finished
	t.Logf("F1: снятие ждало прохода материализации: %v", blocked)
	assert.True(t, blocked, "F1: снятие прошло мимо незафиксированного прохода материализации, читавшего выдачу")

	w.reRegisterX(w.usrC)

	b := w.get(md.GetAccessBindingId())
	assert.Equal(t, iamv1.AccessBinding_REVOKED, b.GetStatus(), "F1: выдача на снятый X не отозвана")
	assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED, b.GetRevocationReason(), "F1: причина")
	assert.Zero(t, w.factsOf(w.usr(w.usrD), pcrRegType, pcrX), "F1: прямой факт usr-D на X пережил снятие")
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, pcrX),
		"F1: usr-D читает X после снятия и повторной регистрации другим владельцем")
}

// F1 · близнец без гонки: проход закончился до снятия.
func TestUnregisterVsCreateForward_NoRaceLeavesNoFactOnKey(t *testing.T) {
	w := newURXWorld(t)
	id := w.grantTo(w.usrD, w.rolRegGet, urTarget(pcrX), false, "F1 близнец: выдача на X")
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRegType, pcrX, true, "F1 близнец контроль: usr-D читает X")

	w.withdrawX()
	w.reRegisterX(w.usrC)

	assert.Equal(t, iamv1.AccessBinding_REVOKED, w.get(id).GetStatus(), "F1 близнец: выдача не отозвана")
	assert.Zero(t, w.factsOf(w.usr(w.usrD), pcrRegType, pcrX), "F1 близнец: прямой факт usr-D на X пережил снятие")
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, pcrX), "F1 близнец: usr-D читает X")
}

// ── второй порядок гонки Р8: писатель держит замок, снятие ждёт ─────────────

// URG-24b · запись выдачи заперла строку регистрации и не зафиксирована —
// снятие ждёт её и после фиксации отзывает выдачу.
func TestURG24b_UnregisterWaitsForBindingWriterHoldingKey(t *testing.T) {
	w := newURXWorld(t)
	hold := &lockHoldRepo{Repository: w.repo}
	create := accessbindingapp.NewCreateAccessBindingUseCase(hold, w.ops, pcrFacts{w.pcrWorld}).
		WithRelationStore(w.door, nil).
		WithReconciler(w.rec).
		WithRegisteredKeys(kanamepg.NewRegisteredKeys(w.pool))
	h := accessbindingapp.NewHandler(create, nil, nil, nil, nil, nil, nil)
	key := raceKey(6000, 0)
	w.registerRegistry(key)
	reached, release := hold.p.arm()

	op, err := h.Create(asUser(w.ctx, w.usrA), w.grantRequest(userSubject(w.usrD), w.rolRegGet, urTarget(key)))
	require.NoError(t, err, "URG-24b: приём выдачи")
	var md iamv1.CreateAccessBindingMetadata
	require.NoError(t, op.GetMetadata().UnmarshalTo(&md))
	select {
	case <-reached:
	case <-time.After(30 * time.Second):
		t.Fatal("URG-24b: запись выдачи не дошла до удержания")
	}

	done := make(chan error, 1)
	go func() { done <- w.withdrawErr(w.ctx, key) }()
	blocked := awaitBlockedOrDone(t, w.ctx, w.pool, done)
	release()
	if blocked {
		require.NoError(t, <-done, "URG-24b: снятие после фиксации записи")
	}
	require.Nil(t, awaitOp(t, w.ctx, w.ops, op.GetId()).Error, "URG-24b: создание выдачи")

	assert.True(t, blocked, "URG-24b: снятие прошло мимо незафиксированной записи, державшей ключ")
	b := w.get(md.GetAccessBindingId())
	assert.Equal(t, iamv1.AccessBinding_REVOKED, b.GetStatus(), "URG-24b: выдача на снятый ключ жива")
	assert.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED, b.GetRevocationReason(), "URG-24b: причина")
}

// URG-26b · запись роли заперла строку регистрации и не зафиксирована —
// снятие ждёт её и после фиксации вычёркивает ключ из правил роли.
func TestURG26b_UnregisterWaitsForRoleWriterHoldingKey(t *testing.T) {
	w := newURXWorld(t)
	hold := &lockHoldRepo{Repository: w.repo}
	src := catalog.Fixed{F: w.facts}
	create := roleapp.NewHandler(roleapp.NewCreateRoleUseCase(hold, w.ops, src).WithRelationStore(w.door, nil).
		WithObjectReconciler(w.rec).WithRegisteredKeys(kanamepg.NewRegisteredKeys(w.pool)), nil, nil, nil, nil)
	key := raceKey(7000, 0)
	w.registerRegistry(key)
	reached, release := hold.p.arm()

	op, err := create.Create(asUser(w.ctx, w.usrA), &iamv1.CreateRoleRequest{
		AccountId: string(w.accA), Name: "urg26b_create", Description: "URG-26b",
		Rules: []*iamv1.Rule{protoNamesRule(key, pcrY)},
	})
	require.NoError(t, err, "URG-26b: приём создания роли")
	select {
	case <-reached:
	case <-time.After(30 * time.Second):
		t.Fatal("URG-26b: запись роли не дошла до удержания")
	}

	done := make(chan error, 1)
	go func() { done <- w.withdrawErr(w.ctx, key) }()
	blocked := awaitBlockedOrDone(t, w.ctx, w.pool, done)
	release()
	if blocked {
		require.NoError(t, <-done, "URG-26b: снятие после фиксации записи")
	}
	require.Nil(t, awaitOp(t, w.ctx, w.ops, op.GetId()).Error, "URG-26b: создание роли")
	var md iamv1.CreateRoleMetadata
	require.NoError(t, op.GetMetadata().UnmarshalTo(&md))

	assert.True(t, blocked, "URG-26b: снятие прошло мимо незафиксированной записи, державшей ключ")
	names, ok := w.roleNames(domain.RoleID(md.GetRoleId()))
	require.True(t, ok, "URG-26b: роли нет")
	assert.NotContains(t, names, key, fmt.Sprintf("URG-26b: роль называет снятый ключ %s", key))
}

// ── F4: имя ключа в правиле роли против снятия ──────────────────────────────

// membersOn — члены выдачи по объекту (то, что материализатор записал на ключ).
func (w *urxWorld) membersOn(bindingID, objectID string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id = $1 AND object_id = $2`,
		bindingID, objectID).Scan(&n))
	return n
}

// unmaterializedGrant — выдача роли человеку usr-D на prj-A, созданная БЕЗ прохода
// материализации: членов у неё нет, поэтому проход по объекту идёт аддитивным путём, а
// не делегирует полному.
func (w *urxWorld) unmaterializedGrant(role domain.RoleID, target *iamv1.AccessTarget, why string) string {
	w.t.Helper()
	create := accessbindingapp.NewCreateAccessBindingUseCase(w.repo, w.ops, pcrFacts{w.pcrWorld}).
		WithRelationStore(w.door, nil).
		WithRegisteredKeys(kanamepg.NewRegisteredKeys(w.pool))
	h := accessbindingapp.NewHandler(create, nil, nil, nil, nil, nil, nil)
	op, err := h.Create(asUser(w.ctx, w.usrA), w.grantRequest(userSubject(w.usrD), role, target))
	require.NoError(w.t, err, why)
	var md iamv1.CreateAccessBindingMetadata
	require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md))
	require.Nil(w.t, awaitOp(w.t, w.ctx, w.ops, op.GetId()).Error, why)
	return md.GetAccessBindingId()
}

// heldWithdraw — снятие ключа, пока проход держится на первой записи; затем отпуск.
// Возвращает, ждало ли снятие прохода на замке.
func (w *urxWorld) heldWithdraw(key string, reached, finished <-chan struct{}, release func(), why string) bool {
	w.t.Helper()
	select {
	case <-reached:
	case <-time.After(30 * time.Second):
		w.t.Fatalf("%s: проход материализации не дошёл до записи", why)
	}
	done := make(chan error, 1)
	go func() { done <- w.withdrawErr(w.ctx, key) }()
	blocked := awaitBlockedOrDone(w.t, w.ctx, w.pool, done)
	release()
	if blocked {
		require.NoErrorf(w.t, <-done, "%s: снятие после отпускания прохода", why)
	}
	<-finished
	return blocked
}

// F4 · проход создания выдачи, прочитавший правило роли с именем ключа до снятия, не
// пишет член и факт по снятому ключу после него.
func TestUnregisterVsCreateForward_RoleNameHeldForwardLeavesNoMember(t *testing.T) {
	w := newURXWorld(t)
	role := w.seedRole("f4_names_x", domain.Rules{namesRule(pcrX)})
	hold := &forwardHold{TxRunner: kanamepg.NewReconcileAdapter(w.pool, catalog.Fixed{F: w.facts})}
	h := w.forwardCreate(hold)
	reached, finished, release := hold.arm()

	op, err := h.Create(asUser(w.ctx, w.usrA), w.grantRequest(userSubject(w.usrD), role, ndAllInScope()))
	require.NoError(t, err, "F4: приём выдачи роли с именем X")
	var md iamv1.CreateAccessBindingMetadata
	require.NoError(t, op.GetMetadata().UnmarshalTo(&md))
	require.Nil(t, awaitOp(t, w.ctx, w.ops, op.GetId()).Error, "F4: создание выдачи")
	id := md.GetAccessBindingId()

	blocked := w.heldWithdraw(pcrX, reached, finished, release, "F4")
	t.Logf("F4 (проход создания): снятие ждало прохода: %v", blocked)

	assert.True(t, blocked, "F4: снятие прошло мимо незафиксированного прохода, читавшего роль")
	assert.Zero(t, w.membersOn(id, pcrX), "F4: член выдачи по снятому X записан")
	assert.Zero(t, w.factsOf(w.usr(w.usrD), pcrRegType, pcrX), "F4: прямой факт usr-D на снятом X")
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, pcrX), "F4: usr-D читает снятый X")
}

// F4 · проход по объекту, прочитавший правило роли с именем ключа до снятия, не пишет
// член и факт по снятому ключу после него.
func TestUnregisterVsObjectForward_RoleNameHeldForwardLeavesNoMember(t *testing.T) {
	w := newURXWorld(t)
	key := raceKey(8000, 0)
	w.registerRegistry(key)
	role := w.seedRole("f4_names_key", domain.Rules{namesRule(key)})
	id := w.unmaterializedGrant(role, ndAllInScope(), "F4 объект: выдача роли с именем ключа")
	require.Zero(t, w.membersOn(id, key), "F4 объект: фикстура — у выдачи уже есть член")
	hold := &forwardHold{TxRunner: kanamepg.NewReconcileAdapter(w.pool, catalog.Fixed{F: w.facts})}
	rec := reconcile.New(hold, nil, catalog.Fixed{F: w.facts})
	reached, finished, release := hold.arm()
	fwd := make(chan error, 1)
	go func() { fwd <- rec.ReconcileObjectForward(w.ctx, pcrRegTgt, key) }()

	blocked := w.heldWithdraw(key, reached, finished, release, "F4 объект")
	require.NoError(t, <-fwd, "F4 объект: проход по объекту")
	t.Logf("F4 (проход по объекту): снятие ждало прохода: %v", blocked)

	assert.True(t, blocked, "F4 объект: снятие прошло мимо незафиксированного прохода, читавшего роль")
	assert.Zero(t, w.membersOn(id, key), "F4 объект: член выдачи по снятому ключу записан")
	assert.Zero(t, w.factsOf(w.usr(w.usrD), pcrRegType, key), "F4 объект: прямой факт usr-D на снятом ключе")
}

// F4 · близнец: проход по объекту закончился до снятия — член снимается снятием.
func TestUnregisterVsObjectForward_RoleNameNoRaceLeavesNoMember(t *testing.T) {
	w := newURXWorld(t)
	key := raceKey(8100, 0)
	w.registerRegistry(key)
	role := w.seedRole("f4_names_key_twin", domain.Rules{namesRule(key)})
	id := w.unmaterializedGrant(role, ndAllInScope(), "F4 близнец: выдача роли с именем ключа")
	require.NoError(t, w.rec.ReconcileObjectForward(w.ctx, pcrRegTgt, key), "F4 близнец: проход по объекту")
	require.NotZero(t, w.membersOn(id, key), "F4 близнец контроль: проход записал член")

	w.withdraw(w.ctx, key)

	assert.Zero(t, w.membersOn(id, key), "F4 близнец: член по снятому ключу пережил снятие")
	assert.Zero(t, w.factsOf(w.usr(w.usrD), pcrRegType, key), "F4 близнец: прямой факт на снятом ключе")
}

// Заказ db r2 · проход по объекту (пакетное чтение выдач) против отзыва по цели: выдача,
// цель которой называет ключ, прочитанная проходом до снятия, не оставляет факта.
func TestUnregisterVsObjectForward_TargetHeldForwardLeavesNoFact(t *testing.T) {
	w := newURXWorld(t)
	key := raceKey(8200, 0)
	w.registerRegistry(key)
	id := w.unmaterializedGrant(w.rolRegGet, urTarget(key), "объект/цель: выдача на ключ")
	hold := &forwardHold{TxRunner: kanamepg.NewReconcileAdapter(w.pool, catalog.Fixed{F: w.facts})}
	rec := reconcile.New(hold, nil, catalog.Fixed{F: w.facts})
	reached, finished, release := hold.arm()
	fwd := make(chan error, 1)
	go func() { fwd <- rec.ReconcileObjectForward(w.ctx, pcrRegTgt, key) }()

	blocked := w.heldWithdraw(key, reached, finished, release, "объект/цель")
	require.NoError(t, <-fwd, "объект/цель: проход по объекту")
	t.Logf("объект/цель: снятие ждало прохода: %v", blocked)

	assert.True(t, blocked, "объект/цель: снятие прошло мимо незафиксированного прохода, читавшего выдачу")
	b := w.get(id)
	assert.Equal(t, iamv1.AccessBinding_REVOKED, b.GetStatus(), "объект/цель: выдача на снятый ключ жива")
	assert.Zero(t, w.factsOf(w.usr(w.usrD), pcrRegType, key), "объект/цель: прямой факт usr-D на снятом ключе")
}
