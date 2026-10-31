// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// unregister_mirror_read_order_world_integration_test.go — отбор членов по
// зеркалу объекта упорядочен со снятием регистрации (PRO-Robotech/kaname#975).
//
// # Предмет
//
// Ветви отбора членов, читающие зеркало объекта, — область выдачи, метки,
// предки вложенного правила — выбирают объект по его строке зеркала, а не по
// выдаче или роли, которые снятие регистрации запирает. Проход материализации,
// прочитавший зеркало до снятия и записавший член после него, оставлял член по
// снятому объекту: пост-фиксационный проход снятия незафиксированного члена не
// видит, а остаток убирал лишь периодический проход.
//
// # Форма
//
// Проход останавливается СРАЗУ после чтения зеркала, вернувшего объект
// (`mirrorReadHold`), в эту паузу снимается регистрация объекта, затем проход
// отпускается. Утверждается ИСХОД после обоих: члена выдачи по снятому объекту
// нет, прямого факта нет, решение отказывает — без участия периодического
// прохода (его в мире пробы нет). Порядок, в котором снятие встало на замке
// либо прошло, проба принимает любой и печатает его.
//
// # Законные близнецы
//
// Та же остановка без снятия: проход записывает член по объекту, как и прежде
// (`…_TwinWritesMember`). Без них ноль после снятия был бы неотличим от
// прохода, не пишущего ничего.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// mirrorBranch — ветвь отбора, после чтения которой стоит удержание.
type mirrorBranch string

const (
	branchScope     mirrorBranch = "область"
	branchLabels    mirrorBranch = "метки"
	branchAncestors mirrorBranch = "предки"
)

// mirrorReadHold — исполнитель транзакций реконсайлера, держащий проход сразу
// после чтения зеркала ветви `branch`, вернувшего объект `objectID`.
type mirrorReadHold struct {
	reconcile.TxRunner
	p        pause
	mu       sync.Mutex
	objectID string
	branch   mirrorBranch
	finished chan struct{}
}

func (h *mirrorReadHold) arm(branch mirrorBranch, objectID string) (reached, finished <-chan struct{}, release func()) {
	h.mu.Lock()
	h.branch, h.objectID = branch, objectID
	h.finished = make(chan struct{})
	finished = h.finished
	h.mu.Unlock()
	reached, release = h.p.arm()
	return reached, finished, release
}

func (h *mirrorReadHold) WithTx(ctx context.Context, fn func(ctx context.Context, s reconcile.ReconcileStore) error) error {
	h.mu.Lock()
	finished, branch, objectID := h.finished, h.branch, h.objectID
	h.finished = nil
	h.mu.Unlock()
	if finished == nil {
		return h.TxRunner.WithTx(ctx, fn)
	}
	defer close(finished)
	return h.TxRunner.WithTx(ctx, func(ctx context.Context, s reconcile.ReconcileStore) error {
		return fn(ctx, &mirrorReadHoldStore{ReconcileStore: s, branch: branch, objectID: objectID, p: &h.p})
	})
}

type mirrorReadHoldStore struct {
	reconcile.ReconcileStore
	branch   mirrorBranch
	objectID string
	p        *pause
}

func (s *mirrorReadHoldStore) holdIfRead(branch mirrorBranch, objs []domain.MirrorObject) {
	if branch != s.branch {
		return
	}
	for _, o := range objs {
		if o.ObjectID == s.objectID {
			s.p.hit()
			return
		}
	}
}

func (s *mirrorReadHoldStore) MatchAllInScope(ctx context.Context, types []string, scope domain.ScopeAnchor) ([]domain.MirrorObject, error) {
	out, err := s.ReconcileStore.MatchAllInScope(ctx, types, scope)
	if err == nil {
		s.holdIfRead(branchScope, out)
	}
	return out, err
}

func (s *mirrorReadHoldStore) MatchSelector(ctx context.Context, types []string, matchLabels map[string]string) ([]domain.MirrorObject, error) {
	out, err := s.ReconcileStore.MatchSelector(ctx, types, matchLabels)
	if err == nil {
		s.holdIfRead(branchLabels, out)
	}
	return out, err
}

func (s *mirrorReadHoldStore) AncestorObjects(ctx context.Context, objectType, objectID string) ([]domain.MirrorObject, error) {
	out, err := s.ReconcileStore.AncestorObjects(ctx, objectType, objectID)
	if err == nil {
		s.holdIfRead(branchAncestors, out)
	}
	return out, err
}

// heldRec — реконсайлер мира поверх удерживающего исполнителя.
func (w *urxWorld) heldRec() (*mirrorReadHold, *reconcile.Reconciler) {
	hold := &mirrorReadHold{TxRunner: kanamepg.NewReconcileAdapter(w.pool, catalog.Fixed{F: w.facts})}
	return hold, reconcile.New(hold, nil, catalog.Fixed{F: w.facts})
}

// passAroundUnregister — проход `run` стоит после чтения зеркала; если `key`
// непуст, в эту паузу снимается регистрация `key`, затем проход отпускается.
// Возвращает, ждало ли снятие прохода на замке.
func (w *urxWorld) passAroundUnregister(run func() error, reached, finished <-chan struct{}, release func(), key, why string) bool {
	w.t.Helper()
	pass := make(chan error, 1)
	go func() { pass <- run() }()
	select {
	case <-reached:
	case <-time.After(30 * time.Second):
		w.t.Fatalf("%s: проход не дошёл до чтения зеркала с объектом", why)
	}
	blocked := false
	var unregErr error
	var done chan error
	if key != "" {
		done = make(chan error, 1)
		go func() { done <- w.withdrawErr(w.ctx, key) }()
		blocked, unregErr = awaitStalledOrDone(w.t, w.ctx, w.pool, done)
	}
	release()
	require.NoErrorf(w.t, <-pass, "%s: проход материализации", why)
	<-finished
	if blocked {
		unregErr = <-done
	}
	require.NoErrorf(w.t, unregErr, "%s: снятие регистрации", why)
	w.t.Logf("%s: снятие встало на замке прохода: %v", why, blocked)
	return blocked
}

// ── область ──────────────────────────────────────────────────────────────────

func (w *urxWorld) scopeFixture(base int) (key, binding string) {
	w.t.Helper()
	key = raceKey(base, 0)
	w.registerRegistry(key)
	binding = w.unmaterializedGrant(w.rolRegGet, ndAllInScope(), "975 область: выдача на всю область")
	require.Zero(w.t, w.membersOn(binding, key), "975 область: фикстура — у выдачи уже есть член на ключе")
	return key, binding
}

// Ветвь области: проход создания выдачи прочитал объекты области, в паузу снята
// регистрация ключа — члена по снятому ключу нет.
func TestUnregisterVsMirrorRead_ScopeHeldPassLeavesNoMember(t *testing.T) {
	w := newURXWorld(t)
	key, id := w.scopeFixture(9500)
	hold, rec := w.heldRec()
	reached, finished, release := hold.arm(branchScope, key)
	w.passAroundUnregister(func() error { return rec.ReconcileBindingForward(w.ctx, domain.AccessBindingID(id)) },
		reached, finished, release, key, "975 область")

	assert.NotZero(t, w.membersOn(id, pcrX), "975 область контроль: проход записал члены соседних объектов области")
	assert.Zero(t, w.membersOn(id, key), "975 область: член по снятому ключу записан")
	assert.Zero(t, w.factsOf(w.usr(w.usrD), pcrRegType, key), "975 область: прямой факт usr-D на снятом ключе")
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, key), "975 область: usr-D читает снятый ключ")
}

// Близнец ветви области: та же остановка без снятия — член записан.
func TestUnregisterVsMirrorRead_ScopeTwinWritesMember(t *testing.T) {
	w := newURXWorld(t)
	key, id := w.scopeFixture(9510)
	hold, rec := w.heldRec()
	reached, finished, release := hold.arm(branchScope, key)
	w.passAroundUnregister(func() error { return rec.ReconcileBindingForward(w.ctx, domain.AccessBindingID(id)) },
		reached, finished, release, "", "975 область близнец")

	assert.NotZero(t, w.membersOn(id, key), "975 область близнец: член по ключу не записан")
	assert.True(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, key), "975 область близнец: usr-D не читает ключ")
}

// Ветвь области, второй порядок: проход уже записывает член (стоит на записи), а
// снятие регистрации идёт в эту паузу — оно не завершается раньше прохода, и его
// пост-фиксационный проход снимает записанное.
func TestUnregisterVsMirrorRead_ScopeWritingPassOutlivedByUnregister(t *testing.T) {
	w := newURXWorld(t)
	key, id := w.scopeFixture(9520)
	hold := &forwardHold{TxRunner: kanamepg.NewReconcileAdapter(w.pool, catalog.Fixed{F: w.facts})}
	rec := reconcile.New(hold, nil, catalog.Fixed{F: w.facts})
	reached, finished, release := hold.arm()
	fwd := make(chan error, 1)
	go func() { fwd <- rec.ReconcileBindingForward(w.ctx, domain.AccessBindingID(id)) }()
	blocked := w.heldWithdraw(key, reached, finished, release, "975 область, второй порядок")
	require.NoError(t, <-fwd, "975 область, второй порядок: проход")

	assert.True(t, blocked, "975 область, второй порядок: снятие завершилось раньше прохода, писавшего член по ключу")
	assert.Zero(t, w.membersOn(id, key), "975 область, второй порядок: член по снятому ключу")
	assert.Zero(t, w.factsOf(w.usr(w.usrD), pcrRegType, key), "975 область, второй порядок: прямой факт на снятом ключе")
}

// ── метки ────────────────────────────────────────────────────────────────────

const uoLabelKey, uoLabelValue = "tier", "t975"

// registerLabeledRegistry — регистрация реестра с метками (тот же путь, что
// registerRegistry, плюс метки зеркала).
func (w *urxWorld) registerLabeledRegistry(id string, labels map[string]string) {
	w.t.Helper()
	obj := pcrRegType + ":" + id
	for _, r := range []*iamv1.RegisterResourceRequest{
		{SubjectId: "project:" + string(w.prjA), Relation: "project", Object: obj},
		{SubjectId: "user:" + string(w.usrA), Relation: "owner", Object: obj},
	} {
		r.ParentProjectId, r.ParentAccountId = string(w.prjA), string(w.accA)
		r.ParentChain = []string{"project:" + string(w.prjA), "account:" + string(w.accA)}
		r.Labels = labels
		require.NoErrorf(w.t, w.reg.Register(w.ctx, r), "975 метки: регистрация реестра %s (%s)", id, r.GetRelation())
	}
}

func (w *urxWorld) labelsFixture(base int) (key, binding string) {
	w.t.Helper()
	key = raceKey(base, 0)
	w.registerLabeledRegistry(key, map[string]string{uoLabelKey: uoLabelValue})
	role := w.seedRole("uo_labels", domain.Rules{{
		Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{uoLabelKey: uoLabelValue},
	}})
	binding = w.unmaterializedGrant(role, ndAllInScope(), "975 метки: выдача роли с правилом по меткам")
	require.Zero(w.t, w.membersOn(binding, key), "975 метки: фикстура — у выдачи уже есть член на ключе")
	return key, binding
}

// Ветвь меток: проход прочитал объекты по меткам, в паузу снята регистрация
// ключа — члена по снятому ключу нет.
func TestUnregisterVsMirrorRead_LabelsHeldPassLeavesNoMember(t *testing.T) {
	w := newURXWorld(t)
	key, id := w.labelsFixture(9530)
	hold, rec := w.heldRec()
	reached, finished, release := hold.arm(branchLabels, key)
	w.passAroundUnregister(func() error { return rec.ReconcileBindingForward(w.ctx, domain.AccessBindingID(id)) },
		reached, finished, release, key, "975 метки")

	assert.Zero(t, w.membersOn(id, key), "975 метки: член по снятому ключу записан")
	assert.Zero(t, w.factsOf(w.usr(w.usrD), pcrRegType, key), "975 метки: прямой факт usr-D на снятом ключе")
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, key), "975 метки: usr-D читает снятый ключ")
}

// Близнец ветви меток: та же остановка без снятия — член записан.
func TestUnregisterVsMirrorRead_LabelsTwinWritesMember(t *testing.T) {
	w := newURXWorld(t)
	key, id := w.labelsFixture(9540)
	hold, rec := w.heldRec()
	reached, finished, release := hold.arm(branchLabels, key)
	w.passAroundUnregister(func() error { return rec.ReconcileBindingForward(w.ctx, domain.AccessBindingID(id)) },
		reached, finished, release, "", "975 метки близнец")

	assert.NotZero(t, w.membersOn(id, key), "975 метки близнец: член по ключу не записан")
	assert.True(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, key), "975 метки близнец: usr-D не читает ключ")
}

// ── предки вложенного правила ────────────────────────────────────────────────

// bareRegister — регистрация без прохода по объекту: строка зеркала есть,
// материализации нет (её проба запускает сама, с удержанием).
func (w *urxWorld) bareRegister() *internaliam.RegisterResourceUseCase {
	return internaliam.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(),
		kanamepg.NewResourceMirrorEmitter(),
		kanamepg.NewPoolTxBeginner(w.pool),
		kanamepg.NewCatalogTypeReader(),
		kanamepg.NewPublicReadPublisher(),
		accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), pcrFacts{w.pcrWorld}),
		kanamepg.NewRegistrationAudit(),
		kanamepg.NewRegistrationScopeReader(),
	)
}

// nestedFixture — реестр-контейнер K, выдача роли с вложенным правилом над
// репозиториями (вся область, материализована) и репозиторий K/late,
// зарегистрированный без прохода по объекту.
func (w *urxWorld) nestedFixture(base int) (container, repo, binding string) {
	w.t.Helper()
	container = raceKey(base, 0)
	w.registerRegistry(container)
	role := w.seedRole("uo_nested", pcrWithChild(pcrRepositoriesRule()))
	binding = w.grantTo(w.usrD, role, ndAllInScope(), false, "975 предки: выдача роли с вложенным правилом")
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRegType, container, true, "975 предки контроль: выдача материализована на контейнере")
	repo = container + "/late"
	obj := pcrRepoType + ":" + repo
	bare := w.bareRegister()
	for _, r := range []*iamv1.RegisterResourceRequest{
		{SubjectId: pcrRegType + ":" + container, Relation: "parent", Object: obj},
		{SubjectId: "user:" + string(w.usrA), Relation: "owner", Object: obj},
	} {
		r.ParentProjectId, r.ParentAccountId = string(w.prjA), string(w.accA)
		r.ParentChain = []string{pcrRegType + ":" + container, "project:" + string(w.prjA), "account:" + string(w.accA)}
		require.NoErrorf(w.t, bare.Register(w.ctx, r), "975 предки: регистрация репозитория %s (%s)", repo, r.GetRelation())
	}
	require.Zero(w.t, w.membersOn(binding, repo), "975 предки: фикстура — у выдачи уже есть член на репозитории")
	return container, repo, binding
}

// Ветвь предков вложенного правила: проход по новому репозиторию прочитал его
// предков (контейнер K), в паузу снята регистрация контейнера — члена по
// репозиторию, чей охват давал снятый контейнер, нет.
func TestUnregisterVsMirrorRead_AncestorsHeldPassLeavesNoMember(t *testing.T) {
	w := newP3UWorld(t)
	container, repo, id := w.nestedFixture(9550)
	hold, rec := w.heldRec()
	reached, finished, release := hold.arm(branchAncestors, container)
	w.passAroundUnregister(func() error { return rec.ReconcileObjectForward(w.ctx, "registry.repositories", repo) },
		reached, finished, release, container, "975 предки")

	assert.Zero(t, w.membersOn(id, repo), "975 предки: член по репозиторию снятого контейнера записан")
	assert.Zero(t, w.factsOf(w.usr(w.usrD), pcrRepoType, repo), "975 предки: прямой факт usr-D на репозитории снятого контейнера")
	// Ответ решения здесь не утверждается: ветвь выдач решения судит вложенное
	// правило по рёбрам цепи, а не по материализованным членам, и о потомке снятого
	// контейнера отвечает независимо от гонки — предмет этой пробы только член и
	// факт, которые пишет проход.
}

// Близнец ветви предков: та же остановка без снятия — член записан.
func TestUnregisterVsMirrorRead_AncestorsTwinWritesMember(t *testing.T) {
	w := newP3UWorld(t)
	container, repo, id := w.nestedFixture(9560)
	hold, rec := w.heldRec()
	reached, finished, release := hold.arm(branchAncestors, container)
	w.passAroundUnregister(func() error { return rec.ReconcileObjectForward(w.ctx, "registry.repositories", repo) },
		reached, finished, release, "", "975 предки близнец")

	assert.NotZero(t, w.membersOn(id, repo), "975 предки близнец: член по репозиторию не записан")
	assert.True(t, w.ask(w.usr(w.usrD), "v_get", pcrRepoType, repo), "975 предки близнец: usr-D не читает репозиторий")
}

// ── кольцо: роль с именем ключа и отбор по области ───────────────────────────

// Проход держит выдачу и её роль (правило по области и правило с именем ключа) и
// стоит после чтения области; снятие регистрации запирает роли с именем ключа.
// Замок строки зеркала, который проход берёт перед записью члена, и замок роли,
// который берёт снятие, обязаны идти в одном порядке родов — выдачи, роли,
// зеркало, — иначе стороны сходятся в кольцо и Postgres снимает одну из них
// (40P01). Исход — как у последовательного выполнения: роль не называет ключ,
// члена и факта по снятому ключу нет.
func TestUnregisterVsMirrorRead_RoleNamingKeyAndScopeNoDeadlock(t *testing.T) {
	w := newURXWorld(t)
	key := raceKey(9570, 0)
	w.registerRegistry(key)
	role := w.seedRole("uo_scope_and_name", domain.Rules{
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}},
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"list"}, ResourceNames: []string{key}},
	})
	id := w.unmaterializedGrant(role, ndAllInScope(), "975 кольцо: выдача роли с областью и именем ключа")
	require.Zero(t, w.membersOn(id, key), "975 кольцо: фикстура — у выдачи уже есть член на ключе")
	hold, rec := w.heldRec()
	reached, finished, release := hold.arm(branchScope, key)

	pass := make(chan error, 1)
	go func() { pass <- rec.ReconcileBindingForward(w.ctx, domain.AccessBindingID(id)) }()
	select {
	case <-reached:
	case <-time.After(30 * time.Second):
		t.Fatal("975 кольцо: проход не дошёл до чтения области")
	}
	done := make(chan error, 1)
	go func() { done <- w.withdrawErr(w.ctx, key) }()
	blocked, unregErr := awaitStalledOrDone(t, w.ctx, w.pool, done)
	release()
	passErr := <-pass
	<-finished
	if blocked {
		unregErr = <-done
	}
	t.Logf("975 кольцо: снятие встало на замке: %v; отказ снятия: %v; отказ прохода: %v", blocked, unregErr, passErr)

	assert.Falsef(t, isDeadlockRefusal(unregErr), "975 кольцо: снятие регистрации получило отказ взаимной блокировки: %v", unregErr)
	assert.Falsef(t, isDeadlockRefusal(passErr), "975 кольцо: проход получил отказ взаимной блокировки: %v", passErr)
	require.NoError(t, unregErr, "975 кольцо: снятие регистрации")
	require.NoError(t, passErr, "975 кольцо: проход")
	names, ok := w.roleNames(role)
	require.True(t, ok, "975 кольцо: роли нет")
	assert.NotContains(t, names, key, "975 кольцо: роль называет снятый ключ")
	assert.Zero(t, w.membersOn(id, key), "975 кольцо: член по снятому ключу")
	assert.Zero(t, w.factsOf(w.usr(w.usrD), pcrRegType, key), "975 кольцо: прямой факт usr-D на снятом ключе")
	assert.False(t, w.ask(w.usr(w.usrD), "v_get", pcrRegType, key), "975 кольцо: usr-D читает снятый ключ")
}
