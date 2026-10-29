// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_forward_expiry_race_integration_test.go — аддитивный форвард и
// истечение срока ОДНОЙ выдачи, идущие одновременно (kaname#919).
//
// ПРЕДМЕТ. Форвард читает факты выдачи, видит её ACTIVE и пишет члена, запись
// реестра и строку журнала, из которой триггер складывает прямой факт.
// Истечение срока снимает выдачу: переводит её в REVOKED, читает членов и
// снимает их кортежи. Если члены форварда легли в базу ПОСЛЕ того, как
// истечение прочитало набор членов, снимать их больше некому: полный проход
// и сведение пропускают не-ACTIVE выдачу, а прямой факт вердикт читает и без
// выдачи. Срок у такого доступа исчезает.
//
// ФОРМА ПРОБЫ. Порядок задаётся, а не угадывается: форвард идёт настоящим
// кодом реконсайлера, а хранилище, которое он получает, останавливает его
// СРАЗУ ПОСЛЕ чтения фактов выдачи — ровно в том месте, где проход уже решил
// «выдача жива», но ещё ничего не записал. В этот момент запускается
// настоящее истечение. Дальше два исхода, и оба проба принимает:
//   - истечение прошло, не дожидаясь форварда (так было до починки), —
//     форвард отпускается после него;
//   - истечение встало на замке строки выдачи (так после починки) — форвард
//     отпускается, и истечение доходит до конца после его коммита.
//
// Утверждается не порядок, а ИСХОД: после обоих выдача снята и у неё нет ни
// одного члена, ни одной записи реестра и ни одного прямого факта. Ожидание
// истечения проба наблюдает в pg_stat_activity, а не временем: «встало на
// замке» — это строка бэкенда с wait_event_type = 'Lock'.
//
// ЗАКОННЫЙ БЛИЗНЕЦ — тот же форвард в той же остановке, но без истечения:
// после отпускания он обязан материализовать объект, как прежде. Без него
// пустота после гонки была бы неотличима от форварда, который не пишет ничего.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// expiryRaceBudget — сколько проба ждёт каждого шага гонки. Здоровый шаг на
// пустой базе — миллисекунды; исчерпание бюджета означает зависание, а не
// медленную машину.
const expiryRaceBudget = 20 * time.Second

// pausingTx — исполнитель транзакций реконсайлера, чьё хранилище
// останавливает проход сразу после чтения фактов выдачи.
type pausingTx struct {
	inner   *kanamepg.ReconcileAdapter
	paused  chan struct{}
	resume  chan struct{}
	once    sync.Once
	release sync.Once
}

func newPausingTx(inner *kanamepg.ReconcileAdapter) *pausingTx {
	return &pausingTx{inner: inner, paused: make(chan struct{}), resume: make(chan struct{})}
}

func (p *pausingTx) WithTx(ctx context.Context, fn func(ctx context.Context, s reconcile.ReconcileStore) error) error {
	return p.inner.WithTx(ctx, func(ctx context.Context, s reconcile.ReconcileStore) error {
		return fn(ctx, &pausingStore{ReconcileStore: s, p: p})
	})
}

// stop — остановка один раз за пробу: второй проход (делегирование полному
// пути) останавливать незачем.
func (p *pausingTx) stop() {
	p.once.Do(func() {
		close(p.paused)
		<-p.resume
	})
}

// let — отпустить остановленный форвард. Однократно: зовётся и телом пробы, и
// снятием пробы — проба, упавшая до отпускания, иначе оставила бы горутину форварда
// с открытым соединением, и закрытие пула ждало бы её до таймаута прогона.
func (p *pausingTx) let() {
	p.release.Do(func() { close(p.resume) })
}

// pausingStore — настоящее хранилище; переопределены только чтения фактов
// выдачи, которыми форвард решает «выдача жива».
type pausingStore struct {
	reconcile.ReconcileStore
	p *pausingTx
}

func (s *pausingStore) LoadBindingsForForward(ctx context.Context, ids []domain.AccessBindingID) (map[domain.AccessBindingID]reconcile.BindingScope, error) {
	out, err := s.ReconcileStore.LoadBindingsForForward(ctx, ids)
	if err == nil {
		s.p.stop()
	}
	return out, err
}

func (s *pausingStore) LoadBindingForForward(ctx context.Context, id domain.AccessBindingID) (reconcile.BindingScope, bool, error) {
	out, ok, err := s.ReconcileStore.LoadBindingForForward(ctx, id)
	if err == nil {
		s.p.stop()
	}
	return out, ok, err
}

// waitDeactivationOutcome — ждёт, пока снятие (истечение, отзыв, удаление) либо
// завершится, либо встанет на строчном замке. Возвращает true, если оно завершилось.
func waitDeactivationOutcome(t *testing.T, ctx context.Context, pool *pgxpool.Pool, done <-chan error) (finished bool, err error) {
	t.Helper()
	deadline := time.NewTimer(expiryRaceBudget)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			return true, err
		case <-deadline.C:
			t.Fatalf("снятие не завершилось и не встало на замке за %s", expiryRaceBudget)
			return false, nil
		case <-tick.C:
			var n int
			require.NoError(t, pool.QueryRow(ctx, `
				SELECT count(*) FROM pg_stat_activity
				 WHERE datname = current_database() AND wait_event_type = 'Lock'
				   AND query ILIKE '%access_bindings%'`).Scan(&n))
			if n > 0 {
				return false, nil
			}
		}
	}
}

// bindingResidue — что осталось у выдачи: члены, записи реестра, прямые факты
// субъекта на объекте.
func bindingResidue(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bid domain.AccessBindingID, subj, objType, objID string) (members, ledger, facts int) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id = $1`,
		string(bid)).Scan(&members))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1`,
		string(bid)).Scan(&ledger))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.relation_fact
		  WHERE object_type = $1 AND object_id = $2 AND subject = $3`,
		objType, objID, subj).Scan(&facts))
	return members, ledger, facts
}

func bindingStatus(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bid domain.AccessBindingID) string {
	t.Helper()
	var st string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT status FROM kaname.access_bindings WHERE id = $1`, string(bid)).Scan(&st))
	return st
}

// forwardKind — какой из двух аддитивных форвардов гонится с истечением.
type forwardKind int

const (
	objectForward forwardKind = iota
	bindingForward
)

// deactivation — какое снятие выдачи запускается в паузу форварда.
type deactivation int

const (
	noDeactivation deactivation = iota
	expiryDeactivation
	revokeDeactivation
	deleteDeactivation
	// projectDeleteDeactivation, accountDeleteDeactivation — снос ОБЛАСТИ, на которую
	// сделана выдача (shared.RevokeBindingsInScope): четвёртый путь снятия выдачи.
	projectDeleteDeactivation
	accountDeleteDeactivation
)

func (d deactivation) String() string {
	switch d {
	case expiryDeactivation:
		return "истечение"
	case revokeDeactivation:
		return "отзыв"
	case deleteDeactivation:
		return "удаление"
	case projectDeleteDeactivation:
		return "удаление проекта"
	case accountDeleteDeactivation:
		return "удаление аккаунта"
	default:
		return "без снятия"
	}
}

// raceFixture — на что сделана выдача гонки и какой ролью.
type raceFixture int

const (
	// projectRoleFixture — выдача на проект ролью этого проекта (снятия выдачи и истечение).
	projectRoleFixture raceFixture = iota
	// projectScopeFixture — выдача на проект СИСТЕМНОЙ ролью: роль проекта держала бы
	// удаление проекта ключом roles_project_fk (RESTRICT), и снос области не дошёл бы
	// до выдач.
	projectScopeFixture
	// accountScopeFixture — выдача на аккаунт системной ролью, объект под аккаунтом
	// без проекта: аккаунт с проектами и ролями продукт не снимает (RESTRICT).
	accountScopeFixture
)

// fixtureFor — фикстура, на которой снятие deact вообще исполнимо.
func fixtureFor(deact deactivation) raceFixture {
	switch deact {
	case projectDeleteDeactivation:
		return projectScopeFixture
	case accountDeleteDeactivation:
		return accountScopeFixture
	default:
		return projectRoleFixture
	}
}

// seedSystemRulesRole — системная роль правил (ярус кластера): её строка не держит
// ни проект, ни аккаунт, и снос области ей не мешает. Имя — форма системной роли
// (roles_system_name_check: первый сегмент без подчёркивания).
func seedSystemRulesRole(t *testing.T, ctx context.Context, repo *kanamepg.Repository, name string, rules domain.Rules) domain.RoleID {
	t.Helper()
	compiled, err := domain.CompileRules(rules)
	require.NoError(t, err)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	// Системную строку пишет писатель системных ролей: Insert ведёт только
	// пользовательский ярус (cluster_id у него пуст by construction).
	inserted, _, err := w.RolesW().UpsertSystemRole(ctx, domain.Role{
		ID: domain.RoleID(ids.NewID(domain.PrefixRole)), ClusterID: domain.ClusterSingletonID,
		Name: domain.RoleName(name), Description: domain.Description("system rules role " + name),
		Rules: rules, Permissions: compiled,
	})
	require.NoError(t, err, "системная роль правил %s", name)
	require.NoError(t, w.RolesW().ReplaceRuleSelectors(ctx, inserted.ID,
		catalogfixture.Facts().GrantSelectors(inserted.Rules.MaterializingSelectors(), domain.TenantPolicy())))
	require.NoError(t, w.Commit(ctx))
	return inserted.ID
}

// seedRaceBinding — выдача гонки, объект под её областью и субъект, чей прямой факт
// судится.
func seedRaceBinding(t *testing.T, ctx context.Context, pool *pgxpool.Pool, fx gammaFixture, suffix string, fix raceFixture) (domain.AccessBindingID, string) {
	t.Helper()
	subj := "user:" + string(fx.member)
	switch fix {
	case projectScopeFixture, accountScopeFixture:
		// Роль проекта фикстуры (gammaFixture.role) — единственное, что держит проект.
		_, err := pool.Exec(ctx, `DELETE FROM kaname.roles WHERE id = $1`, string(fx.role))
		require.NoError(t, err, "ПРЕДПОСЫЛКА: роль проекта фикстуры снимается до гонки")
		roleID := seedSystemRulesRole(t, ctx, fx.repo, "sys-"+suffix, domain.Rules{forwardAnchorRule()})
		if fix == projectScopeFixture {
			bid := insertThinBindingScope(t, ctx, fx.repo, fx.member, roleID, "project", string(fx.prj), domain.ScopeProject)
			seedMirrorRow(t, ctx, pool, "compute.instance", "iRace", string(fx.prj), string(fx.accID), nil, time.Now())
			return bid, subj
		}
		_, err = pool.Exec(ctx, `DELETE FROM kaname.projects WHERE account_id = $1`, string(fx.accID))
		require.NoError(t, err, "ПРЕДПОСЫЛКА: аккаунт с проектами не снимается — проекты фикстуры снимаются до гонки")
		bid := insertThinBindingScope(t, ctx, fx.repo, fx.member, roleID, "account", string(fx.accID), domain.ScopeAccount)
		seedMirrorRow(t, ctx, pool, "compute.instance", "iRace", "", string(fx.accID), nil, time.Now())
		return bid, subj
	default:
		roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, suffix+"role", domain.Rules{forwardAnchorRule()})
		bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
		seedMirrorRow(t, ctx, pool, "compute.instance", "iRace", string(fx.prj), string(fx.accID), nil, time.Now())
		return bid, subj
	}
}

// unregisterRaceObjectFor — удаление проекта продукт отвергает, пока под проектом
// зарегистрирован объект зеркала («Project … is not empty»). Поэтому перед сносом
// проекта объект гонки снимается с регистрации — ПОСЛЕ того, как форвард его
// прочитал: так же снятие регистрации, обогнавшее форвард в полёте, оставляет
// проект пустым, а запись форварда — за его выдачей.
func unregisterRaceObjectFor(t *testing.T, ctx context.Context, pool *pgxpool.Pool, deact deactivation) {
	t.Helper()
	if deact != projectDeleteDeactivation {
		return
	}
	_, err := pool.Exec(ctx,
		`DELETE FROM kaname.resource_mirror WHERE object_type = 'compute.instance' AND object_id = 'iRace'`)
	require.NoError(t, err, "ПРЕДПОСЫЛКА: объект гонки снимается с регистрации до сноса проекта")
}

// startDeactivation — запустить снятие deact и вернуть канал его исхода.
func startDeactivation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, expirer *reconcile.Reconciler, fx gammaFixture, bid domain.AccessBindingID, deact deactivation) <-chan error {
	t.Helper()
	switch deact {
	case noDeactivation:
		return nil
	case expiryDeactivation:
		ch := make(chan error, 1)
		go func() { ch <- expirer.ExpireBinding(ctx, bid) }()
		return ch
	default:
		return startUseCaseDeactivation(t, ctx, pool, fx, bid, deact)
	}
}

// runForwardDeactivationRace — форвард останавливается после чтения фактов
// выдачи; deact решает, какое снятие запускается в эту паузу.
func runForwardDeactivationRace(t *testing.T, kind forwardKind, suffix string, deact deactivation) (pool *pgxpool.Pool, bid domain.AccessBindingID, subj string) {
	t.Helper()
	return runForwardDeactivationRaceOn(t, kind, suffix, fixtureFor(deact), deact)
}

// runForwardDeactivationRaceOn — то же на явно названной фикстуре: близнецы сноса
// области гонят её без снятия.
func runForwardDeactivationRaceOn(t *testing.T, kind forwardKind, suffix string, fix raceFixture, deact deactivation) (pool *pgxpool.Pool, bid domain.AccessBindingID, subj string) {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	fx := setupGamma(t, ctx, pool, suffix)
	_, adapter := newReconciler(pool)
	expirer := reconcile.New(adapter, nil, catalogfixture.Source())
	ptx := newPausingTx(adapter)
	// Снятие регистрируется ПОСЛЕ закрытия пула и потому исполняется ДО него.
	t.Cleanup(ptx.let)
	forwarder := reconcile.New(ptx, nil, catalogfixture.Source())

	bid, subj = seedRaceBinding(t, ctx, pool, fx, suffix, fix)

	fwdDone := make(chan error, 1)
	go func() {
		if kind == bindingForward {
			fwdDone <- forwarder.ReconcileBindingForward(ctx, bid)
			return
		}
		fwdDone <- forwarder.ReconcileObjectForward(ctx, "compute.instance", "iRace")
	}()
	select {
	case <-ptx.paused:
	case err := <-fwdDone:
		t.Fatalf("ПРЕДПОСЫЛКА: форвард завершился (%v), не дойдя до чтения фактов выдачи — гонке не о чем", err)
	case <-time.After(expiryRaceBudget):
		t.Fatalf("ПРЕДПОСЫЛКА: форвард не дошёл до чтения фактов выдачи за %s", expiryRaceBudget)
	}

	unregisterRaceObjectFor(t, ctx, pool, deact)
	expDone := startDeactivation(t, ctx, pool, expirer, fx, bid, deact)
	if expDone != nil {
		finished, err := waitDeactivationOutcome(t, ctx, pool, expDone)
		if finished {
			require.NoError(t, err, deact.String())
			t.Logf("исход: снятие (%s) завершилось, не дожидаясь форварда", deact)
			expDone = nil
		} else {
			t.Logf("исход: снятие (%s) встало на строчном замке выдачи до коммита форварда", deact)
		}
	}

	ptx.let()
	select {
	case err := <-fwdDone:
		require.NoError(t, err, "форвард")
	case <-time.After(expiryRaceBudget):
		t.Fatalf("форвард не завершился за %s после отпускания", expiryRaceBudget)
	}
	if expDone != nil {
		select {
		case err := <-expDone:
			require.NoError(t, err, deact.String()+" после коммита форварда")
		case <-time.After(expiryRaceBudget):
			t.Fatalf("снятие (%s) не завершилось за %s после коммита форварда", deact, expiryRaceBudget)
		}
	}
	return pool, bid, subj
}

// TestForwardVsExpiry_01_ObjectForwardLeavesNothingOnExpiredBinding —
// объектный форвард против истечения: после обоих у выдачи нет ничего.
func TestForwardVsExpiry_01_ObjectForwardLeavesNothingOnExpiredBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, bid, subj := runForwardDeactivationRace(t, objectForward, "fx919a", expiryDeactivation)
	assert.Equal(t, string(domain.AccessBindingStatusRevoked), bindingStatus(t, ctx, pool, bid))
	members, ledger, facts := bindingResidue(t, ctx, pool, bid, subj, "compute_instance", "iRace")
	assert.Zero(t, members, "у снятой выдачи остались члены, записанные форвардом")
	assert.Zero(t, ledger, "у снятой выдачи остались записи реестра, записанные форвардом")
	assert.Zero(t, facts, "у субъекта снятой выдачи остался прямой факт на объекте — доступ без срока")
}

// TestForwardVsExpiry_02_ObjectForwardTwinMaterializesWithoutExpiry — близнец
// 01: та же остановка без истечения — форвард пишет как прежде.
func TestForwardVsExpiry_02_ObjectForwardTwinMaterializesWithoutExpiry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, bid, subj := runForwardDeactivationRace(t, objectForward, "fx919b", noDeactivation)
	assert.Equal(t, string(domain.AccessBindingStatusActive), bindingStatus(t, ctx, pool, bid))
	members, ledger, facts := bindingResidue(t, ctx, pool, bid, subj, "compute_instance", "iRace")
	assert.Positive(t, members, "близнец: форвард без истечения материализует члена")
	assert.Positive(t, ledger, "близнец: форвард без истечения пишет реестр")
	assert.Positive(t, facts, "близнец: форвард без истечения даёт прямой факт — иначе ноль в 01 ни о чём")
}

// TestForwardVsExpiry_03_BindingForwardLeavesNothingOnExpiredBinding — тот же
// класс на форварде СОЗДАНИЯ выдачи (ReconcileBindingForward).
func TestForwardVsExpiry_03_BindingForwardLeavesNothingOnExpiredBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, bid, subj := runForwardDeactivationRace(t, bindingForward, "fx919c", expiryDeactivation)
	assert.Equal(t, string(domain.AccessBindingStatusRevoked), bindingStatus(t, ctx, pool, bid))
	members, ledger, facts := bindingResidue(t, ctx, pool, bid, subj, "compute_instance", "iRace")
	assert.Zero(t, members, "у снятой выдачи остались члены, записанные форвардом создания")
	assert.Zero(t, ledger, "у снятой выдачи остались записи реестра, записанные форвардом создания")
	assert.Zero(t, facts, "у субъекта снятой выдачи остался прямой факт на объекте — доступ без срока")
}

// TestForwardVsExpiry_04_BindingForwardTwinMaterializesWithoutExpiry — близнец 03.
func TestForwardVsExpiry_04_BindingForwardTwinMaterializesWithoutExpiry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, bid, subj := runForwardDeactivationRace(t, bindingForward, "fx919d", noDeactivation)
	assert.Equal(t, string(domain.AccessBindingStatusActive), bindingStatus(t, ctx, pool, bid))
	members, ledger, facts := bindingResidue(t, ctx, pool, bid, subj, "compute_instance", "iRace")
	assert.Positive(t, members, "близнец: форвард создания без истечения материализует члена")
	assert.Positive(t, ledger, "близнец: форвард создания без истечения пишет реестр")
	assert.Positive(t, facts, "близнец: форвард создания без истечения даёт прямой факт")
}
