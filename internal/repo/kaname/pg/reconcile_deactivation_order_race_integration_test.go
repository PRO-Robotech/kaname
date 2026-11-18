// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_deactivation_order_race_integration_test.go — снятие выдачи против
// аддитивного форварда в ОБОИХ порядках начала транзакций, на каждом пути снятия
// (kaname#919, kaname#923).
//
// # Предмет
//
// Пробы reconcile_forward_expiry_race_integration_test.go и
// reconcile_forward_deactivation_race_integration_test.go ставят ПЕРВЫЙ порядок:
// форвард открыл транзакцию и прочитал факты выдачи раньше, чем началось снятие.
// Исход снятия решает не только замок строки выдачи, но и ВЕРСИЯ строки журнала
// намерений: прямой факт снимается строкой снятия лишь тогда, когда его версия не
// новее версии этой строки (свёртка журнала, kaname.relation_fact_fold_row). Версия
// строки без поля владельца — метка created_at. Если эта метка — момент НАЧАЛА
// транзакции, то снятие, открывшее транзакцию раньше форварда и дошедшее до
// чтения реестра после его коммита, пишет строку старше факта, который обязано
// снять, и факт его переживает — доступ без выдачи. Это ВТОРОЙ порядок, и он
// ставится здесь.
//
// # Как поставлен второй порядок
//
// Отзыв, удаление и снос проекта первым
// блокирующим шагом по выдаче берут её advisory-замок (тот же ключ, что у полного
// прохода). Проба держит этот замок своей транзакцией, запускает НАСТОЯЩЕЕ снятие
// и ждёт, пока его бэкенд встанет на замке, — транзакция снятия к этому моменту
// открыта. В этой паузе форвард проходит целиком: берёт строку выдачи и
// фиксируется. Затем замок отпускается, и снятие доходит до конца. Снятие, не
// вставшее на замке, — отказ ПРЕДПОСЫЛКИ, а не исход: второй порядок тогда не
// поставлен. Для истечения и сноса аккаунта пауза стоит в уже открытой TX
// до admission: unsigned admission сериализует legacy writers, поэтому держать
// его у снятия и ждать форвард до освобождения binding lock означало бы цикл
// самой пробы. Начало TX и более поздний durable факт подтверждаются в БД.
//
// # Что утверждается
//
// ИСХОД, тот же, что у первого порядка: прямых фактов субъекта на объекте ноль;
// у удалённой выдачи нет ни строки, ни членов, ни реестра. Законный близнец стоит
// В САМОМ ПРОГОНЕ: после коммита форварда и до отпускания замка прямой факт обязан
// быть — иначе ноль после снятия был бы неотличим от форварда, не написавшего
// ничего.
//
// Здесь же — первый порядок для сноса области (удаление проекта и аккаунта,
// shared.RevokeBindingsInScope) с близнецами без снятия на тех же фикстурах.
// Удаление проекта продукт отвергает, пока под ним зарегистрирован объект, поэтому
// объект гонки снимается с регистрации после того, как форвард его прочитал
// (unregisterRaceObjectFor). Форвард СОЗДАНИЯ выдачи читает объекты области уже
// после остановки пробы, и в первом порядке снятие регистрации отняло бы у него
// предмет — пара «удаление проекта × форвард создания» поэтому стоит только во
// втором порядке (16), где форвард проходит целиком до снятия регистрации.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// waitAdvisoryWaiter — ждёт, пока снятие встанет на advisory-замке выдачи.
// Завершившееся раньше снятие — отказ предпосылки: второй порядок не поставлен.
func waitAdvisoryWaiter(t *testing.T, ctx context.Context, pool *pgxpool.Pool, done <-chan error, deact deactivation) {
	t.Helper()
	deadline := time.NewTimer(expiryRaceBudget)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			t.Fatalf("ПРЕДПОСЫЛКА: снятие (%s) завершилось (%v), не встав на advisory-замке выдачи, — второй порядок не поставлен", deact, err)
		case <-deadline.C:
			t.Fatalf("ПРЕДПОСЫЛКА: снятие (%s) не встало на advisory-замке выдачи за %s", deact, expiryRaceBudget)
		case <-tick.C:
			var n int
			require.NoError(t, pool.QueryRow(ctx, `
				SELECT count(*) FROM pg_stat_activity
				 WHERE datname = current_database()
				   AND wait_event_type = 'Lock' AND wait_event = 'advisory'`).Scan(&n))
			if n > 0 {
				return
			}
		}
	}
}

// runDeactivationFirstRace — второй порядок: снятие открывает транзакцию раньше
// форварда, форвард берёт строку выдачи и фиксируется раньше снятия.
func runDeactivationFirstRace(t *testing.T, kind forwardKind, suffix string, deact deactivation) (pool *pgxpool.Pool, bid domain.AccessBindingID, subj string) {
	t.Helper()
	if deact == accountDeleteDeactivation {
		return runAccountDeactivationEntryPauseRace(t, kind, suffix)
	}
	if deact == expiryDeactivation {
		return runExpiryDeactivationEntryPauseRace(t, kind, suffix)
	}
	ctx := context.Background()
	firstError := &raceFirstPGError{}
	pool = raceTracingPool(t, ctx, firstError)
	// Снимок первой исходной ошибки печатается до pool.Close. Он не меняет
	// результат операции и не подменяет прежние assertions кодом SQLSTATE.
	t.Cleanup(func() { firstError.report(t) })
	fx := setupGamma(t, ctx, pool, suffix)
	forwarder, adapter := newReconciler(pool)
	expirer := reconcile.New(adapter, nil, catalogfixture.Source())
	bid, subj = seedRaceBinding(t, ctx, pool, fx, suffix, fixtureFor(deact))

	holder, err := pool.Begin(ctx)
	require.NoError(t, err)
	// Снятие регистрируется ПОСЛЕ закрытия пула и потому исполняется ДО него; после
	// коммита откат — no-op.
	t.Cleanup(func() { _ = holder.Rollback(context.Background()) })
	_, err = holder.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, string(bid))
	require.NoError(t, err, "ПРЕДПОСЫЛКА: проба держит advisory-замок выдачи")

	done := startDeactivation(t, context.WithValue(ctx, raceFirstPGErrorKey{}, firstError), pool, expirer, fx, bid, deact)
	waitAdvisoryWaiter(t, ctx, pool, done, deact)

	if kind == bindingForward {
		require.NoError(t, forwarder.ReconcileBindingForward(ctx, bid), "форвард создания в паузе снятия")
	} else {
		require.NoError(t, forwarder.ReconcileObjectForward(ctx, "compute.instance", "iRace"), "форвард объекта в паузе снятия")
	}
	_, _, facts := bindingResidue(t, ctx, pool, bid, subj, "compute_instance", "iRace")
	require.Positive(t, facts, "БЛИЗНЕЦ В ПРОГОНЕ: форвард, зафиксированный раньше снятия, обязан дать прямой факт — иначе ноль после снятия ни о чём")
	unregisterRaceObjectFor(t, ctx, pool, deact)

	require.NoError(t, holder.Commit(ctx))
	select {
	case err := <-done:
		require.NoError(t, err, "%s после коммита форварда", deact)
	case <-time.After(2 * expiryRaceBudget):
		t.Fatalf("снятие (%s) не завершилось за %s после отпускания замка", deact, 2*expiryRaceBudget)
	}
	return pool, bid, subj
}

// runExpiryDeactivationEntryPauseRace сохраняет второй порядок НАЧАЛА TX,
// не требуя обхода обязательного admission. Существующий адресный tracer
// останавливает только контекст истечения; SQL в callback tracer не выполняется.
func runExpiryDeactivationEntryPauseRace(t *testing.T, kind forwardKind, suffix string) (*pgxpool.Pool, domain.AccessBindingID, string) {
	t.Helper()
	ctx := context.Background()
	setupCtx, setupCancel := context.WithTimeout(ctx, 30*time.Second)
	defer setupCancel()
	pause := &accountEntryPause{sql: "SELECT kaname.authority_reconcile_enter_v3()", entered: make(chan struct{}), release: make(chan struct{})}
	pool := accountEntryPausePool(t, setupCtx, pause)
	fx := setupGamma(t, setupCtx, pool, suffix)
	forwarder, adapter := newReconciler(pool)
	expirer := reconcile.New(adapter, nil, catalogfixture.Source())
	bid, subj := seedRaceBinding(t, setupCtx, pool, fx, suffix, fixtureFor(expiryDeactivation))

	expiryCtx, expiryCancel := context.WithTimeout(ctx, 30*time.Second)
	defer expiryCancel()
	expiryCtx = context.WithValue(expiryCtx, accountEntryPauseKey{}, pause)
	done := make(chan error, 1)
	finished := make(chan struct{})
	// Отмена, освобождение барьера и join установлены до старта worker и assertions.
	// Cleanup исполняется до pool.Close, даже если предпосылка оказалась ложной.
	t.Cleanup(func() {
		expiryCancel()
		pause.let()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("истечение не завершилось после отмены и освобождения entry")
		}
	})
	go func() {
		defer close(finished)
		done <- expirer.ExpireBinding(expiryCtx, bid)
	}()
	select {
	case <-pause.entered:
	case err := <-done:
		t.Fatalf("ПРЕДПОСЫЛКА: истечение завершилось до остановки admission: %v", err)
	case <-time.After(expiryRaceBudget):
		t.Fatalf("ПРЕДПОСЫЛКА: истечение не дошло до admission за %s", expiryRaceBudget)
	}

	observeCtx, observeCancel := context.WithTimeout(ctx, expiryRaceBudget)
	// Трассировщик видит внешний reconcile entry ДО отправки: вложенный
	// parent-prelock внутри серверной функции не является pgx callback.
	var expiryStart time.Time
	var idle, noOtherLocks bool
	err := pool.QueryRow(observeCtx, `SELECT a.xact_start,
 a.state='idle in transaction',
 NOT EXISTS(SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=a.pid
  AND l.locktype IN ('advisory','relation','tuple'))
 FROM pg_catalog.pg_stat_activity a
 WHERE a.pid=$1 AND a.datname=current_database() AND a.xact_start IS NOT NULL`,
		pause.pid.Load()).Scan(&expiryStart, &idle, &noOtherLocks)
	observeCancel()
	require.NoError(t, err)
	require.True(t, idle, "ПРЕДПОСЫЛКА: настоящая expiry TX уже началась")
	require.True(t, noOtherLocks, "ПРЕДПОСЫЛКА: до внешнего reconcile entry нет root, compat или бизнес-замков")

	forward := func() error {
		requestCtx, cancel := context.WithTimeout(ctx, expiryRaceBudget)
		defer cancel()
		if kind == bindingForward {
			return forwarder.ReconcileBindingForward(requestCtx, bid)
		}
		return forwarder.ReconcileObjectForward(requestCtx, "compute.instance", "iRace")
	}
	require.NoError(t, forward(), "реальный форвард коммитит в паузе expiry TX")
	select {
	case err := <-done:
		t.Fatalf("ПРЕДПОСЫЛКА: истечение завершилось до отпускания admission: %v", err)
	default:
	}
	observeCtx, observeCancel = context.WithTimeout(ctx, expiryRaceBudget)
	defer observeCancel()
	_, _, facts := bindingResidue(t, observeCtx, pool, bid, subj, "compute_instance", "iRace")
	require.Positive(t, facts, "БЛИЗНЕЦ В ПРОГОНЕ: до снятия форвард действительно создал прямой факт")
	var later bool
	err = pool.QueryRow(observeCtx, `SELECT count(*)>0 AND bool_and(created_at>$3)
 FROM kaname.fga_outbox WHERE event_type='fga.tuple.write'
 AND payload->>'user'=$1 AND payload->>'object'=$2`, subj, "compute_instance:iRace", expiryStart).Scan(&later)
	observeCancel()
	require.NoError(t, err)
	require.True(t, later, "ПРЕДПОСЫЛКА: durable запись форварда новее начала expiry TX")

	pause.let()
	select {
	case err := <-done:
		require.NoError(t, err, "истечение после коммита форварда")
	case <-time.After(2 * expiryRaceBudget):
		t.Fatalf("истечение не завершилось за %s после отпускания entry", 2*expiryRaceBudget)
	}
	// Первый исход проверяется ДО повторов: они не вправе исправить ошибку гонки.
	assertDeactivated(t, pool, bid, subj, expiryDeactivation)
	retryCtx, retryCancel := context.WithTimeout(ctx, expiryRaceBudget)
	err = expirer.ExpireBinding(retryCtx, bid)
	retryCancel()
	require.NoError(t, err, "повтор истечения остаётся идемпотентным")
	require.NoError(t, forward(), "повтор форварда не воскрешает истёкшую выдачу")
	assertDeactivated(t, pool, bid, subj, expiryDeactivation)
	return pool, bid, subj
}

// assertDeactivated — исход снятия: прямых фактов ноль; отзыв и истечение оставляют
// строку REVOKED, удаление и снос области — ни строки, ни членов, ни реестра.
func assertDeactivated(t *testing.T, pool *pgxpool.Pool, bid domain.AccessBindingID, subj string, deact deactivation) {
	t.Helper()
	ctx := context.Background()
	members, ledger, facts := bindingResidue(t, ctx, pool, bid, subj, "compute_instance", "iRace")
	switch deact {
	case revokeDeactivation:
		assert.Equal(t, string(domain.AccessBindingStatusRevoked), bindingStatus(t, ctx, pool, bid))
	case expiryDeactivation:
		assert.Equal(t, string(domain.AccessBindingStatusRevoked), bindingStatus(t, ctx, pool, bid))
		assert.Zero(t, members, "у истёкшей выдачи остались члены, записанные форвардом")
		assert.Zero(t, ledger, "у истёкшей выдачи остались записи реестра, записанные форвардом")
	default:
		assert.Zero(t, bindingRows(t, ctx, pool, bid), "%s обязано снять строку выдачи", deact)
		assert.Zero(t, members, "у снятой (%s) выдачи остались члены, записанные форвардом", deact)
		assert.Zero(t, ledger, "у снятой (%s) выдачи остались записи реестра, записанные форвардом", deact)
	}
	assert.Zero(t, facts, "после снятия (%s) у субъекта остался прямой факт, записанный форвардом, — доступ без выдачи", deact)
}

func skipShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
}

// ── второй порядок: снятие открыло транзакцию раньше форварда ────────────────

func TestDeactivationFirst_09_RevokeVsObjectForward(t *testing.T) {
	skipShort(t)
	pool, bid, subj := runDeactivationFirstRace(t, objectForward, "fx919e", revokeDeactivation)
	assertDeactivated(t, pool, bid, subj, revokeDeactivation)
}

func TestDeactivationFirst_10_RevokeVsBindingForward(t *testing.T) {
	skipShort(t)
	pool, bid, subj := runDeactivationFirstRace(t, bindingForward, "fx919f", revokeDeactivation)
	assertDeactivated(t, pool, bid, subj, revokeDeactivation)
}

func TestDeactivationFirst_11_DeleteVsObjectForward(t *testing.T) {
	skipShort(t)
	pool, bid, subj := runDeactivationFirstRace(t, objectForward, "fx919g", deleteDeactivation)
	assertDeactivated(t, pool, bid, subj, deleteDeactivation)
}

func TestDeactivationFirst_12_DeleteVsBindingForward(t *testing.T) {
	skipShort(t)
	pool, bid, subj := runDeactivationFirstRace(t, bindingForward, "fx919h", deleteDeactivation)
	assertDeactivated(t, pool, bid, subj, deleteDeactivation)
}

func TestDeactivationFirst_13_ExpiryVsObjectForward(t *testing.T) {
	skipShort(t)
	pool, bid, subj := runDeactivationFirstRace(t, objectForward, "fx919i", expiryDeactivation)
	assertDeactivated(t, pool, bid, subj, expiryDeactivation)
}

func TestDeactivationFirst_14_ExpiryVsBindingForward(t *testing.T) {
	skipShort(t)
	pool, bid, subj := runDeactivationFirstRace(t, bindingForward, "fx919j", expiryDeactivation)
	assertDeactivated(t, pool, bid, subj, expiryDeactivation)
}

func TestDeactivationFirst_15_ProjectDeleteVsObjectForward(t *testing.T) {
	skipShort(t)
	pool, bid, subj := runDeactivationFirstRace(t, objectForward, "fx919k", projectDeleteDeactivation)
	assertDeactivated(t, pool, bid, subj, projectDeleteDeactivation)
}

func TestDeactivationFirst_16_ProjectDeleteVsBindingForward(t *testing.T) {
	skipShort(t)
	pool, bid, subj := runDeactivationFirstRace(t, bindingForward, "fx919l", projectDeleteDeactivation)
	assertDeactivated(t, pool, bid, subj, projectDeleteDeactivation)
}

func TestDeactivationFirst_17_AccountDeleteVsObjectForward(t *testing.T) {
	skipShort(t)
	pool, bid, subj := runDeactivationFirstRace(t, objectForward, "fx919m", accountDeleteDeactivation)
	assertDeactivated(t, pool, bid, subj, accountDeleteDeactivation)
}

func TestDeactivationFirst_18_AccountDeleteVsBindingForward(t *testing.T) {
	skipShort(t)
	pool, bid, subj := runDeactivationFirstRace(t, bindingForward, "fx919n", accountDeleteDeactivation)
	assertDeactivated(t, pool, bid, subj, accountDeleteDeactivation)
}

// ── первый порядок для сноса области: форвард прочитал выдачу раньше ─────────

func TestForwardVsScopeDelete_19_ProjectDeleteVsObjectForward(t *testing.T) {
	skipShort(t)
	pool, bid, subj := runForwardDeactivationRace(t, objectForward, "fx923e", projectDeleteDeactivation)
	assertDeactivated(t, pool, bid, subj, projectDeleteDeactivation)
}

func TestForwardVsScopeDelete_21_AccountDeleteVsObjectForward(t *testing.T) {
	skipShort(t)
	pool, bid, subj := runForwardDeactivationRace(t, objectForward, "fx923g", accountDeleteDeactivation)
	assertDeactivated(t, pool, bid, subj, accountDeleteDeactivation)
}

func TestForwardVsScopeDelete_22_AccountDeleteVsBindingForward(t *testing.T) {
	skipShort(t)
	pool, bid, subj := runForwardDeactivationRace(t, bindingForward, "fx923h", accountDeleteDeactivation)
	assertDeactivated(t, pool, bid, subj, accountDeleteDeactivation)
}

// ── законные близнецы фикстур сноса области: та же остановка без снятия ──────

func TestForwardVsScopeDelete_23_ProjectScopeTwinMaterializes(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	pool, bid, subj := runForwardDeactivationRaceOn(t, objectForward, "fx923i", projectScopeFixture, noDeactivation)
	members, ledger, facts := bindingResidue(t, ctx, pool, bid, subj, "compute_instance", "iRace")
	assert.Positive(t, members, "близнец: форвард на выдаче системной роли проекта материализует члена")
	assert.Positive(t, ledger, "близнец: форвард пишет реестр")
	assert.Positive(t, facts, "близнец: форвард даёт прямой факт — иначе ноль в 19 ни о чём")
}

func TestForwardVsScopeDelete_24_AccountScopeTwinMaterializes(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	pool, bid, subj := runForwardDeactivationRaceOn(t, objectForward, "fx923j", accountScopeFixture, noDeactivation)
	members, ledger, facts := bindingResidue(t, ctx, pool, bid, subj, "compute_instance", "iRace")
	assert.Positive(t, members, "близнец: форвард на выдаче аккаунта материализует члена")
	assert.Positive(t, ledger, "близнец: форвард пишет реестр")
	assert.Positive(t, facts, "близнец: форвард даёт прямой факт — иначе ноль в 21/22 ни о чём")
}
