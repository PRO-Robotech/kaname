// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// migrate_backfill_p8_integration_test.go — интеграционные пробы pg-адаптера
// подмётки и сверки вместе с use-case seed.BackfillRunner / seed.VerifyGate,
// прогоняемые на testcontainers Postgres 16.
//
// Шаг миграции НЕ снимает каскад вывода FGA и scope_grant — это ПОСЛЕДУЮЩАЯ фаза
// контракта (Contract-A снял каскад и scope_grant, Contract-B — мёртвый тип
// организации B2B). Шаг миграции делает лишь:
//   1. дозаполнение выдач владельца для СУЩЕСТВУЮЩИХ счетов (миграция 0036,
//      миграция данных на SQL — идемпотентна частичным UNIQUE живой выдачи;
//      кортежи на объект материализует ПРЯМЫМ путём подмётка сведения ниже).
//   2. ПОДМЁТКА сведения по КАЖДОЙ живой выдаче (одиночный однократный проход
//      под pg_try_advisory_lock уровня сеанса; размер транзакции ограничен
//      порциями). Каждая выдача сводится ТЕМ ЖЕ единственным путём
//      материализации (сверщик) → её кортежи на объект попадают в ведомость.
//   3. страж сверки (непрерывный): у каждой активной выдачи её явные кортежи
//      материализованы (нет потери доступа). Живость прямого пути на свежем
//      объекте утверждает проба P8-05 настоящим сведением, а не страж (#148).
//
// Покрытие:
//   - дозаполнение не теряет доступа оператора (ведомость после него есть).
//   - идемпотентный повтор: повторное дозаполнение → 0 новых выдач владельца,
//     0 дублей кортежей.
//   - подмётка коммутативна и идемпотентна относительно живой прямой
//     материализации (частичный UNIQUE).
//   - согласование реплик: N одновременных RunOnce → подмётку исполняет ровно
//     один (рекомендательная блокировка-одиночка), дублей в ведомости нет.
//   - размер транзакции ограничен порциями (подмётка не сводит все выдачи одной
//     транзакцией).
//   - страж сверки: 100% отсутствия потери доступа; прямой путь на свежем объекте.
//
// Запуск: `make test` (testcontainers и Docker). Под -short пропускается.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// activeOwnerBindingCount считает АКТИВНЫЕ выдачи роли владельца на счёт.
func activeOwnerBindingCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID domain.AccountID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_bindings
		  WHERE role_id = $1 AND resource_type = 'account' AND resource_id = $2
		    AND revoked_at IS NULL`,
		domain.OwnerRoleID, string(accID)).Scan(&n))
	return n
}

// ownerBindingID возвращает id (единственной) живой выдачи владельца на счёт.
func ownerBindingID(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID domain.AccountID) domain.AccessBindingID {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kaname.access_bindings
		  WHERE role_id = $1 AND resource_type = 'account' AND resource_id = $2
		    AND revoked_at IS NULL
		  LIMIT 1`,
		domain.OwnerRoleID, string(accID)).Scan(&id))
	return domain.AccessBindingID(id)
}

// ledgerTupleCount считает строки access_binding_emitted_tuples выдачи.
func ledgerTupleCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bID domain.AccessBindingID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1`,
		string(bID)).Scan(&n))
	return n
}

// ledgerHasTuple сообщает, записан ли у выдачи кортеж (субъект, отношение, объект).
func ledgerHasTuple(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bID domain.AccessBindingID, fgaUser, relation, object string) bool {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_binding_emitted_tuples
		  WHERE binding_id = $1 AND fga_user = $2 AND relation = $3 AND object = $4`,
		string(bID), fgaUser, relation, object).Scan(&n))
	return n > 0
}

// newBackfill собирает исполнителя подмётки и стража сверки над pg-адаптером.
func newBackfill(pool *pgxpool.Pool) (*seed.BackfillRunner, *seed.VerifyGate) {
	rec, _ := newReconciler(pool)
	adapter := kanamepg.NewBackfillAdapter(pool)
	runner := seed.NewBackfillRunner(rec, adapter, seed.BackfillConfig{ChunkSize: 2})
	gate := seed.NewVerifyGate(adapter, nil)
	return runner, gate
}

// ── дозаполнение выдач владельца для СУЩЕСТВУЮЩИХ счетов (миграция 0036) ────────
//
// Счёт, заведённый до того, как выдачи владельца стали создаваться сами, получает
// выдачу владельца миграцией 0036. Идемпотентно: из-за частичного UNIQUE живой
// выдачи повтор (или счёт, у которого выдача владельца УЖЕ есть) ничего не вставляет.

func TestP8_01_OwnerBindingBackfill_ExistingAccounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t) // goose.Up применяет миграцию 0036 (дозаполнение выдач владельца)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	// Счёт засеян «по-старому» (mustSeedUser вставляет счета напрямую, без
	// AccessBinding владельца), но ПОСЛЕ goose.Up, так что миграция 0036 уже
	// прошла и его НЕ видела. Здесь SQL дозаполнения повторяется идемпотентно,
	// чтобы воспроизвести «счёт существовал в момент миграции».
	owner := mustSeedUser(t, ctx, pool, "p8acc")
	acc := seedAccount(t, ctx, repo, "p8-legacy-acc", owner)

	// До дозаполнения выдачи владельца нет (seedAccount её не создаёт).
	require.Equal(t, 0, activeOwnerBindingCount(t, ctx, pool, acc.ID),
		"seedAccount must not create an owner-binding")

	// Идемпотентный SQL дозаполнения (тело миграции 0036) вынесен наружу, чтобы
	// покрыть и счёт, заведённый после goose.Up.
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))

	require.Equal(t, 1, activeOwnerBindingCount(t, ctx, pool, acc.ID),
		"backfill must create exactly one owner-binding for the existing account")

	// идемпотентно: повтор → по-прежнему ровно одна (частичный UNIQUE живой выдачи).
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	require.Equal(t, 1, activeOwnerBindingCount(t, ctx, pool, acc.ID),
		"re-running owner-binding backfill must be a no-op (idempotent, H-02)")

	// Субъект выдачи владельца — owner_user_id счёта, роль — владелец.
	bID := ownerBindingID(t, ctx, pool, acc.ID)
	var subjType, subjID, roleID string
	var protected bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT subject_type, subject_id, role_id, deletion_protection
		   FROM kaname.access_bindings WHERE id = $1`, string(bID)).
		Scan(&subjType, &subjID, &roleID, &protected))
	assert.Equal(t, "user", subjType)
	assert.Equal(t, string(owner), subjID)
	assert.Equal(t, domain.OwnerRoleID, roleID)
	assert.True(t, protected, "backfilled owner-binding must be deletion_protected (D-8a)")

	// В access_binding_subjects есть единственная спроецированная строка субъекта.
	var subjRows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_binding_subjects WHERE binding_id = $1`,
		string(bID)).Scan(&subjRows))
	assert.Equal(t, 1, subjRows, "owner-binding must have its projected subject row")

	// Нет потери доступа: дозаполнение обязано ТАКЖЕ поставить в fga_outbox
	// намерение родительского указателя иерархии для ОБЪЕКТА выдачи владельца
	//   account:<A>#account@iam_access_binding:<bindingID>
	// чтобы владелец счёта получал Get/Delete на ОБЪЕКТ выдачи владельца через
	// каскад FGA `viewer/editor from account` (подмётка сведения материализует
	// СОДЕРЖИМОЕ на объект, а НЕ этот указатель жизненного цикла выдачи). Без него
	// Get/Delete на объекте выдачи владельца получают отказ прав (403).
	var hierTuples int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.fga_outbox
		  WHERE event_type        = 'fga.tuple.write'
		    AND payload->>'user'     = 'account:' || $1
		    AND payload->>'relation' = 'account'
		    AND payload->>'object'   = 'iam_access_binding:' || $2`,
		string(acc.ID), string(bID)).Scan(&hierTuples))
	assert.Equal(t, 1, hierTuples,
		"backfill must queue exactly one owner-binding hierarchy parent-pointer "+
			"account:<A>#account@iam_access_binding:<id> (no-access-loss, КФ-БАГ-2)")

	// Идемпотентно: выпуск кортежа иерархии отсекает дубль условием NOT EXISTS по payload.
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.fga_outbox
		  WHERE event_type        = 'fga.tuple.write'
		    AND payload->>'user'     = 'account:' || $1
		    AND payload->>'relation' = 'account'
		    AND payload->>'object'   = 'iam_access_binding:' || $2`,
		string(acc.ID), string(bID)).Scan(&hierTuples))
	assert.Equal(t, 1, hierTuples,
		"re-running backfill must NOT duplicate the hierarchy parent-pointer intent (H-02)")
}

// ── подмётка сведения материализует кортежи на объект ────────
//
// После дозаполнения выдач владельца кортежей владельца на объект account:<A> в
// ведомости ЕЩЁ нет (миграция заводит лишь строку выдачи, содержимое
// материализуется ПРЯМЫМ путём). Подмётка сведения (одиночный RunOnce) сводит
// КАЖДУЮ живую выдачу единственным путём материализации → ведомость заполняется.

func TestP8_02_ReconcileSweep_MaterializesPerObjectTuples(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "p8sweep")
	acc := seedAccount(t, ctx, repo, "p8-sweep-acc", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	bID := ownerBindingID(t, ctx, pool, acc.ID)

	// До подмётки выдача владельца есть, но её кортежи «сама область» НЕ материализованы.
	require.Equal(t, 0, ledgerTupleCount(t, ctx, pool, bID),
		"owner-binding ledger empty before the reconcile sweep (forward materialization)")

	runner, _ := newBackfill(pool)
	res, err := runner.RunOnce(ctx)
	require.NoError(t, err)
	assert.True(t, res.Executed, "the (only) RunOnce must execute the sweep")
	assert.GreaterOrEqual(t, res.BindingsReconciled, 1, "at least the owner-binding reconciled")

	// После подмётки кортежи v_* «сама область» владельца на account:<A> в ведомости
	// (правило владельца `*.*.*` даёт глаголы «сама область» на объекте области).
	assert.Greater(t, ledgerTupleCount(t, ctx, pool, bID), 0,
		"reconcile sweep must materialize the owner-binding scope-self tuples (H-01)")
	obj := "account:" + string(acc.ID)
	user := "user:" + string(owner)
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, user, "v_get", obj),
		"owner scope-self v_get on account:<A> materialized")
	assert.True(t, ledgerHasTuple(t, ctx, pool, bID, user, "admin", obj),
		"owner scope-self admin tier on account:<A> materialized (write-authz anchor)")

	// идемпотентно: повтор подмётки → число в ведомости прежнее (частичный UNIQUE).
	before := ledgerTupleCount(t, ctx, pool, bID)
	_, err = runner.RunOnce(ctx)
	require.NoError(t, err)
	assert.Equal(t, before, ledgerTupleCount(t, ctx, pool, bID),
		"re-running the sweep is idempotent — no new ledger rows (H-02/H-04)")
}

// ── одиночка: из N одновременных RunOnce исполняет ровно один ─────

func TestP8_03_Singleton_ConcurrentRunOnce_ExactlyOneExecutes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "p8conc")
	acc := seedAccount(t, ctx, repo, "p8-conc-acc", owner)
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	bID := ownerBindingID(t, ctx, pool, acc.ID)

	// N исполнителей над ТЕМ ЖЕ пулом наперегонки зовут RunOnce. Блокировка-
	// одиночка pg_try_advisory_lock уровня сеанса (попытка БЕЗ ожидания) даёт
	// ровно одному взять её и исполнить подмётку; прочие пропускают
	// (Executed=false). Дублей в ведомости нет в любом случае.
	const n = 6
	var executed int32
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runner, _ := newBackfill(pool)
			res, rerr := runner.RunOnce(ctx)
			if rerr != nil {
				errs <- rerr
				return
			}
			if res.Executed {
				atomic.AddInt32(&executed, 1)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e)
	}
	assert.Equal(t, int32(1), atomic.LoadInt32(&executed),
		"exactly ONE concurrent RunOnce executes the singleton backfill (КФ-1/H-05)")

	// Единственное исполнение материализовало ведомость ровно один раз (дублей нет).
	var dups int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) - count(DISTINCT (fga_user, relation, object))
		   FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1`,
		string(bID)).Scan(&dups))
	assert.Equal(t, 0, dups, "no duplicate ledger tuples after concurrent backfill (partial-UNIQUE)")
}

// ── размер транзакции порциями: подмётка делит работу на ограниченные порции ──────────

func TestP8_04_ChunkedTxSizeBound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	// Засеять несколько выдач владельца (несколько счетов) → выдач больше, чем ChunkSize.
	const accounts = 5
	for i := 0; i < accounts; i++ {
		o := mustSeedUser(t, ctx, pool, "p8chunk"+string(rune('a'+i)))
		seedAccount(t, ctx, repo, "p8-chunk-acc-"+string(rune('a'+i)), o)
	}
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))

	runner, _ := newBackfill(pool) // ChunkSize=2 задаёт newBackfill
	res, err := runner.RunOnce(ctx)
	require.NoError(t, err)
	assert.True(t, res.Executed)
	assert.GreaterOrEqual(t, res.BindingsReconciled, accounts,
		"every owner-binding reconciled across chunks")
	// при ChunkSize=2 и ≥5 выдачах подмётка прошла ≥3 порциями (без одной
	// исполинской транзакции). Каждая выдача по-прежнему сводится в СВОЕЙ пишущей
	// транзакции сведения, так что транзакция на выдачу ограничена сама собой;
	// Chunks сообщает число порций перечня.
	assert.GreaterOrEqual(t, res.Chunks, 3, "work split into bounded chunks (КФ-5)")
}

// ── страж сверки: нет потери доступа + прямая материализация свежего объекта ──

// TestP8_05_VerifyGate_NoAccessLoss_ForwardMaterializes — после подмётки страж
// сверки сообщает 100% отсутствия потери доступа, а объект, заведённый ПОСЛЕ
// выдачи, получает кортеж обычной селекторной выдачи прямым путём сведения.
//
// Прежде вторую половину утверждала дымовая проба стража (`ForwardSmoke`): она
// сама клала синтетику в боевое зеркало, сводила её и снимала. Механизм снят
// (#148) — прод-потребителя у него не было с #119, а единственным потребителем
// была эта проба. Свойство, которое он доказывал, утверждается здесь напрямую:
// строка зеркала — тем же оператором, каким её кладёт регистрация в пробах
// сведения, и настоящее `ReconcileObject` по ней, без посредника в прод-коде.
//
// Это селекторная полоса (ARM_ANCHOR обычной роли на проекте, `vpc.network`);
// владельческая покрыта `Test224_OwnerWildcard_ForwardMaterializesContent`.
func TestP8_05_VerifyGate_NoAccessLoss_ForwardMaterializes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "p8verify")
	member := mustSeedUser(t, ctx, pool, "p8verifymem")
	acc := seedAccount(t, ctx, repo, "p8-verify-acc", owner)
	prj := seedProject(t, ctx, repo, acc.ID, "p8-verify-prj")
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))

	// Обычная селекторная выдача ARM_ANCHOR (vpc.network get, all) на проекте.
	selRole := seedAccountRulesRole(t, ctx, pool, repo, acc.ID, "p8_net_viewer",
		domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}})
	selBinding := insertThinBindingScope(t, ctx, repo, member, selRole, "project", string(prj.ID), domain.ScopeProject)

	runner, gate := newBackfill(pool)
	_, err = runner.RunOnce(ctx)
	require.NoError(t, err)

	report, err := gate.Verify(ctx)
	require.NoError(t, err)
	assert.True(t, report.NoAccessLoss,
		"verify-gate must report 100%% no-access-loss before contract is permitted (КФ-4)")
	assert.Empty(t, report.Failures, "no binding without materialized explicit tuples")
	assert.GreaterOrEqual(t, report.BindingsChecked, 2, "owner-binding + selector binding checked")

	// Объект, которого при выдаче не было: до сведения кортежа на нём нет, после
	// прямого пути — есть. Пара «до/после» отличает материализацию сведением от
	// кортежа, оставшегося от подмётки.
	fresh := ids.NewID("net")
	freshObject := "vpc_network:" + fresh
	memberUser := "user:" + string(member)
	seedMirrorRow(t, ctx, pool, "vpc.network", fresh, string(prj.ID), string(acc.ID), nil, time.Now())
	require.False(t, ledgerHasTuple(t, ctx, pool, selBinding, memberUser, "v_get", freshObject),
		"до сведения у свежего объекта кортежа нет — иначе утверждение ниже ничего не доказывает")

	rec, _ := newReconciler(pool)
	require.NoError(t, rec.ReconcileObject(ctx, "vpc.network", fresh))
	assert.True(t, ledgerHasTuple(t, ctx, pool, selBinding, memberUser, "v_get", freshObject),
		"прямой путь обязан материализовать кортеж селекторной выдачи на объекте, "+
			"заведённом после выдачи (КФ-4/H-06)")
}

// ── отозванная выдача владельца НЕ должна мешать повторной выдаче при дозаполнении ───
//
// backfillOwnerBindingsSQL брал ДЕТЕРМИНИРОВАННЫЙ id 'acb'||substr(md5('owner-binding:'
// ||a.id),1,17) с ON CONFLICT (id) DO NOTHING. Если выдачу владельца счёта прежде
// ОТОЗВАЛИ (строка живёт надгробием с тем же id и заполненным revoked_at), условие
// NOT EXISTS(... revoked_at IS NULL) верно не находит живой выдачи владельца и
// отдаёт строку на вставку, но INSERT упирается в PK надгробия, и DO NOTHING молча
// её роняет → у счёта НЕ остаётся живой выдачи владельца (дыра потери доступа).
// Починка обязана заново заводить АКТИВНУЮ выдачу владельца всякий раз, когда её
// нет, независимо от отозванного надгробия.
func TestReview15_RevokedOwnerBinding_BackfillRecreatesActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "rv15own")
	acc := seedAccount(t, ctx, repo, "acc-rv15", owner)

	// Первое дозаполнение заводит выдачу владельца (детерминированный id).
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	require.Equal(t, 1, activeOwnerBindingCount(t, ctx, pool, acc.ID), "owner-binding created by first backfill")
	revokedID := ownerBindingID(t, ctx, pool, acc.ID)

	// Отозвать её (надгробие: status=REVOKED, revoked_at заполнен), оставив
	// детерминированный id занятым. Ровно такое состояние оставляют TransitionStatus
	// и Delete.
	_, err = pool.Exec(ctx,
		`UPDATE kaname.access_bindings SET status='REVOKED', revoked_at=now() WHERE id=$1`,
		string(revokedID))
	require.NoError(t, err)
	require.Equal(t, 0, activeOwnerBindingCount(t, ctx, pool, acc.ID), "no ACTIVE owner-binding after revoke")

	// Повторить дозаполнение. Оно ОБЯЗАНО заново завести АКТИВНУЮ выдачу владельца
	// счёта (отозванное надгробие не должно подавлять повторную выдачу).
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	assert.Equal(t, 1, activeOwnerBindingCount(t, ctx, pool, acc.ID),
		"revoked owner-binding must be re-created as ACTIVE on backfill (no-access-loss, review #15)")

	// Новая живая выдача владельца — строка, ОТЛИЧНАЯ от отозванного надгробия.
	newID := ownerBindingID(t, ctx, pool, acc.ID)
	assert.NotEqual(t, revokedID, newID,
		"re-grant uses a fresh id, not the revoked deterministic id (idempotency via active-grant partial-UNIQUE)")

	// Идемпотентно: второе дозаполнение при живой выдаче владельца ничего не добавляет.
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	assert.Equal(t, 1, activeOwnerBindingCount(t, ctx, pool, acc.ID),
		"backfill remains idempotent once an ACTIVE owner-binding exists (H-02)")
}

// ── Verify обязан отмечать выдачу, которая ДОЛЖНА материализовать ≥1 члена ──
//
//	а дала 0 (полный провал сведения, к которому был слеп Verify, выведенный из
//	active_members). АКТИВНАЯ выдача ВЛАДЕЛЬЦА уровня счёта ВСЕГДА материализует
//	≥1 члена (своего члена «сама область» на account:<A>: ScopeSelfVerbs роли
//	владельца `*.*` непусты, а счёт всегда содержится в собственной области),
//	поэтому выдача владельца с 0 АКТИВНЫХ членов — однозначно провал сведения,
//	вычислимый без ложных находок. Verify теперь её отмечает.
func TestReview16_Verify_FlagsOwnerBindingWithZeroMembers(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "rv16own")
	acc := seedAccount(t, ctx, repo, "acc-rv16", owner)

	// Выдача владельца заведена, но НИ РАЗУ не сведена → 0 АКТИВНЫХ целевых членов.
	// Прежний Verify (ExpectsTuples = active_members>0) читал это как «ничего не
	// ожидает» и молча пропускал — слепая зона полного провала сведения.
	require.NoError(t, seed.BackfillOwnerBindings(ctx, pool))
	ownerBID := ownerBindingID(t, ctx, pool, acc.ID)
	require.Equal(t, 0, ledgerTupleCount(t, ctx, pool, ownerBID),
		"precondition: owner-binding not yet reconciled (empty ledger / no members)")

	runner, gate := newBackfill(pool)
	report, err := gate.Verify(ctx)
	require.NoError(t, err)

	assert.False(t, report.NoAccessLoss,
		"Verify must FAIL: an owner-binding that should materialize ≥1 member produced 0 (review #16)")
	var flagged bool
	for _, f := range report.Failures {
		if f.BindingID == ownerBID {
			flagged = true
		}
	}
	assert.True(t, flagged, "the un-reconciled owner-binding must be listed as a failure (review #16)")

	// После того как подмётка сведения материализует члена «сама область» каждой
	// выдачи владельца (включая выдачу владельца засеянного счёта kacho-system),
	// Verify чист: ни одной выдачи владельца с 0 членов не остаётся.
	_, err = runner.RunOnce(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, ledgerTupleCount(t, ctx, pool, ownerBID), 1,
		"sweep reconciled the owner-binding (scope-self member + ledger present)")

	report2, err := gate.Verify(ctx)
	require.NoError(t, err)
	assert.True(t, report2.NoAccessLoss,
		"after the reconcile-sweep every owner-binding has ≥1 member → Verify passes (review #16)")
	for _, f := range report2.Failures {
		assert.NotEqual(t, ownerBID, f.BindingID, "reconciled owner-binding must no longer be flagged")
	}
}

var _ = reconcile.New // держит импорт reconcile упомянутым, если путь проб сменится
