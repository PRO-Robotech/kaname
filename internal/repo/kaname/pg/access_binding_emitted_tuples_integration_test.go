// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_emitted_tuples_integration_test.go — пробы ведомости отправленных кортежей.
//
// Интеграционные пробы с testcontainers Postgres 16 для сохраняемой ведомости
// отправленных кортежей (kaname.access_binding_emitted_tuples, миграция 0024),
// которая делает отзыв AccessBinding и согласование Role.Update побайтово симметричными выдаче:
//
//   - -COMMIT: InsertEmittedTuples фиксируется вместе с EmitRelationWrite,
//     а SelectEmittedTuples читает в точности записанный набор.
//   - -CASCADE: удаление строки выдачи каскадно удаляет строки отправленных кортежей
//     (FK ON DELETE CASCADE) — после отзыва нет осиротевших строк ведомости.
//   - -REPLACE: ReplaceEmittedTuples целиком заменяет набор (путь согласования).
//   - -ROLLBACK: откат транзакции писателя НЕ оставляет строк ведомости (атомарная
//     запись в транзакции, запрет #10).
//   - -RACE: конкурентные ReplaceEmittedTuples в стиле Role.Update ∥ отзыв Delete
//     ОДНОЙ выдачи сериализуются в согласованное конечное состояние: либо выдача
//     удалена (CASCADE очистил ведомость, осиротевших строк нет), либо она
//     сохранилась с точно заменённым набором; промежуточного состояния нет.

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	reconcileapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

func emittedTuplesCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bindingID domain.AccessBindingID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1`,
		string(bindingID)).Scan(&n))
	return n
}

// seedABForEmitted создаёт настоящую строку access_bindings в области аккаунта,
// чтобы у внешнего ключа отправленного кортежа была родительская строка.
func seedABForEmitted(t *testing.T, ctx context.Context, repo *kanamepg.Repository, uid domain.UserID, accID domain.AccountID) domain.AccessBinding {
	t.Helper()
	return insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       domain.SystemViewerRoleID,
		ResourceType: "account",
		ResourceID:   string(accID),
	})
}

// TestABEmittedTuples_B14_ConcurrentScopeGrantLedger_OneTupleSet — требование
// конкурентности модели правил RBAC 2026 для отправленного набора scope_grant.
//
// Отправленный набор scope_grant (выход rulesBindingTuples для правила ARM_NAMES /
// ARM_ANCHOR) сохраняется через InsertEmittedTuples с PK (binding_id,
// fga_user, relation, object) + ON CONFLICT DO NOTHING. N горутин, конкурентно
// сохраняющих ОДИНАКОВЫЙ набор кортежей scope_grant для одной выдачи,
// должны сойтись РОВНО к этому набору: без повторных строк и разрастания
// от второго писателя (запрет #10, идемпотентность в базе, а не проверка перед записью).
func TestABEmittedTuples_B14_ConcurrentScopeGrantLedger_OneTupleSet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "b14")
	acc := seedAccount(t, ctx, repo, "acc-b14", uid)
	ab := seedABForEmitted(t, ctx, repo, uid, acc.ID)

	// Набор кортежей scope_grant правила ARM_NAMES {vpc.address,[get,update],addr5k}:
	// кортежи на каждый объект и глагол + кортеж уровня для обратной совместимости.
	// Одинаков во всех горутинах (реальная форма конкурентной повторной выдачи).
	scopeGrantSet := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "v_get", Object: "vpc_address:addr5k"},
		{User: "user:" + string(uid), Relation: "v_update", Object: "vpc_address:addr5k"},
		{User: "user:" + string(uid), Relation: "editor", Object: "vpc_address:addr5k"},
	}

	const N = 8
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, ierr := repo.Writer(ctx)
			if ierr != nil {
				errs <- ierr
				return
			}
			if ierr := w.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, scopeGrantSet); ierr != nil {
				_ = w.Rollback(ctx)
				errs <- ierr
				return
			}
			errs <- w.Commit(ctx)
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		require.NoError(t, e, "concurrent idempotent InsertEmittedTuples must not error (ON CONFLICT DO NOTHING)")
	}

	// Сохранены ровно 3 кортежа — без повторов и разрастания при конкуренции.
	require.Equal(t, len(scopeGrantSet), emittedTuplesCount(t, ctx, pool, ab.ID),
		"concurrent identical scope_grant ledger writes must converge to ONE tuple-set")
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, err := rd.AccessBindings().SelectEmittedTuples(ctx, ab.ID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	require.ElementsMatch(t, scopeGrantSet, got, "the converged set must be exactly the emitted scope_grant set")
}

func TestABEmittedTuples_178_InsertSelect_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "em01")
	acc := seedAccount(t, ctx, repo, "acc-em01", uid)
	ab := seedABForEmitted(t, ctx, repo, uid, acc.ID)

	tuples := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "admin", Object: "account:" + string(acc.ID)},
		{User: "account:" + string(acc.ID), Relation: "account", Object: "iam_access_binding:" + string(ab.ID)},
	}

	// Фиксируем отправку и ведомость одной транзакцией писателя.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().EmitRelationWrite(ctx, tuples))
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, tuples))
	require.NoError(t, w.Commit(ctx))

	// Читаем в точности записанный набор.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, err := rd.AccessBindings().SelectEmittedTuples(ctx, ab.ID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	require.ElementsMatch(t, tuples, got, "SelectEmittedTuples must return the exact persisted set")

	// Идемпотентная повторная вставка (ON CONFLICT DO NOTHING) не даёт повторов.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w2.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, tuples))
	require.NoError(t, w2.Commit(ctx))
	require.Equal(t, 2, emittedTuplesCount(t, ctx, pool, ab.ID), "re-insert must be idempotent (PK)")
}

func TestABEmittedTuples_178_DeleteBinding_CascadesLedger(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "em02")
	acc := seedAccount(t, ctx, repo, "acc-em02", uid)
	ab := seedABForEmitted(t, ctx, repo, uid, acc.ID)

	tuples := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "admin", Object: "account:" + string(acc.ID)},
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, tuples))
	require.NoError(t, w.Commit(ctx))
	require.Equal(t, 1, emittedTuplesCount(t, ctx, pool, ab.ID))

	// Отзыв (удаление строки выдачи) → FK ON DELETE CASCADE очищает ведомость.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w2.AccessBindingsW().Delete(ctx, ab.ID))
	require.NoError(t, w2.Commit(ctx))
	require.Equal(t, 0, emittedTuplesCount(t, ctx, pool, ab.ID),
		"deleting the binding must CASCADE-drop its emitted-tuple ledger rows (no orphan store rows)")
}

func TestABEmittedTuples_178_Replace_WholesaleSwap(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "em03")
	acc := seedAccount(t, ctx, repo, "acc-em03", uid)
	ab := seedABForEmitted(t, ctx, repo, uid, acc.ID)

	oldSet := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "admin", Object: "account:" + string(acc.ID)},
	}
	newSet := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "viewer", Object: "account:" + string(acc.ID)},
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, oldSet))
	require.NoError(t, w.Commit(ctx))

	// Согласование: целиком заменяем admin → viewer.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w2.AccessBindingsW().ReplaceEmittedTuples(ctx, ab.ID, newSet))
	require.NoError(t, w2.Commit(ctx))

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, err := rd.AccessBindings().SelectEmittedTuples(ctx, ab.ID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	require.ElementsMatch(t, newSet, got, "ReplaceEmittedTuples must wholesale-swap the ledger to the new set")
}

// TestABEmittedTuples_RoleUpdateReconcile_PreservesMemberTuples — модель правил
// RBAC 2026, КРИТИЧНАЯ правка разделения источников ведомости.
//
// Ведомость отправленных кортежей хранит И кортежи уровня выдачи (InsertEmittedTuples /
// RoleTupleReconciler при Role.Update через ReplaceEmittedTuples), И кортежи ARM_LABELS
// на каждого участника (RecordEmittedTuples согласователя участников). Согласование
// Role.Update уровня выдачи (ReplaceEmittedTuples) НЕ ДОЛЖНО отзывать или стирать
// кортежи участников: ими владеет RoleMembershipFanout, а не согласователь
// уровня выдачи. До разделения по `source` ReplaceEmittedTuples выполнял полное
// удаление `DELETE … WHERE binding_id`, стирая строки участников при каждом
// изменяющем правила Role.Update пользовательской роли, сочетающей ветвь уровня выдачи
// с ARM_LABELS. Это временно лишало доступа по меткам (а при отказе распространения
// после коммита — до следующего полного обхода).
func TestABEmittedTuples_RoleUpdateReconcile_PreservesMemberTuples(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "emsrc")
	acc := seedAccount(t, ctx, repo, "acc-emsrc", uid)
	ab := seedABForEmitted(t, ctx, repo, uid, acc.ID)

	// (1) Отправленный набор уровня выдачи, которым владеет RoleTupleReconciler (якорь/иерархия).
	bindingLevel := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "admin", Object: "account:" + string(acc.ID)},
		{User: "account:" + string(acc.ID), Relation: "account", Object: "iam_access_binding:" + string(ab.ID)},
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, bindingLevel))
	require.NoError(t, w.Commit(ctx))

	// (2) Кортежи ARM_LABELS участников, которыми владеет согласователь участников, записаны
	// ПРОДУКТОВЫМ писателем участников (RecordEmittedTuples), пространство объектов <fga_type>:<id>.
	memberTuples := []domain.MembershipTuple{
		{User: "user:" + string(uid), Relation: "v_get", Object: "vpc_subnet:sub-emsrc"},
		{User: "user:" + string(uid), Relation: "viewer", Object: "vpc_subnet:sub-emsrc"},
	}
	adapter := kanamepg.NewReconcileAdapter(pool, catalogfixture.Source())
	require.NoError(t, adapter.WithTx(ctx, func(ctx context.Context, s reconcileapp.ReconcileStore) error {
		return s.RecordEmittedTuples(ctx, ab.ID, reconcileapp.MemberCoord{ObjectType: "vpc.subnet", ObjectID: "sub-emsrc"}, memberTuples)
	}))
	require.Equal(t, len(bindingLevel)+len(memberTuples), emittedTuplesCount(t, ctx, pool, ab.ID),
		"precondition: ledger holds both binding-level and member tuples")

	// (3) Согласование Role.Update: смена уровня выдачи (admin → viewer) через
	// ReplaceEmittedTuples — ровно то, что делает RoleTupleReconciler при изменении
	// правил. Заменяться должно ТОЛЬКО подмножество уровня выдачи.
	newBindingLevel := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "viewer", Object: "account:" + string(acc.ID)},
		{User: "account:" + string(acc.ID), Relation: "account", Object: "iam_access_binding:" + string(ab.ID)},
	}
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w2.AccessBindingsW().ReplaceEmittedTuples(ctx, ab.ID, newBindingLevel))
	require.NoError(t, w2.Commit(ctx))

	// (4) Кортежи ARM_LABELS участников ДОЛЖНЫ пережить согласование уровня выдачи.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	got, err := rd.AccessBindings().SelectEmittedTuples(ctx, ab.ID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)

	wantMember := []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "v_get", Object: "vpc_subnet:sub-emsrc"},
		{User: "user:" + string(uid), Relation: "viewer", Object: "vpc_subnet:sub-emsrc"},
	}
	for _, m := range wantMember {
		require.Contains(t, got, m,
			"ARM_LABELS member tuple %v must NOT be wiped by a binding-level Role.Update reconcile", m)
	}
	// А подмножество уровня выдачи заменено (admin удалён, viewer присутствует).
	require.Contains(t, got, repoab.RelationTuple{User: "user:" + string(uid), Relation: "viewer", Object: "account:" + string(acc.ID)})
	require.NotContains(t, got, repoab.RelationTuple{User: "user:" + string(uid), Relation: "admin", Object: "account:" + string(acc.ID)},
		"binding-level reconcile must still replace its own (admin → viewer) subset")
}

func TestABEmittedTuples_178_RollbackDiscardsLedger(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "em04")
	acc := seedAccount(t, ctx, repo, "acc-em04", uid)
	ab := seedABForEmitted(t, ctx, repo, uid, acc.ID)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "admin", Object: "account:" + string(acc.ID)},
	}))
	require.NoError(t, w.Rollback(ctx))
	require.Equal(t, 0, emittedTuplesCount(t, ctx, pool, ab.ID),
		"rolled-back writer-tx must leave NO ledger row (atomic emit-in-tx, ban #10)")
}

// TestABEmittedTuples_178_ConcurrentReplaceVsRevoke_Consistent — конкурентные
// ReplaceEmittedTuples в стиле Role.Update ∥ отзыв Delete ОДНОЙ выдачи
// сериализуются блокировкой строки выдачи / FK в согласованное конечное состояние:
// либо победил Delete (выдачи нет, CASCADE очистил ведомость → 0 строк), либо
// победил Replace, а затем Delete удалил обе сущности (тоже 0 строк). Инвариант:
// НЕТ осиротевших строк ведомости со ссылкой на удалённую выдачу и промежуточного состояния.
func TestABEmittedTuples_178_ConcurrentReplaceVsRevoke_Consistent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "em05")
	acc := seedAccount(t, ctx, repo, "acc-em05", uid)
	ab := seedABForEmitted(t, ctx, repo, uid, acc.ID)

	// Сеем начальный отправленный набор.
	wSeed, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, wSeed.AccessBindingsW().InsertEmittedTuples(ctx, ab.ID, []repoab.RelationTuple{
		{User: "user:" + string(uid), Relation: "admin", Object: "account:" + string(acc.ID)},
	}))
	require.NoError(t, wSeed.Commit(ctx))

	var wg sync.WaitGroup
	wg.Add(2)
	// Горутина A — согласование (распространение Role.Update): заменяем admin → viewer.
	go func() {
		defer wg.Done()
		w, e := repo.Writer(ctx)
		if e != nil {
			return
		}
		if e := w.AccessBindingsW().ReplaceEmittedTuples(ctx, ab.ID, []repoab.RelationTuple{
			{User: "user:" + string(uid), Relation: "viewer", Object: "account:" + string(acc.ID)},
		}); e != nil {
			_ = w.Rollback(ctx)
			return
		}
		_ = w.Commit(ctx)
	}()
	// Горутина B — отзыв: удаляем выдачу (CASCADE удаляет ведомость).
	go func() {
		defer wg.Done()
		w, e := repo.Writer(ctx)
		if e != nil {
			return
		}
		if e := w.AccessBindingsW().Delete(ctx, ab.ID); e != nil {
			_ = w.Rollback(ctx)
			return
		}
		_ = w.Commit(ctx)
	}()
	wg.Wait()

	// Конечный инвариант: если строки выдачи нет, ведомость ДОЛЖНА быть пустой
	// (CASCADE). Если выдача сохранилась (замена зафиксирована, удаление проиграло,
	// строка оставалась — хотя удаление существующей строки никогда не «проигрывает»),
	// ведомость содержит заменённый набор. В любом случае: ноль СТРОК со ссылкой на НЕСУЩЕСТВУЮЩУЮ выдачу.
	var bindingExists bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM kaname.access_bindings WHERE id = $1)`, string(ab.ID)).Scan(&bindingExists))
	ledger := emittedTuplesCount(t, ctx, pool, ab.ID)
	if !bindingExists {
		require.Equal(t, 0, ledger,
			"binding deleted ⇒ ledger MUST be CASCADE-cleared (no orphan rows)")
	} else {
		require.LessOrEqual(t, ledger, 1, "surviving binding holds at most the replaced single-tuple set")
	}
	// Страховка от осиротевших строк: НОЛЬ строк ведомости с binding_id,
	// для которого нет соответствующей строки access_bindings.
	var orphans int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.access_binding_emitted_tuples e
		 WHERE NOT EXISTS (SELECT 1 FROM kaname.access_bindings ab WHERE ab.id = e.binding_id)`).Scan(&orphans))
	require.Equal(t, 0, orphans, "no emitted-tuple row may reference a non-existent binding (FK CASCADE invariant)")
}
