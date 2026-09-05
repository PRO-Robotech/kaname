// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// f10_revoke_lock_integration_test.go — redesign-2026 F10 (IAM-1-28) revoke
// critical-section, END-TO-END on testcontainers PG16.
//
// The soft-revoke reads the binding's emitted-tuple ledger and removes exactly that
// set. A concurrent ReconcileBindingForward pass materializes NEW members and appends
// their tuples to the same ledger. If the revoke writer-tx takes no lock at
// all, the two txs never conflict: the forward row lands after the revoke's snapshot
// and is never in the delete-set — and because a REVOKED binding short-circuits
// `!bs.Active` in reconcileBinding AND in both forward paths, nothing ever reclaims
// it. The revoked subject keeps that object's verbs forever.
//
// This test stands in for a concurrent writer with a raw tx that holds SHARE on the
// binding key and inserts the ledger row, and asserts the revoke (a) BLOCKS while that
// tx is open (proving the EXCLUSIVE lock is really taken on the same hashtext key) and
// (b) removes the racing tuple once it proceeds.
//
// РАСХОЖДЕНИЕ ДУБЛЁРА С ПРОДУКТОМ — названо, а не подразумевается. Сегодня форвард
// advisory-блокировки НЕ БЕРЁТ ВОВСЕ (см. «LOCK CHOICE» в reconcile/forward.go), поэтому
// дублёр здесь СТРОЖЕ продукта: он держит SHARE, а настоящий форвард не держит ничего.
// Утверждение теста от этого остаётся верным — оно про отзыв: тот и правда берёт
// EXCLUSIVE на том же ключе, и это доказывается ожиданием. Чего этот тест НЕ утверждает:
// что настоящий форвард встал бы в очередь за отзывом — он не встанет.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	accessbindingapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/access_binding"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	abrepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/access_binding"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// denyingRelations — RelationStore that denies every question.
//
// # Почему дублёр ТОЛЬКО отказывает, и почему это не выхолащивание
//
// Отказ здесь несущий: право отзывать обязано прийти по пути ВЛАДЕЛЬЦА аккаунта,
// а не по короткому замыканию администратора облака. Дублёр, отвечающий «да»,
// открыл бы второй путь, и проба перестала бы различать, какой из них сработал.
//
// # Что здесь стояло раньше и куда переехало наблюдение
//
// Прежняя редакция записывала набор, переданный пост-коммитному СНЯТИЮ кортежей у
// внешнего движка, и утверждала состав по этой записи. Снятия больше нет — и не
// потому, что от него отказались, а потому что отзыв теперь ЗАЯВЛЯЕТСЯ В ТОЙ ЖЕ
// транзакции, что снимает выдачу: строка журнала `kacho_iam.fga_outbox`, из
// которой триггер `relation_fact_follows_journal` (миграции 0098/0100) убирает
// прямой факт — до коммита, а не после него.
//
// Дублёр, сохранивший метод снятия, был бы ШИРЕ настоящего порта: метод никто не
// зовёт, запись остаётся пустой, и утверждение о составе стало бы утверждением о
// пустоте. Поэтому наблюдение переехало туда, где след действительно появляется, —
// в журнал той же базы.
type denyingRelations struct{}

func (denyingRelations) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}

var _ clients.RelationStore = (*denyingRelations)(nil)

// journalDeletes — тройки, ЗАЯВЛЕННЫЕ к снятию в журнале.
//
// Читается из настоящей таблицы, а не из дублёра: предмет пробы — что писатель
// действительно положил строку, а не что кто-то вызвал метод.
//
// # Обе формы полезной нагрузки, и это не перестраховка
//
// Строка журнала группируется по паре (субъект, объект) и несёт ВЕСЬ набор
// отношений этого субъекта на этом объекте: набор из одного отношения сохраняет
// историческую форму `relation`, настоящий набор принимает форму `relations`
// массивом. Читатель, знающий одну форму, молча теряет вторую — и утверждение о
// покрытии зеленело бы ровно там, где отзыв снимает НЕСКОЛЬКО глаголов сразу,
// то есть в самом обычном случае. Ровно это здесь и произошло при первом
// написании: два глагола из трёх были «не покрыты», хотя лежали в журнале.
func journalDeletes(t *testing.T, ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) [][3]string {
	t.Helper()
	rows, err := q.Query(ctx, `
		SELECT payload->>'user' AS u,
		       COALESCE(rel.value, payload->>'relation') AS r,
		       payload->>'object' AS o
		  FROM kacho_iam.fga_outbox
		  LEFT JOIN LATERAL jsonb_array_elements_text(
		                COALESCE(payload->'relations', '[]'::jsonb)) AS rel(value) ON TRUE
		 WHERE event_type = 'fga.tuple.delete'`)
	require.NoError(t, err, "чтение журнала намерений")
	defer rows.Close()
	var out [][3]string
	for rows.Next() {
		var u, r, o *string
		require.NoError(t, rows.Scan(&u, &r, &o))
		deref := func(p *string) string {
			if p == nil {
				return ""
			}
			return *p
		}
		out = append(out, [3]string{deref(u), deref(r), deref(o)})
	}
	require.NoError(t, rows.Err())
	return out
}

func hasDelete(set [][3]string, user, relation, object string) bool {
	for _, t := range set {
		if t[0] == user && t[1] == relation && t[2] == object {
			return true
		}
	}
	return false
}

// TestAB_IAM_1_28_Revoke_SerializesWithConcurrentForwardPass — the failing scenario
// of the missing advisory lock, end-to-end.
func TestAB_IAM_1_28_Revoke_SerializesWithConcurrentForwardPass(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	owner := mustSeedUser(t, ctx, pool, "rvlk")
	acc := seedAccountByOwner(t, ctx, pool, "acc-rvlk", owner)
	member := mustSeedUser(t, ctx, pool, "rvlkm")
	role := seedAccountCustomRole(t, ctx, pool, acc, "rvlk_role")

	// One ACTIVE binding with a two-tuple ledger (the grant-time emitted set).
	abID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID: abID, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: role, ResourceType: "account", ResourceID: string(acc),
	})
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().InsertEmittedTuples(ctx, abID, []abrepo.RelationTuple{
		{User: "user:" + string(member), Relation: "v_get", Object: "vpc_network:net-1"},
		{User: "user:" + string(member), Relation: "v_update", Object: "vpc_network:net-1"},
	}))
	require.NoError(t, w.Commit(ctx))

	// Дублёр параллельного писателя: SHARE на hashtext(binding_id) + НОВАЯ строка журнала,
	// ещё не закоммиченная. Настоящий форвард блокировки не берёт — см. шапку файла.
	fwd, err := pool.Begin(ctx)
	require.NoError(t, err)
	fwdDone := false
	defer func() {
		if !fwdDone {
			_ = fwd.Rollback(ctx)
		}
	}()
	_, err = fwd.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtext($1))`, string(abID))
	require.NoError(t, err)
	_, err = fwd.Exec(ctx, `
		INSERT INTO kacho_iam.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
		VALUES ($1, $2, $3, $4, 'member')`,
		string(abID), "user:"+string(member), "v_get", "vpc_network:net-race")
	require.NoError(t, err)

	uc := accessbindingapp.NewRevokeAccessBindingUseCase(repo, opsRepo).WithRelationStore(denyingRelations{}, nil)

	op, err := uc.Execute(asUser(ctx, owner), abID)
	require.NoError(t, err, "the sync path (authz + protection) must pass for the account owner")

	// (1) The revoke writer-tx must BLOCK on the EXCLUSIVE binding lock while the
	// forward tx holds SHARE. Without the lock it races to completion here.
	require.False(t, opDoneWithin(t, ctx, opsRepo, op.ID, 1500*time.Millisecond),
		"the revoke writer-tx must WAIT for the concurrent forward pass "+
			"(EXCLUSIVE pg_advisory_xact_lock(hashtext(binding_id)) ⊥ its SHARE lock)")

	// (2) Release the forward pass; the revoke now sees the full ledger.
	require.NoError(t, fwd.Commit(ctx))
	fwdDone = true

	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error, "revoke must succeed after the forward pass commits")

	stated := journalDeletes(t, ctx, pool)
	require.NotEmpty(t, stated,
		"отзыв не заявил в журнале НИ ОДНОЙ строки снятия — без неё триггер проекции не уберёт "+
			"прямой факт, и отозванная выдача продолжает давать доступ")
	assert.True(t, hasDelete(stated, "user:"+string(member), "v_get", "vpc_network:net-race"),
		"кортеж, добавленный гонящимся прямым проходом, обязан попасть в заявленный набор снятия — "+
			"ОТОЗВАННУЮ привязку пропускает каждый путь реконсиляции, и подобрать его больше некому")

	// СИММЕТРИЯ ОТЗЫВА: каждая строка ведомости привязки покрыта заявленным снятием.
	//
	// Ведомость при этом НЕ очищается, и это осознанно: она — запись о том, что было
	// эмитировано, и переживает отзыв. Поэтому утверждается не её пустота, а
	// ПОКРЫТИЕ: строка ведомости, которой нет в заявленном наборе, — это выдача,
	// пережившая свой отзыв, и подобрать её больше некому (ОТОЗВАННУЮ привязку
	// пропускает каждый путь реконсиляции).
	//
	// Проверяется поимённо, а не сравнением длин: два набора одинакового размера
	// могут не пересекаться вовсе, и счёт дал бы зелёное ровно на подмене набора.
	rows, err := pool.Query(ctx,
		`SELECT fga_user, relation, object FROM kacho_iam.access_binding_emitted_tuples
		  WHERE binding_id = $1`, string(abID))
	require.NoError(t, err)
	var ledger [][3]string
	for rows.Next() {
		var u, r, o string
		require.NoError(t, rows.Scan(&u, &r, &o))
		ledger = append(ledger, [3]string{u, r, o})
	}
	rows.Close()
	require.NoError(t, rows.Err())
	require.NotEmpty(t, ledger, "ведомость привязки пуста — покрывать нечего, "+
		"и утверждение ниже прошло бы на отзыве, который не сделал ничего")
	for _, l := range ledger {
		assert.Truef(t, hasDelete(stated, l[0], l[1], l[2]),
			"строка ведомости %v не покрыта заявленным снятием — эта выдача переживает свой отзыв", l)
	}
	t.Logf("перепись: заявлено к снятию строк %d, строк ведомости %d", len(stated), len(ledger))
}

// opDoneWithin polls the operation for at most d and reports whether it completed.
func opDoneWithin(t *testing.T, ctx context.Context, opsRepo operations.Repo, id string, d time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		op, err := opsRepo.Get(ctx, id)
		require.NoError(t, err)
		if op.Done {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}
