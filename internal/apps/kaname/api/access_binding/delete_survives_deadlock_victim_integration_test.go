// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// delete_survives_deadlock_victim_integration_test.go — снятие выдачи, ставшее
// ЖЕРТВОЙ взаимной блокировки, не завершает операцию отказом: его транзакция
// откатилась целиком, и тело исполняется заново.
//
// ПРЕДМЕТ (kaname#679, корень 2). На автономном стенде под параллельным прогоном
// наборов снятие выдачи на аккаунт завершилось `done:true` с
// `{"code":10,"message":"conflicting concurrent change, the operation was not
// applied; submit a new request"}`: транзакция снятия проиграла взаимную
// блокировку фоновой материализации того же субъекта (в журнале службы той же
// секундой — `deadlock detected (SQLSTATE 40P01)` на записи журнала намерений).
// Выдача осталась жива, и каждое следующее создание той же тройки получало
// `ALREADY_EXISTS` — двадцать упавших утверждений в двух наборах.
//
// Сторона арендатора не обязана проигрывать фоновой работе: взаимная блокировка —
// отказ, после которого база откатила транзакцию снятия ЦЕЛИКОМ, ничего не
// применив, и повтор той же транзакции — ровно то, что PostgreSQL предписывает
// на 40P01/40001. Тело снятия — ОДНА транзакция записи, после коммита оно не
// делает ничего (см. delete.go), поэтому повтор его безопасен по построению.
//
// КАК РАССТАВЛЕНА БЛОКИРОВКА — ДЕРЖАТЕЛЕМ, А НЕ ПАУЗАМИ. Контрагент на стенде —
// фоновая транзакция, удерживающая строку, до которой снятие обязано дойти, и
// ждущая замка, который держит снятие. Держатель `hold` воспроизводит ровно эту
// пару ожиданий:
//
//  1. держатель берёт строку спора (форма — `deadlockHolderForms`);
//  2. снятие берёт advisory-замок выдачи (первый свой стейтмент) и встаёт за
//     держателем на этой строке;
//  3. держатель просит advisory-замок выдачи — цикл замкнут.
//
// Жертва выбирается детерминированно: держатель поднимает свой `deadlock_timeout`
// до минуты, поэтому проверку цикла первой выполняет снятие (у него умолчание
// сервера) и снимается именно оно — тот самый исход, что на стенде.
//
// Близнец (законный исход той же расстановки без цикла) — соседняя проба
// TestAB_DeleteAndObjectFanout_DoNotDeadlock: там снятие ждёт, но не становится
// жертвой, и операция завершается без отказа в обоих мирах.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// rowLockWaiters — сколько бэкендов ЭТОЙ базы ждут чужой транзакции (строковый
// замок ждётся как замок идентификатора транзакции-держателя).
func rowLockWaiters(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_locks
		 WHERE locktype = 'transactionid' AND NOT granted
		   AND pid IN (SELECT pid FROM pg_stat_activity WHERE datname = current_database())`).Scan(&n))
	return n
}

func waitRowLockWaiters(t *testing.T, ctx context.Context, pool *pgxpool.Pool, want int, what string) {
	t.Helper()
	deadline := time.Now().Add(deadlockQueueBudget)
	for time.Now().Before(deadline) {
		if rowLockWaiters(t, ctx, pool) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s не встал(а) за держателем строки за %s: ожидающих %d, требуется %d",
		what, deadlockQueueBudget, rowLockWaiters(t, ctx, pool), want)
}

// deadlockHolderForm — какую строку держатель удерживает до того, как попросить
// advisory-замок выдачи. Форм две, и это ДВА разных стейтмента снятия, на которых
// оно встаёт за держателем: строка самой выдачи (так держит её фоновая
// материализация, вставившая дочернюю строку по внешнему ключу, — `FOR KEY SHARE`)
// и строка прямого факта (её держит запись журнала намерений). На стенде снятие
// проиграло на первой — отказ пришёл кодом 10; вторая до починки отдавала
// `internal error`, потому что запись журнала единственная в транзакции не
// переводила отказ базы в признак.
type deadlockHolderForm struct {
	name string
	// lockSQL берёт строку; $1 — id выдачи, $2 — объект, $3 — субъект.
	lockSQL string
}

var deadlockHolderForms = []deadlockHolderForm{
	{
		name: "строка выдачи (снятие встаёт на DELETE выдачи)",
		lockSQL: `SELECT 1 FROM kaname.access_bindings WHERE id = $1
		            AND $2::text IS NOT NULL AND $3::text IS NOT NULL FOR KEY SHARE`,
	},
	{
		name: "строка прямого факта (снятие встаёт на записи журнала)",
		lockSQL: `SELECT 1 FROM kaname.relation_fact
		           WHERE $1::text IS NOT NULL AND object_type = 'compute_instance'
		             AND object_id = $2 AND relation = 'viewer' AND subject = $3
		             FOR UPDATE`,
	},
}

func TestAB_DeleteThatLosesADeadlockIsRetriedNotRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	for _, form := range deadlockHolderForms {
		t.Run(form.name, func(t *testing.T) { deleteLosesDeadlock(t, form) })
	}
}

func deleteLosesDeadlock(t *testing.T, form deadlockHolderForm) {
	ctx := context.Background()
	pool := poolFromDSN(t, setupTestDB(t))
	repo := kanamepg.New(pool, nil)
	// Репозиторий операций — в той же обёртке, что в композиционном корне: отказ
	// терминального исхода приходит вызывающему ТЕРМИНАЛЬНЫМ текстом, и проба
	// краснеет ровно тем текстом, что на стенде.
	opsRepo := shared.NewTerminalRefusalRepo(operations.NewRepo(pool, "kaname"))
	rec := reconcile.New(kanamepg.NewReconcileAdapter(pool, catalogfixture.Source()), nil, catalogfixture.Source())

	owner := mustSeedUser(t, ctx, pool, "dlv-own")
	member := mustSeedUser(t, ctx, pool, "dlv-mem")
	acc := seedAccountByOwner(t, ctx, pool, "acc-dlv", owner)
	prj := seedProjectInAccount(t, ctx, pool, acc, "prj-dlv")

	rules := domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}}}
	role := seedRulesRoleWithSelectors(t, ctx, repo, acc, "dlv_a", rules)
	const obj = "i-dlv-0001"
	seedMirrorObject(t, ctx, pool, "compute.instance", obj, string(prj), string(acc))

	victim := insertAccountBinding(t, ctx, repo, member, role, acc)
	require.NoError(t, rec.ReconcileBindingForward(ctx, victim))
	subject := "user:" + string(member)
	require.True(t, factRowExists(t, ctx, pool, "compute_instance", obj, "viewer", subject),
		"контроль: выдача обязана материализовать прямой факт — иначе снятие ниже "+
			"не тронуло бы строку, за которую идёт спор")

	// ── 1) ДЕРЖАТЕЛЬ берёт строку спора; проверку цикла он не ведёт ─────────
	hold, err := pool.Begin(ctx)
	require.NoError(t, err)
	released := false
	defer func() {
		if !released {
			_ = hold.Rollback(ctx)
		}
	}()
	_, err = hold.Exec(ctx, `SET LOCAL deadlock_timeout = '60s'`)
	require.NoError(t, err)
	tag, err := hold.Exec(ctx, form.lockSQL, string(victim), obj, subject)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "контроль: держатель удерживает ровно строку спора")

	// ── 2) СНЯТИЕ: advisory выдачи взят, ждёт строку держателя ──────────────
	delUC := accessbindingapp.NewDeleteAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(denyingRelations{}, nil)
	op, err := delUC.Execute(asUser(ctx, owner), victim)
	require.NoError(t, err, "снятие принято к исполнению")
	waitRowLockWaiters(t, ctx, pool, 1, "снятие")

	// ── 3) ДЕРЖАТЕЛЬ просит advisory выдачи — цикл замкнут ───────────────────
	holderLocked := make(chan error, 1)
	go func() {
		_, lerr := hold.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, string(victim))
		holderLocked <- lerr
	}()
	select {
	case lerr := <-holderLocked:
		require.NoError(t, lerr, "держатель получает advisory, когда жертва снята")
	case <-time.After(deadlockQueueBudget):
		t.Fatal("держатель не получил advisory: цикл не разрешился снятием жертвы")
	}
	// Держатель уходит — повтору снятия больше ничто не мешает.
	released = true
	require.NoError(t, hold.Rollback(ctx))

	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error,
		"снятие, проигравшее взаимную блокировку, не должно завершаться отказом: его "+
			"транзакция откатилась целиком, и тело исполняется заново; отказ здесь "+
			"оставляет выдачу живой, а каждое следующее создание того же набора получает "+
			"ALREADY_EXISTS")

	var alive int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_bindings WHERE id=$1`, string(victim)).Scan(&alive))
	require.Zero(t, alive, "снятая выдача обязана исчезнуть")
	require.False(t, factRowExists(t, ctx, pool, "compute_instance", obj, "viewer", subject),
		"прямой факт снятой выдачи обязан уйти той же транзакцией")
}
