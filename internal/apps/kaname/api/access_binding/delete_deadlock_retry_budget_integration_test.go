// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// delete_deadlock_retry_budget_integration_test.go — у повтора снятия выдачи,
// проигравшей взаимную блокировку, есть ПРЕДЕЛ, и исход его исчерпания — прежний
// терминальный отказ кода 10, а не бесконечное ожидание и не другой код.
//
// ПРЕДМЕТ (kaname#683, второй пункт предиката снятия). Соседняя проба
// TestAB_DeleteThatLosesADeadlockIsRetriedNotRefused держит ОДИН проигрыш: снятие
// стало жертвой цикла один раз и следующей попыткой дошло до коммита. Она зелена и
// при повторе без предела, и при исчерпании, отдающем `internal error`: ни одна её
// строка не доходит до третьего проигрыша. Здесь цикл ожиданий ставится КАЖДОЙ
// попытке снятия, пока операция не завершится, и утверждается:
//
//   - попыток ровно wantDeleteAttempts — ни повтора сверх предела, ни отказа раньше;
//   - исход — ABORTED (10) прежним терминальным текстом;
//   - выдача жива, прямой факт и ведомость эмитированного целы — изменение НЕ
//     применено ни частично, ни целиком;
//   - состояние осталось годным: следующее снятие без спора доходит до коммита.
//
// Законный близнец — та же расстановка, где спор стихает за одну попытку до
// предела: wantDeleteAttempts−1 проигрышей подряд, после чего держатель уходит, и
// снятие завершается без отказа. Пара «предел−1 → успех, предел → отказ» держит
// число с обеих сторон: предел меньше краснит близнеца, больше — основной случай.
//
// КАК ЦИКЛ СТАВИТСЯ ЗАНОВО КАЖДОЙ ПОПЫТКЕ — БЕЗ ПАУЗ. Держатель — одна транзакция,
// удерживающая строку спора все раунды (формы — `deadlockHolderForms` соседней
// пробы: строка выдачи и строка прямого факта). Замок выдачи он берёт
// СЕССИОННЫМ advisory того же ключа, что `pg_advisory_xact_lock` снятия: ключевое
// пространство у них общее, а сессионный замок, в отличие от транзакционного,
// отпускается посреди транзакции. Раунд:
//
//  1. снятие держит advisory выдачи и стоит за держателем на строке спора;
//  2. держатель просит advisory — цикл; держатель поднял свой `deadlock_timeout`,
//     поэтому жертва — снятие, его транзакция откатывается целиком;
//  3. повтор снятия встаёт в очередь за advisory держателя — держатель его
//     отпускает, повтор берёт advisory и встаёт на строке спора: раунд 1 снова.
//
// Каждый шаг ждёт НАБЛЮДАЕМОГО состояния замков (pg_locks), а не времени.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// wantDeleteAttempts — сколько раз тело снятия исполняет свою транзакцию, прежде
// чем отдать отказ. Число — контракт `deleteAttempts` в delete.go (там же довод,
// почему три); проба держит его снаружи, потому что смена предела — смена
// наблюдаемого исхода, и она обязана пройти через эту строку.
const wantDeleteAttempts = 3

// awaitRetryOrDone ждёт одного из двух исходов после проигрыша снятия: повтор
// встал в очередь за advisory держателя (true) либо операция завершилась (false).
func awaitRetryOrDone(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	opsRepo operations.Repo, opID string, round int) (retried bool, done *operations.Operation) {
	t.Helper()
	deadline := time.Now().Add(deadlockQueueBudget)
	for time.Now().Before(deadline) {
		if advisoryWaiters(t, ctx, pool) >= 1 {
			return true, nil
		}
		op, err := opsRepo.Get(ctx, opID)
		require.NoError(t, err)
		if op.Done {
			return false, op
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("после проигрыша %d снятие за %s ни повторилось, ни завершилось", round, deadlockQueueBudget)
	return false, nil
}

func emittedTupleCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id domain.AccessBindingID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1`, string(id)).Scan(&n))
	return n
}

func bindingRowCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id domain.AccessBindingID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_bindings WHERE id=$1`, string(id)).Scan(&n))
	return n
}

func TestAB_DeleteThatKeepsLosingADeadlockExhaustsIntoAborted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	for _, form := range deadlockHolderForms {
		t.Run(form.name, func(t *testing.T) {
			t.Run("спор не стихает — исчерпание даёт ABORTED, выдача цела", func(t *testing.T) {
				deleteKeepsLosingDeadlock(t, form, 0)
			})
			t.Run("близнец: спор стихает до предела — снятие доходит до коммита", func(t *testing.T) {
				deleteKeepsLosingDeadlock(t, form, wantDeleteAttempts-1)
			})
		})
	}
}

// deleteKeepsLosingDeadlock ставит снятию цикл ожиданий на каждой попытке. stopAfter
// — после скольких проигрышей держатель уходит (близнец); 0 — не уходит, пока
// операция не завершится.
func deleteKeepsLosingDeadlock(t *testing.T, form deadlockHolderForm, stopAfter int) {
	ctx := context.Background()
	pool := poolFromDSN(t, setupTestDB(t))
	repo := kanamepg.New(pool, nil)
	opsRepo := shared.NewTerminalRefusalRepo(operations.NewRepo(pool, "kaname"))
	rec := reconcile.New(kanamepg.NewReconcileAdapter(pool, catalogfixture.Source()), nil, catalogfixture.Source())

	owner := mustSeedUser(t, ctx, pool, "dlx-own")
	member := mustSeedUser(t, ctx, pool, "dlx-mem")
	acc := seedAccountByOwner(t, ctx, pool, "acc-dlx", owner)
	prj := seedProjectInAccount(t, ctx, pool, acc, "prj-dlx")

	rules := domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}}}
	role := seedRulesRoleWithSelectors(t, ctx, repo, acc, "dlx_a", rules)
	const obj = "i-dlx-0001"
	seedMirrorObject(t, ctx, pool, "compute.instance", obj, string(prj), string(acc))

	victim := insertAccountBinding(t, ctx, repo, member, role, acc)
	require.NoError(t, rec.ReconcileBindingForward(ctx, victim))
	subject := "user:" + string(member)
	require.True(t, factRowExists(t, ctx, pool, "compute_instance", obj, "viewer", subject),
		"контроль: выдача обязана материализовать прямой факт — иначе снятие не тронуло "+
			"бы строку, за которую идёт спор")
	emittedBefore := emittedTupleCount(t, ctx, pool, victim)
	require.Positive(t, emittedBefore, "контроль: ведомость эмитированного непуста — иначе её целость ничего не значит")

	// Держатель — ОДНА транзакция на все раунды: строку спора он не отпускает.
	hold, err := pool.Begin(ctx)
	require.NoError(t, err)
	holding := true
	release := func() {
		if !holding {
			return
		}
		holding = false
		// Сессионный замок переживает откат транзакции — отпускается явно.
		_, _ = hold.Exec(ctx, `SELECT pg_advisory_unlock_all()`)
		_ = hold.Rollback(ctx)
	}
	defer release()
	_, err = hold.Exec(ctx, `SET LOCAL deadlock_timeout = '60s'`)
	require.NoError(t, err)
	tag, err := hold.Exec(ctx, form.lockSQL, string(victim), obj, subject)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "контроль: держатель удерживает ровно строку спора")

	delUC := accessbindingapp.NewDeleteAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(denyingRelations{}, nil)
	op, err := delUC.Execute(asUser(ctx, owner), victim)
	require.NoError(t, err, "снятие принято к исполнению")

	var done *operations.Operation
	lost := 0
	for done == nil {
		// Попытка снятия держит advisory выдачи и стоит за держателем на строке.
		waitRowLockWaiters(t, ctx, pool, 1, "снятие")
		inflictDeadlock(t, ctx, hold, victim)
		lost++

		if stopAfter > 0 && lost == stopAfter {
			release()
			done = awaitOp(t, ctx, opsRepo, op.ID)
			break
		}
		retried, d := awaitRetryOrDone(t, ctx, pool, opsRepo, op.ID, lost)
		if !retried {
			done = d
			break
		}
		require.Less(t, lost, wantDeleteAttempts,
			"снятие исполнило транзакцию в %d-й раз: повтор сверх предела %d — спор, "+
				"который не стихает, держит операцию незавершённой, а вызывающего без ответа",
			lost+1, wantDeleteAttempts)
		// Повтор стоит за advisory держателя — отпустить, чтобы он встал на строке.
		_, err = hold.Exec(ctx, `SELECT pg_advisory_unlock(hashtext($1))`, string(victim))
		require.NoError(t, err)
	}
	release()

	if stopAfter > 0 {
		require.Equal(t, stopAfter, lost, "контроль: проигрышей ровно столько, сколько поставлено")
		require.Nil(t, done.Error,
			"снятие, проигравшее %d раз из %d допустимых, обязано дойти до коммита на следующей "+
				"попытке; отказ здесь — предел повтора меньше объявленного", lost, wantDeleteAttempts)
		require.Zero(t, bindingRowCount(t, ctx, pool, victim), "снятая выдача обязана исчезнуть")
		require.False(t, factRowExists(t, ctx, pool, "compute_instance", obj, "viewer", subject),
			"прямой факт снятой выдачи обязан уйти той же транзакцией")
		return
	}

	require.NotNil(t, done.Error,
		"снятие, проигравшее взаимную блокировку на каждой из %d попыток, обязано завершиться "+
			"отказом: изменение не применено, и вызывающий должен это узнать", wantDeleteAttempts)
	require.Equal(t, int32(codes.Aborted), done.Error.Code,
		"исчерпание повторов отдаёт прежний код 10 (ABORTED), а не %s: «%s» (проигрышей %d)",
		codes.Code(done.Error.Code), done.Error.Message, lost)
	require.Equal(t, iamerr.SerializationConflictTerminalText, done.Error.Message,
		"исчерпание повторов отдаёт прежний терминальный текст")
	require.Equal(t, wantDeleteAttempts, lost,
		"снятие обязано исполнить свою транзакцию ровно %d раз, прежде чем отказать", wantDeleteAttempts)

	require.Equal(t, 1, bindingRowCount(t, ctx, pool, victim),
		"выдача, чьё снятие отказано, обязана остаться живой")
	require.True(t, factRowExists(t, ctx, pool, "compute_instance", obj, "viewer", subject),
		"прямой факт неснятой выдачи обязан остаться: отказ означает «не применено»")
	require.Equal(t, emittedBefore, emittedTupleCount(t, ctx, pool, victim),
		"ведомость эмитированного неснятой выдачи обязана остаться целой")

	// Состояние годно: следующее снятие без спора доходит до коммита.
	again, err := delUC.Execute(asUser(ctx, owner), victim)
	require.NoError(t, err, "повторное снятие принято к исполнению")
	redo := awaitOp(t, ctx, opsRepo, again.ID)
	require.Nil(t, redo.Error, "снятие после отказанного обязано пройти: отказ не оставил полусостояния")
	require.Zero(t, bindingRowCount(t, ctx, pool, victim), "выдача снята повторным снятием")
	require.False(t, factRowExists(t, ctx, pool, "compute_instance", obj, "viewer", subject),
		"прямой факт уходит вместе с выдачей")
}

// inflictDeadlock замыкает цикл: держатель (строка спора у него) просит advisory
// выдачи, который держит стоящее за ним снятие. Возврат — держатель получил замок,
// то есть база сняла жертву; жертва — снятие, потому что держатель поднял свой
// deadlock_timeout.
func inflictDeadlock(t *testing.T, ctx context.Context, hold pgx.Tx, id domain.AccessBindingID) {
	t.Helper()
	lctx, cancel := context.WithTimeout(ctx, deadlockQueueBudget)
	defer cancel()
	_, err := hold.Exec(lctx, `SELECT pg_advisory_lock(hashtext($1))`, string(id))
	require.NoError(t, err, "держатель получает advisory, когда жертва снята; иначе цикл не разрешился")
}
