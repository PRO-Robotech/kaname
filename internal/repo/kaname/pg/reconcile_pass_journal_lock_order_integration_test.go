// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_pass_journal_lock_order_integration_test.go — два полных прохода
// реконсайлера РАЗНЫХ выдач одного субъекта с пересекающимися объектами не встают
// в тупик на строках прямого факта (kaname#617).
//
// ПРЕДМЕТ. Строку журнала в прямой факт складывает операторный триггер
// (`kaname.relation_fact_from_journal`): внутри ОДНОГО оператора он берёт замки
// строк факта в общем порядке (объект, субъект). Проход реконсайлера писал журнал
// НЕСКОЛЬКИМИ операторами — запись по члену в цикле сверки и строки снятия в конце
// прохода (flushDeletes), — и между операторами порядок задавал писатель. Проход
// выдачи B, у которой объект «a» выпал из отбора, а объект «b» в него вошёл, брал
// «b» (запись) раньше «a» (снятие); проход выдачи A того же субъекта, в чей отбор
// входят оба, брал «a» раньше «b». Встречные замки — и база снимает одну из
// транзакций отказом 40P01.
//
// КАК ПРОБА ДЕЛАЕТ ГОНКУ ДЕТЕРМИНИРОВАННОЙ. Держатель берёт строку факта объекта
// «a» (меньший идентификатор). Проход A стартует первым и становится за держателем
// на «a» — своей первой записи. Проход B стартует вторым: в мире «встречно» он
// успевает записать «b» и встаёт за держателем на снятии «a»; в мире «одинаково»
// его первая строка — «a», и он встаёт за держателем, ничего не взяв. Держатель
// отпускает строку — дальше исход определён порядком внутри проходов, а не случаем.
//
// Близнец меняет РОВНО ОДИН факт — какой из двух объектов выдача B снимает, а какой
// пишет (метки объектов переставлены); отбор, субъект, роли, держатель — те же.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestReconcilePassesOfOneSubjectCommitWhenOneRevokesWhatTheOtherWrites — проход B
// пишет «b» и снимает «a», проход A пишет «a» и «b»: обе транзакции коммитятся.
func TestReconcilePassesOfOneSubjectCommitWhenOneRevokesWhatTheOtherWrites(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	errA, errB := raceTwoReconcilePasses(t, "p617x", "i617a", "i617b")
	require.NoError(t, errA, "проход выдачи A не должен падать тупиком на проходе соседней выдачи того же субъекта")
	require.NoError(t, errB, "проход выдачи B не должен падать тупиком на проходе соседней выдачи того же субъекта")
}

// TestReconcilePassesOfOneSubjectCommitWhenTheyMeetInOneOrder — законный близнец:
// выдача B снимает «b» и пишет «a», то есть оба прохода берут «a» раньше «b». Зелен
// на любой реализации прохода; без него красное выше не отличить от поломки гонки.
func TestReconcilePassesOfOneSubjectCommitWhenTheyMeetInOneOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	errA, errB := raceTwoReconcilePasses(t, "p617y", "i617b", "i617a")
	require.NoError(t, errA)
	require.NoError(t, errB)
}

// raceTwoReconcilePasses поднимает трёх держателей прав одного субъекта на двух
// объектах и сталкивает полные проходы выдач A и B под держателем строки факта
// объекта с меньшим идентификатором.
//
//   - выдача B (отбор team=b) до гонки держит `revoked`; к гонке метка переезжает на
//     `written`: проход B пишет `written` и снимает `revoked`;
//   - выдача C (отбор keep=y) держит `written` — его строка факта существует до
//     гонки, и запись прохода B берёт замок существующей строки;
//   - выдача A (отбор pool=x) новая: её проход пишет оба объекта в порядке
//     идентификаторов.
func raceTwoReconcilePasses(t *testing.T, suffix, revoked, written string) (errA, errB error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	fx := setupGamma(t, ctx, pool, suffix)
	rec, _ := newReconciler(pool)
	rule := func(labels map[string]string) domain.Rules {
		return domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}, MatchLabels: labels}}
	}
	roleA := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "a"+suffix, rule(map[string]string{"pool": "x"}))
	roleB := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "b"+suffix, rule(map[string]string{"team": "b"}))
	roleC := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "c"+suffix, rule(map[string]string{"keep": "y"}))

	v0 := time.Now()
	seedMirrorRow(t, ctx, pool, "compute.instance", revoked, string(fx.prj), string(fx.accID), map[string]string{"pool": "x", "team": "b"}, v0)
	seedMirrorRow(t, ctx, pool, "compute.instance", written, string(fx.prj), string(fx.accID), map[string]string{"pool": "x", "keep": "y"}, v0)

	bindB := insertThinBinding(t, ctx, fx.repo, fx.member, roleB, fx.prj)
	bindC := insertThinBinding(t, ctx, fx.repo, fx.member, roleC, fx.prj)
	require.NoError(t, rec.ReconcileBinding(ctx, bindB))
	require.NoError(t, rec.ReconcileBinding(ctx, bindC))

	subject := "user:" + string(fx.member)
	require.Equal(t, 1, factRows(t, ctx, pool, subject, revoked), "предусловие: факт снимаемого объекта выдан выдачей B")
	require.Equal(t, 1, factRows(t, ctx, pool, subject, written), "предусловие: факт записываемого объекта выдан выдачей C")

	// Метка выдачи B переезжает: снимаемый объект выпадает из её отбора, записываемый входит.
	v1 := v0.Add(time.Second)
	seedMirrorRow(t, ctx, pool, "compute.instance", revoked, string(fx.prj), string(fx.accID), map[string]string{"pool": "x"}, v1)
	seedMirrorRow(t, ctx, pool, "compute.instance", written, string(fx.prj), string(fx.accID), map[string]string{"pool": "x", "keep": "y", "team": "b"}, v1)
	bindA := insertThinBinding(t, ctx, fx.repo, fx.member, roleA, fx.prj)

	held := min(revoked, written)
	holder, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = holder.Rollback(context.Background()) })
	var locked int
	require.NoError(t, holder.QueryRow(ctx,
		`SELECT count(*) FROM (SELECT 1 FROM kaname.relation_fact
		  WHERE object_type = 'compute_instance' AND object_id = $1 AND subject = $2 FOR UPDATE) s`,
		held, subject).Scan(&locked))
	require.Equal(t, 1, locked, "предусловие: строка факта объекта %s взята держателем", held)

	run := func(bid domain.AccessBindingID) <-chan error {
		done := make(chan error, 1)
		go func() { done <- rec.ReconcileBinding(ctx, bid) }()
		return done
	}
	doneA := run(bindA)
	waitPassLockWaiters(t, ctx, pool, 1)
	doneB := run(bindB)
	waitPassLockWaiters(t, ctx, pool, 2)

	require.NoError(t, holder.Commit(ctx))
	errA, errB = <-doneA, <-doneB
	for _, e := range []error{errA, errB} {
		var pgErr *pgconn.PgError
		if errors.As(e, &pgErr) {
			t.Logf("отказ базы: SQLSTATE %s — %s", pgErr.Code, pgErr.Message)
		}
	}
	return errA, errB
}

// factRows — сколько строк прямого факта субъекта стоит на объекте compute_instance.
func factRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subject, objectID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.relation_fact
		  WHERE object_type = 'compute_instance' AND object_id = $1 AND subject = $2`,
		objectID, subject).Scan(&n))
	return n
}

// waitPassLockWaiters ждёт, пока в базе пробы не наберётся n сеансов, ждущих
// замок: гонка поставлена, когда база её видит, а не когда истёк сон.
func waitPassLockWaiters(t *testing.T, ctx context.Context, pool *pgxpool.Pool, n int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		var waiting int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting))
		if waiting >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("предусловие гонки не создано: ждущих замок %d из %d", waiting, n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
