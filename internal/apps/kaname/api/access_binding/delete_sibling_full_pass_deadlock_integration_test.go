// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// delete_sibling_full_pass_deadlock_integration_test.go — снятие выдачи и ПОЛНЫЙ проход
// соседней выдачи того же субъекта не роняют друг друга взаимной блокировкой.
//
// ПРЕДМЕТ. Субъект держит две выдачи одной роли: A — на аккаунт, P — на проект этого
// аккаунта. Прямой факт ключуется субъектом, объектом и отношением, а не выдачей, поэтому
// объекты проекта у A и P — ОДНИ И ТЕ ЖЕ строки `kaname.relation_fact`. Замков advisory
// у сторон разные (A и P), и они друг друга не упорядочивают.
//
//   - Снятие A складывает свой набор в журнал одним упорядоченным набором (объект,
//     субъект, отношение) — порядок, общий для всех писателей журнала.
//   - Полный проход P (периодическое сведение; оно же дожимает выдачу, чей быстрый путь
//     на создании не прошёл) писал журнал ПО ЧЛЕНУ: строка члена, его кортежи, следующий
//     член. Порядок членов — порядок правил роли и объектов внутри правила, а не порядок
//     журнала, и проход приходил к очередной строке прямого факта, уже удерживая строку
//     предыдущего члена.
//
// Два порядка одних строк — цикл ожидания, из которого Postgres выходит, снимая одну
// сторону (40P01). Когда снятой оказывается снятие, A остаётся жива, и каждое следующее
// создание того же набора получает ALREADY_EXISTS — ровно этот исход наблюдался на
// конвейере (kaname#689, коллекция iam-access-binding-account-scope).
//
// ПОЧЕМУ ПОРЯДОК ЗАДАЁТСЯ ДЕРЖАТЕЛЕМ, А НЕ ПАУЗАМИ. Роль несёт два правила, и первым
// стоит то, чей объект в порядке журнала ПОСЛЕДНИЙ (vpc_network после compute_instance).
// Держатель вставляет (не коммитя) строку члена P на объекте второго правила — проход P
// встаёт за ней в очередь, записав всё, что успел до неё. Снятие A идёт следом. Держатель
// уходит, и стороны встречаются так, как встретились бы без него, — но всегда в одном и
// том же расположении.
//
// Исход утверждается НАБЛЮДАЕМЫЙ, в обоих мирах один: обе стороны завершились без отказа,
// A исчезла, а прямой факт P на обоих объектах есть — живая выдача своё право получила.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/PRO-Robotech/kaname/internal/testsupport/journalfixture"
)

// lockWaiters — сколько бэкендов ЭТОЙ базы ждут замка строки или транзакции.
// «Встал в очередь» — наблюдаемое состояние, и проба дожидается именно его.
func lockWaiters(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_stat_activity
		 WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&n))
	return n
}

// insertProjectBinding — ACTIVE-выдача субъекту на область проекта.
func insertProjectBinding(t *testing.T, ctx context.Context, repo *kanamepg.Repository,
	subject domain.UserID, role domain.RoleID, prj domain.ProjectID) domain.AccessBindingID {
	t.Helper()
	bid := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w, err := repo.Writer(journalfixture.Writing(ctx))
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	_, err = w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID: bid, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(subject),
		RoleID: role, ResourceType: "project", ResourceID: string(prj),
		Scope: domain.ScopeProject, Status: domain.AccessBindingStatusActive,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return bid
}

func TestAB_DeleteAndSiblingFullPass_DoNotDeadlock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool := poolFromDSN(t, setupTestDB(t))
	repo := kanamepg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kaname")
	rec := reconcile.New(kanamepg.NewReconcileAdapter(pool, catalogfixture.Source()), nil, catalogfixture.Source())

	owner := mustSeedUser(t, ctx, pool, "dsf-own")
	member := mustSeedUser(t, ctx, pool, "dsf-mem")
	acc := seedAccountByOwner(t, ctx, pool, "acc-dsf", owner)
	prj := seedProjectInAccount(t, ctx, pool, acc, "prj-dsf")

	// Первым стоит правило, чей объект в порядке журнала ПОСЛЕДНИЙ: проход P
	// возьмёт строку факта vpc_network раньше, чем строку compute_instance, а
	// снятие A — наоборот.
	rules := domain.Rules{
		{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}},
		{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}},
	}
	role := seedRulesRoleWithSelectors(t, ctx, repo, acc, "dsf", rules)

	const netID, vmID = "net-dsf-0001", "i-dsf-0001"
	seedMirrorObject(t, ctx, pool, "vpc.network", netID, string(prj), string(acc))
	seedMirrorObject(t, ctx, pool, "compute.instance", vmID, string(prj), string(acc))

	subject := "user:" + string(member)
	a := insertAccountBinding(t, ctx, repo, member, role, acc)
	require.NoError(t, rec.ReconcileBinding(ctx, a))
	require.True(t, factRowExists(t, ctx, pool, "vpc_network", netID, "viewer", subject),
		"контроль: A материализовала факт на сети — снятие A обязано до него дойти")
	require.True(t, factRowExists(t, ctx, pool, "compute_instance", vmID, "viewer", subject),
		"контроль: A материализовала факт на машине — снятие A обязано до него дойти")

	// P не материализована: так её застаёт полный проход, когда быстрый путь создания
	// не прошёл. Её реестр пуст, и снятие A ничего у неё не «оставляет».
	p := insertProjectBinding(t, ctx, repo, member, role, prj)
	require.False(t, ledgerHas(t, ctx, pool, string(p), subject, "viewer", "compute_instance:"+vmID),
		"контроль: P не материализована — её полный проход обязан записать факт сам")

	// ── ДЕРЖАТЕЛЬ: строка члена P на объекте ВТОРОГО правила ─────────────────
	hold, err := pool.Begin(ctx)
	require.NoError(t, err)
	released := false
	defer func() {
		if !released {
			_ = hold.Rollback(ctx)
		}
	}()
	_, err = hold.Exec(ctx, `
		INSERT INTO kaname.access_binding_target_members
		  (binding_id, role_id, rule_fp, object_type, object_id, verification_status, created_at, updated_at)
		VALUES ($1, $2, $3, 'compute.instance', $4, 'ACTIVE', now(), now())`,
		string(p), string(role), rules[1].Fingerprint(), vmID)
	require.NoError(t, err)

	// ── 1) ПОЛНЫЙ ПРОХОД P встаёт за держателем ──────────────────────────────
	pass := make(chan error, 1)
	go func() { pass <- rec.ReconcileBinding(ctx, p) }()
	deadline := time.Now().Add(deadlockQueueBudget)
	for lockWaiters(t, ctx, pool) < 1 {
		require.True(t, time.Now().Before(deadline), "полный проход P не встал в очередь за держателем")
		time.Sleep(20 * time.Millisecond)
	}

	// ── 2) СНЯТИЕ A ───────────────────────────────────────────────────────────
	delUC := accessbindingapp.NewDeleteAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(denyingRelations{}, nil)
	op, err := delUC.Execute(asUser(ctx, owner), a)
	require.NoError(t, err, "снятие принято к исполнению")
	// Снятие либо встаёт в очередь (вторым ожидающим), либо проходит целиком, если
	// проход P до держателя не взял ни одной строки факта. Оба расположения законны;
	// незаконен только исход с отказом ниже.
	deadline = time.Now().Add(deadlockQueueBudget)
	for {
		if lockWaiters(t, ctx, pool) >= 2 {
			break
		}
		got, gerr := opsRepo.Get(ctx, op.ID)
		require.NoError(t, gerr)
		if got.Done {
			break
		}
		require.True(t, time.Now().Before(deadline), "снятие A ни встало в очередь, ни завершилось")
		time.Sleep(20 * time.Millisecond)
	}

	// ── 3) Держатель уходит ───────────────────────────────────────────────────
	released = true
	require.NoError(t, hold.Rollback(ctx))

	select {
	case perr := <-pass:
		require.NoError(t, perr, "полный проход P не должен сниматься взаимной блокировкой")
	case <-time.After(deadlockQueueBudget):
		t.Fatal("полный проход P не завершился")
	}
	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error,
		"снятие A не должно завершаться отказом: отказ здесь — взаимная блокировка, после "+
			"которой A остаётся жива, а следующее создание того же набора получает ALREADY_EXISTS")

	var alive int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_bindings WHERE id=$1`, string(a)).Scan(&alive))
	require.Zero(t, alive, "снятая выдача обязана исчезнуть")
	require.True(t, factRowExists(t, ctx, pool, "vpc_network", netID, "viewer", subject),
		"живая выдача P держит право на сети")
	require.True(t, factRowExists(t, ctx, pool, "compute_instance", vmID, "viewer", subject),
		"живая выдача P держит право на машине")
}
