// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// delete_fanout_deadlock_integration_test.go — снятие выдачи и веер материализации
// по объекту НЕ роняют друг друга взаимной блокировкой.
//
// ПРЕДМЕТ. Обе стороны трогают ОДНИ И ТЕ ЖЕ строки прямого факта
// (`kaname.relation_fact` ключуется парой субъект+объект и отношением, а не выдачей),
// и обе берут advisory-замок выдачи. Снятие берёт замок ПЕРВЫМ стейтментом и лишь
// потом трогает прямой факт; веер до недавнего времени брал замок ОЧЕРЕДНОЙ выдачи
// уже удерживая строки прямого факта предыдущей — обратный порядок, из которого
// Postgres выходит, снимая одну сторону как взаимную блокировку (40P01). Жертвой
// оказывалась сторона арендатора: операция снятия завершалась `done:true` с
// `ABORTED`, выдача оставалась жива, и каждое следующее создание того же набора
// получало `ALREADY_EXISTS`.
//
// ЧЕМ ЭТА ПРОБА ОТЛИЧАЕТСЯ ОТ СОСЕДНЕЙ (f10_revoke_lock_integration_test.go). Та
// про ОТЗЫВ и её дублёр моделирует контрагента, которого в продукте нет (держит
// SHARE-advisory, тогда как форвард не берёт никакой). Здесь обе стороны — НАСТОЯЩИЕ:
// use-case снятия и `Reconciler.ReconcileObject`.
//
// ПОЧЕМУ ПОРЯДОК ЗАДАЁТСЯ ДЕРЖАТЕЛЕМ, А НЕ ПАУЗАМИ. Взаимная блокировка возникает на
// одном взаимном расположении двух транзакций; ловить его паузами значит получить
// пробу, которая краснеет иногда. Держатель `hold` ничего не моделирует — он лишь
// удерживает advisory жертвы, пока ОБЕ стороны не встанут в очередь за ним:
//
//	1. снятие встаёт первым — advisory это его первый стейтмент, оно НЕ держит ничего;
//	2. веер встаёт вторым — но до очереди он успевает записать прямой факт первой
//	   выдачи, то есть встаёт УЖЕ удерживая строку;
//	3. держатель уходит, снятие просыпается первым (очередь ожидания FIFO) и идёт к
//	   прямому факту, который держит веер, а веер ждёт advisory, который держит снятие.
//
// До починки шаг 3 давал 40P01. После — снятие проходит целиком, потому что веер
// берёт ВСЕ свои advisory-замки ДО первой записи и в очереди не держит ни строки.
// Расположение сторон от починки не меняется: оба ожидания на шагах 1-2 наступают
// в обоих мирах, поэтому зелёное здесь означает «прошли», а не «разминулись».

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
)

// deadlockQueueBudget — сколько даётся стороне, чтобы встать в очередь за
// держателем. Щедро относительно здорового прохода на пустой базе и заведомо
// меньше срока самого прогона: исчерпание означает, что сторона в очередь не
// встала, то есть проба перестала расставлять транзакции так, как объявляет.
const deadlockQueueBudget = 20 * time.Second

// advisoryWaiters — сколько бэкендов ЭТОЙ базы ждут advisory-замка.
//
// Читается из pg_locks, а не выводится из пауз: «встал в очередь» — наблюдаемое
// состояние, и проба обязана дожидаться именно его. Фильтр по базе нужен потому,
// что pg_locks — общий на кластер, а контейнер у пакета один на весь бинарь.
func advisoryWaiters(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM pg_locks
		 WHERE locktype = 'advisory' AND NOT granted
		   AND database = (SELECT oid FROM pg_database WHERE datname = current_database())`).Scan(&n))
	return n
}

func waitAdvisoryWaiters(t *testing.T, ctx context.Context, pool *pgxpool.Pool, want int, what string) {
	t.Helper()
	deadline := time.Now().Add(deadlockQueueBudget)
	for time.Now().Before(deadline) {
		if advisoryWaiters(t, ctx, pool) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s не встал(а) в очередь за держателем за %s: ожидающих advisory %d, требуется %d",
		what, deadlockQueueBudget, advisoryWaiters(t, ctx, pool), want)
}

// seedRulesRoleWithSelectors — роль аккаунта с правилами; селекторы правил проецируются
// тем же писателем, что и в продукте (без них веер не считает выдачу кандидатом).
func seedRulesRoleWithSelectors(t *testing.T, ctx context.Context, repo *kanamepg.Repository,
	acc domain.AccountID, name string, rules domain.Rules) domain.RoleID {
	t.Helper()
	rid := domain.RoleID(ids.NewID(domain.PrefixRole))
	compiled, err := domain.CompileRules(rules)
	require.NoError(t, err)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	inserted, err := w.RolesW().Insert(ctx, domain.Role{
		ID: rid, AccountID: acc, Name: domain.RoleName(name),
		Description: domain.Description("rules role " + name),
		Rules:       rules, Permissions: compiled,
	})
	require.NoError(t, err)
	require.NoError(t, w.RolesW().ReplaceRuleSelectors(ctx, inserted.ID, inserted.Rules.MaterializingSelectors()))
	require.NoError(t, w.Commit(ctx))
	return rid
}

// insertAccountBinding — ACTIVE-выдача субъекту на область аккаунта.
func insertAccountBinding(t *testing.T, ctx context.Context, repo *kanamepg.Repository,
	subject domain.UserID, role domain.RoleID, acc domain.AccountID) domain.AccessBindingID {
	t.Helper()
	bid := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	_, err = w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID: bid, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(subject),
		RoleID: role, ResourceType: "account", ResourceID: string(acc),
		Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return bid
}

// seedMirrorObject кладёт строку зеркала — то, что оставляет регистрация ресурса
// владельцем-модулем; веер материализации читает кандидатов именно из неё.
func seedMirrorObject(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID, prj, acc string) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.resource_mirror
		  (object_type, object_id, parent_project_id, parent_account_id, labels, source_version, updated_at)
		VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, now())`,
		objType, objID, prj, acc, time.Now())
	require.NoError(t, err, "строка зеркала объекта")
}

func factRowExists(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID, relation, subject string) bool {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject=$4`,
		objType, objID, relation, subject).Scan(&n))
	return n > 0
}

func TestAB_DeleteAndObjectFanout_DoNotDeadlock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool := poolFromDSN(t, setupTestDB(t))
	repo := kanamepg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kaname")
	rec := reconcile.New(kanamepg.NewReconcileAdapter(pool, catalogfixture.Source()), nil, catalogfixture.Source())

	owner := mustSeedUser(t, ctx, pool, "dfd-own")
	member := mustSeedUser(t, ctx, pool, "dfd-mem")
	acc := seedAccountByOwner(t, ctx, pool, "acc-dfd", owner)
	prj := seedProjectInAccount(t, ctx, pool, acc, "prj-dfd")

	// ДВЕ роли с ОДИНАКОВЫМ содержанием правил. Разные роли нужны потому, что
	// вторая ACTIVE-выдача того же субъекта с той же ролью на ту же область
	// отвергается частичной уникальностью; одинаковое содержание — потому что
	// предмет пробы в том, что обе стороны трогают ОДНУ строку прямого факта.
	rules := domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}}}
	roleA := seedRulesRoleWithSelectors(t, ctx, repo, acc, "dfd_a", rules)
	roleB := seedRulesRoleWithSelectors(t, ctx, repo, acc, "dfd_b", rules)

	const obj = "i-dfd-0001"
	seedMirrorObject(t, ctx, pool, "compute.instance", obj, string(prj), string(acc))

	b1 := insertAccountBinding(t, ctx, repo, member, roleA, acc)
	b2 := insertAccountBinding(t, ctx, repo, member, roleB, acc)
	// Веер обходит выдачи в глобально согласованном порядке по возрастанию id,
	// поэтому жертвой берётся БОЛЬШИЙ: к ней веер приходит последней, уже удерживая
	// строку прямого факта, записанную первой выдачей.
	victim, first := b1, b2
	if b1 < b2 {
		victim, first = b2, b1
	}

	// Жертва материализована ЗАРАНЕЕ: её реестр выпущенных кортежей непуст, значит
	// снятие действительно дойдёт до прямого факта, а не окажется пустой работой.
	require.NoError(t, rec.ReconcileBindingForward(ctx, victim))
	subject := "user:" + string(member)
	require.True(t, factRowExists(t, ctx, pool, "compute_instance", obj, "viewer", subject),
		"контроль: жертва обязана материализовать прямой факт — иначе снятие ниже "+
			"не тронуло бы строку, за которую идёт спор")
	require.False(t, ledgerHas(t, ctx, pool, string(first), subject, "viewer", "compute_instance:"+obj),
		"контроль: вторая выдача НЕ материализована — веер обязан её записать, "+
			"иначе он не возьмёт строку прямого факта до очереди за advisory")

	// ── ДЕРЖАТЕЛЬ: пинит расположение, ничего не моделируя ────────────────────
	hold, err := pool.Begin(ctx)
	require.NoError(t, err)
	released := false
	defer func() {
		if !released {
			_ = hold.Rollback(ctx)
		}
	}()
	_, err = hold.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, string(victim))
	require.NoError(t, err)

	// ── 1) СНЯТИЕ встаёт в очередь первым, не удерживая ничего ────────────────
	delUC := accessbindingapp.NewDeleteAccessBindingUseCase(repo, opsRepo).
		WithRelationStore(denyingRelations{}, nil)
	op, err := delUC.Execute(asUser(ctx, owner), victim)
	require.NoError(t, err, "снятие принято к исполнению")
	waitAdvisoryWaiters(t, ctx, pool, 1, "снятие")

	// ── 2) ВЕЕР встаёт вторым — уже удержав строку прямого факта первой выдачи ─
	fanout := make(chan error, 1)
	go func() { fanout <- rec.ReconcileObject(ctx, "compute.instance", obj) }()
	waitAdvisoryWaiters(t, ctx, pool, 2, "веер материализации")

	// ── 3) Держатель уходит; порядок пробуждения задан очередью ───────────────
	released = true
	require.NoError(t, hold.Rollback(ctx))

	select {
	case ferr := <-fanout:
		require.NoError(t, ferr, "веер материализации не должен сниматься взаимной блокировкой")
	case <-time.After(deadlockQueueBudget):
		t.Fatal("веер материализации не завершился")
	}

	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error,
		"снятие выдачи не должно завершаться отказом: отказ здесь означает взаимную "+
			"блокировку, после которой выдача остаётся жива, а следующее создание того же "+
			"набора получает ALREADY_EXISTS")

	// Снятие доведено до конца — а не просто «не упало».
	var alive int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_bindings WHERE id=$1`, string(victim)).Scan(&alive))
	require.Zero(t, alive, "снятая выдача обязана исчезнуть")
}
