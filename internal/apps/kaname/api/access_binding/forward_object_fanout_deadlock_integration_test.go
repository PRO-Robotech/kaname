// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// forward_object_fanout_deadlock_integration_test.go — быстрый путь создания выдачи и
// веер материализации по объекту не роняют друг друга взаимной блокировкой.
//
// ПРЕДМЕТ. Две выдачи одного субъекта (на аккаунт и на проект) покрывают один объект.
// Строки прямого факта у них ОБЩИЕ (факт ключуется субъектом, объектом и отношением), а
// строки членов — свои у каждой выдачи.
//
//   - Быстрый путь создания второй выдачи пишет свои строки членов, затем журнал.
//   - Веер по объекту обходит выдачи по возрастанию id и писал журнал ПО ВЫДАЧЕ: член
//     первой, её кортежи, член второй — то есть приходил к строке члена второй выдачи,
//     уже удерживая строку прямого факта, записанную через первую.
//
// Быстрый путь держит строку члена и ждёт строку факта; веер держит строку факта и ждёт
// строку члена — цикл, из которого Postgres выходит, снимая одну сторону (40P01).
// Наблюдалось на стенде (журнал базы):
//
//	Process 95: INSERT INTO kaname.fga_outbox … (быстрый путь, триггер прямого факта)
//	Process 88: INSERT INTO kaname.access_binding_target_members … (веер)
//
// Снятая сторона — быстрый путь создания; выдача остаётся без членов до сведения, и
// полный проход, который её дожимает, сам встречается со снятием соседней выдачи
// (delete_sibling_full_pass_deadlock_integration_test.go).
//
// ПОРЯДОК ЗАДАЁТ ДЕРЖАТЕЛЬ — незакоммиченная строка реестра ПЕРВОЙ выдачи на объекте.
// Веер встаёт за ней первым, записав до неё всё, что пишет по первой выдаче. Быстрый
// путь второй выдачи идёт следом. Держатель уходит, и веер идёт к строке члена второй
// выдачи, которую быстрый путь уже вставил. Строка реестра выбрана потому, что веер
// доходит до неё в обоих мирах: и когда журнал пишется по выдаче, и когда — в конце
// прохода.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

func TestAB_CreateForwardAndObjectFanout_DoNotDeadlock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool := poolFromDSN(t, setupTestDB(t))
	repo := kanamepg.New(pool, nil)
	rec := reconcile.New(kanamepg.NewReconcileAdapter(pool, catalogfixture.Source()), nil, catalogfixture.Source())

	owner := mustSeedUser(t, ctx, pool, "fof-own")
	member := mustSeedUser(t, ctx, pool, "fof-mem")
	acc := seedAccountByOwner(t, ctx, pool, "acc-fof", owner)
	prj := seedProjectInAccount(t, ctx, pool, acc, "prj-fof")

	rules := domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"}}}
	role := seedRulesRoleWithSelectors(t, ctx, repo, acc, "fof", rules)

	const vmID = "i-fof-0001"
	seedMirrorObject(t, ctx, pool, "compute.instance", vmID, string(prj), string(acc))

	onAccount := insertAccountBinding(t, ctx, repo, member, role, acc)
	onProject := insertProjectBinding(t, ctx, repo, member, role, prj)
	// Веер обходит выдачи по возрастанию id; быстрый путь берётся у БОЛЬШЕЙ — к ней
	// веер приходит последней, уже записав факт через меньшую.
	first, second := onAccount, onProject
	if second < first {
		first, second = second, first
	}
	subject := "user:" + string(member)
	require.False(t, factRowExists(t, ctx, pool, "compute_instance", vmID, "viewer", subject),
		"контроль: факт ещё не записан — обе стороны обязаны писать его сами")

	// ── ДЕРЖАТЕЛЬ: строка реестра первой выдачи на объекте ───────────────────
	hold, err := pool.Begin(ctx)
	require.NoError(t, err)
	released := false
	defer func() {
		if !released {
			_ = hold.Rollback(ctx)
		}
	}()
	_, err = hold.Exec(ctx, `
		INSERT INTO kaname.access_binding_emitted_tuples (binding_id, fga_user, relation, object, source)
		VALUES ($1, $2, 'viewer', $3, 'member')`,
		string(first), subject, "compute_instance:"+vmID)
	require.NoError(t, err)

	waitWaiters := func(want int, what string) {
		t.Helper()
		deadline := time.Now().Add(deadlockQueueBudget)
		for lockWaiters(t, ctx, pool) < want {
			require.True(t, time.Now().Before(deadline), "%s не встал(а) в очередь за держателем", what)
			time.Sleep(20 * time.Millisecond)
		}
	}

	// ── 1) ВЕЕР по объекту встаёт за держателем ──────────────────────────────
	fanout := make(chan error, 1)
	go func() { fanout <- rec.ReconcileObject(ctx, "compute.instance", vmID) }()
	waitWaiters(1, "веер материализации")

	// ── 2) БЫСТРЫЙ ПУТЬ создания второй выдачи ───────────────────────────────
	// Он либо встаёт в очередь (за строкой факта, которую веер уже записал), либо
	// проходит целиком, если веер до держателя строк факта не брал. Оба
	// расположения законны; незаконен только исход с отказом ниже.
	forward := make(chan error, 1)
	go func() { forward <- rec.ReconcileBindingForward(ctx, second) }()
	var forwardErr error
	forwardDone := false
	deadline := time.Now().Add(deadlockQueueBudget)
	for !forwardDone && lockWaiters(t, ctx, pool) < 2 {
		select {
		case forwardErr = <-forward:
			forwardDone = true
		default:
			require.True(t, time.Now().Before(deadline), "быстрый путь ни встал в очередь, ни завершился")
			time.Sleep(20 * time.Millisecond)
		}
	}

	// ── 3) Держатель уходит ───────────────────────────────────────────────────
	released = true
	require.NoError(t, hold.Rollback(ctx))

	if !forwardDone {
		select {
		case forwardErr = <-forward:
		case <-time.After(deadlockQueueBudget):
			t.Fatal("быстрый путь создания не завершился")
		}
	}
	require.NoError(t, forwardErr, "быстрый путь создания не должен сниматься взаимной блокировкой")
	select {
	case ferr := <-fanout:
		require.NoError(t, ferr, "веер материализации не должен сниматься взаимной блокировкой")
	case <-time.After(deadlockQueueBudget):
		t.Fatal("веер материализации не завершился")
	}
	require.True(t, factRowExists(t, ctx, pool, "compute_instance", vmID, "viewer", subject),
		"обе выдачи живы — право субъекта на объекте записано")
	require.True(t, ledgerHas(t, ctx, pool, string(second), subject, "viewer", "compute_instance:"+vmID),
		"вторая выдача записала свою строку реестра — её снятие найдёт, что снимать")
}
