// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// asker_integration_test.go — адаптер формы E под теневое сравнение: объединение
// отношений, признак полноты ответа, снятие повторов.
//
// # Что здесь предмет, а что уже проверено соседями
//
// Сами запросы (`List`, `Subjects`, `Expand`) проверены своими пробами и здесь не
// перепроверяются. Предмет адаптера — три вещи, которых у запросов нет:
//
//  1. ОБЪЕДИНЕНИЕ отношений в одном снимке базы: движок отвечает на читающее
//     действие объединением двух отношений, и спросить форму об одном значило бы
//     сравнить два разных вопроса;
//  2. ПРИЗНАК ПОЛНОТЫ: неполный ответ сравнивать нельзя, и адаптер обязан сказать
//     об этом словом, а не оставлять сравнение гадать по длине;
//  3. СНЯТИЕ ПОВТОРОВ: один объект, доступный по двум отношениям сразу, обязан
//     занять в ответе одно место — иначе множества расходятся на кратности.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// withCommittedPool сеет данные и ОТДАЁТ пул: адаптер открывает свою транзакцию
// чтения, поэтому посев обязан быть закоммичен — иначе адаптер честно не увидит
// ничего, и проба зеленела бы на пустоте.
func withCommittedPool(t *testing.T, seed func(ctx context.Context, tx pgx.Tx)) (*pgxpool.Pool, context.Context) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция посева: %v", err)
	}
	seed(ctx, tx)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("коммит посева: %v", err)
	}
	return pool, ctx
}

// seedNetworks кладёт n объектов под областью проекта.
func seedNetworks(t *testing.T, ctx context.Context, tx pgx.Tx, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("net-%02d", i)
		ids = append(ids, id)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_mirror (object_type, object_id) VALUES ($2, $1)`,
			id, catalogFormOf(t, "vpc_network"))
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('vpc_network', $1, 'project', 'prj-1', 1)`, id)
	}
	return ids
}

// bindRole выдаёт роль субъекту на проект.
func bindRole(t *testing.T, ctx context.Context, tx pgx.Tx, bindingID, roleID string) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		 VALUES ($1, 'user', 'usr-1', $2, 'project', 'prj-1', 'ACTIVE')`, bindingID, roleID)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ($1, 'user', 'usr-1')`, bindingID)
}

// Объединение двух отношений даёт ОДНО множество без повторов.
func TestAsker_ObjectsUnionsRelationsWithoutRepeating(t *testing.T) {
	pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-get", "vpc_network", "get", "anchor", "{}")
		seedRole(t, ctx, tx, "rol-list", "vpc_network", "list", "anchor", "{}")
		bindRole(t, ctx, tx, "acb-get", "rol-get")
		bindRole(t, ctx, tx, "acb-list", "rol-list")
		seedNetworks(t, ctx, tx, 3)
	})

	ids, complete, err := relverdict.NewAsker(pool).
		Objects(ctx, "user:usr-1", "vpc_network", []string{"v_get", "v_list"}, 100)
	if err != nil {
		t.Fatalf("перечисление: %v", err)
	}
	if !complete {
		t.Fatalf("ответ объявлен неполным, хотя помещается целиком: %v", ids)
	}
	seen := map[string]int{}
	for _, id := range ids {
		seen[id]++
	}
	if len(seen) != 3 {
		t.Fatalf("объединение отдало %v — ожидались три объекта", ids)
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("объект %s назван %d раза — доступный по двум отношениям сразу обязан "+
				"занять в множестве одно место, иначе сравнение расходится на кратности", id, n)
		}
	}
}

// Ответ, не помещающийся в предел, объявляется НЕПОЛНЫМ.
//
// Это и есть то, ради чего признак существует: сравнение, принявшее усечённую
// страницу за всё множество, объявило бы расхождением границу страницы.
func TestAsker_ObjectsReportsAnAnswerThatDoesNotFit(t *testing.T) {
	pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-get", "vpc_network", "get", "anchor", "{}")
		bindRole(t, ctx, tx, "acb-get", "rol-get")
		seedNetworks(t, ctx, tx, 5)
	})

	ids, complete, err := relverdict.NewAsker(pool).
		Objects(ctx, "user:usr-1", "vpc_network", []string{"v_get"}, 2)
	if err != nil {
		t.Fatalf("перечисление: %v", err)
	}
	if complete {
		t.Fatalf("страница из %d при пяти доступных объявлена полным ответом (%v) — сравнение "+
			"тогда объявит расхождением границу страницы", len(ids), ids)
	}
}

// Обратные вопросы адаптера отвечают тем же, что и запросы под ним, и снимают
// повторы субъектов у оснований.
func TestAsker_SubjectsAndSourcesAnswerThroughTheirOwnReadTransaction(t *testing.T) {
	pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-get", "vpc_network", "get", "anchor", "{}")
		bindRole(t, ctx, tx, "acb-get", "rol-get")
		seedNetworks(t, ctx, tx, 1)
	})
	asker := relverdict.NewAsker(pool)

	subs, complete, err := asker.Subjects(ctx, "vpc_network", "net-00", "v_get", 100)
	if err != nil {
		t.Fatalf("перечисление субъектов: %v", err)
	}
	if !complete {
		t.Fatalf("ответ объявлен неполным: %v", subs)
	}
	if len(subs) == 0 {
		t.Fatal("субъект выдачи не назван — пустой ответ неотличим от честного «никто не имеет»")
	}

	grounds, err := asker.Sources(ctx, "vpc_network", "net-00", "v_get")
	if err != nil {
		t.Fatalf("разворот: %v", err)
	}
	if len(grounds) == 0 {
		t.Fatal("основания не названы — ответ «да» без них неразбираем")
	}
	seen := map[string]int{}
	for _, g := range grounds {
		seen[g]++
		if seen[g] > 1 {
			t.Fatalf("субъект %s назван дважды — повторы оснований обязаны сниматься, иначе "+
				"множества расходятся на кратности: %v", g, grounds)
		}
	}
}
