// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// list_integration_test.go — перечисление отдаёт СТРАНИЦУ и продолжение, а не
// усечённый ответ без продолжения.
//
// # Предмет
//
// У движка перечисление имеет жёсткий серверный предел и продолжения не имеет:
// ресурсы сверх предела становились владельцу невидимы навсегда ПРИ ЖИВЫХ
// ПРАВАХ. Здесь предела нет by construction — это наш запрос к нашей таблице.
//
// Проба обязана утверждать именно ОБХОД: одна страница ничего не говорит о том,
// что за ней есть продолжение и что оно не теряет строк.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

func TestList_PagesThroughEverythingTheSubjectMaySee(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-list", "vpc_network", "get", "anchor", "{}")
		exec(t, ctx, tx,
			`INSERT INTO kaname.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ('acb-l', 'user', 'usr-1', 'rol-list', 'project', 'prj-1', 'ACTIVE')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-l', 'user', 'usr-1')`)

		// Семь объектов под выдачей и один ВНЕ её области: последний обязан не
		// попасть ни на одну страницу, иначе обход отдаёт чужое.
		const inScope = 7
		for i := 0; i < inScope; i++ {
			id := fmt.Sprintf("net-%02d", i)
			exec(t, ctx, tx,
				`INSERT INTO kaname.resource_mirror (object_type, object_id) VALUES ($2, $1)`,
				id, catalogFormOf(t, "vpc_network"))
			exec(t, ctx, tx,
				`INSERT INTO kaname.resource_parent_edge
				   (object_type, object_id, parent_type, parent_id, depth)
				 VALUES ('vpc_network', $1, 'project', 'prj-1', 1)`, id)
		}
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_mirror (object_type, object_id) VALUES ($1, 'net-99')`,
			catalogFormOf(t, "vpc_network"))
		exec(t, ctx, tx,
			`INSERT INTO kaname.projects (id, account_id, name) VALUES ('prj-9', 'acc-1', 'other')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('vpc_network', 'net-99', 'project', 'prj-9', 1)`)

		// Обход страницами по три: продолжение обязано довести до конца.
		var seen []string
		after := ""
		for page := 0; page < 10; page++ {
			ids, next, err := relverdict.List(ctx, tx, relverdict.ListQuery{
				Subject: "user:usr-1", ObjectType: "vpc_network", Relation: "v_get",
				AfterID: after, Limit: 3,
			})
			if err != nil {
				t.Fatalf("страница %d: %v", page, err)
			}
			seen = append(seen, ids...)
			if next == "" {
				break
			}
			after = next
		}

		if len(seen) != inScope {
			t.Fatalf("обход отдал %d объектов (%v), ожидалось %d — страница без продолжения "+
				"делает остаток НЕВИДИМЫМ при живых правах, и это ровно тот дефект, ради "+
				"которого перечисление переписано", len(seen), seen, inScope)
		}
		for _, id := range seen {
			if id == "net-99" {
				t.Errorf("в обход попал объект вне области выдачи — перечисление отдаёт чужое")
			}
		}

		// Отрицание рядом: субъект без выдачи не видит ничего. Без него «семь»
		// зеленело бы и на запросе, который отдаёт весь тип всем.
		other, _, err := relverdict.List(ctx, tx, relverdict.ListQuery{
			Subject: "user:usr-9", ObjectType: "vpc_network", Relation: "v_get", Limit: 100,
		})
		if err != nil {
			t.Fatalf("перечисление для чужого: %v", err)
		}
		if len(other) != 0 {
			t.Errorf("субъект без выдачи увидел %d объектов: %v", len(other), other)
		}

		t.Logf("осмотрено: в области %d, вне области 1, обход отдал %d", inScope, len(seen))
	})
}

// Неполный вопрос — ошибка, а не пустой список.
func TestList_IncompleteQuestionIsAnErrorNotAnEmptyPage(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		if _, _, err := relverdict.List(ctx, tx, relverdict.ListQuery{
			Subject: "user:usr-1", ObjectType: "", Relation: "v_get",
		}); err == nil {
			t.Fatal("пустой тип принят — пустой список за него неотличим от честного " +
				"«ничего не доступно»")
		}
	})
}
