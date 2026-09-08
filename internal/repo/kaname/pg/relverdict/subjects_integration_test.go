// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// subjects_integration_test.go — перечисление субъектов называет и адресата
// выдачи, и того, кто ею пользуется.
//
// # Предмет
//
// Выдача, сделанная ГРУППЕ, называет субъектом группу. Спрашивающий «кто может
// это над объектом» ожидает увидеть и людей: ответ, назвавший одну лишь группу,
// формально верен и практически бесполезен — по нему нельзя понять, чей доступ
// отзывать.
//
// Свести к одному нельзя ни в какую сторону: назвать только членов — потерять
// адресата выдачи (а отзывают именно её); назвать только группу — потерять тех,
// кто правом пользуется.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

func TestSubjects_NamesBothTheGrantedGroupAndItsMembers(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-sub", "vpc_network", "get", "anchor", "{}")
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_mirror (object_type, object_id) VALUES ($1, 'net-1')`,
			catalogFormOf(t, "vpc_network"))
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('vpc_network', 'net-1', 'project', 'prj-1', 1)`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.groups (id, account_id, name) VALUES ('grp-1', 'acc-1', 'devs')
			 ON CONFLICT DO NOTHING`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ('acb-s', 'group', 'grp-1', 'rol-sub', 'project', 'prj-1', 'ACTIVE')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-s', 'group', 'grp-1')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.group_members (group_id, member_type, member_id)
			 VALUES ('grp-1', 'user', 'usr-1')`)

		got, _, err := relverdict.Subjects(ctx, tx, relverdict.SubjectsQuery{
			ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get", Limit: 100,
		})
		if err != nil {
			t.Fatalf("перечисление субъектов: %v", err)
		}

		set := map[string]bool{}
		for _, s := range got {
			set[s] = true
		}
		if !set["group:grp-1"] {
			t.Errorf("не назван АДРЕСАТ выдачи (%v) — отзывают именно её, и без него ответ "+
				"не говорит, что снимать", got)
		}
		if !set["user:usr-1"] {
			t.Errorf("не назван тот, кто правом ПОЛЬЗУЕТСЯ (%v) — по такому ответу нельзя "+
				"понять, чей доступ закрывается", got)
		}

		// Отрицание рядом: не член группы не появляется.
		if set["user:usr-9"] {
			t.Errorf("назван субъект без права: %v", got)
		}

		t.Logf("осмотрено: субъектов %d %v", len(got), got)
	})
}

// Неполный вопрос — ошибка, а не пустой ответ.
func TestSubjects_IncompleteQuestionIsAnError(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		if _, _, err := relverdict.Subjects(ctx, tx, relverdict.SubjectsQuery{
			ObjectType: "vpc_network", ObjectID: "", Relation: "v_get",
		}); err == nil {
			t.Fatal("пустой объект принят — пустой список за него неотличим от честного " +
				"«никто не имеет»")
		}
	})
}
