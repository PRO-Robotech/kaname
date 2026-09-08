// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// Глагол на САМОМ проекте выводится из выдачи, привязанной к этому проекту (#884).
//
// ПОЧЕМУ ЭТО ОТДЕЛЬНАЯ ПРОБА, А НЕ ЧАСТЬ СОСЕДНИХ. Соседние спрашивают глагол на
// ресурсе, ВЛОЖЕННОМ в область выдачи (сеть в проекте) — то есть проверяют
// цепочку «объект → его область → выдача». Здесь объект И ЕСТЬ область: выдача
// висит на проекте, и спрашивают про сам проект, глубина цепи ноль.
//
// Разница не умозрительная. Сквозная проба приглашения (`IAM-USR-INV-FLOW-
// INVITEE-GETS-ACCESS`) спрашивает ровно это — `v_get` на подаренном проекте — и
// не сходится на ветке снятия внешнего движка, тогда как на стволе, где вердикт
// считает движок, она зелена. Пока у формы не было пробы на нулевую глубину,
// класс был виден только через двадцать минут прогона стенда и назывался
// «приглашение не работает» — то есть не там, где живёт.
func TestAsk_VerbOnTheScopeObjectItself(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-selfscope", "iam.project", "get", "anchor", "{}")
		exec(t, ctx, tx,
			`INSERT INTO kaname.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ('acb-self', 'user', 'usr-1', 'rol-selfscope', 'project', 'prj-1', 'ACTIVE')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-self', 'user', 'usr-1')`)

		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "project", ObjectID: "prj-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("вопрос о глаголе на самой области: %v", err)
		}
		if got != relverdict.Allow {
			t.Errorf("глагол на объекте-области: вердикт = %s, ожидался %s — "+
				"выдача висит на этом самом проекте, и спрашивают про него же; "+
				"именно этого ждёт сквозная проба приглашения", got, relverdict.Allow)
		}

		// ЗАКОННЫЙ БЛИЗНЕЦ: чужой проект той же формы остаётся закрытым. Без него
		// проба зеленела бы на форме, разрешающей всё подряд.
		exec(t, ctx, tx,
			`INSERT INTO kaname.projects (id, name, account_id)
			 VALUES ('prj-2', 'other', 'acc-1') ON CONFLICT DO NOTHING`)
		other, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "project", ObjectID: "prj-2", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("вопрос о чужом проекте: %v", err)
		}
		if other != relverdict.Deny {
			t.Errorf("чужой проект: вердикт = %s, ожидался %s", other, relverdict.Deny)
		}
	})
}
