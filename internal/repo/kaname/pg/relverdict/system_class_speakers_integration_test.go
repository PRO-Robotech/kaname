// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// system_class_speakers_integration_test.go — классы говорящего на КАЖДОЙ из
// трёх форм вопроса (приёмка anonymous-and-authenticated-are-subject-classes.md,
// отпечаток ae9ba373…0427f51; задача PRO-Robotech/kaname#829; разбор CE-01).
//
// Классы приходят во все три запроса (прямой вопрос, вопрос о странице,
// перечень) от одного производителя, `domain.SpeakerClasses`. Проба держит
// именно ПАРИТЕТ форм: правка двух из трёх оставила бы третью с прежним смыслом,
// и перечень отдал бы анониму то, что вопрос отвергает. Близнецы на каждой
// форме — человек (оба класса), аноним (только свой), группа (ни одного).
// Вторая ось — выдача классу раздаёт только чтение на каждой ветви выдач
// (SC-23): роль, чья проекция несёт пишущий глагол, классу его не даёт, а
// человеку той же ролью — даёт.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// scSpeakers — говорящие и ожидаемый ответ каждого при выдаче классу `class`.
type scSpeaker struct {
	subject string
	want    bool
}

func scForms(t *testing.T, ctx context.Context, tx pgx.Tx, relation string, speakers []scSpeaker, why string) {
	t.Helper()
	for _, sp := range speakers {
		v, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: sp.subject, ObjectType: "vpc_network", ObjectID: "net-sc-1", Relation: relation,
		})
		if err != nil {
			t.Fatalf("%s: Ask(%s): %v", why, sp.subject, err)
		}
		if got := v == relverdict.Allow; got != sp.want {
			t.Errorf("%s: прямой вопрос %s %s = %v, ждали %v", why, sp.subject, relation, got, sp.want)
		}

		vs, _, err := relverdict.AskMany(ctx, tx, relverdict.QueryMany{
			Subject: sp.subject, ObjectType: "vpc_network", ObjectIDs: []string{"net-sc-1", "net-sc-2"},
			Relation: relation,
		})
		if err != nil {
			t.Fatalf("%s: AskMany(%s): %v", why, sp.subject, err)
		}
		if got := vs[0] == relverdict.Allow; got != sp.want {
			t.Errorf("%s: вопрос о странице %s %s = %v, ждали %v", why, sp.subject, relation, got, sp.want)
		}
		if vs[1] == relverdict.Allow {
			t.Errorf("%s: вопрос о странице отдал %s объект вне выдачи", why, sp.subject)
		}

		ids, _, err := relverdict.List(ctx, tx, relverdict.ListQuery{
			Subject: sp.subject, ObjectType: "vpc_network", Relation: relation, Limit: 100,
		})
		if err != nil {
			t.Fatalf("%s: List(%s): %v", why, sp.subject, err)
		}
		listed := len(ids) == 1 && ids[0] == "net-sc-1"
		if listed != sp.want || (!sp.want && len(ids) != 0) {
			t.Errorf("%s: перечень %s %s = %v, ждали объект: %v", why, sp.subject, relation, ids, sp.want)
		}
	}
}

func scSeedClassGrant(t *testing.T, ctx context.Context, tx pgx.Tx, bindingID, class string) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kaname.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		 VALUES ($1, 'system_class', $2, 'rol-sc', 'project', 'prj-1', 'ACTIVE')`, bindingID, class)
	exec(t, ctx, tx,
		`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ($1, 'system_class', $2)`, bindingID, class)
}

func TestSystemClass_CE01_ThreeFormsAgreeOnSpeakerClasses(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		// Роль ЧИТАЕТ по правилам (страж выдачи классу её принимает), а проекция
		// глаголов несёт ещё и `update` — так выглядит роль, получившая пишущий
		// глагол путём, который правкой роли не является (SC-23).
		seedRole(t, ctx, tx, "rol-sc", "vpc_network", "get", "anchor", "{}")
		exec(t, ctx, tx,
			`INSERT INTO kaname.role_verb (role_id, object_type, verb) VALUES ('rol-sc', $1, 'update')`,
			catalogFormOf(t, "vpc_network"))
		// Пишущий глагол несёт и само правило роли (kaname#878): решение о
		// доступе берёт глагол со строки селектора, и без него человек не
		// получил бы `update` вовсе — контроль пробы потерял бы предмет.
		exec(t, ctx, tx,
			`UPDATE kaname.role_rule_selectors
			    SET verbs_by_type = jsonb_build_object($1::text, jsonb_build_array('get', 'update'))
			  WHERE role_id = 'rol-sc'`,
			catalogFormOf(t, "vpc_network"))
		exec(t, ctx, tx,
			`INSERT INTO kaname.groups (id, account_id, name) VALUES ('grp-sc', 'acc-1', 'grp-sc')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.group_members (group_id, member_type, member_id) VALUES ('grp-sc', 'user', 'usr-1')`)
		for _, id := range []string{"net-sc-1"} {
			exec(t, ctx, tx,
				`INSERT INTO kaname.resource_mirror (object_type, object_id) VALUES ($2, $1)`,
				id, catalogFormOf(t, "vpc_network"))
			exec(t, ctx, tx,
				`INSERT INTO kaname.resource_parent_edge (object_type, object_id, parent_type, parent_id, depth)
				 VALUES ('vpc_network', $1, 'project', 'prj-1', 1)`, id)
		}
		exec(t, ctx, tx,
			`INSERT INTO kaname.projects (id, account_id, name) VALUES ('prj-sc-9', 'acc-1', 'other-sc')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_mirror (object_type, object_id) VALUES ($1, 'net-sc-2')`,
			catalogFormOf(t, "vpc_network"))
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_parent_edge (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('vpc_network', 'net-sc-2', 'project', 'prj-sc-9', 1)`)

		// До выдачи классу — никому ничего: близнец, без которого «да» ниже
		// неотличимо от формы, разрешающей тип всем.
		scForms(t, ctx, tx, "v_get", []scSpeaker{
			{"user:usr-1", false}, {"system_class:anonymous", false}, {"group:grp-sc#member", false},
		}, "до выдачи")

		// Выдача «вошедшим»: человек читает, аноним — нет (SC-10), группа как
		// говорящий классов не несёт (SC-11).
		scSeedClassGrant(t, ctx, tx, "acb-sc-auth", "authenticated")
		scForms(t, ctx, tx, "v_get", []scSpeaker{
			{"user:usr-1", true}, {"service_account:sva-sc", true},
			{"system_class:anonymous", false}, {"group:grp-sc#member", false},
		}, "выдача authenticated")
		// Пишущий глагол из проекции роли класс не получает ни одной формой (SC-23).
		scForms(t, ctx, tx, "v_update", []scSpeaker{
			{"user:usr-1", false}, {"system_class:anonymous", false},
		}, "выдача authenticated, пишущий глагол")

		// Выдача анониму: читают и аноним, и вошедший (включение, Р2).
		// Подстановка `user:*` классов не получает ни одной формой (SC-15, полоса
		// L6 kaname#832): переходное отображение в аноним снято, и даже вопрос,
		// миновавший отказ разбора двери, не читает выданного анониму.
		exec(t, ctx, tx, `DELETE FROM kaname.access_binding_subjects WHERE binding_id = 'acb-sc-auth'`)
		exec(t, ctx, tx, `DELETE FROM kaname.access_bindings WHERE id = 'acb-sc-auth'`)
		scSeedClassGrant(t, ctx, tx, "acb-sc-anon", "anonymous")
		scForms(t, ctx, tx, "v_get", []scSpeaker{
			{"user:usr-1", true}, {"system_class:anonymous", true}, {"user:*", false},
			{"group:grp-sc#member", false},
		}, "выдача anonymous")

		// Положительный контроль второй оси: та же роль ЧЕЛОВЕКУ даёт и `update` —
		// иначе «нет» выше мерило бы сломанный посев, а не правило класса.
		exec(t, ctx, tx,
			`INSERT INTO kaname.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ('acb-sc-usr', 'user', 'usr-1', 'rol-sc', 'project', 'prj-1', 'ACTIVE')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-sc-usr', 'user', 'usr-1')`)
		scForms(t, ctx, tx, "v_update", []scSpeaker{
			{"user:usr-1", true}, {"system_class:anonymous", false},
		}, "контроль: пишущий глагол человеку")
	})
}
