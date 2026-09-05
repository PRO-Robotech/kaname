// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// expand_integration_test.go — разбор называет ВСЕ основания, а не первое.
//
// # Предмет
//
// Одно и то же право нередко приходит с двух сторон сразу: своя выдача и выдача
// группе. Ответ, назвавший одно основание, читается как «снять это — и доступа
// не станет», а доступ останется. Именно за этим вопрос и задают: не «есть ли
// право», а «что снять, чтобы его не было».

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
)

func TestExpand_NamesEverySourceNotJustTheFirst(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-exp", "vpc_network", "get", "anchor", "{}")
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_mirror (object_type, object_id) VALUES ($1, 'net-1')`,
			catalogFormOf(t, "vpc_network"))
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('vpc_network', 'net-1', 'project', 'prj-1', 1)`)

		// Основание 1: прямой факт (владение). Отношение названо так, как его
		// называет МОДЕЛЬ (`v_get`): в этой таблице лежат модельные имена, а не
		// глаголы роли — глагол живёт в `role_verb`, и это разные словари.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject)
			 VALUES ('vpc_network', 'net-1', 'v_get', 'user:usr-1')`)
		// Основание 2: своя выдача на проект.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ('acb-own', 'user', 'usr-1', 'rol-exp', 'project', 'prj-1', 'ACTIVE')`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-own', 'user', 'usr-1')`)
		// Основание 3: выдача ГРУППЕ, в которой тот же человек.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.groups (id, account_id, name) VALUES ('grp-1', 'acc-1', 'devs')
			 ON CONFLICT DO NOTHING`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ('acb-grp', 'group', 'grp-1', 'rol-exp', 'project', 'prj-1', 'ACTIVE')`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-grp', 'group', 'grp-1')`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.group_members (group_id, member_type, member_id)
			 VALUES ('grp-1', 'user', 'usr-1')`)

		got, err := relverdict.Expand(ctx, tx, "vpc_network", "net-1", "v_get")
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}

		kinds := map[string]int{}
		for _, s := range got {
			kinds[s.Kind]++
		}
		for _, want := range []string{"fact", "binding", "group"} {
			if kinds[want] == 0 {
				t.Errorf("основание %q не названо (%+v) — ответ, назвавший часть, читается "+
					"как «снять это, и доступа не станет», а доступ останется", want, got)
			}
		}

		// Область названа: без неё непонятно, ГДЕ снимать выдачу.
		for _, s := range got {
			if s.Kind == "binding" && (s.ScopeType == "" || s.ScopeID == "") {
				t.Errorf("выдача названа без области: %+v — снять её негде", s)
			}
		}

		t.Logf("осмотрено: оснований %d (факт %d, выдача %d, членство %d)",
			len(got), kinds["fact"], kinds["binding"], kinds["group"])
	})
}

// Неполный вопрос — ошибка, а не пустой разбор.
func TestExpand_IncompleteQuestionIsAnError(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		if _, err := relverdict.Expand(ctx, tx, "vpc_network", "net-1", ""); err == nil {
			t.Fatal("пустой глагол принят — пустой разбор за него неотличим от честного " +
				"«оснований нет»")
		}
	})
}
