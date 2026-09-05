// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// canonical_group_integration_test.go — форма имени группы, которую производит
// САМ ПРОДУКТ, находится всеми четырьмя вопросами.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТА ПРОБА СУЩЕСТВУЕТ ОТДЕЛЬНО ОТ ПРОБ ПРО ЧЛЕНСТВО
//
// Пробы про членство уже были — и все сеяли ГОЛУЮ форму `group:<id>`. Канонический
// производитель кортежей пишет `group:<id>#member`: хвост отношения раскрывает
// членство на стороне модели. Фикстура, сеющая только голую форму, СНИСХОДИТЕЛЬНЕЕ
// продукта — она делает невидимым ровно тот недоответ, ради которого пробу и
// пишут: право, выданное каноническим путём, не находилось ни одним из четырёх
// вопросов, и выглядело это как честное «прав нет».
//
// Обе формы законны и обе проверяются здесь: голой адресуется сама группа как
// субъект выдачи, канонической — членство.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
)

// seedGroupFact кладёт факт, выданный ГРУППЕ в названной форме, и члена в ней.
func seedGroupFact(t *testing.T, ctx context.Context, tx pgx.Tx, groupID, subjectForm string) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.groups (id, account_id, name) VALUES ($1, 'acc-1', $1)
		 ON CONFLICT DO NOTHING`, groupID)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.group_members (group_id, member_type, member_id)
		 VALUES ($1, 'user', 'usr-member')`, groupID)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject)
		 VALUES ('vpc_network', 'net-1', 'v_get', $1)`, subjectForm)
}

func TestGroupSubjectFormsAreBothHonoured(t *testing.T) {
	for _, tc := range []struct {
		name  string
		group string
		form  string
	}{
		{"каноническая (её производит продукт)", "grp-canon", "group:grp-canon#member"},
		{"голая (группа как субъект выдачи)", "grp-bare", "group:grp-bare"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withTx(t, func(ctx context.Context, tx pgx.Tx) {
				seedTenant(t, ctx, tx)
				exec(t, ctx, tx,
					`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
					 VALUES ('usr-member', 'ext-m', 'm@kacho.local', 'acc-1') ON CONFLICT DO NOTHING`)
				exec(t, ctx, tx,
					`INSERT INTO kacho_iam.resource_mirror (object_type, object_id)
					 VALUES ($1, 'net-1') ON CONFLICT DO NOTHING`,
					catalogFormOf(t, "vpc_network"))
				seedGroupFact(t, ctx, tx, tc.group, tc.form)

				// (1) прямой вопрос — членство даёт право
				got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
					Subject: "user:usr-member", ObjectType: "vpc_network",
					ObjectID: "net-1", Relation: "v_get",
				})
				if err != nil {
					t.Fatalf("прямой вопрос: %v", err)
				}
				if got != relverdict.Allow {
					t.Errorf("член группы не получил права в форме %q: вердикт %s — "+
						"недоответ выглядит как честное «прав нет»", tc.form, got)
				}

				// (2) кто имеет право — член обязан быть НАЗВАН
				subs, _, err := relverdict.Subjects(ctx, tx, relverdict.SubjectsQuery{
					ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
				})
				if err != nil {
					t.Fatalf("субъекты: %v", err)
				}
				if !containsStr(subs, "user:usr-member") {
					t.Errorf("член группы не назван среди субъектов (%v) при форме %q — "+
						"разбор доступа тогда не находит того, у кого доступ есть", subs, tc.form)
				}

				// (3) из чего складывается — основание через членство названо
				src, err := relverdict.Expand(ctx, tx, "vpc_network", "net-1", "v_get")
				if err != nil {
					t.Fatalf("разбор: %v", err)
				}
				viaGroup := false
				for _, s := range src {
					if s.Kind == "group" && s.Subject == "user:usr-member" {
						viaGroup = true
					}
				}
				if !viaGroup {
					t.Errorf("основание через членство не названо (%+v) при форме %q — "+
						"снимать право пошли бы не туда", src, tc.form)
				}

				// Отрицание рядом: посторонний не получает ничего ни одним вопросом.
				other, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
					Subject: "user:usr-outsider", ObjectType: "vpc_network",
					ObjectID: "net-1", Relation: "v_get",
				})
				if err != nil {
					t.Fatalf("отрицание: %v", err)
				}
				if other != relverdict.Deny {
					t.Errorf("посторонний получил право: %s — тогда утверждения выше зеленели бы "+
						"и на реализации, разрешающей всем", other)
				}
			})
		})
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
