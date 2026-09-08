// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// Право на ОДИН названный объект — ветвь перечня имён (#881/#884).
//
// ЧТО ЭТО ЗА ВЕТВЬ. Правило роли может адресовать объекты тремя способами:
// якорем (весь тип в области), метками и ПЕРЕЧНЕМ ИМЁН. Третьей ветвью
// арендатор выдаёт доступ к одной подсети, не отдавая весь тип, — и именно её
// сеют сквозные пробы пообъектной фильтрации списка.
//
// ПОЧЕМУ ПРОБА ЗАВЕДЕНА ЗДЕСЬ. Сквозная проба на стенде говорит только
// «подсеть не видна» — и говорит это через двадцать минут, назвав виновником
// список. Форма же отвечает за то, выводится ли глагол из выдачи, и спросить
// её можно за три секунды. Пока такой пробы не было, ветвь перечня у формы не
// проверялась ничем.
func TestAsk_NamesArmGrantsTheNamedObject(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)

		// Роль с ветвью ПЕРЕЧНЯ: право на подсеть, названную поимённо.
		seedRoleNames(t, ctx, tx, "rol-names", "vpc.subnet", "get", []string{"snet-1"})
		exec(t, ctx, tx,
			`INSERT INTO kaname.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ('acb-names', 'user', 'usr-1', 'rol-names', 'project', 'prj-1', 'ACTIVE')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-names', 'user', 'usr-1')`)

		// Обе подсети существуют и лежат в том же проекте: названная и НЕ названная.
		//
		// Принадлежность проекту выражается РЕБРОМ, а не полем зеркала: цепь
		// областей строится из `resource_parent_edge`, и без ребра выдача,
		// висящая на проекте, до объекта не доходит — сколько бы его ни называли
		// в перечне. Первая редакция этой пробы ребро не сеяла и краснела на
		// исправном запросе; проверено чтением соседних проб, а не догадкой.
		for _, id := range []string{"snet-1", "snet-2"} {
			exec(t, ctx, tx,
				`INSERT INTO kaname.resource_mirror (object_type, object_id, labels)
				 VALUES ($1, $2, '{}'::jsonb) ON CONFLICT DO NOTHING`,
				catalogFormOf(t, "vpc_subnet"), id)
			exec(t, ctx, tx,
				`INSERT INTO kaname.resource_parent_edge
				   (object_type, object_id, parent_type, parent_id, depth)
				 VALUES ('vpc_subnet', $1, 'project', 'prj-1', 1)`, id)
		}

		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_subnet", ObjectID: "snet-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("вопрос о названной подсети: %v", err)
		}
		if got != relverdict.Allow {
			t.Errorf("названная подсеть: вердикт = %s, ожидался %s — "+
				"выдача перечнем имён не даёт права, и это ровно то, чем краснеет "+
				"сквозная проба пообъектной фильтрации", got, relverdict.Allow)
		}

		// ЗАКОННЫЙ БЛИЗНЕЦ: НЕ названная подсеть того же проекта закрыта. Без него
		// проба зеленела бы и на выдаче, отдающей весь тип.
		other, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_subnet", ObjectID: "snet-2", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("вопрос о неназванной подсети: %v", err)
		}
		if other != relverdict.Deny {
			t.Errorf("неназванная подсеть: вердикт = %s, ожидался %s — "+
				"перечень имён обязан сужать, иначе это якорь под другим именем", other, relverdict.Deny)
		}
	})
}

// seedRoleNames — роль, чьё правило адресует объекты ПЕРЕЧНЕМ ИМЁН.
//
// Соседний `seedRole` сеет якорную и меточную ветви; третья ветвь до сих пор не
// сеялась ничем, поэтому и не проверялась. Форма записи та же, что кладёт
// продукт: `arm='names'` плюс непустой `resource_names`.
func seedRoleNames(t *testing.T, ctx context.Context, tx pgx.Tx, roleID, objType, verb string, names []string) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kaname.clusters (id, name) VALUES ('cluster_root', 'kacho')
		 ON CONFLICT DO NOTHING`)
	exec(t, ctx, tx,
		`INSERT INTO kaname.roles (id, name, permissions, rules, cluster_id)
		 VALUES ($1, $2, '[]'::jsonb,
		         jsonb_build_array(jsonb_build_object(
		             'module',    'vpc',
		             'resources', jsonb_build_array('subnet'),
		             'verbs',     jsonb_build_array($3::text))),
		         'cluster_root')`, roleID, "names."+verb, verb)
	exec(t, ctx, tx,
		`INSERT INTO kaname.role_verb (role_id, object_type, verb) VALUES ($1, $2, $3)`,
		roleID, objType, verb)
	exec(t, ctx, tx,
		`INSERT INTO kaname.role_rule_selectors
		   (role_id, rule_fp, arm, object_types, match_labels, resource_names)
		 VALUES ($1, 'fp-names', 'names', ARRAY[$2::text], '{}'::jsonb, $3::text[])`,
		roleID, objType, names)
}
