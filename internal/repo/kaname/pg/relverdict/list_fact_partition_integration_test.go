// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/pkg/ownerregister"
)

// На одной странице соседствуют собственный факт, факт разрешённого планом
// предка и закрытые соседи. Выдач ролей нет: они не могут скрыть поломку фактов.
// Аккаунт достигается прямо и через проект; кластер наследует оба пути.
func TestList_FactsStayWithTheirCandidateAcrossRepeatedAncestorPaths(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		exec(t, ctx, tx, `INSERT INTO kaname.clusters (id, name)
		 VALUES ('cluster_root', 'list-fact-partition') ON CONFLICT DO NOTHING`)
		base := time.Now().UTC().Truncate(time.Microsecond)
		network := catalogFormOf(t, "vpc_network")
		for _, id := range []string{"net-fp-00-closed", "net-fp-10-self", "net-fp-30-closed"} {
			registerThroughProducer(t, ctx, tx, network, id, nil, "", "", base)
		}
		registerThroughProducer(t, ctx, tx, network, "net-fp-20-ancestor",
			ownerregister.ParentChain(nil, "prj-1", "acc-1"), "prj-1", "acc-1", base)
		registerThroughProducer(t, ctx, tx, catalogFormOf(t, "account"), "acc-1",
			[]string{"cluster:cluster_root"}, "", "", base)

		// Проверяем реальные рёбра, а не собственную копию рекурсивного обхода.
		var links int
		if err := tx.QueryRow(ctx, `SELECT count(*)::int FROM kaname.resource_scope_edge
		 WHERE (object_type='vpc_network' AND object_id='net-fp-20-ancestor'
		        AND ((parent_type='project' AND parent_id='prj-1')
		          OR (parent_type='account' AND parent_id='acc-1')))
		    OR (object_type='project' AND object_id='prj-1' AND parent_type='account' AND parent_id='acc-1')
		    OR (object_type='account' AND object_id='acc-1' AND parent_type='cluster' AND parent_id='cluster_root')`).Scan(&links); err != nil {
			t.Fatalf("предпосылка повторных путей: %v", err)
		}
		if links != 4 {
			t.Fatalf("предпосылка: найдено %d рёбер вместо 4; два пути к аккаунту и кластеру не установлены", links)
		}
		var grants int
		// Миграции оставляют чужие bootstrap-выдачи. Исключаем основания
		// именно всех говорящих usr-1: его самого, его групп и ОБОИХ классов.
		// role_id необходим боевому JOIN role_verb; NULL его пройти не может.
		// Остальные ограничения выдачи намеренно не сужаем: ноль этого
		// надмножества исключает любое маскирующее основание на всех кандидатах.
		if err := tx.QueryRow(ctx, `SELECT count(*)::int
		 FROM kaname.access_binding_subjects bs
		 JOIN kaname.access_bindings b ON b.id=bs.binding_id
		 WHERE b.role_id IS NOT NULL
		   AND ((bs.subject_type='user' AND bs.subject_id='usr-1')
		     OR (bs.subject_type='group' AND EXISTS (
		          SELECT 1 FROM kaname.group_members gm
		           WHERE gm.group_id=bs.subject_id AND gm.member_type='user' AND gm.member_id='usr-1'))
		     OR (bs.subject_type='system_class' AND (bs.subject_type || ':' || bs.subject_id)=ANY($1::text[])))`,
			domain.SpeakerClasses("user:usr-1")).Scan(&grants); err != nil {
			t.Fatalf("перепись оснований всех говорящих usr-1: %v", err)
		}
		if grants != 0 {
			t.Fatalf("найдено %d возможных ролевых оснований usr-1, его групп или классов: они могли бы скрыть поломку ветви фактов", grants)
		}
		wantPage := func(why string, want []string) {
			t.Helper()
			ids, next, err := relverdict.List(ctx, tx, relverdict.ListQuery{
				Subject: "user:usr-1", ObjectType: "vpc_network", Relation: "v_get", Limit: 10,
			})
			if err != nil {
				t.Fatalf("%s: List: %v", why, err)
			}
			if !slices.Equal(ids, want) || next != "" {
				t.Fatalf("%s: ids=%v, cursor=%q; ожидались ids=%v и пустой курсор", why, ids, next, want)
			}
		}
		wantPage("без фактов", nil)
		exec(t, ctx, tx, `INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
		 VALUES ('vpc_network','net-fp-10-self','v_get','user:usr-1'),
		        ('cluster','cluster_root','system_admin','user:usr-1')`)
		wantPage("факт на себе и разрешённом предке без повторов и утечки соседям",
			[]string{"net-fp-10-self", "net-fp-20-ancestor"})
		exec(t, ctx, tx, `DELETE FROM kaname.relation_fact
		 WHERE object_type='vpc_network' AND object_id='net-fp-10-self' AND relation='v_get' AND subject='user:usr-1'`)
		wantPage("снятие собственного факта оставляет только предка", []string{"net-fp-20-ancestor"})
		exec(t, ctx, tx, `DELETE FROM kaname.relation_fact
		 WHERE object_type='cluster' AND object_id='cluster_root' AND relation='system_admin' AND subject='user:usr-1'`)
		// v_get на проекте не является источником v_get сети: атом собственного
		// факта требует depth=0. Один лишь совпавший текст отношения недостаточен.
		exec(t, ctx, tx, `INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
		 VALUES ('project','prj-1','v_get','user:usr-1')`)
		wantPage("собственный атом не превращается в наследуемый", nil)
	})
}
