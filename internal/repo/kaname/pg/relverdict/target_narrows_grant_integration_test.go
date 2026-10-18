// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// target_narrows_grant_integration_test.go — ЦЕЛЬ ПРИВЯЗКИ СУЖАЕТ get И list ДО
// НАЗВАННЫХ ОБЪЕКТОВ (kaname#857).
//
// Требование: выдача с `target.resources:[…]` даёт право ТОЛЬКО на названные
// объекты (тип и идентификатор); `allInScope` и пустая цель — на всю область.
// Ровно это же пересечение делает материализатор (`filterMatchedToTarget`), и
// решение о доступе обязано отвечать тем же множеством: иначе две формы одного
// права расходятся.
//
// Вход — ТОТ ЖЕ, что провязывает композиционный корень (`cmd/kaname`:
// `relverdict.NewAsker(pool)`), поэтому посев коммитится, а вопросы задаёт сам
// адаптер в своей транзакции чтения. Формы вопроса — все, у которых есть ветвь
// выдач: прямой (`Allowed`), о странице (`AllowedMany`), перечень (`Objects`),
// кто имеет право (`Subjects`) и разбор оснований (`Sources`).
//
// Посев — той же формы, что `seedGetGrant` пробы чтения: роль с якорной ветвью
// правила и проекцией глагола, выдача на область АККАУНТА, её субъект.
//
// Каждое «нет» стоит в паре с «да» того же посева: законный близнец
// (`allInScope`) разрешает оба объекта, и без него запрет ниже был бы неотличим
// от сломанной фикстуры.

import (
	"context"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

const (
	tgObjX     = "net-tg-x"
	tgObjY     = "net-tg-y"
	tgRole     = "rol-tg"
	tgBinding  = "acb-tg"
	tgSpeaker  = "user:usr-1"
	tgRelation = "v_get"
)

// tgTargetResources — цель, называющая ровно перечисленные пары «тип, id».
func tgTargetResources(t *testing.T, pairs ...[2]string) string {
	t.Helper()
	out := `{"resources":[`
	for i, p := range pairs {
		if i > 0 {
			out += ","
		}
		out += `{"type":"` + p[0] + `","id":"` + p[1] + `"}`
	}
	return out + `]}`
}

// tgSeedTopology кладёт аккаунт, проект, два объекта одного типа X и Y и объект
// ДРУГОГО типа с тем же идентификатором, что у X. Роль читает оба типа якорной
// ветвью. Выдачи здесь нет — её кладёт случай.
func tgSeedTopology(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	seedTenant(t, ctx, tx)
	seedRole(t, ctx, tx, tgRole, "vpc_network", "get", "anchor", "{}")
	subnet := catalogFormOf(t, "vpc_subnet")
	exec(t, ctx, tx,
		`INSERT INTO kaname.role_verb (role_id, object_type, verb) VALUES ($1, $2, 'get')`,
		tgRole, subnet)
	exec(t, ctx, tx,
		`INSERT INTO kaname.role_rule_selectors
		   (role_id, rule_fp, arm, object_types, match_labels, verbs_by_type)
		 VALUES ($1, 'fp-2', 'anchor', ARRAY[$2::text], '{}'::jsonb,
		         jsonb_build_object($2::text, jsonb_build_array('get')))`, tgRole, subnet)

	for _, o := range []struct{ model, id string }{
		{"vpc_network", tgObjX}, {"vpc_network", tgObjY}, {"vpc_subnet", tgObjX},
	} {
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_mirror (object_type, object_id) VALUES ($1, $2)`,
			catalogFormOf(t, o.model), o.id)
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ($1, $2, 'project', 'prj-1', 1)`, o.model, o.id)
	}
}

// tgSeedBinding кладёт выдачу роли на область АККАУНТА с заданной целью и её
// субъектом.
func tgSeedBinding(t *testing.T, ctx context.Context, tx pgx.Tx, subjectType, subjectID, target string) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kaname.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status, target)
		 VALUES ($1, $2, $3, $4, 'account', 'acc-1', 'ACTIVE', $5::jsonb)`,
		tgBinding, subjectType, subjectID, tgRole, target)
	exec(t, ctx, tx,
		`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ($1, $2, $3)`, tgBinding, subjectType, subjectID)
}

// tgWant — ожидаемое по каждой форме вопроса.
type tgWant struct {
	x, y   bool     // Allowed по X и Y (vpc_network)
	subnet bool     // Allowed по объекту vpc_subnet с идентификатором X
	listed []string // Objects по vpc_network
}

// tgAskAll задаёт вопрос всеми формами через адаптер и сверяет с ожидаемым.
func tgAskAll(t *testing.T, ctx context.Context, a *relverdict.Asker, speaker string, want tgWant) {
	t.Helper()
	for _, c := range []struct {
		typ, id string
		want    bool
	}{
		{"vpc_network", tgObjX, want.x},
		{"vpc_network", tgObjY, want.y},
		{"vpc_subnet", tgObjX, want.subnet},
	} {
		got, err := a.Allowed(ctx, speaker, c.typ, c.id, tgRelation, nil)
		if err != nil {
			t.Fatalf("Allowed(%s, %s:%s): %v", speaker, c.typ, c.id, err)
		}
		if got != c.want {
			t.Errorf("Allowed(%s, %s:%s) = %v, ждали %v", speaker, c.typ, c.id, got, c.want)
		}
	}

	many, err := a.AllowedMany(ctx, speaker, "vpc_network", []string{tgObjX, tgObjY}, tgRelation, nil)
	if err != nil {
		t.Fatalf("AllowedMany(%s): %v", speaker, err)
	}
	if wantMany := []bool{want.x, want.y}; !slices.Equal(many, wantMany) {
		t.Errorf("AllowedMany(%s, [X Y]) = %v, ждали %v", speaker, many, wantMany)
	}

	ids, complete, err := a.Objects(ctx, speaker, "vpc_network", []string{tgRelation}, 100)
	if err != nil {
		t.Fatalf("Objects(%s): %v", speaker, err)
	}
	if !complete {
		t.Fatalf("Objects(%s) объявлен неполным при ответе из %d объектов", speaker, len(ids))
	}
	slices.Sort(ids)
	wantListed := slices.Clone(want.listed)
	slices.Sort(wantListed)
	if !slices.Equal(ids, wantListed) {
		t.Errorf("Objects(%s) = %v, ждали %v", speaker, ids, wantListed)
	}
}

// tgSubjectNamed — назван ли субъект выдачи в обратных формах (кто имеет право и
// разбор оснований) на объекте сети.
func tgSubjectNamed(t *testing.T, ctx context.Context, a *relverdict.Asker, objectID, subject string) (bySubjects, bySources bool) {
	t.Helper()
	subs, _, err := a.Subjects(ctx, "vpc_network", objectID, tgRelation, 100)
	if err != nil {
		t.Fatalf("Subjects(%s): %v", objectID, err)
	}
	src, err := a.Sources(ctx, "vpc_network", objectID, tgRelation)
	if err != nil {
		t.Fatalf("Sources(%s): %v", objectID, err)
	}
	return slices.Contains(subs, subject), slices.Contains(src, subject)
}

// Выдача с целью [X] даёт право на X и только на X — каждой формой вопроса.
func TestTarget_ResourcesNarrowTheGrantToTheNamedObjects(t *testing.T) {
	pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
		tgSeedTopology(t, ctx, tx)
		tgSeedBinding(t, ctx, tx, "user", "usr-1",
			tgTargetResources(t, [2]string{catalogFormOf(t, "vpc_network"), tgObjX}))
	})
	a := relverdict.NewAsker(pool)

	tgAskAll(t, ctx, a, tgSpeaker, tgWant{x: true, y: false, subnet: false, listed: []string{tgObjX}})

	for _, c := range []struct {
		id   string
		want bool
	}{{tgObjX, true}, {tgObjY, false}} {
		bySubjects, bySources := tgSubjectNamed(t, ctx, a, c.id, tgSpeaker)
		if bySubjects != c.want {
			t.Errorf("Subjects(%s) называет %s = %v, ждали %v", c.id, tgSpeaker, bySubjects, c.want)
		}
		if bySources != c.want {
			t.Errorf("Sources(%s) называет %s = %v, ждали %v", c.id, tgSpeaker, bySources, c.want)
		}
	}
}

// Законный близнец: `allInScope`, пустая цель и пустой перечень — вся область.
// Без него запрет выше был бы неотличим от фикстуры, не достающей до объектов.
func TestTarget_WholeScopeTwinsReachEveryObject(t *testing.T) {
	for name, target := range map[string]string{
		"allInScope":      `{"allInScope": true}`,
		"пустая цель":     `{}`,
		"пустой перечень": `{"resources": []}`,
	} {
		t.Run(name, func(t *testing.T) {
			pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
				tgSeedTopology(t, ctx, tx)
				tgSeedBinding(t, ctx, tx, "user", "usr-1", target)
			})
			a := relverdict.NewAsker(pool)
			tgAskAll(t, ctx, a, tgSpeaker, tgWant{x: true, y: true, subnet: true, listed: []string{tgObjX, tgObjY}})
			for _, id := range []string{tgObjX, tgObjY} {
				bySubjects, bySources := tgSubjectNamed(t, ctx, a, id, tgSpeaker)
				if !bySubjects || !bySources {
					t.Errorf("обратные формы на %s: Subjects=%v Sources=%v, ждали оба true",
						id, bySubjects, bySources)
				}
			}
		})
	}
}

// Отрицательный контроль: тот же посев без выдачи — ни одного права.
func TestTarget_ControlWithoutBindingGrantsNothing(t *testing.T) {
	pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
		tgSeedTopology(t, ctx, tx)
	})
	tgAskAll(t, ctx, relverdict.NewAsker(pool), tgSpeaker, tgWant{x: false, y: false, subnet: false, listed: []string{}})
}

// Сверка типа: цель называет пару «тип, id», а не один id. Объект другого типа с
// тем же идентификатором не проходит; цель, называющая его тип, — пропускает его
// и только его.
func TestTarget_TypeIsComparedNotOnlyTheId(t *testing.T) {
	t.Run("цель называет сеть", func(t *testing.T) {
		pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
			tgSeedTopology(t, ctx, tx)
			tgSeedBinding(t, ctx, tx, "user", "usr-1",
				tgTargetResources(t, [2]string{catalogFormOf(t, "vpc_network"), tgObjX}))
		})
		tgAskAll(t, ctx, relverdict.NewAsker(pool), tgSpeaker,
			tgWant{x: true, y: false, subnet: false, listed: []string{tgObjX}})
	})
	t.Run("цель называет подсеть с тем же id", func(t *testing.T) {
		pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
			tgSeedTopology(t, ctx, tx)
			tgSeedBinding(t, ctx, tx, "user", "usr-1",
				tgTargetResources(t, [2]string{catalogFormOf(t, "vpc_subnet"), tgObjX}))
		})
		tgAskAll(t, ctx, relverdict.NewAsker(pool), tgSpeaker,
			tgWant{x: false, y: false, subnet: true, listed: []string{}})
	})
}

// Субъект — класс говорящего: та же ветвь выдач, тот же ответ. Близнец
// `allInScope` у класса — оба объекта.
func TestTarget_SystemClassSubjectIsNarrowedTheSameWay(t *testing.T) {
	for name, c := range map[string]struct {
		target func(t *testing.T) string
		want   tgWant
	}{
		"цель [X]": {
			target: func(t *testing.T) string {
				return tgTargetResources(t, [2]string{catalogFormOf(t, "vpc_network"), tgObjX})
			},
			want: tgWant{x: true, y: false, subnet: false, listed: []string{tgObjX}},
		},
		"allInScope": {
			target: func(*testing.T) string { return `{"allInScope": true}` },
			want:   tgWant{x: true, y: true, subnet: true, listed: []string{tgObjX, tgObjY}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			pool, ctx := withCommittedPool(t, func(ctx context.Context, tx pgx.Tx) {
				tgSeedTopology(t, ctx, tx)
				tgSeedBinding(t, ctx, tx, "system_class", "authenticated", c.target(t))
			})
			tgAskAll(t, ctx, relverdict.NewAsker(pool), tgSpeaker, c.want)
		})
	}
}
