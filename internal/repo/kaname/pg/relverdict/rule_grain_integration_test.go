// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// rule_grain_integration_test.go — ГЛАГОЛ ДАЁТ ТО ПРАВИЛО, ЧЕЙ СЕЛЕКТОР ВЫБРАЛ
// ОБЪЕКТ (kaname#878).
//
// Роль из нескольких правил разных глаголов: решение о доступе не вправе
// сочетать глагол одного правила с охватом другого. Материализатор считает
// глаголы по правилу; решение обязано давать то же.
//
// Вход — тот же, что у пробы вложенных правил (`ndSeedRole`): роль пишется
// продуктовым писателем, проекция глаголов — из каталожного факта, фикстура не
// снисходительнее продукта. Формы вопроса — все пять, у которых есть ветвь
// выдач. У каждого отрицательного случая есть положительный близнец, меняющий
// ровно один факт: состав правил роли.

import (
	"context"
	"slices"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

const rgAll = `{"allInScope": true}`

// rgAskVerb — Allowed по глаголу с отказом пробы на ошибке.
func rgAskVerb(t *testing.T, ctx context.Context, a *relverdict.Asker, typ, id, rel string) bool {
	t.Helper()
	got, err := a.Allowed(ctx, ndUsrD, typ, id, rel, nil)
	if err != nil {
		t.Fatalf("Allowed(%s, %s:%s): %v", rel, typ, id, err)
	}
	return got
}

// rgFormsAgree — пять форм вопроса о ОДНОМ глаголе на наборе объектов одного
// типа: Allowed, AllowedMany, Objects, Subjects и Sources обязаны назвать одно и
// то же множество разрешённых.
func rgFormsAgree(t *testing.T, ctx context.Context, a *relverdict.Asker, typ, rel string, ids []string, want map[string]bool) {
	t.Helper()
	wantMany := make([]bool, len(ids))
	var wantObjects []string
	for i, id := range ids {
		wantMany[i] = want[id]
		if want[id] {
			wantObjects = append(wantObjects, id)
		}
		if got := rgAskVerb(t, ctx, a, typ, id, rel); got != want[id] {
			t.Errorf("Allowed(%s, %s:%s) = %v, ждали %v", rel, typ, id, got, want[id])
		}
		subs, _, err := a.Subjects(ctx, typ, id, rel, 100)
		if err != nil {
			t.Fatalf("Subjects(%s:%s, %s): %v", typ, id, rel, err)
		}
		if slices.Contains(subs, ndUsrD) != want[id] {
			t.Errorf("Subjects(%s:%s, %s) = %v: называет %s — %v, ждали %v",
				typ, id, rel, subs, ndUsrD, slices.Contains(subs, ndUsrD), want[id])
		}
		src, err := a.Sources(ctx, typ, id, rel)
		if err != nil {
			t.Fatalf("Sources(%s:%s, %s): %v", typ, id, rel, err)
		}
		if slices.Contains(src, ndUsrD) != want[id] {
			t.Errorf("Sources(%s:%s, %s) = %v: называет %s — %v, ждали %v",
				typ, id, rel, src, ndUsrD, slices.Contains(src, ndUsrD), want[id])
		}
	}
	many, err := a.AllowedMany(ctx, ndUsrD, typ, ids, rel, nil)
	if err != nil {
		t.Fatalf("AllowedMany(%s, %v): %v", rel, ids, err)
	}
	if !slices.Equal(many, wantMany) {
		t.Errorf("AllowedMany(%s, %v) = %v, ждали %v", rel, ids, many, wantMany)
	}
	objs, complete, err := a.Objects(ctx, ndUsrD, typ, []string{rel}, 100)
	if err != nil || !complete {
		t.Fatalf("Objects(%s, %s): %v (полнота %v)", typ, rel, err, complete)
	}
	slices.Sort(objs)
	slices.Sort(wantObjects)
	if !slices.Equal(objs, wantObjects) {
		t.Errorf("Objects(%s, %s) = %v, ждали %v", typ, rel, objs, wantObjects)
	}
}

// RG-01: правило А — реестры [get] якорем, правило Б — реестры [delete] по имени
// X. Выдача на весь проект. delete — только на X, get — на все.
func TestRuleGrain_RG01_VerbComesFromTheRuleThatSelectedTheObject(t *testing.T) {
	pool, ctx, a := ndWorld(t, "{}", "{}")
	ndSeedRole(t, ctx, pool, "rol-rg-split", domain.Rules{
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}},
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"delete"},
			ResourceNames: []string{ndX}},
	})
	ndBind(t, ctx, pool, "acb-rg01", "user", "usr-1", "rol-rg-split", rgAll)

	ids := []string{ndX, ndY}
	rgFormsAgree(t, ctx, a, ndRegType, "v_get", ids, map[string]bool{ndX: true, ndY: true})
	rgFormsAgree(t, ctx, a, ndRegType, "v_delete", ids, map[string]bool{ndX: true, ndY: false})
}

// RG-01 близнец: те же глаголы ОДНИМ правилом якорем — delete на всех законно.
func TestRuleGrain_RG01Twin_OneRuleWithBothVerbsGivesBothEverywhere(t *testing.T) {
	pool, ctx, a := ndWorld(t, "{}", "{}")
	ndSeedRole(t, ctx, pool, "rol-rg-one", domain.Rules{
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "delete"}},
	})
	ndBind(t, ctx, pool, "acb-rg01t", "user", "usr-1", "rol-rg-one", rgAll)

	ids := []string{ndX, ndY}
	rgFormsAgree(t, ctx, a, ndRegType, "v_get", ids, map[string]bool{ndX: true, ndY: true})
	rgFormsAgree(t, ctx, a, ndRegType, "v_delete", ids, map[string]bool{ndX: true, ndY: true})
}

// RG-02: вложенное правило несёт СВОИ глаголы. Правило А — реестры [get, list] с
// children репозитории [get, list]; правило Б — репозитории [delete] верхнего
// уровня. Цель выдачи — реестр X. Правило Б целью [X] не охватывает ни одного
// репозитория (сравнение точное, kaname#857), поэтому delete на репозиториях X
// не даётся; get — даётся вложенным правилом.
func TestRuleGrain_RG02_NestedRuleCarriesItsOwnVerbs(t *testing.T) {
	pool, ctx, a := ndWorld(t, "{}", "{}")
	ndSeedRole(t, ctx, pool, "rol-rg-nested", domain.Rules{
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "list"},
			Children: []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get", "list"}}}},
		{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"delete"}},
	})
	ndBind(t, ctx, pool, "acb-rg02", "user", "usr-1", "rol-rg-nested", ndTarget(ndX))

	ids := []string{ndXApp, ndXMoved, ndYApp}
	rgFormsAgree(t, ctx, a, ndRepoType, "v_get", ids, map[string]bool{ndXApp: true, ndXMoved: true, ndYApp: false})
	rgFormsAgree(t, ctx, a, ndRepoType, "v_delete", ids, map[string]bool{ndXApp: false, ndXMoved: false, ndYApp: false})
	// Сам реестр: delete не объявлен ни одним правилом над реестрами.
	rgFormsAgree(t, ctx, a, ndRegType, "v_delete", []string{ndX, ndY}, map[string]bool{ndX: false, ndY: false})
}

// RG-02 близнец: delete назван В САМОМ вложенном правиле — тогда он даётся на
// репозиториях X и только на них.
func TestRuleGrain_RG02Twin_DeleteInTheNestedRuleReachesTheDescendants(t *testing.T) {
	pool, ctx, a := ndWorld(t, "{}", "{}")
	ndSeedRole(t, ctx, pool, "rol-rg-nested-del", domain.Rules{
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "list"},
			Children: []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get", "list", "delete"}}}},
	})
	ndBind(t, ctx, pool, "acb-rg02t", "user", "usr-1", "rol-rg-nested-del", ndTarget(ndX))

	ids := []string{ndXApp, ndXMoved, ndYApp}
	rgFormsAgree(t, ctx, a, ndRepoType, "v_delete", ids, map[string]bool{ndXApp: true, ndXMoved: true, ndYApp: false})
}
