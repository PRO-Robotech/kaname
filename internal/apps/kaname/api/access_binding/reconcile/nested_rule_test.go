// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// nested_rule_test.go — материализатор и вложенное правило роли (kaname#874,
// приёмка docs/engineering/acceptance/nested-rule-reaches-descendants-of-a-named-container.md,
// редакция 2): ND-08 (глубина, вся область, ветвь владельца), R1 (ветвь меток
// владельца), ND-09 (перенос по цепи), ND-10 (у класса нет второй дороги),
// ND-03 и ND-07 (б) (`public_reader` пишется по вложенному правилу и только по
// нему).
//
// Каталожный факт — из фикстуры П3 (`probemod.children-fixture.yaml`): три
// уровня родства, которых нет в каноне (замер Р2). Отбор и цепь объекта — у
// хранилища-двойника; его `MatchDescendants` и `AncestorObjects` отвечают по
// тем же предкам, что регистрация кладёт в `resource_parent_edge`.

import (
	"context"
	"slices"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

const (
	ndPrj = "prj0000000000000nd08"
	ndAcc = "acc0000000000000nd08"
)

// MatchDescendants — объекты типов types, у которых среди предков есть
// контейнер containerType с id из containerIDs.
func (f *fakeStore) MatchDescendants(_ context.Context, types []string, containerType string, containerIDs []string) ([]domain.MirrorObject, error) {
	var out []domain.MirrorObject
	for _, t := range types {
		for _, o := range f.mirror[t] {
			for _, a := range f.ancestors[memberKey(o.ObjectType, o.ObjectID)] {
				if a.ObjectType == containerType && slices.Contains(containerIDs, a.ObjectID) {
					out = append(out, o)
					break
				}
			}
		}
	}
	return out, nil
}

// AncestorObjects — предки объекта из его цепи.
func (f *fakeStore) AncestorObjects(_ context.Context, objectType, objectID string) ([]domain.MirrorObject, error) {
	return f.ancestors[memberKey(objectType, objectID)], nil
}

func ndObj(typ, id string, labels map[string]string) domain.MirrorObject {
	return domain.MirrorObject{ObjectType: typ, ObjectID: id, ParentProjectID: ndPrj,
		ParentAccountIDs: []string{ndAcc}, Labels: labels}
}

// ndFacts — каталожный факт с фикстурой П3.
func ndFacts(t *testing.T) *catalog.Facts {
	t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.ChildrenProbemodFile)
	if err != nil {
		t.Fatalf("фикстура П3: %v", err)
	}
	f := sc65Facts(t, doc)
	if typ, ok := f.FGAObjectType("probemod.tags"); !ok || typ != "probemod_tag" {
		t.Fatalf("фикстура П3: каталог не знает probemod.tags → probemod_tag (%q, %v)", typ, ok)
	}
	return f
}

// ndStore — мир П3: ящики b1 (метка team=a), b2 (team=b); предметы i1 (в b1),
// i3 (в b2); ярлыки t1 (в i1), t3 (в i3).
func ndStore(subjectType, subjectID string, rules domain.Rules, target domain.AccessTarget) *fakeStore {
	b1 := ndObj("probemod.boxes", "b1", map[string]string{"team": "a"})
	b2 := ndObj("probemod.boxes", "b2", map[string]string{"team": "b"})
	i1, i3 := ndObj("probemod.items", "i1", nil), ndObj("probemod.items", "i3", nil)
	t1, t3 := ndObj("probemod.tags", "t1", nil), ndObj("probemod.tags", "t3", nil)
	return &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: ndPrj},
		subjectType: subjectType, subjectID: subjectID, active: true,
		selectors: rules.MaterializingSelectorsInScope(domain.ScopeProject),
		target:    target,
		mirror: map[string][]domain.MirrorObject{
			"probemod.boxes": {b1, b2}, "probemod.items": {i1, i3}, "probemod.tags": {t1, t3},
		},
		ancestors: map[string][]domain.MirrorObject{
			memberKey("probemod.items", "i1"): {b1},
			memberKey("probemod.items", "i3"): {b2},
			memberKey("probemod.tags", "t1"):  {i1, b1},
			memberKey("probemod.tags", "t3"):  {i3, b2},
		},
	}
}

func ndReaderRules(ownerNames []string, ownerLabels map[string]string, child string) domain.Rules {
	return domain.Rules{{
		Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get", "list"},
		ResourceNames: ownerNames, MatchLabels: ownerLabels,
		Children: []domain.Rule{{Resources: []string{child}, Verbs: []string{"get", "list"}}},
	}}
}

func ndBoxTarget(id string) domain.AccessTarget {
	return domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "probemod.boxes", ID: id}}}
}

// ndMembers — объекты, на которых материализован `v_get` (по кортежам записи).
func ndMembers(f *fakeStore, fgaType string) []string {
	var out []string
	for _, tu := range allWrites(f) {
		if tu.Relation != "v_get" {
			continue
		}
		if len(tu.Object) > len(fgaType)+1 && tu.Object[:len(fgaType)+1] == fgaType+":" {
			out = append(out, tu.Object[len(fgaType)+1:])
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func ndReconcile(t *testing.T, f *fakeStore) {
	t.Helper()
	rec := New(fakeRunner{s: f}, nil, catalog.Fixed{F: ndFacts(t)})
	if err := rec.ReconcileBinding(context.Background(), "acb0000000000000nd08"); err != nil {
		t.Fatalf("проход материализатора: %v", err)
	}
}

// ND-08: внук охватывается на любой глубине; соседний контейнер — нет; тип без
// правила (items) — нет. Близнец — цель b2.
func TestReconcileNested_ND08_GrandchildOfTheNamedContainer(t *testing.T) {
	f := ndStore("user", "usrnd08", ndReaderRules(nil, nil, "tags"), ndBoxTarget("b1"))
	ndReconcile(t, f)
	if got := ndMembers(f, "probemod_tag"); !slices.Equal(got, []string{"t1"}) {
		t.Errorf("v_get на ярлыках = %v, ждали [t1] (предок b1 на глубине 2)", got)
	}
	if got := ndMembers(f, "probemod_item"); len(got) != 0 {
		t.Errorf("v_get на предметах = %v: правила над items нет", got)
	}

	twin := ndStore("user", "usrnd08", ndReaderRules(nil, nil, "tags"), ndBoxTarget("b2"))
	ndReconcile(t, twin)
	if got := ndMembers(twin, "probemod_tag"); !slices.Equal(got, []string{"t3"}) {
		t.Errorf("близнец (цель b2): v_get на ярлыках = %v, ждали [t3]", got)
	}
}

// ND-08 «И» (B1 = (б)): цель — вся область; ветвь владельца выбирает контейнеры —
// якорь все, имена только b1. R1: ветвь меток владельца — так же.
func TestReconcileNested_ND08_WholeScopeFollowsTheOwnersArm(t *testing.T) {
	for name, c := range map[string]struct {
		rules domain.Rules
		want  []string
	}{
		"якорь":        {ndReaderRules(nil, nil, "tags"), []string{"t1", "t3"}},
		"имена [b1]":   {ndReaderRules([]string{"b1"}, nil, "tags"), []string{"t1"}},
		"метки team=a": {ndReaderRules(nil, map[string]string{"team": "a"}, "tags"), []string{"t1"}},
	} {
		t.Run(name, func(t *testing.T) {
			f := ndStore("user", "usrnd08", c.rules, domain.AccessTarget{AllInScope: true})
			ndReconcile(t, f)
			if got := ndMembers(f, "probemod_tag"); !slices.Equal(got, c.want) {
				t.Errorf("v_get на ярлыках = %v, ждали %v", got, c.want)
			}
		})
	}
}

// ND-09: путь по объекту (событие регистрации) читает ТЕКУЩУЮ цепь объекта. После
// переноса t1 под b2 член выдачи на b1 снимается; выдача на b2 его получает.
func TestReconcileNested_ND09_ObjectPassFollowsTheCurrentChain(t *testing.T) {
	ctx := context.Background()
	f := ndStore("user", "usrnd08", ndReaderRules(nil, nil, "tags"), ndBoxTarget("b1"))
	f.selectorBindings = []domain.AccessBindingID{"acb0000000000000nd08"}
	rec := New(fakeRunner{s: f}, nil, catalog.Fixed{F: ndFacts(t)})
	if err := rec.ReconcileObject(ctx, "probemod.tags", "t1"); err != nil {
		t.Fatalf("проход по объекту: %v", err)
	}
	if got := ndMembers(f, "probemod_tag"); !slices.Equal(got, []string{"t1"}) {
		t.Fatalf("до переноса: v_get на ярлыках = %v, ждали [t1]", got)
	}

	// Перенос: цепь t1 теперь через i3 и b2; член на t1 уже стоит.
	moved := ndStore("user", "usrnd08", ndReaderRules(nil, nil, "tags"), ndBoxTarget("b1"))
	moved.ancestors[memberKey("probemod.tags", "t1")] = moved.ancestors[memberKey("probemod.tags", "t3")]
	moved.bindingsForObject = []domain.AccessBindingID{"acb0000000000000nd08"}
	moved.current = f.upserts
	rec2 := New(fakeRunner{s: moved}, nil, catalog.Fixed{F: ndFacts(t)})
	if err := rec2.ReconcileObject(ctx, "probemod.tags", "t1"); err != nil {
		t.Fatalf("проход по объекту после переноса: %v", err)
	}
	if !slices.Contains(moved.deletes, memberKey("probemod.tags", "t1")) {
		t.Errorf("после переноса t1 под b2 член выдачи на b1 не снят: удалено %v", moved.deletes)
	}
}

// ND-10: у класса нет второй дороги к потомкам — материализатор вложенное
// правило к выдаче классу не применяет: членов `v_*` на детях нет. Близнец —
// та же роль у человека.
func TestReconcileNested_ND10_ClassGetsNoMembersOnDescendants(t *testing.T) {
	cls := ndStore("system_class", "anonymous", ndReaderRules(nil, nil, "items"), ndBoxTarget("b1"))
	ndReconcile(t, cls)
	if got := ndMembers(cls, "probemod_item"); len(got) != 0 {
		t.Errorf("выдача классу материализовала v_get на предметах %v — вторая дорога к потомкам", got)
	}
	usr := ndStore("user", "usrnd08", ndReaderRules(nil, nil, "items"), ndBoxTarget("b1"))
	ndReconcile(t, usr)
	if got := ndMembers(usr, "probemod_item"); !slices.Equal(got, []string{"i1"}) {
		t.Errorf("близнец (человек): v_get на предметах = %v, ждали [i1]", got)
	}
}

func ndPublicReaderOn(f *fakeStore, box string) bool {
	return hasTuple(allWrites(f), "public_reader", "probemod_box:"+box)
}

// ND-03 и ND-07 (б): выдача классу на объявленный контейнер пишет `public_reader`
// по вложенному правилу над ПРЯМЫМ ребёнком, читающему его целиком; правило
// верхнего уровня над ребёнком (прежняя форма) — не пишет; вложенное над внуком —
// не пишет (до внука `public_reader` не доходит).
func TestReconcileNested_ND03_PublicReaderComesFromTheNestedRuleOnly(t *testing.T) {
	nested := ndStore("system_class", "anonymous", ndReaderRules(nil, nil, "items"), ndBoxTarget("b1"))
	ndReconcile(t, nested)
	if !ndPublicReaderOn(nested, "b1") {
		t.Errorf("вложенное правило над прямым ребёнком: public_reader на b1 не записан; записано %v", allWrites(nested))
	}
	if ndPublicReaderOn(nested, "b2") {
		t.Errorf("public_reader записан на b2, не названном целью")
	}

	flat := ndStore("system_class", "anonymous", domain.Rules{{
		Module: "probemod", Resources: []string{"boxes", "items"}, Verbs: []string{"get", "list"},
	}}, ndBoxTarget("b1"))
	ndReconcile(t, flat)
	if ndPublicReaderOn(flat, "b1") {
		t.Errorf("ND-07 (б): прежняя форма (правило верхнего уровня над ребёнком) пишет public_reader")
	}

	grand := ndStore("system_class", "anonymous", ndReaderRules(nil, nil, "tags"), ndBoxTarget("b1"))
	ndReconcile(t, grand)
	if ndPublicReaderOn(grand, "b1") {
		t.Errorf("вложенное правило над внуком пишет public_reader: до внука он не доходит")
	}
}

// R1 на пути по объекту: изменились метки КОНТЕЙНЕРА — ветвь меток владельца его
// больше не выбирает, и члены выдачи на его потомках снимаются тем же событием,
// а не следующим обходом. Близнец — метки не изменились: член на месте.
func TestReconcileNested_ND08_ContainerLabelChangeRecomputesDescendants(t *testing.T) {
	ctx := context.Background()
	rules := ndReaderRules(nil, map[string]string{"team": "a"}, "tags")
	f := ndStore("user", "usrnd08", rules, domain.AccessTarget{AllInScope: true})
	ndReconcile(t, f)
	if got := ndMembers(f, "probemod_tag"); !slices.Equal(got, []string{"t1"}) {
		t.Fatalf("Дано: v_get на ярлыках = %v, ждали [t1]", got)
	}
	for name, c := range map[string]struct {
		team    string
		removed bool
	}{"метка сменилась": {"b", true}, "близнец: метка прежняя": {"a", false}} {
		t.Run(name, func(t *testing.T) {
			g := ndStore("user", "usrnd08", rules, domain.AccessTarget{AllInScope: true})
			g.mirror["probemod.boxes"][0].Labels = map[string]string{"team": c.team}
			for _, k := range []string{memberKey("probemod.items", "i1"), memberKey("probemod.tags", "t1")} {
				for i := range g.ancestors[k] {
					if g.ancestors[k][i].ObjectID == "b1" {
						g.ancestors[k][i].Labels = map[string]string{"team": c.team}
					}
				}
			}
			g.current = f.upserts
			g.bindingsForObject = []domain.AccessBindingID{"acb0000000000000nd08"}
			rec := New(fakeRunner{s: g}, nil, catalog.Fixed{F: ndFacts(t)})
			if err := rec.ReconcileObject(ctx, "probemod.boxes", "b1"); err != nil {
				t.Fatalf("проход по контейнеру: %v", err)
			}
			if got := slices.Contains(g.deletes, memberKey("probemod.tags", "t1")); got != c.removed {
				t.Errorf("член на t1 снят = %v, ждали %v (удалено %v)", got, c.removed, g.deletes)
			}
		})
	}
}
