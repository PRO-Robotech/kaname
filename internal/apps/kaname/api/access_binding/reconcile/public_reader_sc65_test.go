// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// public_reader_sc65_test.go — разворачивание выдачи классу пишет
// `public_reader` на объект объявленного контейнера, и только при ВЛОЖЕННОМ
// правиле роли над типом-ребёнком (задачи PRO-Robotech/kaname#856, #874).
//
// Приёмка docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md,
// редакция 12, отпечаток bd6325e384a1e03e2acceee8841ac2ee23b589ad5fbdff6a8df0674e79b67fd6:
// SC-65 «И (механизм общий, У1)» — половина разворачивания; Р9 «Сужение по цели»
// (решение по N1, вариант (а)); SC-73 — то же условие на модуле registry
// утверждают интеграционные пробы `TestPublicContainerRead_SC73_…`.
//
// Модуль — `probemod`, отличный от registry: имени модуля в механизме нет.
// Источник «тип объявлен» — каталожный факт, выведенный из ДОСТАВЛЕННОГО
// манифеста тем же выводом, что у применителя каталога (`modulecatalog.RowsOf`),
// а не литерал с именем модуля (SC-65, «Сфера отказа»).
//
// Вход — `desiredMembersForObject`: единственная функция разворачивания, которой
// видны сразу объект, каталог и ВСЕ правила роли выдачи (ребёнок контейнера в
// цель не входит, поэтому правило над ним с объектом не сопоставляется, и
// «покрывает ли роль тип-ребёнок» видно только по набору правил целиком).
//
// # Порядок несущий
//
// Сначала фикстура: probemod без ключа загружается, каталожный факт строится, и
// выдача ЧЕЛОВЕКУ на контейнер даёт `v_get` (контроль живости разворачивания).
// Потом предмет.

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

const (
	sc65Project = "prj0000000000000sc65"
	sc65Account = "acc0000000000000sc65"
	sc65Box     = "box0000000000000sc65"
)

// sc65Facts — каталожный факт: посеянный литерал плюс строки probemod,
// выведенные из манифеста `doc`.
func sc65Facts(t *testing.T, doc []byte) *catalog.Facts {
	t.Helper()
	m, err := manifest.Load(doc)
	if err != nil {
		t.Fatalf("SC-65: загрузчик отверг probemod (%d Б): %v", len(doc), err)
	}
	decl, err := modulecatalog.RowsOf(m)
	if err != nil {
		t.Fatalf("фикстура: строки каталога probemod не выведены: %v", err)
	}
	live := seed.LiteralRows()
	live.Modules = append(live.Modules, decl.Module)
	live.Resources = append(live.Resources, decl.Resources...)
	live.Verbs = append(live.Verbs, decl.Verbs...)
	f, err := catalog.NewFacts(catalog.Halves{Live: live})
	if err != nil {
		t.Fatalf("фикстура: каталожный факт не построен: %v", err)
	}
	if typ, ok := f.FGAObjectType("probemod.boxes"); !ok || typ != "probemod_box" {
		t.Fatalf("фикстура: каталог не знает probemod.boxes → probemod_box (получено %q, %v)", typ, ok)
	}
	return f
}

// sc65Scope — выдача субъекту `subject` ролью с правилами `rules` на проект,
// цель — один контейнер.
func sc65Scope(subjectType, subjectID string, rules domain.Rules) BindingScope {
	return BindingScope{
		BindingID:   "acb0000000000000sc65",
		Scope:       domain.ScopeAnchor{Type: "project", ID: sc65Project},
		SubjectType: subjectType,
		SubjectID:   subjectID,
		Selectors:   rules.MaterializingSelectorsInScope(domain.ScopeProject),
		Target: domain.AccessTarget{Resources: []domain.ResourceRef{
			{Type: "probemod.boxes", ID: sc65Box},
		}},
	}
}

func sc65BoxObject() domain.MirrorObject {
	return domain.MirrorObject{
		ObjectType: "probemod.boxes", ObjectID: sc65Box,
		ParentProjectID: sc65Project, ParentAccountIDs: []string{sc65Account},
	}
}

// sc65Tuples — все кортежи, которые разворачивание выдачи даёт объекту.
func sc65Tuples(cat *catalog.Facts, bs BindingScope) map[domain.MembershipTuple]bool {
	out := map[domain.MembershipTuple]bool{}
	for _, dm := range desiredMembersForObject(cat, bs, sc65BoxObject()) {
		for _, tu := range dm.Tuples {
			out[tu] = true
		}
	}
	return out
}

var (
	// sc65ReadBoth — роль с ВЛОЖЕННЫМ правилом над ребёнком (редакция 11 соседа,
	// kaname#874): правило над ящиками `[get, list]`, под ним — над предметами
	// `[get, list]`. Прежняя форма — одно правило над обоими типами — потомков
	// классу больше не открывает (ND-07 (б)).
	sc65ReadBoth = domain.Rules{{Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get", "list"},
		Children: []domain.Rule{{Resources: []string{"items"}, Verbs: []string{"get", "list"}}}}}
	sc65ReadBox = domain.Rules{{Module: "probemod", Resources: []string{"boxes"}, Verbs: []string{"get", "list"}}}
)

const sc65Anon = "system_class:anonymous"

func sc65PublicReader() domain.MembershipTuple {
	return domain.MembershipTuple{User: sc65Anon, Relation: "public_reader", Object: "probemod_box:" + sc65Box}
}

// sc65Control — фикстура: probemod без ключа, выдача человеку на контейнер даёт
// `v_get` на нём (разворачивание живо и видит объект).
func sc65Control(t *testing.T) (keyed []byte, keyless *catalog.Facts) {
	t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	twin, err := publicreadfixture.WithoutKey(doc)
	if err != nil {
		t.Fatalf("фикстура: близнец без ключа: %v", err)
	}
	cat := sc65Facts(t, twin)
	want := domain.MembershipTuple{User: "user:usr0000000000000sc65", Relation: "v_get", Object: "probemod_box:" + sc65Box}
	if got := sc65Tuples(cat, sc65Scope("user", "usr0000000000000sc65", sc65ReadBoth)); !got[want] {
		t.Fatalf("фикстура: выдача человеку не развернулась в %v; получено %v — разворачивание не видит объект", want, got)
	}
	return doc, cat
}

// TestRuleObjectTuples_SC65_DeclaredContainerGetsPublicReader — объявленный тип
// получает `public_reader` при выдаче классу ролью с вложенным правилом над ребёнком.
// Близнец — тот же манифест без ключа: `public_reader` нет. Один факт — ключ.
func TestRuleObjectTuples_SC65_DeclaredContainerGetsPublicReader(t *testing.T) {
	doc, keyless := sc65Control(t)
	if got := sc65Tuples(keyless, sc65Scope("system_class", "anonymous", sc65ReadBoth)); got[sc65PublicReader()] {
		t.Fatalf("SC-65 близнец: без ключа `public_reader` писаться не вправе, получено %v", got)
	}

	keyed := sc65Facts(t, doc)
	got := sc65Tuples(keyed, sc65Scope("system_class", "anonymous", sc65ReadBoth))
	if !got[sc65PublicReader()] {
		t.Fatalf("SC-65: выдача классу на объявленный контейнер ролью с вложенным правилом над ребёнком обязана писать %v; получено %v",
			sc65PublicReader(), got)
	}
}

// TestRuleObjectTuples_SC65_RoleWithoutAChildRuleWritesNoPublicReader — та же
// роль без вложенного правила над типом-ребёнком `public_reader` не пишет (Р9 «Сужение по
// цели», решение по N1). Близнец — предыдущая проба. Один факт — вложенное
// правило роли над ребёнком.
func TestRuleObjectTuples_SC65_RoleWithoutAChildRuleWritesNoPublicReader(t *testing.T) {
	doc, _ := sc65Control(t)
	keyed := sc65Facts(t, doc)

	if got := sc65Tuples(keyed, sc65Scope("system_class", "anonymous", sc65ReadBoth)); !got[sc65PublicReader()] {
		t.Fatalf("SC-65 близнец: роль с вложенным правилом над ребёнком обязана писать %v; получено %v", sc65PublicReader(), got)
	}
	if got := sc65Tuples(keyed, sc65Scope("system_class", "anonymous", sc65ReadBox)); got[sc65PublicReader()] {
		t.Fatalf("SC-65: роль без вложенного правила над ребёнком `public_reader` писать не вправе; получено %v", got)
	}
}

// TestRuleObjectTuples_SC65_HumanGrantWritesNoPublicReader — `public_reader`
// принимает лишь `system_class`: выдача человеку его не пишет (Р9 «Сужение по
// цели»). Близнец — та же выдача классу. Один факт — вид субъекта.
func TestRuleObjectTuples_SC65_HumanGrantWritesNoPublicReader(t *testing.T) {
	doc, _ := sc65Control(t)
	keyed := sc65Facts(t, doc)

	if got := sc65Tuples(keyed, sc65Scope("system_class", "anonymous", sc65ReadBoth)); !got[sc65PublicReader()] {
		t.Fatalf("SC-65 близнец: выдача классу обязана писать %v; получено %v", sc65PublicReader(), got)
	}
	for tu := range sc65Tuples(keyed, sc65Scope("user", "usr0000000000000sc65", sc65ReadBoth)) {
		if tu.Relation == "public_reader" {
			t.Fatalf("SC-65: выдача человеку пишет %v — `public_reader` принимает лишь system_class", tu)
		}
	}
}
