// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package toproto

// role_preview_reads_the_live_catalog_test.go — превью роли называет набор ТИПА
// по ЖИВЫМ строкам каталога (#1994, #1816).
//
// # Предмет
//
// `roleTypeVerbLookup` резолвил пару `(модуль, ресурс)` закрытой таблицей
// `authzmap.ObjectType` — словарём, ПОРОЖДЁННЫМ СБОРКОЙ. На типе, заведённом
// применением манифеста в РАБОТАЮЩЕМ процессе, она отвечала `ok=false`, и
// вызывающий брал запасной набор — глаголы ВСЕЙ платформы.
//
// Запасной набор заведён осознанно и для ДРУГОГО входа: правило, не резолвящееся
// ни в один тип (форма `*.*`), обязано показывать всё, иначе роль-суперпользователь
// выглядела бы ничего не дающей. Довод верен — и он молча накрыл второй вход,
// которого при его заведении не существовало.
//
// Следствие арендатору: превью его роли обещает глаголы, которых его тип не
// объявлял. Доступа это не расширяет (материализация идёт по набору ЖИВОГО типа),
// но превью объявлено ЧЕСТНЫМ показом, и здесь оно им быть перестаёт.
//
// # Почему обе стороны в одной пробе
//
// Утверждение «тип применения показывает свой набор» зеленело бы на реализации,
// отнявшей запасной набор у `*.*`, — а это уже наблюдавшийся дефект (#1189).
// Поэтому положительный контроль стоит здесь же: `*.*` обязана по-прежнему
// называть ВЕСЬ словарь живого каталога.

import (
	"sort"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// appliedTypeFacts — каталожный факт, в котором есть тип, СБОРКЕ НЕИЗВЕСТНЫЙ.
//
// `billing.invoice` заведён «применением»: в таблице, порождённой сборкой, его
// нет, а живая строка есть. Рядом `vpc.network` — тип, который знают ОБА
// источника: без него «показали набор billing» было бы неотличимо от «показали
// набор чего попало».
func appliedTypeFacts(t *testing.T) *catalog.Facts {
	t.Helper()
	f, err := catalog.NewFacts(catalog.Rows{
		Modules: []string{"billing", "vpc"},
		Resources: []catalog.ResourceRow{
			{Module: "billing", Resource: "invoice", ObjectType: "billing_invoice"},
			{Module: "vpc", Resource: "network", ObjectType: "vpc_network"},
		},
		Verbs: []catalog.VerbRow{
			{Module: "billing", Resource: "invoice", Verb: "get", PerObject: true},
			{Module: "billing", Resource: "invoice", Verb: "list", PerObject: true},
			{Module: "vpc", Resource: "network", Verb: "get", PerObject: true},
			{Module: "vpc", Resource: "network", Verb: "list", PerObject: true},
			{Module: "vpc", Resource: "network", Verb: "update", PerObject: true},
			{Module: "vpc", Resource: "network", Verb: "delete", PerObject: true},
		},
	})
	if err != nil {
		t.Fatalf("фикстура каталога не собралась: %v", err)
	}
	return f
}

// TestRolePreviewNamesTheVerbsOfTheAppliedType — превью роли над типом, которого
// сборка не знает, называет набор ЭТОГО типа.
func TestRolePreviewNamesTheVerbsOfTheAppliedType(t *testing.T) {
	facts := appliedTypeFacts(t)

	// Предпосылка пробы: тип обязан быть НЕИЗВЕСТЕН сборке — иначе запасной путь
	// не исполняется и проба утверждает о ветке, которой не достигает.
	if _, known := facts.FGAObjectType("billing.invoice"); !known {
		t.Fatal("живой каталог не знает billing.invoice — фикстура собрана неверно")
	}

	r := domain.Role{
		ID:        "rol_applied_preview",
		Name:      "applied-preview",
		ClusterID: "cluster",
		Rules: domain.Rules{
			{Module: "billing", Resources: []string{"invoice"}, Verbs: []string{"*"}},
		},
		TypeVerbs: facts.RolePreviewLookup(),
	}

	pb, err := roleObj{}.toPb(r)
	if err != nil {
		t.Fatalf("проекция роли отказала: %v", err)
	}

	got := append([]string(nil), pb.GetEffectiveVerbs()...)
	sort.Strings(got)
	want := []string{"get", "list"}
	if len(got) != len(want) {
		t.Fatalf("превью назвало %v, живая строка billing.invoice объявляет %v — "+
			"превью взяло запасной набор вместо набора типа (#1994)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("превью назвало %v, живая строка billing.invoice объявляет %v (#1994)", got, want)
		}
	}
}

// TestRolePreviewStillShowsEveryVerbForTheWildcardRole — положительный контроль.
//
// Меняется РОВНО ОДИН факт против пробы выше: правило адресует `*.*` вместо
// названной пары. Без этого контроля правка отняла бы у роли-суперпользователя
// её же показ — наблюдалось при #1189.
func TestRolePreviewStillShowsEveryVerbForTheWildcardRole(t *testing.T) {
	facts := appliedTypeFacts(t)

	r := domain.Role{
		ID:        "rol_wildcard_preview",
		Name:      "wildcard-preview",
		ClusterID: "cluster",
		Rules: domain.Rules{
			{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}},
		},
		TypeVerbs: facts.RolePreviewLookup(),
	}

	pb, err := roleObj{}.toPb(r)
	if err != nil {
		t.Fatalf("проекция роли отказала: %v", err)
	}

	got := append([]string(nil), pb.GetEffectiveVerbs()...)
	sort.Strings(got)
	all := append([]string(nil), facts.AllVerbVocabulary()...)
	sort.Strings(all)
	if len(got) != len(all) {
		t.Fatalf("превью роли `*.*` назвало %v, живой каталог объявляет %v — "+
			"роль-суперпользователь обещает не то, что даёт (#1189)", got, all)
	}
	for i := range all {
		if got[i] != all[i] {
			t.Fatalf("превью роли `*.*` назвало %v, живой каталог объявляет %v (#1189)", got, all)
		}
	}

	// Контроль внутри контроля: объединение обязано быть ШИРЕ пересечения, иначе
	// две величины совпадают и проба не различает «весь словарь» от «общий набор».
	if len(facts.AllVerbVocabulary()) <= len(facts.CommonVerbVocabulary()) {
		t.Fatalf("фикстура выродилась: объединение %v не шире пересечения %v — "+
			"утверждение выше не различает два источника",
			facts.AllVerbVocabulary(), facts.CommonVerbVocabulary())
	}
}

// TestRoleProjectionRefusesWithoutTheCatalog — отсутствие каталожного факта есть
// ОТКАЗ, а не показ по словарю сборки.
//
// Тихий запасной путь здесь и был бы снятым дефектом: превью, собранное не тем
// источником, выглядит как исправное превью. Отказ виден сразу и называет предмет.
func TestRoleProjectionRefusesWithoutTheCatalog(t *testing.T) {
	r := domain.Role{
		ID:        "rol_no_catalog",
		Name:      "no-catalog",
		ClusterID: "cluster",
		Rules: domain.Rules{
			{Module: "billing", Resources: []string{"invoice"}, Verbs: []string{"*"}},
		},
	}
	if _, err := (roleObj{}).toPb(r); err == nil {
		t.Fatal("проекция роли без каталожного факта обязана ОТКАЗАТЬ: показ по " +
			"словарю сборки неотличим от честного превью (#1994)")
	}
}
