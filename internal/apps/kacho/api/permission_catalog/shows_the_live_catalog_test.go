// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// shows_the_live_catalog_test.go — витрина разрешений отвечает СТРОКАМИ каталога,
// а не перечнем, порождённым сборкой (#1976, #1816).
//
// # Предмет
//
// Витрина строила ответ из `authzmap.Catalog()` — таблицы, ПОРОЖДЁННОЙ СБОРКОЙ, —
// и базы не спрашивала. Строки каталога расходятся с этой таблицей В ОБЕ стороны,
// и обе половины наблюдаемы арендатору:
//
//	СНЯТИЕ    строка снята (#1861), перечень сборки её по-прежнему называет →
//	          витрина предлагает тип, на который выдача отвергается ключом
//	          (`role_rule_ref_res_fk` / `role_verb_type_fk`);
//	ЗАВЕДЕНИЕ тип заведён применением манифеста в РАБОТАЮЩЕМ процессе, сборка о
//	          нём не знает → витрина о нём молчит, и арендатор не находит в ней
//	          того, что сам же и объявил.
//
// Вторая половина тише первой и потому опаснее: отказа нет ни одного, есть
// отсутствие строки в перечне, которое читается как «такого ресурса у платформы
// нет».
//
// # Почему обе стороны, а не одна
//
// Проба, утверждающая только снятие, зеленела бы на витрине, которая просто
// пересекает перечень сборки с живыми строками; проба, утверждающая только
// заведение, — на витрине, которая их объединяет. Расхождение ловит ровно ПАРА:
// перечень витрины обязан РАВНЯТЬСЯ живым строкам, а не быть с ними в каком-либо
// отношении включения.
package permission_catalog

import (
	"sort"
	"testing"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
)

// liveRows — каталог из ДВУХ строк, ни одна из которых не совпадает с деревом:
// пара `billing.invoice` сборке неизвестна вовсе (заведена применением), пара
// `vpc.network` сборке известна и здесь СОХРАНЕНА — она положительный контроль,
// без которого «витрина отдала только billing» было бы неотличимо от «витрина
// сломалась и отдаёт одну строку».
//
// Набор ГЛАГОЛОВ у обеих строк тоже свой, и выбран он так, чтобы РАЗЛИЧАТЬ
// источники: `update` несут ОБЕ живые строки, а в пересечении перечня сборки его
// нет. Ответ, совпадающий с обоими источниками, на такой фикстуре невозможен —
// без этого условия утверждение об общем наборе зеленело бы по совпадению.
func liveRows() catalog.Rows {
	return catalog.Rows{
		Modules: []string{"billing", "vpc"},
		Resources: []catalog.ResourceRow{
			{Module: "billing", Resource: "invoice", ObjectType: "billing_invoice"},
			{Module: "vpc", Resource: "network", ObjectType: "vpc_network"},
		},
		Verbs: []catalog.VerbRow{
			{Module: "billing", Resource: "invoice", Verb: "get", PerObject: true},
			{Module: "billing", Resource: "invoice", Verb: "list", PerObject: true},
			{Module: "billing", Resource: "invoice", Verb: "update", PerObject: true},
			{Module: "vpc", Resource: "network", Verb: "get", PerObject: true},
			{Module: "vpc", Resource: "network", Verb: "list", PerObject: true},
			{Module: "vpc", Resource: "network", Verb: "update", PerObject: true},
			{Module: "vpc", Resource: "network", Verb: "delete", PerObject: true},
		},
	}
}

// catalogOverRows — витрина, провязанная НАЗВАННЫМ каталожным фактом.
func catalogOverRows(t *testing.T, rows catalog.Rows) *iamv1.ListPermissionCatalogResponse {
	t.Helper()
	f, err := catalog.NewFacts(rows)
	if err != nil {
		t.Fatalf("фикстура каталога не собралась: %v", err)
	}
	h := NewHandler(NewListPermissionCatalogUseCase(catalog.Fixed{F: f}))
	resp, err := h.ListPermissionCatalog(authedCtx(), &iamv1.ListPermissionCatalogRequest{})
	if err != nil {
		t.Fatalf("ListPermissionCatalog вернул ошибку: %v", err)
	}
	return resp
}

// TestCatalogOffersExactlyTheLiveRows — перечень витрины РАВЕН живым строкам.
func TestCatalogOffersExactlyTheLiveRows(t *testing.T) {
	resp := catalogOverRows(t, liveRows())

	got := make([]string, 0, 2)
	for _, m := range resp.GetModules() {
		for _, r := range m.GetResources() {
			got = append(got, m.GetModule()+"."+r.GetResource())
		}
	}
	sort.Strings(got)

	want := []string{"billing.invoice", "vpc.network"}
	if len(got) != len(want) {
		t.Fatalf("витрина назвала %d пар, живых строк %d: %v\n"+
			"перечень витрины обязан РАВНЯТЬСЯ живым строкам каталога (#1976)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("витрина назвала %v, живые строки называют %v (#1976)", got, want)
		}
	}
}

// TestCatalogVerbsComeFromTheLiveRow — набор глаголов принадлежит ЖИВОЙ строке.
//
// Утверждает ОБЕ строки: у заведённой применением набор короче, у знакомой сборке
// — свой. Утверждение об одной строке зеленело бы на витрине, которая знакомой
// паре отвечает сборкой, а незнакомой — строками.
func TestCatalogVerbsComeFromTheLiveRow(t *testing.T) {
	resp := catalogOverRows(t, liveRows())
	pairs := responsePairs(resp)

	for _, tc := range []struct {
		dotted string
		want   []string
	}{
		{"billing.invoice", []string{"get", "list", "update"}},
		{"vpc.network", []string{"delete", "get", "list", "update"}},
	} {
		r, ok := pairs[tc.dotted]
		if !ok {
			t.Fatalf("витрина не назвала пару %q, объявленную живой строкой (#1976)", tc.dotted)
		}
		got := append([]string(nil), r.GetVerbs()...)
		sort.Strings(got)
		if len(got) != len(tc.want) {
			t.Fatalf("%s: витрина назвала глаголы %v, живая строка объявляет %v (#1976)", tc.dotted, got, tc.want)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Fatalf("%s: витрина назвала глаголы %v, живая строка объявляет %v (#1976)", tc.dotted, got, tc.want)
			}
		}
		if !r.GetHasVerbRelations() {
			t.Fatalf("%s: живая строка объявляет глаголы, витрина говорит, что отношений действия нет (#1976)", tc.dotted)
		}
	}
}

// TestCatalogCommonVerbsAreTheIntersectionOfLiveRows — общий набор считается по
// ЖИВЫМ строкам.
//
// Положительный контроль внутри самого утверждения: пересечение здесь заведомо
// УЖЕ объединения (`update` есть у сети и нет у счёта), поэтому проба различает
// пересечение и объединение и не зеленеет на «отдали всё подряд».
func TestCatalogCommonVerbsAreTheIntersectionOfLiveRows(t *testing.T) {
	resp := catalogOverRows(t, liveRows())
	got := append([]string(nil), resp.GetClosedVerbs()...)
	sort.Strings(got)
	// `update` есть у ОБЕИХ живых строк и в пересечении ПЕРЕЧНЯ СБОРКИ его нет —
	// поэтому ответ витрины различает два источника, а не совпадает с обоими.
	want := []string{"get", "list", "update"}
	if len(got) != len(want) {
		t.Fatalf("общий набор витрины %v, пересечение живых строк %v (#1976)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("общий набор витрины %v, пересечение живых строк %v (#1976)", got, want)
		}
	}
}
