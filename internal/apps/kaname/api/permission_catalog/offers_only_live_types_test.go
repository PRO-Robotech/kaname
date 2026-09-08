// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// offers_only_live_types_test.go — витрина не предлагает того, на что ключ
// выдачу не примет (#1976).
//
// # Предмет
//
// Витрина строила ответ из ПЕРЕЧНЯ СБОРКИ (`authzmap.Catalog()`) и базы не
// спрашивала. Строки каталога с #1861 вправе быть УЖЕ этого перечня: снятая
// строка живой не считается, а перечень сборки её по-прежнему называл. Тогда
// арендатор видел в витрине тип, на который выдача отвергается ключом
// (`role_rule_ref_res_fk` / `role_verb_type_fk` → `catalog_resource(..., live)`).
//
// # Что изменилось и почему проба ОСТАЁТСЯ
//
// Исход выбран первый из трёх названных задачей: витрина спрашивает ЖИВЫЕ строки
// (`shows_the_live_catalog_test.go`), и снятый тип она не называет уже BY
// CONSTRUCTION. Проба от этого не стала вакуумной, а сменила сторону: она держит
// свойство ОТ ВОЗВРАТА. Читатель, вернувший сюда перечень сборки, получит
// пересечение с ведомостью снятого — то есть красное с именем типа, — и получит
// его в тот же день, а не тогда, когда арендатор упрётся в отказ ключа.
//
// Перепись печатает ДВА числа рядом — сколько пар называет витрина и сколько
// перечень сборки. Пока они равны, расхождения нет; в день, когда разойдутся,
// число само скажет, на сколько.
package permission_catalog

import (
	"sort"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// offeredButRetired — пары, которые витрина называет, а решение о снятии уже
// вынесено. Вынесено отдельной функцией, чтобы предикат можно было предъявить
// синтетическому входу: на живом дереве пересечение пусто, и без такого
// предъявления «ноль находок» было бы неотличимо от «предикат ничего не ищет».
func offeredButRetired(offered []string, retired map[string]bool) []string {
	var out []string
	for _, dotted := range offered {
		if retired[dotted] {
			out = append(out, dotted)
		}
	}
	sort.Strings(out)
	return out
}

// offeredPairs — точечные пары, которые витрина отдаёт арендатору.
func offeredPairs(t *testing.T) []string {
	t.Helper()
	resp := callCatalog(t)
	var out []string
	for _, m := range resp.GetModules() {
		for _, r := range m.GetResources() {
			out = append(out, m.GetModule()+"."+r.GetResource())
		}
	}
	sort.Strings(out)
	return out
}

// TestCatalogOffersNoRetiredType — витрина не называет типа, чья строка снята.
func TestCatalogOffersNoRetiredType(t *testing.T) {
	offered := offeredPairs(t)
	retiredList := domain.RetiredTypes()

	retired := make(map[string]bool, len(retiredList))
	for _, ty := range retiredList {
		retired[ty] = true
	}

	// Два положительных контроля. Без ПЕРВОГО отрицание зеленело бы на витрине,
	// не назвавшей ничего; без ВТОРОГО — на пустом перечне снятого, то есть
	// тогда, когда сверять не с чем. Оба состояния снаружи выглядят как «чисто».
	if len(offered) == 0 {
		t.Fatal("витрина не назвала ни одной пары: обход пуст, и всякое отрицание ниже " +
			"зеленеет, ничего не проверив")
	}
	if len(retired) == 0 {
		t.Fatal("перечень снятых типов пуст: сверять не с чем, и «пересечение пусто» " +
			"означало бы «не искали», а не «чисто»")
	}

	got := offeredButRetired(offered, retired)

	t.Logf("осмотрено: витрина называет пар %d, перечень сборки %d, снятых типов %d; "+
		"предложено снятого %d", len(offered), len(authzmap.Catalog()), len(retired), len(got))

	if len(got) > 0 {
		t.Errorf("витрина предлагает %d снятых типов %v: выдача на них отвергается ключом "+
			"каталога, то есть возможность объявлена и неисполнима. Витрина обязана "+
			"спрашивать ЖИВЫЕ строки (#1976) — вернулось чтение перечня сборки?", len(got), got)
	}
}

// TestCatalogOffersNoRetiredTypeDetectsAnOverlap — предъявление предиката
// синтетическому входу: на живом дереве пересечение пусто, и без этой пробы
// «ноль находок» было бы неотличимо от предиката, который не ищет ничего.
//
// Меняется РОВНО ОДИН факт против положительного близнеца выше: тот же перечень
// витрины, но снятым объявлен тип, который витрина называет.
func TestCatalogOffersNoRetiredTypeDetectsAnOverlap(t *testing.T) {
	offered := offeredPairs(t)
	if len(offered) == 0 {
		t.Fatal("витрина не назвала ни одной пары — предъявлять предикат не на чем")
	}

	// Законный близнец: снятым объявлен тип, которого витрина НЕ называет.
	if got := offeredButRetired(offered, map[string]bool{"compute.disk": true}); len(got) != 0 {
		t.Fatalf("законный близнец обязан молчать: тип снят, но витриной не предлагается, "+
			"получено %v", got)
	}

	// Инъекция: снятым объявлен ПЕРВЫЙ из тех, что витрина называет.
	victim := offered[0]
	got := offeredButRetired(offered, map[string]bool{victim: true})
	if len(got) != 1 || got[0] != victim {
		t.Fatalf("предикат обязан назвать пересечение по имени, ждали [%s], получено %v",
			victim, got)
	}
}
