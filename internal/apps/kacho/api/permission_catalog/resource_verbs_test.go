// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package permission_catalog

// resource_verbs_test.go — СЛОВАРЬ ГЛАГОЛОВ ПО РЕСУРСУ (#1128).
//
// # Предмет
//
// Публичное поле `closed_verbs` — ПЕРЕСЕЧЕНИЕ наборов всех типов, и редактор
// ролей строил из него выпадающий список. Пока набор глаголов был платформенной
// константой, пересечение равнялось ему и различие не наблюдалось. С набором,
// ставшим атрибутом ТИПА, оно наблюдается в обе стороны:
//
//   - сузив набор у ОДНОГО типа, мы вынимали глагол из словаря у ВСЕХ остальных
//     (замер: 27 глагольных типов каталога, все 27 объявляют `update`);
//   - расширив набор у одного типа, мы не давали его даже ему самому — глагол
//     энфорсился, но не предлагался (`addTargets`/`removeTargets` у
//     `loadbalancer.targetGroups`, `create` у `registry.registries`).
//
// Отсюда `CatalogResource.verbs`: редактор спрашивает глаголы У РЕСУРСА.
//
// # Что здесь утверждается — три оси
//
//  1. СОСТАВ поля равен набору ЭТОГО типа, в каноническом порядке показа;
//     неглагольный тип не предлагает ничего.
//  2. НИКТО НЕ ПОТЕРЯЛ. Прежде редактор предлагал каждому ресурсу ровно
//     `[get,list,update,delete]`. После правки каждый ресурс обязан предлагать
//     НЕ МЕНЬШЕ — кроме поимённо названных суженных, у которых снятие глагола и
//     есть предмет изменения. Перечень самоистекает: запись, чей тип снова
//     предлагает всё, — находка.
//  3. КТО ПРИОБРЁЛ. Типы с набором шире прежнего общего предлагают теперь свои
//     глаголы — то есть класс «энфорсится, но не предлагается» закрыт, а не
//     переписан.
//
// Ожидаемое в оси 2 записано ЛИТЕРАЛОМ намеренно: сверка поля с его собственным
// источником зеленела бы при любом сужении — форма проверки без содержания.

import (
	"sort"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// previouslyOfferedToEveryResource — что выпадающий список предлагал КАЖДОМУ
// ресурсу до появления словаря по ресурсу. Литерал, а не выражение: он и есть
// база сравнения «никто не потерял».
var previouslyOfferedToEveryResource = []string{"get", "list", "update", "delete"}

// narrowedBelowThePreviousOffering — ресурсы, у которых набор СУЖЕН осознанно, с
// причиной. Перечень самоистекает в обе стороны: тип, снова предлагающий всё, —
// находка; тип, суженный без записи, — тоже.
var narrowedBelowThePreviousOffering = map[string]string{
	"iam.user": "у `iam_user` снят `v_update`: правку записи спрашивает record_writer, " +
		"запрет — identity_suspender (#1102), снятие строки — identity_remover (#1131); " +
		"читателя у глагола нет ни одного (#1128)",
}

// TestCatalogResourceVerbs_AreTheTypesOwnSet — ось 1.
func TestCatalogResourceVerbs_AreTheTypesOwnSet(t *testing.T) {
	resp := callCatalog(t)

	checked, verbBearing := 0, 0
	for _, m := range resp.GetModules() {
		for _, r := range m.GetResources() {
			dotted := m.GetModule() + "." + r.GetResource()
			fgaType, ok := authzmap.ObjectType(m.GetModule(), r.GetResource())
			if !ok {
				t.Errorf("%s: каталог отдал ресурс, которого нет в таблице типов", dotted)
				continue
			}
			checked++
			want := domain.OrderVerbsForDisplay(authzmap.VerbsOfType(fgaType))
			got := r.GetVerbs()
			if len(want) > 0 {
				verbBearing++
			}
			if !equalStrings(got, want) {
				t.Errorf("%s: verbs=%v, want %v (набор ЭТОГО типа в каноническом порядке)",
					dotted, got, want)
			}
			if r.GetHasVerbRelations() != (len(want) > 0) {
				t.Errorf("%s: hasVerbRelations=%t при наборе %v — два поля об одном предмете разошлись",
					dotted, r.GetHasVerbRelations(), want)
			}
		}
	}

	if checked == 0 {
		t.Fatal("каталог не отдал ни одного ресурса — предпосылка пробы сломана")
	}
	if verbBearing == 0 {
		t.Fatal("ни один ресурс каталога не глагольный — утверждение о наборах вакуумно")
	}
	t.Logf("перепись: ресурсов каталога %d, из них глагольных %d", checked, verbBearing)
}

// TestCatalogResourceVerbs_NobodyLostWhatTheEditorUsedToOffer — ось 2.
func TestCatalogResourceVerbs_NobodyLostWhatTheEditorUsedToOffer(t *testing.T) {
	resp := callCatalog(t)

	lost := map[string][]string{}
	checked := 0
	for _, m := range resp.GetModules() {
		for _, r := range m.GetResources() {
			if !r.GetHasVerbRelations() {
				continue // неглагольному ресурсу словарь не предлагали и раньше
			}
			checked++
			dotted := m.GetModule() + "." + r.GetResource()
			have := map[string]bool{}
			for _, v := range r.GetVerbs() {
				have[v] = true
			}
			for _, v := range previouslyOfferedToEveryResource {
				if !have[v] {
					lost[dotted] = append(lost[dotted], v)
				}
			}
		}
	}

	if checked == 0 {
		t.Fatal("глагольных ресурсов ноль — утверждение «никто не потерял» вакуумно")
	}

	for dotted, verbs := range lost {
		sort.Strings(verbs)
		if _, known := narrowedBelowThePreviousOffering[dotted]; !known {
			t.Errorf("%s больше не предлагает %v, и это НЕ записано. Прежде выпадающий список "+
				"давал каждому ресурсу %v; сужение обязано быть решением с причиной, а не "+
				"побочным эффектом чужой правки", dotted, verbs, previouslyOfferedToEveryResource)
		}
	}
	for dotted, reason := range narrowedBelowThePreviousOffering {
		if reason == "" {
			t.Errorf("narrowedBelowThePreviousOffering[%s] обязана нести причину", dotted)
		}
		if len(lost[dotted]) == 0 {
			t.Errorf("перечень суженных пережил свой предмет: %s снова предлагает всё, что "+
				"предлагалось раньше — запись пора снять", dotted)
		}
	}
	t.Logf("перепись: глагольных ресурсов %d; суженных %d (%v)", checked, len(lost), lost)
}

// TestCatalogResourceVerbs_WiderTypesNowOfferTheirOwn — ось 3.
//
// Класс «глагол энфорсится, но не предлагается» существовал ровно потому, что
// словарь был один на всех. Здесь утверждается, что он закрыт наблюдаемо, а не
// переписан прозой.
func TestCatalogResourceVerbs_WiderTypesNowOfferTheirOwn(t *testing.T) {
	resp := callCatalog(t)

	common := map[string]bool{}
	for _, v := range authzmap.CommonVerbVocabulary() {
		common[v] = true
	}

	byDotted := map[string][]string{}
	for _, m := range resp.GetModules() {
		for _, r := range m.GetResources() {
			byDotted[m.GetModule()+"."+r.GetResource()] = r.GetVerbs()
		}
	}

	outside := 0
	for _, e := range authzmap.Catalog() {
		fgaType, ok := authzmap.ObjectType(e.Module, e.Resource)
		if !ok {
			continue
		}
		dotted := e.Module + "." + e.Resource
		offered := map[string]bool{}
		for _, v := range byDotted[dotted] {
			offered[v] = true
		}
		for _, v := range authzmap.VerbsOfType(fgaType) {
			if common[v] {
				continue
			}
			outside++
			if !offered[v] {
				t.Errorf("%s энфорсит %q, а редактор его не предлагает — класс «энфорсится, но "+
					"не предлагается» не закрыт", dotted, v)
			}
		}
	}

	if outside == 0 {
		t.Fatal("ни один тип не объявляет глагола вне общего словаря — утверждение вакуумно; " +
			"проба обязана иметь предмет, иначе она зеленеет на любом каталоге")
	}
	t.Logf("перепись: пар (тип, глагол вне общего словаря): %d", outside)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
