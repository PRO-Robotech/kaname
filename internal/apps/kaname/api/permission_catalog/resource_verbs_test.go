// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
//   - сужение набора у ОДНОГО типа вынимало глагол из словаря у ВСЕХ остальных
//     (замер: глагольных типов каталога 27, `update` объявляли все 27);
//   - расширение набора у одного типа не доходило даже до него самого — глагол
//     энфорсился, но не предлагался (`addtargets`/`removetargets` у
//     `loadbalancer.targetGroups`, `create` у `registry.registries`).
//
// Отсюда `CatalogResource.verbs`: редактор спрашивает глаголы У РЕСУРСА.
//
// # Три оси, каждая падает сама
//
//  1. СОСТАВ — поле равно набору ЭТОГО типа в каноническом порядке показа;
//     неглагольный ресурс не предлагает ничего, и два поля об одном предмете
//     (`verbs` и `has_verb_relations`) не расходятся.
//  2. НИКТО НЕ ПОТЕРЯЛ — прежде редактор предлагал каждому ресурсу ровно
//     `[get,list,update,delete]`; после правки каждый обязан предлагать НЕ
//     МЕНЬШЕ, кроме поимённо названных суженных. Перечень самоистекает в обе
//     стороны.
//  3. КТО ПРИОБРЁЛ — глагол вне общего словаря предлагается своим ресурсом, то
//     есть класс «энфорсится, но не предлагается» закрыт, а не переписан.
//
// Ожидаемое в оси 2 записано ЛИТЕРАЛОМ намеренно: сверка поля с его собственным
// источником зеленела бы при любом сужении — форма проверки без содержания.
//
// Способность предиката упасть и смолчать доказана рядом
// (resource_verbs_injection_test.go): порча вносится ПО КЛЮЧУ ТИПА, а не заменой
// подстроки, поэтому опыт заведомо ставится над тем типом, который назван.

import (
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// previouslyOfferedToEveryResource — что выпадающий список предлагал КАЖДОМУ
// ресурсу до появления словаря по ресурсу. Литерал, а не выражение: он и есть
// база сравнения «никто не потерял».
var previouslyOfferedToEveryResource = []string{"get", "list", "update", "delete"}

// narrowedBelowThePreviousOffering — ресурсы, чей набор СУЖЕН осознанно, с
// причиной. Перечень самоистекает в обе стороны: ресурс, снова предлагающий всё,
// — находка; суженный без записи — тоже.
var narrowedBelowThePreviousOffering = map[string]string{
	"iam.user": "у `iam_user` сняты ОБА распоряжающихся глагола — `v_update` (#1128) и " +
		"`v_delete` (#1189). Распоряжение строкой личности выражено именованными отношениями: " +
		"правку записи спрашивает record_writer, запрет и его снятие — identity_suspender " +
		"(#1102), снятие самой строки — identity_remover (#1131); читателя не осталось ни у " +
		"одного из двух глаголов. Аккаунту остаётся чтение (`get`/`list`) и распоряжение " +
		"УЧАСТИЕМ человека — account.member_remover (#1127), а не глобальной строкой личности",
}

// resourceOffering — что каталог отдал про один ресурс и что о том же ресурсе
// говорит таблица типов. Обе стороны в одной записи: предикат сверяет их между
// собой, а не делает одну источником истины для другой.
type resourceOffering struct {
	// Dotted — `module.resource`, как его называет каталог.
	Dotted string
	// HasVerbRelations — флаг, который отдал каталог.
	HasVerbRelations bool
	// Offered — глаголы, которые каталог ПРЕДЛАГАЕТ редактору.
	Offered []string
	// Declared — глаголы, которые тип ОБЪЯВЛЯЕТ в модели (через таблицу типов),
	// в том же каноническом порядке.
	Declared []string
}

// auditResourceVerbs — предикат всех трёх осей. Возвращает находки; пусто = норма.
//
// `common` — общий словарь (пересечение наборов всех типов); ось 3 спрашивает
// именно его, потому что предмет класса — глагол, В НЕГО НЕ ВХОДЯЩИЙ.
func auditResourceVerbs(offerings []resourceOffering, common []string, narrowed map[string]string) []string {
	inCommon := make(map[string]bool, len(common))
	for _, v := range common {
		inCommon[v] = true
	}

	var found []string
	lost := map[string][]string{}

	for _, o := range offerings {
		// ── ось 1 ────────────────────────────────────────────────────────────
		if !equalStrings(o.Offered, o.Declared) {
			found = append(found, o.Dotted+": предлагается "+fmtVerbs(o.Offered)+
				", а тип объявляет "+fmtVerbs(o.Declared)+
				" — редактор обещает не то, что даст материализация")
		}
		if o.HasVerbRelations != (len(o.Declared) > 0) {
			found = append(found, o.Dotted+": has_verb_relations="+fmtBool(o.HasVerbRelations)+
				" при наборе "+fmtVerbs(o.Declared)+" — два поля об одном предмете разошлись")
		}
		if !o.HasVerbRelations {
			continue // неглагольному ресурсу словарь не предлагали и раньше
		}

		// ── ось 2 ────────────────────────────────────────────────────────────
		have := make(map[string]bool, len(o.Offered))
		for _, v := range o.Offered {
			have[v] = true
		}
		for _, v := range previouslyOfferedToEveryResource {
			if !have[v] {
				lost[o.Dotted] = append(lost[o.Dotted], v)
			}
		}

		// ── ось 3 ────────────────────────────────────────────────────────────
		for _, v := range o.Declared {
			if inCommon[v] || have[v] {
				continue
			}
			found = append(found, o.Dotted+" энфорсит "+v+
				", а редактор его не предлагает — класс «энфорсится, но не предлагается» не закрыт")
		}
	}

	for _, dotted := range sortedLostKeys(lost) {
		verbs := lost[dotted]
		sort.Strings(verbs)
		if _, known := narrowed[dotted]; !known {
			found = append(found, dotted+" больше не предлагает "+fmtVerbs(verbs)+
				", и это НЕ записано. Прежде выпадающий список давал каждому ресурсу "+
				fmtVerbs(previouslyOfferedToEveryResource)+
				"; сужение обязано быть решением с причиной, а не побочным эффектом чужой правки")
		}
	}
	for dotted, reason := range narrowed {
		if reason == "" {
			found = append(found, dotted+": запись перечня суженных обязана нести причину")
		}
		if len(lost[dotted]) == 0 {
			found = append(found, "перечень суженных пережил свой предмет: "+dotted+
				" снова предлагает всё, что предлагалось раньше — запись пора снять")
		}
	}
	return found
}

// TestCatalogResourceVerbs_DescribeTheTypesOwnSets — гейт на дереве.
func TestCatalogResourceVerbs_DescribeTheTypesOwnSets(t *testing.T) {
	offerings := treeOfferings(t)
	common := authzmap.CommonVerbVocabulary()

	// ПРЕДПОСЫЛКИ. «Ноль находок» обязано быть отличимо от «ноль прочитанного».
	if len(offerings) == 0 {
		t.Fatal("каталог не отдал ни одного ресурса — предпосылка гейта сломана")
	}
	verbBearing, outsideCommon := 0, 0
	inCommon := map[string]bool{}
	for _, v := range common {
		inCommon[v] = true
	}
	for _, o := range offerings {
		if o.HasVerbRelations {
			verbBearing++
		}
		for _, v := range o.Declared {
			if !inCommon[v] {
				outsideCommon++
			}
		}
	}
	if verbBearing == 0 {
		t.Fatal("ни один ресурс каталога не глагольный — утверждения о наборах вакуумны")
	}
	if len(common) == 0 {
		t.Fatal("общий словарь пуст — ось 3 меряла бы всё подряд")
	}
	if outsideCommon == 0 {
		t.Fatal("ни один тип не объявляет глагола вне общего словаря — ось 3 вакуумна: " +
			"она обязана иметь предмет, иначе зеленеет на любом каталоге")
	}

	if found := auditResourceVerbs(offerings, common, narrowedBelowThePreviousOffering); len(found) > 0 {
		t.Errorf("словарь глаголов каталога расходится с наборами типов:\n  %s",
			strings.Join(found, "\n  "))
	}

	t.Logf("перепись: ресурсов каталога %d, из них глагольных %d; общий словарь %v; "+
		"пар (тип, глагол вне общего словаря) %d; суженных с причиной %d",
		len(offerings), verbBearing, common, outsideCommon, len(narrowedBelowThePreviousOffering))
}

// treeOfferings — то, что каталог отдаёт СЕГОДНЯ, рядом с тем, что объявляет
// таблица типов.
func treeOfferings(t *testing.T) []resourceOffering {
	t.Helper()
	resp := callCatalog(t)
	var out []resourceOffering
	for _, m := range resp.GetModules() {
		for _, r := range m.GetResources() {
			dotted := m.GetModule() + "." + r.GetResource()
			fgaType, ok := authzmap.ObjectType(m.GetModule(), r.GetResource())
			if !ok {
				t.Errorf("%s: каталог отдал ресурс, которого нет в таблице типов", dotted)
				continue
			}
			out = append(out, resourceOffering{
				Dotted:           dotted,
				HasVerbRelations: r.GetHasVerbRelations(),
				Offered:          r.GetVerbs(),
				Declared:         domain.OrderVerbsForDisplay(authzmap.VerbsOfType(fgaType)),
			})
		}
	}
	return out
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

func fmtVerbs(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	return "[" + strings.Join(v, " ") + "]"
}

func fmtBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func sortedLostKeys(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
