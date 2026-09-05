// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package permission_catalog

// resource_verbs_injection_test.go — опыт: способен ли предикат словаря глаголов
// упасть и способен ли он смолчать.
//
// # Предикат ТОТ ЖЕ, а не копия
//
// Опыт зовёт `auditResourceVerbs` — ровно ту функцию, что зовёт гейт. Копия
// доказывала бы, что работает копия: разойдясь с оригиналом, она разошлась бы
// молча и именно там, где расхождение не видно.
//
// # ПОРЧА ВНОСИТСЯ ПО КЛЮЧУ ТИПА, А НЕ ЗАМЕНОЙ ПОДСТРОКИ
//
// Это условие годности опыта, а не стиль. Наборы глаголов у типов совпадают
// дословно (`[get list update delete]` у двадцати шести), поэтому текстовая
// замена попала бы в первый попавшийся, опыт ставился бы над ЧУЖИМ типом, и
// зелёный результат читался бы как доказательство. Здесь порча адресуется
// записью по имени `module.resource`, и каждая ось утверждает, что порча
// ДЕЙСТВИТЕЛЬНО внеслась и что соседняя запись не тронута.
//
// # Вход НАСТОЯЩИЙ
//
// Все оси стартуют от того, что каталог отдаёт сегодня, и портят одну величину.
// Полностью синтетический каталог доказывал бы лишь то, что предикат различает
// два среза.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
)

// injectionTargets — по кому ставится опыт. Имена настоящие и выбраны по роли в
// классе: суженный, обычный сосед, расширенный.
const (
	narrowedResource  = "iam.user"                  // единственный суженный сегодня
	neighbourResource = "vpc.network"               // обычный набор, ничего не терял
	widerResource     = "loadbalancer.targetGroups" // набор шире общего словаря
)

// withOffering — копия среза с заменённой ОДНОЙ записью по имени ресурса.
// Возвращает копию и признак того, что запись нашлась: опыт, не нашедший своей
// записи, обязан упасть на предпосылке, а не «не поймать порчу».
func withOffering(in []resourceOffering, dotted string, mutate func(resourceOffering) resourceOffering) ([]resourceOffering, bool) {
	out := make([]resourceOffering, len(in))
	copy(out, in)
	for i, o := range out {
		if o.Dotted == dotted {
			out[i] = mutate(o)
			return out, true
		}
	}
	return out, false
}

func offeringOf(in []resourceOffering, dotted string) (resourceOffering, bool) {
	for _, o := range in {
		if o.Dotted == dotted {
			return o, true
		}
	}
	return resourceOffering{}, false
}

func without(verbs []string, drop string) []string {
	out := make([]string, 0, len(verbs))
	for _, v := range verbs {
		if v != drop {
			out = append(out, v)
		}
	}
	return out
}

// TestResourceVerbsGate_SilentOnTheTree — положительный контроль.
//
// Без него всякое отрицание ниже зеленело бы и на предикате, который находит
// нарушение всегда.
func TestResourceVerbsGate_SilentOnTheTree(t *testing.T) {
	offerings := treeOfferings(t)
	if found := auditResourceVerbs(offerings, authzmap.CommonVerbVocabulary(),
		narrowedBelowThePreviousOffering); len(found) > 0 {
		t.Fatalf("предикат находит нарушение на исправном дереве — он ловит форму, а не существо:\n  %s",
			strings.Join(found, "\n  "))
	}

	// Предпосылка ОПЫТА: все три подопытных существуют и играют разные роли.
	// Опыт над отсутствующим ресурсом молчал бы, и это молчание читалось бы как
	// «порча не поймана» либо как «всё в порядке» — оба вывода ложны.
	narrow, ok := offeringOf(offerings, narrowedResource)
	if !ok {
		t.Fatalf("ресурса %s нет в каталоге — опыт над суженным не поставить", narrowedResource)
	}
	var narrowedBy []string
	// Предпосылка спрашивает СВОЙСТВО («набор уже́ прежнего предложения»), а не
	// отсутствие названного глагола: имя одного глагола устаревает при следующем
	// сужении того же типа, и предпосылка начала бы утверждать не то, что меряет.
	for _, v := range previouslyOfferedToEveryResource {
		if !contains(narrow.Declared, v) {
			narrowedBy = append(narrowedBy, v)
		}
	}
	if len(narrowedBy) == 0 {
		t.Fatalf("%s снова объявляет всё, что предлагалось каждому ресурсу (%v) — он перестал "+
			"быть суженным, и оси ниже меряют не то", narrowedResource, narrow.Declared)
	}
	neighbour, ok := offeringOf(offerings, neighbourResource)
	if !ok || !contains(neighbour.Declared, "update") {
		t.Fatalf("сосед %s не объявляет `update` — контраст, ради которого он выбран, исчез",
			neighbourResource)
	}
	wider, ok := offeringOf(offerings, widerResource)
	if !ok || len(wider.Declared) <= len(neighbour.Declared) {
		t.Fatalf("%s больше не шире обычного набора — ось расширения потеряла предмет", widerResource)
	}
	t.Logf("перепись опыта: суженный %s=%v (не хватает %v); сосед %s=%v; расширенный %s=%v",
		narrowedResource, narrow.Declared, narrowedBy, neighbourResource, neighbour.Declared,
		widerResource, wider.Declared)
}

// TestResourceVerbsGate_FallsOnEachAxis — четыре порчи, каждая по одной величине
// и каждая адресована КОНКРЕТНОМУ типу.
func TestResourceVerbsGate_FallsOnEachAxis(t *testing.T) {
	base := treeOfferings(t)
	common := authzmap.CommonVerbVocabulary()

	t.Run("ось 1: предложенное разошлось с набором типа", func(t *testing.T) {
		// Ресурс предлагает глагол, которого его тип не объявляет: редактор
		// обещал бы право, которого материализация не даст.
		got, ok := withOffering(base, neighbourResource, func(o resourceOffering) resourceOffering {
			o.Offered = append(append([]string(nil), o.Offered...), "addtargets")
			return o
		})
		requireInjected(t, ok, neighbourResource)
		requireFindingAbout(t, auditResourceVerbs(got, common, narrowedBelowThePreviousOffering),
			neighbourResource+": предлагается")
	})

	t.Run("ось 2: сужение соседа НЕ записано", func(t *testing.T) {
		// Ровно исходный класс: глагол исчез у типа, которого нет в перечне.
		got, ok := withOffering(base, neighbourResource, func(o resourceOffering) resourceOffering {
			o.Declared = without(o.Declared, "update")
			o.Offered = without(o.Offered, "update")
			return o
		})
		requireInjected(t, ok, neighbourResource)
		findings := auditResourceVerbs(got, common, narrowedBelowThePreviousOffering)
		requireFindingAbout(t, findings, neighbourResource+" больше не предлагает")
		// И порча НЕ задела соседнюю запись: находка ровно одна и она про
		// названный тип. Иначе опыт доказывал бы, что предикат краснеет «где-то».
		for _, f := range findings {
			if strings.Contains(f, widerResource) {
				t.Errorf("порча по ключу %s задела %s: %s", neighbourResource, widerResource, f)
			}
		}
	})

	t.Run("ось 2 обратная: запись перечня пережила свой предмет", func(t *testing.T) {
		// Суженному вернули полный набор — запись перечня стало нечего исключать.
		//
		// Возвращается ИМЕННО ТО, ЧЕГО НЕ ХВАТАЕТ, а не выписанный глагол: здесь
		// стояло дописывание одного `update`, и оно перестало восстанавливать полный
		// набор, как только у того же типа сняли второй глагол (#1189) — порча
		// «вносилась», а предмета не создавала, то есть опыт молча перестал бы
		// доказывать что-либо. Дополнение до `previouslyOfferedToEveryResource`
		// переживёт и следующее сужение.
		got, ok := withOffering(base, narrowedResource, func(o resourceOffering) resourceOffering {
			full := append([]string(nil), o.Declared...)
			for _, v := range previouslyOfferedToEveryResource {
				if !contains(full, v) {
					full = append(full, v)
				}
			}
			o.Declared, o.Offered = full, full
			return o
		})
		requireInjected(t, ok, narrowedResource)
		requireFindingAbout(t, auditResourceVerbs(got, common, narrowedBelowThePreviousOffering),
			"перечень суженных пережил свой предмет: "+narrowedResource)
	})

	t.Run("ось 3: расширенный тип не предлагает своего глагола", func(t *testing.T) {
		// Состояние ДО #1128 для этого типа: глагол объявлен и энфорсится, а
		// редактору не предлагается.
		got, ok := withOffering(base, widerResource, func(o resourceOffering) resourceOffering {
			o.Offered = without(without(o.Offered, "addtargets"), "removetargets")
			return o
		})
		requireInjected(t, ok, widerResource)
		requireFindingAbout(t, auditResourceVerbs(got, common, narrowedBelowThePreviousOffering),
			widerResource+" энфорсит addtargets")
	})

	t.Run("два поля об одном предмете разошлись", func(t *testing.T) {
		got, ok := withOffering(base, neighbourResource, func(o resourceOffering) resourceOffering {
			o.HasVerbRelations = false
			return o
		})
		requireInjected(t, ok, neighbourResource)
		requireFindingAbout(t, auditResourceVerbs(got, common, narrowedBelowThePreviousOffering),
			neighbourResource+": has_verb_relations=false")
	})

	t.Run("запись перечня без причины", func(t *testing.T) {
		requireFindingAbout(t, auditResourceVerbs(base, common,
			map[string]string{narrowedResource: ""}),
			narrowedResource+": запись перечня суженных обязана нести причину")
	})
}

func requireInjected(t *testing.T, ok bool, dotted string) {
	t.Helper()
	if !ok {
		t.Fatalf("порча не внеслась: записи %s в каталоге нет — опыт не поставлен", dotted)
	}
}

func requireFindingAbout(t *testing.T, found []string, want string) {
	t.Helper()
	if len(found) == 0 {
		t.Fatalf("порча не найдена: предикат молчит там, где обязан назвать координату (%s)", want)
	}
	if !strings.Contains(strings.Join(found, "\n"), want) {
		t.Fatalf("находка есть, но не та: ждали %q, получили:\n  %s", want, strings.Join(found, "\n  "))
	}
}

func contains(in []string, v string) bool {
	for _, x := range in {
		if x == v {
			return true
		}
	}
	return false
}
