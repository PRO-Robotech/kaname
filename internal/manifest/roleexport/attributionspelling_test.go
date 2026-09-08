// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// attributionspelling_test.go — привязка называет ресурс ТЕМ ЖЕ написанием, что
// закрытая таблица типов (задача #1884).
//
// # Предмет — третий словарь, а не единственное против множественного
//
// Расхождение между ключом таблицы и средним сегментом токена права намеренно и
// объяснено шапкой fga_types.go: у них разные референты, и сравнивать их некому.
// Здесь предмет другой — написание, которое привязка ВЫВОДИТ из имени службы.
// Оно не объявлено нигде, читателя на пути запроса не имеет и до этой задачи
// расходилось с ключом таблицы у трёх модулей из шести.
//
// # Почему проба судит ДОСТИЖИМОСТЬ, а не одну пару
//
// Одна пара доказывает экземпляр. Достижимость — свойство словаря: ключ закрытой
// таблицы, которого привязка не производит, означает, что ВСЕ действия его
// ресурса выпадают из проверок манифеста молча, кодом 0. Единица счёта названа:
// КЛЮЧ закрытой таблицы, не действие и не запись каталога.
//
// # Вход настоящий с обеих сторон
//
// Каталог — встроенный, тот самый, что читает посев; таблица — та, что резолвит
// эмиттер. Ни одна сторона не сочинена, поэтому проба судит продукт, а не
// фикстуру.
package roleexport_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/manifest/roleexport"
)

func TestAttributionProducesTheClosedTableSpelling(t *testing.T) {
	entries := mustCatalog(t)

	actions, outside := roleexport.Attribute(entries)
	if len(actions) == 0 {
		t.Fatal("привязано ноль действий: «ноль находок» стало бы неотличимо от " +
			"«ноль прочитанного»")
	}

	produced := map[string]struct{}{}
	for _, a := range actions {
		produced[a.Module+"."+a.Resource] = struct{}{}
	}

	keys := authzmap.CatalogKeys()
	if len(keys) == 0 {
		t.Fatal("закрытая таблица прочитана пустой — судить нечего")
	}
	without := authzmap.CatalogResourcesWithoutOwnService()

	unreachable, reached := judgeSpellingReach(produced, keys, without)

	t.Logf("перепись: ключей закрытой таблицы %d · производится привязкой %d · "+
		"объявлено без своей службы %d · записей каталога %d · вне формы модуля %d",
		len(keys), reached, len(without), len(entries), len(outside))

	if len(unreachable) > 0 {
		t.Fatalf("привязка не производит написание %d ключей закрытой таблицы:\n  %s\n\n"+
			"Правило роли обязано называть ресурс написанием ТАБЛИЦЫ — иначе его "+
			"отвергает validateRuleCatalog на пути запроса, — а привязка выводит другое "+
			"написание, и тогда ни одно действие ресурса не сопоставляется ни с одной "+
			"записью каталога: они выпадают из проверок манифеста молча, кодом 0. "+
			"Чинится записью в authzmap.catalogSpellingByServiceName либо, если своей "+
			"службы у ресурса нет вовсе, — в catalogResourcesWithoutOwnService с причиной",
			len(unreachable), strings.Join(unreachable, "\n  "))
	}

	// Обратный контроль: выдуманное написание производиться НЕ должно — иначе
	// «производится» зеленело бы на чём угодно.
	if _, ok := produced["loadbalancer.targetGroupses"]; ok {
		t.Fatal("привязка произвела выдуманное написание: проба зеленела бы на любом входе")
	}
}

// TestDeclaredSpellingDivergencesStillHaveASubject — объявленное расхождение
// ИСТЕКАЕТ САМО.
//
// Запись, чьи стороны совпали, ничего не объявляет; запись, чья цель не является
// ключом закрытой таблицы, приводит написание к несуществующему ключу. Обе делают
// перечень полнее, чем он есть, и обе молчат: приведение к самому себе неотличимо
// от отсутствия записи.
func TestDeclaredSpellingDivergencesStillHaveASubject(t *testing.T) {
	div := authzmap.CatalogSpellingDivergences()
	if len(div) == 0 {
		t.Skip("расхождений не объявлено — истекать нечему")
	}

	keys := map[string]struct{}{}
	for _, k := range authzmap.CatalogKeys() {
		keys[k] = struct{}{}
	}

	faults := judgeSpellingDivergences(div, keys)

	t.Logf("перепись: объявлено расхождений %d · ключей таблицы %d", len(div), len(keys))

	if len(faults) > 0 {
		t.Fatalf("объявленные расхождения потеряли предмет (%d):\n  %s",
			len(faults), strings.Join(faults, "\n  "))
	}
}

// TestResourcesWithoutOwnServiceAreStillUnreachable — исключение истекает само.
//
// Запись, чьё написание привязка всё же производит, больше нечего исключать: без
// этой пробы исключение пережило бы появление службы и продолжало бы выводить
// живой ресурс из-под наблюдения.
func TestResourcesWithoutOwnServiceAreStillUnreachable(t *testing.T) {
	without := authzmap.CatalogResourcesWithoutOwnService()
	if len(without) == 0 {
		t.Skip("исключений не объявлено — истекать нечему")
	}

	actions, _ := roleexport.Attribute(mustCatalog(t))
	produced := map[string]struct{}{}
	for _, a := range actions {
		produced[a.Module+"."+a.Resource] = struct{}{}
	}

	var faults []string
	for key, why := range without {
		if why == "" {
			faults = append(faults, "исключение "+key+" не называет причины: через полгода "+
				"перечень без причин читается как список неисправностей")
		}
		if _, ok := produced[key]; ok {
			faults = append(faults, "исключение "+key+" потеряло предмет: привязка это "+
				"написание производит, значит служба у ресурса появилась — снимите запись")
		}
	}

	t.Logf("перепись: исключений %d · привязано действий %d", len(without), len(actions))

	if len(faults) > 0 {
		sort.Strings(faults)
		t.Fatalf("исключения потеряли предмет (%d):\n  %s", len(faults), strings.Join(faults, "\n  "))
	}
}

// --- вердикты отдельными функциями ------------------------------------------
//
// Пробы выше добывают вход (встроенный каталог, закрытая таблица), а СУДЯТ его
// эти две функции. Разделение здесь не украшение: инъекция подаёт им
// синтетический вход тем же путём, каким пробы подают настоящий, поэтому
// доказательство способности упасть относится к той же функции, которую
// исполняет гейт, — а не к её похожей копии
// (attributionspelling_injection_test.go).

// judgeSpellingReach — какие ключи закрытой таблицы привязка не производит.
// Вторым значением — сколько произведено: «ноль находок» обязано быть отличимо
// от «ноль осмотренного».
func judgeSpellingReach(produced map[string]struct{}, keys []string,
	without map[string]string) (unreachable []string, reached int) {

	for _, key := range keys {
		if _, ok := produced[key]; ok {
			reached++
			continue
		}
		if _, declared := without[key]; declared {
			continue
		}
		unreachable = append(unreachable, key)
	}
	sort.Strings(unreachable)
	return unreachable, reached
}

// judgeSpellingDivergences — записи приведения, потерявшие предмет.
func judgeSpellingDivergences(div map[string]string, keys map[string]struct{}) []string {
	var faults []string
	for from, to := range div {
		if from == to {
			faults = append(faults, "запись "+from+" приводит написание к самому себе: "+
				"расхождения нет, и запись не объявляет ничего")
			continue
		}
		if _, ok := keys[to]; !ok {
			faults = append(faults, "запись "+from+" → "+to+
				": цель не является ключом закрытой таблицы, приведение ведёт в никуда")
		}
		if _, ok := keys[from]; ok {
			faults = append(faults, "запись "+from+" → "+to+
				": ИСТОЧНИК сам является ключом таблицы, то есть приведение "+
				"переписывает годное написание в другое")
		}
	}
	sort.Strings(faults)
	return faults
}
