// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// rolenamedverbs.go — ПОИМЁННАЯ форма права роли на стороне ЗАГРУЗЧИКА
// (kacho#1844, приёмка `module-manifest-roles-and-seed-grants.md` §3.6,
// сценарии MOD-RL-04 и MOD-RL-04a).
//
// # Что здесь судится, и почему ровно это
//
// Загрузчику доступен ОДИН документ и ничего больше. Поэтому здесь — две
// проверки, обе манифест-внутренние:
//
//	ФОРМА       — две записи права рядом не стоят (§3.1);
//	СУЩЕСТВОВАНИЕ — каждое названное имя объявлено разделом `resources` либо
//	              разделом `deprecatedVerbs` ЭТОГО манифеста (MOD-RL-04).
//
// ПОЛНОТА перечня по классу (MOD-RL-18) и ПРИГОДНОСТЬ названного действия
// (MOD-RL-19) здесь не судятся и судиться не могут: обе спрашивают каталог
// прав, а он у разбора отсутствует by construction — загрузчика зовёт и
// оснастка дерева, у которой ни базы, ни каталога нет. Тянуть каталог сюда
// значило бы сделать разбор функцией чужого состояния.
//
// # Почему проверка существования — здесь, а не у экспортёра
//
// Она отвечает на вопрос о ДОКУМЕНТЕ («манифест называет действие, которого сам
// же не объявляет»), а не о продукте. Автор чинит её, не выходя из файла, и
// узнать о ней обязан раньше — до вердикта о производимости, которая на
// несуществующем имени беспредметна.
//
// Отсюда пара MOD-RL-04a ↔ MOD-RL-18 на ОДНОМ входе с разными исходами:
// «целостно» — вердикт загрузчика, и «экспортируемо» он не означает.
//
// # Снятое действие остаётся ДЕЙСТВИЕМ
//
// Имя, объявленное `deprecatedVerbs`, названо законно (MOD-RL-06): манифест
// сам объявляет, во что оно разрешается. Иначе ярус чтения, воспроизводимый
// дословно (`read` · `list` · `get`), получил бы отказ на первом же глаголе.

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	// ErrRoleRuleRightFormsCollide — правило записало право ОБЕИМИ формами.
	//
	// Отдельный отказ, а не «неизвестное поле»: оба ключа законны по
	// отдельности, и негодно именно их СОСЕДСТВО. Значение, выразимое двумя
	// способами, даёт вопрос «какой из них решает», у которого нет ответа в
	// коде, — и молча победивший ключ увёз бы второй.
	ErrRoleRuleRightFormsCollide = errors.New(
		"manifest: role rule writes its right in both forms at once")
	// ErrRoleRuleVerbUnknownToContract — поимённое право назвало действие,
	// которого манифест не объявляет ни разделом `resources`, ни разделом
	// `deprecatedVerbs`.
	//
	// Отдельный отказ, а не общий «право негодно»: чинится он ИМЕНЕМ действия
	// либо возвращением снятого действия в контракт, а не формой права.
	ErrRoleRuleVerbUnknownToContract = errors.New(
		"manifest: role rule names an action this manifest does not declare")
)

// validateRuleRightForm — две записи права рядом не стоят.
func validateRuleRightForm(rule Rule, doc *yaml.Node, i, j int) []error {
	if len(rule.Classes) == 0 || len(rule.Verbs) == 0 {
		return nil
	}
	return []error{linkFault{
		kind:  ErrRoleRuleRightFormsCollide,
		coord: locate(doc, "roles", i, "rules", j),
		detail: fmt.Sprintf("roles[%d].rules[%d]: право записано ОБЕИМИ формами сразу — "+
			"и `classes` (%s), и `verbs` (%s). Формы взаимоисключающи: значение, выразимое "+
			"двумя способами, даёт вопрос «какой из них решает», у которого нет ответа в "+
			"коде, а молча победивший ключ увёз бы второй. Оставьте ОДНУ: `classes` — "+
			"обозначения класса, `verbs` — поимённый перечень действий, обязанный быть "+
			"полным по своему классу",
			i, j, strings.Join(rule.Classes, ", "), strings.Join(rule.Verbs, ", ")),
	}}
}

// validateRuleNamedVerbs — каждое названное действие объявлено этим манифестом.
//
// Проверка ГЛУШИТСЯ на манифесте без раздела `resources`: судить названное
// имя не с чем, и отказ на всяком имени был бы отказом по отсутствию предмета,
// а не по нарушению. Молчание здесь названо, а не подразумевается: манифест без
// ресурсов судит своя проверка, у неё своя единица.
func validateRuleNamedVerbs(m *Manifest, rule Rule, roleID string, doc *yaml.Node, i, j int) []error {
	if len(rule.Verbs) == 0 || len(m.Resources) == 0 {
		return nil
	}
	// Правило вправе называть ресурсы ЧУЖОГО модуля (владение судит
	// `validateRuleOwnership`); действия чужого ресурса этот манифест не
	// объявляет by construction, и требовать их объявления здесь значило бы
	// требовать невозможного.
	if rule.Module != "" && rule.Module != m.Module {
		return nil
	}
	declared, known := declaredVerbs(m, rule.Resources)
	if len(known) == 0 {
		return nil
	}
	var faults []error
	for _, verb := range rule.Verbs {
		if declared[verb] {
			continue
		}
		if _, ok := m.DeprecatedVerbs[verb]; ok {
			continue
		}
		faults = append(faults, linkFault{
			kind:  ErrRoleRuleVerbUnknownToContract,
			coord: locate(doc, "roles", i, "rules", j, "verbs"),
			detail: fmt.Sprintf("roles[%d].rules[%d].verbs: роль %q модуля %q называет на ресурсе "+
				"%s действие %q, а контракт его не объявляет: ни раздел `resources` этого "+
				"манифеста, ни его `deprecatedVerbs` такого действия не несут. Право, "+
				"ссылающееся на несуществующее действие, применилось бы, легло бы строкой "+
				"роли и ВЫГЛЯДЕЛО БЫ действующим — отличить его от работающего можно было "+
				"бы только вызовом. Объявленные действия этих ресурсов: %s",
				i, j, roleID, rule.Module, strings.Join(rule.Resources, ", "), verb,
				strings.Join(known, ", ")),
		})
	}
	return faults
}

// declaredVerbs — действия, объявленные разделом `resources` для названных
// ресурсов: множеством для решения и перечнем для отказа.
//
// Перечень ОТСОРТИРОВАН: отказ, зависящий от обхода карты, читался бы по-разному
// от прогона к прогону, и автор не смог бы сверить два своих запуска.
func declaredVerbs(m *Manifest, resources []string) (map[string]bool, []string) {
	want := map[string]bool{}
	for _, r := range resources {
		want[r] = true
	}
	set := map[string]bool{}
	for k := range m.Resources {
		res := &m.Resources[k]
		if !want[res.Name] {
			continue
		}
		for _, v := range res.Verbs {
			if v.Name != "" {
				set[v.Name] = true
			}
		}
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return set, names
}
