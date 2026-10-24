// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// object_refs.go — манифест модуля не ссылается на конкретные объекты
// (kaname#965, расширение по ревью приёмки #963).
//
// Манифест применяется на КАЖДОМ старте и возвращает объявленные в нём выдачи и
// роли. Объект же адресуется идентификатором, который присваивает запись и
// который снимается вместе с регистрацией объекта (#963): манифест его знать не
// может, а ссылка, объявленная им, восстановилась бы на следующем старте после
// снятия. Поэтому манифест называет только ТИПЫ и ОБЛАСТИ.
//
// Отказов два, и оба судятся по сырому узлу документа — по НАЛИЧИЮ, а не по
// длине разобранного значения:
//
//  1. выдача посева с охватом `resources` (перечень объектов). Сверх довода
//     выше: применитель посева охват не пишет вовсе, и колонка цели выдачи
//     получает умолчание — весь ярус. Принятая, такая выдача молча дала бы
//     доступ ко всей области вместо названных объектов;
//  2. ключ `resourceNames` в правиле роли и во вложенном правиле (`children`).
//     Пустой перечень — тоже отказ: схема объявляет ключ недопустимым, а не
//     «допустимым пустым», и два ответа об одном ключе разошлись бы молча.
//
// Сужение метками (`matchLabels`) объекта не называет и остаётся законным.
// Роли с `resourceNames`, создаваемые арендатором через API, этот отказ не
// трогает: он о манифесте, а не о домене.

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

// ErrObjectRefInManifest — манифест модуля называет КОНКРЕТНЫЙ объект.
var ErrObjectRefInManifest = errors.New("manifest: a module manifest names a concrete object")

// objectRefWhy — общая часть причины: почему манифесту объект не назвать.
const objectRefWhy = "идентификатор объекта присваивает запись, и снимается он вместе с " +
	"регистрацией объекта, а манифест применяется на каждом старте и вернул бы ссылку снова"

// refuseObjectRefs — оба отказа шапки файла; находки собираются все.
func refuseObjectRefs(doc *yaml.Node) []error {
	var faults []error
	bindings := mapValue(mapValue(doc, "seed"), "accessBindings")
	if bindings != nil && bindings.Kind == yaml.SequenceNode {
		for i, b := range bindings.Content {
			target := mapValue(b, "target")
			if target == nil || target.Value != bindingTargetResources {
				continue
			}
			faults = append(faults, linkFault{
				kind:  ErrObjectRefInManifest,
				coord: locate(doc, "seed", "accessBindings", i, "target"),
				detail: fmt.Sprintf("seed.accessBindings[%d].target: охват %q (перечень объектов) "+
					"в манифесте модуля не допускается — выдача посева действует на ярус целиком "+
					"(%s); %s. Применитель посева перечня не пишет, и принятая выдача легла бы "+
					"на весь ярус вместо названных объектов",
					i, bindingTargetResources, bindingTargetAllInScope, objectRefWhy),
			})
		}
	}

	roles := mapValue(doc, "roles")
	if roles == nil || roles.Kind != yaml.SequenceNode {
		return faults
	}
	for i, role := range roles.Content {
		rules := mapValue(role, "rules")
		if rules == nil || rules.Kind != yaml.SequenceNode {
			continue
		}
		for j, rule := range rules.Content {
			if mapValue(rule, "resourceNames") != nil {
				faults = append(faults, objectRefRuleFault(doc,
					fmt.Sprintf("roles[%d].rules[%d]", i, j), "roles", i, "rules", j, "resourceNames"))
			}
			children := mapValue(rule, "children")
			if children == nil || children.Kind != yaml.SequenceNode {
				continue
			}
			for k, child := range children.Content {
				if mapValue(child, "resourceNames") != nil {
					faults = append(faults, objectRefRuleFault(doc,
						fmt.Sprintf("roles[%d].rules[%d].children[%d]", i, j, k),
						"roles", i, "rules", j, "children", k, "resourceNames"))
				}
			}
		}
	}
	return faults
}

// objectRefRuleFault — находка о `resourceNames` в правиле по пути at.
func objectRefRuleFault(doc *yaml.Node, at string, steps ...any) error {
	return linkFault{
		kind:  ErrObjectRefInManifest,
		coord: locate(doc, steps...),
		detail: fmt.Sprintf("%s.resourceNames: сужение по идентификаторам объектов в роли манифеста "+
			"модуля не допускается — правило называет типы (resources) и вправе сузиться метками "+
			"(matchLabels); %s", at, objectRefWhy),
	}
}
