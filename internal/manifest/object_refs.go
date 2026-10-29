// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// object_refs.go — манифест модуля не ссылается на конкретные объекты
// (kaname#965, расширение по ревью приёмки kaname#963).
//
// Объект адресуется идентификатором, который присваивает запись; манифест же
// применяется на каждом старте и вернул бы ссылку снова. Поэтому манифест
// называет только ТИПЫ и ОБЛАСТИ.
//
// Отказов два, и судятся они разным материалом — каждый тем, где предмет виден
// целиком:
//
//  1. цель выдачи посева — по РАЗОБРАННОМУ значению: псевдоним YAML в сыром
//     узле несёт имя якоря, а не значение. Годна одна цель, [TargetAllInScope];
//     `resources` (перечень объектов) — ссылка на объекты, всякое иное значение —
//     неизвестная цель. Пустая цель — находка неполной выдачи (linkage.go);
//  2. ключ `resourceNames` в правиле роли и во вложенном правиле (`children`) —
//     по НАЛИЧИЮ в узле документа: разобранный перечень не отличает пустой
//     ключ от отсутствующего. Пустой перечень — тоже отказ: схема объявляет
//     ключ недопустимым, а не «допустимым пустым».
//
// Координата находки берётся из узла документа в обоих случаях.
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

// ErrBindingTargetUnknown — цель выдачи посева названа значением, которого
// манифест модуля не знает.
var ErrBindingTargetUnknown = errors.New("manifest: seed access binding target is unknown")

// objectRefWhy — общая часть причины: почему манифесту объект не назвать.
const objectRefWhy = "идентификатор объекта присваивает запись, и снимается он вместе с " +
	"регистрацией объекта, а манифест применяется на каждом старте и вернул бы ссылку снова"

// refuseObjectRefs — оба отказа шапки файла; находки собираются все.
func refuseObjectRefs(m *Manifest, doc *yaml.Node) []error {
	var faults []error
	if m.Seed != nil {
		for i, b := range m.Seed.AccessBindings {
			coord := locate(doc, "seed", "accessBindings", i, "target")
			switch b.Target {
			case TargetAllInScope, "":
				continue
			case bindingTargetResources:
				faults = append(faults, linkFault{
					kind:  ErrObjectRefInManifest,
					coord: coord,
					detail: fmt.Sprintf("seed.accessBindings[%d].target: охват %q (перечень объектов) "+
						"в манифесте модуля не допускается — выдача посева действует на ярус целиком "+
						"(%s); %s",
						i, bindingTargetResources, TargetAllInScope, objectRefWhy),
				})
			default:
				faults = append(faults, linkFault{
					kind:  ErrBindingTargetUnknown,
					coord: coord,
					detail: fmt.Sprintf("seed.accessBindings[%d].target: охват %q манифесту модуля "+
						"не известен — годное значение одно (%s)", i, b.Target, TargetAllInScope),
				})
			}
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
