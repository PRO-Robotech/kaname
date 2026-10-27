// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package roleexport

// containerverbs.go — контейнерное действие в стадиях MOD-RL-18/19 (задача
// PRO-Robotech/kaname#1003; приёмка `service-account-creation-is-its-own-right.md`,
// Р2а, строка «roleexport»).
//
// MOD-RL-19 считает названное контейнерное действие производимым ровно тогда,
// когда ресурс объявляет его контейнерным действием (`containerVerbs`) и гейт
// действия спрашивает объявленное отношение на объявленном родителе: правило
// роли пишет ровно этот кортеж на объекте области выдачи. Любое иное — находка
// прежним путём: объявление и гейт разошлись, и право не дало бы того, что
// обещает.
//
// MOD-RL-18 к контейнерному действию не применяется: класса у него нет, и
// правило экспортируется поимённо (`splitContainerVerbs`).

import "github.com/PRO-Robotech/kaname/internal/manifest"

// containerProduces — гейт действия `a` спрашивает отношение, объявленное
// контейнерным действием `verb` ресурса `resource` этого манифеста, на объекте
// типа его родителя.
func containerProduces(m *manifest.Manifest, module, resource, verb string, a Action) bool {
	if m == nil || (module != "" && module != m.Module) {
		return false
	}
	for i := range m.Resources {
		r := m.Resources[i]
		if r.Name != resource {
			continue
		}
		cv, ok := r.ContainerVerbNamed(verb)
		if !ok {
			return false
		}
		parent := r.ParentTypeOf(cv)
		return parent != "" && a.Relation == cv.Relation && a.Object == parent
	}
	return false
}

// splitContainerVerbs — поимённое право правила, разделённое на действия типа
// (сводятся к классу) и контейнерные действия (едут поимённо), в порядке
// перечня.
func splitContainerVerbs(m *manifest.Manifest, rule manifest.Rule, named []string) (object, container []string) {
	containers := map[string]bool{}
	if rule.Module == "" || rule.Module == m.Module {
		for i := range m.Resources {
			r := m.Resources[i]
			for _, res := range rule.Resources {
				if r.Name != res {
					continue
				}
				for _, cv := range r.ContainerVerbs {
					containers[cv.Name] = true
				}
			}
		}
	}
	for _, v := range named {
		if containers[v] {
			container = append(container, v)
			continue
		}
		object = append(object, v)
	}
	return object, container
}
