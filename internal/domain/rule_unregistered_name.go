// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// rule_unregistered_name.go — что становится с правилами роли, когда снята
// регистрация объекта, названного в их `resourceNames` (kaname#963, приёмка
// `unregistration-revokes-its-grants.md`, Р1 (д), Р7, Д5).

// WithoutResourceName возвращает правила роли без ключа объекта
// (`dottedType`, `id`): id убирается из `ResourceNames` каждого правила и
// каждого вложенного правила, которое называет его на типе `dottedType`.
//
// ПУСТОЙ ПЕРЕЧЕНЬ ИМЁН НЕ ХРАНИТСЯ. Правило без имён — ветвь `anchor`, то есть
// все объекты типа в области; хранить его значило бы расширить доступ ровно
// там, где снятие обязано его сузить. Поэтому правило верхнего уровня, у
// которого имён не осталось, снимается целиком (`removed` считает такие), а
// вложенное — снимается из `Children` (правило-владелец остаётся).
//
// Тип правила — точечное имя `<module>.<resource>`; у вложенного правила модуль
// берётся у владельца. Правило над подстановкой (`*`) имени конкретного типа не
// называет и не трогается. Правило с меткой (`MatchLabels`) имён не несёт.
//
// `changed = false` — ни одно правило ключ не называло; вызывающий тогда роль не
// пишет вовсе (сужения нет, строки аудита нет — URG-22, URG-37).
func (rs Rules) WithoutResourceName(dottedType, id string) (out Rules, removed int, changed bool) {
	out = make(Rules, 0, len(rs))
	for _, r := range rs {
		names, hit := withoutName(r.ResourceNames, r.Module, r.Resources, dottedType, id)
		var children []Rule
		childHit := false
		for _, c := range r.Children {
			cnames, chit := withoutName(c.ResourceNames, r.Module, c.Resources, dottedType, id)
			if !chit {
				children = append(children, c)
				continue
			}
			childHit = true
			if len(cnames) == 0 {
				continue // вложенное правило без имён снимается (Р7)
			}
			c.ResourceNames = cnames
			children = append(children, c)
		}
		if !hit && !childHit {
			out = append(out, r)
			continue
		}
		changed = true
		if hit && len(names) == 0 {
			removed++
			continue // правило без имён снимается (Р1 (д), Д5)
		}
		if hit {
			r.ResourceNames = names
		}
		if childHit {
			// nil, а не пустой срез: пустой непустой срез формой не является
			// (второй способ сказать «вложенных нет», комментарий `Rule.Children`).
			r.Children = children
			if len(children) == 0 {
				r.Children = nil
			}
		}
		out = append(out, r)
	}
	return out, removed, changed
}

// withoutName — `names` без `id`, если правило с модулем `module` и ресурсами
// `resources` называет id на типе `dottedType`. hit=false — не называет.
func withoutName(names []string, module string, resources []string, dottedType, id string) ([]string, bool) {
	if len(names) == 0 || !coversDotted(module, resources, dottedType) {
		return names, false
	}
	out := make([]string, 0, len(names))
	hit := false
	for _, n := range names {
		if n == id {
			hit = true
			continue
		}
		out = append(out, n)
	}
	if !hit {
		return names, false
	}
	return out, true
}

// coversDotted — правило над модулем `module` и ресурсами `resources` называет
// тип `dottedType` по имени (подстановка конкретного типа не называет).
func coversDotted(module string, resources []string, dottedType string) bool {
	for _, res := range resources {
		if res != wildcard && module+"."+res == dottedType {
			return true
		}
	}
	return false
}
