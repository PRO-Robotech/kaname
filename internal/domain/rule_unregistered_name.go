// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// rule_unregistered_name.go — что становится с правилами роли, когда снята
// регистрация объекта, названного в их `resourceNames` (kaname#963, приёмка
// `unregistration-revokes-its-grants.md`, Р1 (д), Р7, Д1, Д5).

// WithoutResourceName возвращает правила роли без ключа объекта
// (`dottedType`, `id`): id перестаёт называться на типе `dottedType` в каждом
// правиле и каждом вложенном правиле, которое называет его на этом типе.
//
// КЛЮЧ — ПАРА (тип, id), А ПЕРЕЧЕНЬ ИМЁН ОДИН НА ВСЕ ТИПЫ ПРАВИЛА. Правило над
// `resources: [a, b]` с `resourceNames: [N]` даёт и (a, N), и (b, N); снятие
// (a, N) обязано отнять только первое — (b, N) другой объект (Д1, URG-05).
// Поэтому правило, называющее снятый тип вместе с другими, расщепляется: прежнее
// правило остаётся над остальными типами с прежними именами, а снятый тип
// уходит в своё правило с именами без id. Правило над одним снятым типом просто
// теряет имя.
//
// ПУСТОЙ ПЕРЕЧЕНЬ ИМЁН НЕ ХРАНИТСЯ. Правило без имён — ветвь `anchor`, то есть
// все объекты типа в области; хранить его значило бы расширить доступ ровно
// там, где снятие обязано его сузить. Поэтому правило верхнего уровня, у
// которого имён не осталось, снимается (`removed` считает правила, исчезнувшие
// целиком), а вложенное — снимается из `Children` (правило-владелец остаётся).
//
// ПРЕДЕЛ ЧИСЛА ПРАВИЛ. Расщепление добавляет правило. Если правил роли (или
// вложенных правил одного владельца) после него стало бы больше предела
// (`MaxRules`, `maxChildren`), снятый id вычёркивается из общего перечня этого
// правила целиком — сужение вместо расширения: доступ к (b, N) теряется, но
// снятый ключ не остаётся названным, и роль не выходит за предел, который её
// чтение отвергло бы.
//
// Тип правила — точечное имя `<module>.<resource>`; у вложенного правила модуль
// берётся у владельца. Правило над подстановкой (`*`) имён не несёт (`Validate`)
// и не трогается. Правило с меткой (`MatchLabels`) имён не несёт.
//
// `changed = false` — ни одно правило ключ не называло; вызывающий тогда роль не
// пишет вовсе (сужения нет, строки аудита нет — URG-22, URG-37).
func (rs Rules) WithoutResourceName(dottedType, id string) (out Rules, removed int, changed bool) {
	out, removed, changed = rs.withoutResourceName(dottedType, id, true)
	if len(out) > MaxRules {
		out, removed, changed = rs.withoutResourceName(dottedType, id, false)
	}
	return out, removed, changed
}

func (rs Rules) withoutResourceName(dottedType, id string, split bool) (out Rules, removed int, changed bool) {
	out = make(Rules, 0, len(rs))
	for _, r := range rs {
		children, childHit := withoutNameInChildren(r.Children, r.Module, dottedType, id, split)
		if childHit {
			changed = true
			r.Children = children
		}
		parts, hit := withoutNameSplit(r, r.Module, dottedType, id, split)
		if !hit {
			out = append(out, r)
			continue
		}
		changed = true
		if len(parts) == 0 {
			removed++ // правило без имён снимается (Р1 (д), Д5)
			continue
		}
		out = append(out, parts...)
	}
	return out, removed, changed
}

// withoutNameInChildren — вложенные правила владельца без ключа. nil, а не пустой
// срез, когда не осталось ни одного: пустой непустой срез формой не является
// (второй способ сказать «вложенных нет», комментарий `Rule.Children`).
func withoutNameInChildren(children []Rule, module, dottedType, id string, split bool) ([]Rule, bool) {
	if len(children) == 0 {
		return children, false
	}
	out, hit := childrenWithout(children, module, dottedType, id, split)
	if hit && split && len(out) > maxChildren {
		out, _ = childrenWithout(children, module, dottedType, id, false)
	}
	if !hit {
		return children, false
	}
	if len(out) == 0 {
		return nil, true
	}
	return out, true
}

func childrenWithout(children []Rule, module, dottedType, id string, split bool) ([]Rule, bool) {
	var out []Rule
	hit := false
	for _, c := range children {
		parts, chit := withoutNameSplit(c, module, dottedType, id, split)
		if !chit {
			out = append(out, c)
			continue
		}
		hit = true
		out = append(out, parts...) // вложенное правило без имён снимается (Р7)
	}
	return out, hit
}

// withoutNameSplit — правило `r` (модуль — `module`) без id на типе
// `dottedType`. hit=false — правило ключ не называет. Иначе `parts` — то, чем
// правило становится: ноль, одно или (при расщеплении) два правила.
func withoutNameSplit(r Rule, module, dottedType, id string, split bool) (parts []Rule, hit bool) {
	if len(r.ResourceNames) == 0 || !namesID(r.ResourceNames, id) {
		return nil, false
	}
	var named, rest []string
	for _, res := range r.Resources {
		if res != wildcard && module+"."+res == dottedType {
			named = append(named, res)
			continue
		}
		rest = append(rest, res)
	}
	if len(named) == 0 {
		return nil, false
	}
	remaining := make([]string, 0, len(r.ResourceNames)-1)
	for _, n := range r.ResourceNames {
		if n != id {
			remaining = append(remaining, n)
		}
	}
	if len(rest) == 0 || !split {
		if len(remaining) == 0 {
			return nil, true
		}
		r.ResourceNames = remaining
		return []Rule{r}, true
	}
	// Расщепление: остальные типы — прежнее правило с прежними именами; снятый тип —
	// своё правило без id (и без вложенных: владелец вложенных называет ровно один
	// тип, `validateChildren`, поэтому до расщепления правило с детьми не доходит).
	kept := r
	kept.Resources = rest
	parts = []Rule{kept}
	if len(remaining) > 0 {
		narrowed := r
		narrowed.Resources = named[:1]
		narrowed.ResourceNames = remaining
		narrowed.Children = nil
		parts = append(parts, narrowed)
	}
	return parts, true
}

// namesID — перечень имён называет id.
func namesID(list []string, id string) bool {
	for _, n := range list {
		if n == id {
			return true
		}
	}
	return false
}
