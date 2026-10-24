// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// class_grants_only.go — модуль решает публичность своих объектов сам (стадия
// S7, задача PRO-Robotech/kaname#950).
//
// Приёмка docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md,
// редакция 17, Р11 пп. 2–5: модуль, объявивший ключ оболочки манифеста
// `classGrantsOnlyOnContainers`, принимает выдачу системному классу, достающую до
// его типов, только на объявленном контейнере публичного чтения. Ветвей ДВЕ, по
// виду цели:
//   - (а) цель — объекты: хотя бы один объект цели имеет тип модуля с ключом, и
//     этот тип не объявлен контейнером ([ClassGrantObjectsRefusal], SC-78);
//   - (б) цель — вся область: хотя бы одно правило роли (верхнего уровня либо
//     вложенное) покрывает тип модуля с ключом, не объявленный контейнером
//     ([ClassGrantWholeScopeRefusal], SC-81).
//
// Источник фактов — живой каталог ([ClassGrantsKeyedModules]), тот же, из
// которого ворота SC-65 берут «тип объявлен» (Р11 п. 7).

import (
	"fmt"
	"sort"
	"strings"
)

// ClassGrantsModuleType — живой тип модуля с ключом S7, каким его видят ворота.
type ClassGrantsModuleType struct {
	// Resource — имя ресурса (второй сегмент точечного имени типа).
	Resource string
	// Container — тип объявлен контейнером публичного чтения
	// (`catalog_resource.public_read_to_children`).
	Container bool
}

// ClassGrantsKeyedModules — модули, объявившие ключ S7, и их ЖИВЫЕ типы.
//
// Модуль с ключом и без единого живого типа — законная запись с пустым
// перечнем: его тип цели, которого живой каталог не знает, отвергается ветвью
// (а) — отсутствие факта «объявлен» закрывает, а не открывает.
type ClassGrantsKeyedModules map[string][]ClassGrantsModuleType

// Sorted — та же карта, где типы каждого модуля стоят в порядке имён ресурса
// (байтовым сравнением). Порядок называет приёмка (Р11 п. 5): при ресурсе `*`
// отказ называет первый необъявленный тип в порядке имён.
func (k ClassGrantsKeyedModules) Sorted() ClassGrantsKeyedModules {
	out := make(ClassGrantsKeyedModules, len(k))
	for m, types := range k {
		cp := append([]ClassGrantsModuleType(nil), types...)
		sort.SliceStable(cp, func(i, j int) bool { return cp[i].Resource < cp[j].Resource })
		out[m] = cp
	}
	return out
}

// declared — тип `<module>.<resource>` модуля с ключом объявлен контейнером.
// Тип, которого среди живых нет, объявленным не считается.
func (k ClassGrantsKeyedModules) declared(module, resource string) bool {
	for _, t := range k[module] {
		if t.Resource == resource {
			return t.Container
		}
	}
	return false
}

// ClassGrantObjectsText — текст отказа ветви (а), дословно приёмочный (SC-78).
func ClassGrantObjectsText(module, dottedType string) string {
	return fmt.Sprintf("Module %s admits system class grants on its public read containers only; type %s is not one",
		module, dottedType)
}

// ClassGrantWholeScopeText — текст отказа ветви (б), дословно приёмочный (SC-81):
// у цели «вся область» типа нет, и текст называет роль и тип, который она
// покрывает.
func ClassGrantWholeScopeText(module string, role RoleID, dottedType string) string {
	return fmt.Sprintf("Module %s admits system class grants on its public read containers only; "+
		"the whole scope is not one, and role %s covers type %s", module, role, dottedType)
}

// ClassGrantObjectsRefusal — ветвь (а): первый в порядке цели тип модуля с
// ключом, не объявленный контейнером; refused=false — такого типа нет.
func ClassGrantObjectsRefusal(keyed ClassGrantsKeyedModules, target AccessTarget) (string, bool) {
	for _, dotted := range target.DistinctTypes() {
		module, resource, ok := splitDottedType(dotted)
		if !ok {
			continue
		}
		if _, isKeyed := keyed[module]; !isKeyed {
			continue
		}
		if !keyed.declared(module, resource) {
			return ClassGrantObjectsText(module, dotted), true
		}
	}
	return "", false
}

// classGrantPair — пара «модуль × ресурс», которую называет правило роли либо
// её скомпилированное право; `*` в любой половине — подстановка.
type classGrantPair struct{ module, resource string }

// classGrantPairsOf — пары роли в порядке, который называет приёмка (Р11 п. 5):
// правила — в порядке роли, вложенное — сразу за своим владельцем (с модулем
// владельца), ресурсы — в порядке правила. У роли без правил — её
// скомпилированные права `<модуль>.<ресурс>.<имя>.<глагол>` в порядке роли.
func classGrantPairsOf(role Role) []classGrantPair {
	var out []classGrantPair
	if len(role.Rules) > 0 {
		for _, r := range role.Rules {
			for _, res := range r.Resources {
				out = append(out, classGrantPair{r.Module, res})
			}
			for _, child := range r.EffectiveChildren() {
				for _, res := range child.Resources {
					out = append(out, classGrantPair{child.Module, res})
				}
			}
		}
		return out
	}
	for _, p := range role.Permissions {
		seg := strings.SplitN(string(p), ".", 4)
		if len(seg) < 2 {
			continue
		}
		out = append(out, classGrantPair{seg[0], seg[1]})
	}
	return out
}

// ClassGrantWholeScopeRefusal — ветвь (б): первый тип модуля с ключом, не
// объявленный контейнером, который покрывает пара роли. «Покрывает» — модуль
// пары равен модулю типа либо `*`, и ресурс пары равен ресурсу типа либо `*`;
// вид селектора правила не важен (Р11 п. 2 (б)). Правило над объявленным
// контейнером отказа не даёт (Р11 п. 3).
//
// Порядок поиска — порядок пар роли; внутри пары с модулем `*` — модули с
// ключом в порядке имён; внутри модуля — его живые типы в порядке имён.
// `keyed` ожидается упорядоченной ([ClassGrantsKeyedModules.Sorted]).
func ClassGrantWholeScopeRefusal(keyed ClassGrantsKeyedModules, roleID RoleID, role Role) (string, bool) {
	if len(keyed) == 0 {
		return "", false
	}
	modules := make([]string, 0, len(keyed))
	for m := range keyed {
		modules = append(modules, m)
	}
	sort.Strings(modules)
	for _, pair := range classGrantPairsOf(role) {
		for _, m := range modules {
			if pair.module != wildcard && pair.module != m {
				continue
			}
			for _, t := range keyed[m] {
				if pair.resource != wildcard && pair.resource != t.Resource {
					continue
				}
				if !t.Container {
					return ClassGrantWholeScopeText(m, roleID, m+"."+t.Resource), true
				}
			}
		}
	}
	return "", false
}
