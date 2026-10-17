// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// public_reader.go — разворачивание выдачи системному классу в отношение
// `public_reader` на объекте объявленного контейнера (стадия S5 приёмки
// anonymous-and-authenticated-are-subject-classes.md, Р9; kaname#856).
//
// # Условие — три факта сразу, и каждый закрывает, а не открывает
//
//   - субъект выдачи — системный класс: `public_reader` принимает лишь
//     `system_class` (Р9 «Сужение по цели»), человеку, учётке и группе потомков
//     открывает только ветвь выдач по вложенному правилу;
//   - тип объекта объявлен контейнером в ЖИВОМ каталоге — источник признака
//     доставленный манифест, имени модуля здесь нет (У1);
//   - у правила роли, которым контейнер В СОСТАВЕ выдачи, есть ВЛОЖЕННОЕ правило
//     над ПРЯМЫМ ребёнком контейнера, читающее его целиком — ровно `get` и
//     `list`, без имён и меток (kaname#874, приёмка
//     `nested-rule-reaches-descendants-of-a-named-container.md`, Р5;
//     `domain.RuleSelector.PublicReadsChildOf`). Правило верхнего уровня над
//     ребёнком (прежняя форма роли) `public_reader` не пишет (ND-07 (б)), роль
//     чтения самого контейнера — тоже (SC-73), вложенное правило над внуком —
//     тоже: `public_reader from <указатель>` до внука не доходит.
//
// # Отдельный член состава, а не лишний кортеж у соседа
//
// Кортеж живёт СВОИМ членом с ключом, выведенным из вложенных правил, которые
// его дают. Приклеенный к члену правила над контейнером, он пережил бы снятие
// вложенного правила: член контейнера не менял бы ни ключа, ни статуса, и
// проход счёл бы его неизменным. Свой ключ уходит вместе с правилом, и снятие
// кортежа приходит тем же путём, что снятие `v_*` (реестр выданного,
// `revokeMemberTuples`).

import (
	"sort"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// publicReaderRuleFPPrefix — приставка ключа члена `public_reader`. Отпечатки
// правил, покрывающих детей, идут после неё отсортированно, через запятую.
const publicReaderRuleFPPrefix = "public_reader:"

// publicReaderMember — член состава с кортежем `public_reader` на контейнере
// (objectType, objectID), если выдача его даёт; ok=false — не даёт.
// `ownerFPs` — отпечатки правил, которыми контейнер в составе выдачи
// ДЕЙСТВУЮЩИМ членом: основание даёт только вложенное правило под одним из них.
//
// Вызывающий отвечает за то, что объект ЕСТЬ в составе выдачи действующим
// членом правила: его сопоставило правило-селектор, он входит в цель
// (least-priv, IAM-1-21) и в область выдачи (`IsContainedIn`). Здесь эти
// вопросы не задаются второй раз.
func publicReaderMember(cat *catalog.Facts, bs BindingScope, subject, objectType, objectID string,
	ownerFPs map[string]bool) (DesiredMember, bool) {
	if !isClassBinding(bs) {
		return DesiredMember{}, false
	}
	children := cat.PublicReadChildren(objectType)
	if len(children) == 0 {
		return DesiredMember{}, false
	}
	var fps []string
	for _, sel := range bs.Selectors {
		if sel.Container == nil || !ownerFPs[sel.Container.OwnerFP] {
			continue
		}
		if sel.PublicReadsChildOf(objectType, children) {
			fps = append(fps, sel.RuleFP)
		}
	}
	if len(fps) == 0 {
		return DesiredMember{}, false
	}
	fgaType, ok := cat.FGAObjectType(objectType)
	if !ok {
		return DesiredMember{}, false
	}
	sort.Strings(fps)
	return DesiredMember{
		RuleFP:     publicReaderRuleFPPrefix + strings.Join(fps, ","),
		ObjectType: objectType,
		ObjectID:   objectID,
		Status:     domain.VerificationActive,
		Tuples: []domain.MembershipTuple{{
			User: subject, Relation: domain.PublicReaderRelation, Object: fgaType + ":" + objectID,
		}},
	}, true
}

// withPublicReaders дополняет состав членами `public_reader` по каждому объекту,
// который в составе уже есть ДЕЙСТВУЮЩИМ членом правила. Объект с отвергнутой
// принадлежностью области (REJECTED) кортежа не получает; член якоря области
// (`scope_self`) — не объект содержимого и тоже не получает.
func withPublicReaders(cat *catalog.Facts, bs BindingScope, subject string, members []DesiredMember) []DesiredMember {
	if !isClassBinding(bs) {
		return members
	}
	type object struct{ typ, id string }
	owners := map[object]map[string]bool{}
	var order []object
	for _, m := range members {
		if m.Status != domain.VerificationActive || m.RuleFP == scopeSelfRuleFP {
			continue
		}
		key := object{m.ObjectType, m.ObjectID}
		if owners[key] == nil {
			owners[key] = map[string]bool{}
			order = append(order, key)
		}
		owners[key][m.RuleFP] = true
	}
	out := members
	for _, key := range order {
		if pm, ok := publicReaderMember(cat, bs, subject, key.typ, key.id, owners[key]); ok {
			out = append(out, pm)
		}
	}
	return out
}
