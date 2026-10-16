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
//     открывает только ветвь выдач по правилу над типом-ребёнком;
//   - тип объекта объявлен контейнером в ЖИВОМ каталоге — источник признака
//     доставленный манифест, имени модуля здесь нет (У1);
//   - правило роли покрывает тип-ребёнок контейнера (решение диспетчера по N1,
//     вариант (а)): роль чтения самого контейнера (`registries:get`) потомков не
//     открывает ни человеку, ни классу (SC-73).
//
// # Отдельный член состава, а не лишний кортеж у соседа
//
// Кортеж живёт СВОИМ членом с ключом, выведенным из правил, которые покрывают
// детей. Приклеенный к члену правила над контейнером, он пережил бы снятие правила
// над ребёнком: член контейнера не менял бы ни ключа, ни статуса, и проход счёл бы
// его неизменным. Свой ключ уходит вместе с правилом, и снятие кортежа приходит
// тем же путём, что снятие `v_*` (реестр выданного, `revokeMemberTuples`).

import (
	"sort"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// publicReaderRuleFPPrefix — приставка ключа члена `public_reader`. Отпечатки
// правил, покрывающих детей, идут после неё отсортированно, через запятую.
const publicReaderRuleFPPrefix = "public_reader:"

// publicReaderMember — член состава с кортежем `public_reader` на объекте
// (objectType, objectID), если выдача его даёт; ok=false — не даёт.
//
// Вызывающий отвечает за то, что объект ЕСТЬ в составе выдачи ДЕЙСТВУЮЩИМ членом
// правила: его сопоставило правило-селектор, он входит в цель (least-priv,
// IAM-1-21) и в область выдачи (`IsContainedIn`). Здесь эти вопросы не
// задаются второй раз — повторённые по объекту без его предков, они отвергли бы
// законный объект.
func publicReaderMember(cat *catalog.Facts, bs BindingScope, subject, objectType, objectID string) (DesiredMember, bool) {
	if bs.SubjectType != string(domain.SubjectTypeSystemClass) {
		return DesiredMember{}, false
	}
	children := cat.PublicReadChildren(objectType)
	if len(children) == 0 {
		return DesiredMember{}, false
	}
	var fps []string
	for _, sel := range bs.Selectors {
		if selectorCoversAny(sel, children) {
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

// selectorCoversAny — правило-селектор называет хотя бы один из типов.
func selectorCoversAny(sel domain.RuleSelector, types []string) bool {
	for _, t := range sel.ObjectTypes {
		for _, want := range types {
			if t == want {
				return true
			}
		}
	}
	return false
}

// withPublicReaders дополняет состав членами `public_reader` по каждому объекту,
// который в составе уже есть ДЕЙСТВУЮЩИМ членом правила. Объект с отвергнутой
// принадлежностью области (REJECTED) кортежа не получает; член якоря области
// (`scope_self`) — не объект содержимого и тоже не получает.
func withPublicReaders(cat *catalog.Facts, bs BindingScope, subject string, members []DesiredMember) []DesiredMember {
	if bs.SubjectType != string(domain.SubjectTypeSystemClass) {
		return members
	}
	seen := map[string]bool{}
	out := members
	for _, m := range members {
		if m.Status != domain.VerificationActive || m.RuleFP == scopeSelfRuleFP {
			continue
		}
		key := m.ObjectType + "\x00" + m.ObjectID
		if seen[key] {
			continue
		}
		seen[key] = true
		if pm, ok := publicReaderMember(cat, bs, subject, m.ObjectType, m.ObjectID); ok {
			out = append(out, pm)
		}
	}
	return out
}
