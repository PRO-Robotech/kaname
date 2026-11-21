// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// public_reader.go — разворачивание выдачи системному классу в отношение
// `public_reader` на объекте объявленного контейнера (стадия S5 приёмки
// anonymous-and-authenticated-are-subject-classes.md, Р9; kaname#856).
//
// # Условие — три факта сразу, и каждый закрывает, а не открывает
//
//   - субъект — системный класс: `public_reader` принимает лишь `system_class`
//     (Р9 «Сужение по цели»), человеку, учётке и группе потомков открывает
//     только ветвь выдач по вложенному правилу; кортеж получает КАЖДЫЙ класс
//     перечня субъектов выдачи, при любом их порядке (kaname#880);
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
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// publicReaderRuleFPPrefix — приставка ключа члена `public_reader`. После неё —
// отпечатки правил, покрывающих детей, отсортированно, через запятую; затем
// [publicReaderClassesSep] и классы выдачи, отсортированно, через запятую.
//
// Классы — часть ключа потому, что кортежи члена — функция ОБОИХ множеств.
// Сверка прохода судит член по ключу и статусу, а не по кортежам: член, чей
// набор кортежей вырос при прежнем ключе, счёлся бы неизменным, и недостающий
// кортеж не был бы записан никогда. Так выглядел член выдачи, развёрнутой до
// kaname#880 одному первому классу: с классами в ключе он выпадает из состава
// при следующем проходе, а новый пишется тем же проходом — снятие вычитает
// кортежи, которые новый член удерживает (`survivingClaims`), разрыва чтения нет.
const publicReaderRuleFPPrefix = catalog.PublicReaderRuleFPPrefix

// publicReaderClassesSep — разделитель отпечатков правил и классов в ключе члена
// `public_reader`; в отпечатке правила (шестнадцатеричном) и в имени класса его
// не бывает.
const publicReaderClassesSep = catalog.PublicReaderClassesSep

// publicReaderMember — член состава с кортежами `public_reader` на контейнере
// (objectType, objectID) — по одному на каждый класс выдачи, если
// выдача его даёт; ok=false — не даёт. `ownerFPs` — отпечатки правил, которыми
// контейнер в составе выдачи ДЕЙСТВУЮЩИМ членом с чтением класса: основание
// даёт только вложенное правило под одним из них.
//
// Основание судится по глаголам КЛАССА (только чтение, Р4): у классов они одни
// и те же, поэтому член один, а кортежей столько, сколько классов (kaname#880).
//
// Вызывающий отвечает за то, что объект ЕСТЬ в составе выдачи действующим
// членом правила: его сопоставило правило-селектор, он входит в цель
// (least-priv, IAM-1-21) и в область выдачи (`IsContainedIn`). Здесь эти
// вопросы не задаются второй раз.
func publicReaderMember(cat *catalog.Facts, bs BindingScope, objectType, objectID string,
	ownerFPs map[string]bool) (DesiredMember, bool) {
	effect, ok := cat.PublicReaderEffect(bs.Selectors, bs.Subjects, objectType, ownerFPs)
	if !ok {
		return DesiredMember{}, false
	}
	return DesiredMember{
		RuleFP:     effect.RuleFP,
		ObjectType: objectType,
		ObjectID:   objectID,
		Status:     domain.VerificationActive,
		Tuples:     effect.Tuples(objectID),
	}, true
}

// withPublicReaders дополняет состав членами `public_reader` по каждому объекту,
// который в составе уже есть ДЕЙСТВУЮЩИМ членом правила, дающего классу чтение.
// Объект с отвергнутой принадлежностью области (REJECTED) кортежа не получает;
// член якоря области (`scope_self`) — не объект содержимого и тоже не получает.
//
// Член правила, которое классу чтения не даёт (оно есть в составе ради человека
// той же выдачи), основанием не служит: у одного класса в выдаче такого члена
// не было бы вовсе, и исход не должен зависеть от соседства (kaname#880).
func withPublicReaders(cat *catalog.Facts, bs BindingScope, members []DesiredMember) []DesiredMember {
	classes := domain.SystemClassSubjects(bs.Subjects)
	if len(classes) == 0 {
		return members
	}
	classRead := domain.PublicReaderOwnerRuleFPs(bs.Selectors)
	type object struct{ typ, id string }
	owners := map[object]map[string]bool{}
	var order []object
	for _, m := range members {
		if m.Status != domain.VerificationActive || !classRead[m.RuleFP] {
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
		if pm, ok := publicReaderMember(cat, bs, key.typ, key.id, owners[key]); ok {
			out = append(out, pm)
		}
	}
	return out
}
