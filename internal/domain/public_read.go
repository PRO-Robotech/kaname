// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import "fmt"

// public_read.go — публичное чтение контейнера (стадия S5 приёмки
// anonymous-and-authenticated-are-subject-classes.md, Р9; kaname#856).
//
// Тип объявляет в манифесте своего модуля, что публичное чтение переходит на его
// детей (`publicReadToChildren: true`). Выдача системному классу на объект такого
// типа ролью, у правила которой над этим типом есть ВЛОЖЕННОЕ правило над прямым
// ребёнком, читающее его целиком (kaname#874, nested_rule.go), разворачивается в
// отношение `public_reader` на этом объекте; дети читают его формой
// `or public_reader from <указатель>` в своих `v_get` и `v_list`. Имени модуля в
// механизме нет: признак контейнера и связь «ребёнок → контейнер» приходят из
// живого каталога, куда их кладёт доставленный манифест.

// PublicReaderRelation — имя отношения публичного чтения в блоке контейнера.
//
// Объявлено ОДИН раз: его порождает генератор блоков модели, пишет разворачивание
// выдачи и принимает страж прямого факта (`relation_fact_subject_class_reads_only`),
// и второе написание разошлось бы с первым молча.
const PublicReaderRelation = "public_reader"

// PublicReadContainer — что живой каталог говорит о типе цели выдачи классу.
type PublicReadContainer struct {
	// Type — точечный тип, о котором ответ (kaname#874): по нему ворота находят
	// вложенные правила, стоящие под этим типом.
	Type string
	// Declared — тип объявлен контейнером публичного чтения.
	Declared bool
	// ChildTypes — точечные типы живых строк каталога, чей указатель называет
	// этот тип, отсортированно. Пусто — детей у типа нет либо каталог их не знает.
	ChildTypes []string
}

// CoveredChild — первый (в порядке ChildTypes) тип-ребёнок, чтение которого роль
// открывает ЦЕЛИКОМ ([Rule.ReadsWholeType]); ok=false — такого ребёнка нет.
//
// Читаются ОБЕ формы (kaname#874, M1 круга 1): правило верхнего уровня над
// ребёнком (исход SC-65 соседа не меняется) и вложенное правило под правилом
// над ЭТИМ типом (ND-05 (в)). Прежде ворота читали только верхний уровень, и
// роль, открывающая детей вложенным правилом, проходила на необъявленный
// контейнер молча.
func (c PublicReadContainer) CoveredChild(rules Rules) (string, bool) {
	for _, child := range c.ChildTypes {
		for _, r := range rules {
			if r.ReadsWholeType(child) {
				return child, true
			}
			if c.Type == "" || r.OwnerType() != c.Type {
				continue
			}
			for _, nested := range r.EffectiveChildren() {
				if nested.ReadsWholeType(child) {
					return child, true
				}
			}
		}
	}
	return "", false
}

// publicReadVerbsOfChild — действия, которых касается публичное чтение: метаданные
// объекта и перечень (Р9 п. 2). Ключ контейнера ставит класс в их отношения у
// контейнера и `public_reader from <указатель>` — у детей; пишущие действия ключ
// не трогает (Р9 п. 3).
//
// Объявлено ОДИН раз (kaname#866, CE-03): набор читают рендер блока (какие
// отношения несут следствия ключа), загрузчик манифеста (Р2: класс в составе
// этих действий у ресурса с ключом) и ворота выдачи ([readsWhole]). Прежде у
// рендера была своя копия, и два написания расходились бы молча. Имя осталось
// прежним («детей»), потому что на него ссылается запись замера приёмки
// nested-rule-reaches-descendants-of-a-named-container.md.
var publicReadVerbsOfChild = []string{"get", "list"}

// IsPublicReadVerb — действие с этим именем касается публичное чтение
// ([publicReadVerbsOfChild]). Имя сравнивается в нормальной форме ([NormalizeVerb]).
func IsPublicReadVerb(verb string) bool {
	v := NormalizeVerb(verb)
	for _, c := range publicReadVerbsOfChild {
		if v == c {
			return true
		}
	}
	return false
}

// readsWhole — ЕДИНСТВЕННЫЙ предикат «правило открывает чтение типа целиком»:
// правило не сужено (вид — якорь, без имён и меток) и даёт ВСЕ глаголы, которые
// публичное чтение открывает на детях.
//
// Публичное чтение наследует сужение правила роли: отношение `public_reader`
// открывает детей целиком, включая будущих, поэтому писать его вправе только
// правило, которое и само открывает их целиком. Правило по меткам, по именам
// либо с одним глаголом чтения разворачивается обычным путём — в отношения
// `v_*` на тех объектах и с теми глаголами, которые оно называет.
func readsWhole(arm Arm, verbs []string) bool {
	if arm != ArmAnchor {
		return false
	}
	for _, want := range publicReadVerbsOfChild {
		found := false
		for _, v := range verbs {
			if NormalizeVerb(v) == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// ReadsWholeType — правило называет тип `dotted` и открывает его чтение целиком
// ([readsWhole]). Им судят ворота выдачи классу (SC-65).
func (r Rule) ReadsWholeType(dotted string) bool {
	if !Rules([]Rule{r}).CoversType(dotted) {
		return false
	}
	return readsWhole(r.Arm(), r.Verbs)
}

// ReadsWholeType — то же правило в форме селектора материализации ([readsWhole]).
// Им судит разворачивание выдачи, когда решает, писать ли `public_reader`.
func (s RuleSelector) ReadsWholeType(dotted string) bool {
	named := false
	for _, t := range s.ObjectTypes {
		if t == dotted {
			named = true
			break
		}
	}
	return named && readsWhole(s.Arm, s.Verbs)
}

// UndeclaredContainerText — текст отказа выдачи классу на объект типа, не
// объявленного контейнером, ролью, правило которой покрывает его тип-ребёнок
// (SC-65). Контракт тона — дословно приёмочный.
func UndeclaredContainerText(targetType string, role RoleID, childType string) string {
	return fmt.Sprintf("Type %s does not pass public read to its children; role %s covers its child type %s",
		targetType, role, childType)
}
