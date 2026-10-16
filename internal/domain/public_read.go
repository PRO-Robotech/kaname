// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import "fmt"

// public_read.go — публичное чтение контейнера (стадия S5 приёмки
// anonymous-and-authenticated-are-subject-classes.md, Р9; kaname#856).
//
// Тип объявляет в манифесте своего модуля, что публичное чтение переходит на его
// детей (`publicReadToChildren: true`). Выдача системному классу на объект такого
// типа ролью, правило которой покрывает тип-ребёнок, разворачивается в отношение
// `public_reader` на этом объекте; дети читают его формой
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
	// Declared — тип объявлен контейнером публичного чтения.
	Declared bool
	// ChildTypes — точечные типы живых строк каталога, чей указатель называет
	// этот тип, отсортированно. Пусто — детей у типа нет либо каталог их не знает.
	ChildTypes []string
}

// CoveredChild — первый (в порядке ChildTypes) тип-ребёнок, который покрывает
// правило роли; ok=false — роль не покрывает ни одного ребёнка.
func (c PublicReadContainer) CoveredChild(rules Rules) (string, bool) {
	for _, child := range c.ChildTypes {
		if rules.CoversType(child) {
			return child, true
		}
	}
	return "", false
}

// UndeclaredContainerText — текст отказа выдачи классу на объект типа, не
// объявленного контейнером, ролью, правило которой покрывает его тип-ребёнок
// (SC-65). Контракт тона — дословно приёмочный.
func UndeclaredContainerText(targetType string, role RoleID, childType string) string {
	return fmt.Sprintf("Type %s does not pass public read to its children; role %s covers its child type %s",
		targetType, role, childType)
}
