// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// own_door_form.go — класс глаголов, у которых дверь спрашивает модель о
// КОНКРЕТНОМ объекте, имя которого принесло поле запроса (kaname#168, приёмка
// `non-empty-project-is-not-deleted.md` §11).
//
// # Почему принадлежность классу — одна функция
//
// Классом пользуются двое: звено публичного слушателя, которое судит форму
// идентификатора до вопроса о праве, и проба этого звена (IAM-PNE-1-21 А),
// которая обходит класс целиком. Выпиши каждый свой отбор — и два перечня
// разошлись бы молча, ровно на глаголе, который один из них не увидел.
// Поэтому отбор живёт здесь и выводится из ТЕХ ЖЕ аннотаций контракта, из
// которых дверь строит свою карту (`OwnDoorProtoPackages`), — без выписанного
// перечня глаголов и без чтения каталога.

import (
	"sort"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/PRO-Robotech/corelib/authz/catalogderive"
)

// ObjectScopedRPC — глагол, о чьей области дверь спрашивает модель по
// идентификатору из поля запроса.
type ObjectScopedRPC struct {
	// Method — полное имя gRPC-метода (`/пакет.Служба/Метод`).
	Method string
	// Field — поле запроса, из которого дверь берёт идентификатор области.
	Field string
	// ObjectType — вид объекта, о котором спрашивает дверь.
	ObjectType string
}

// ObjectScopedRPCs — класс глаголов с пообъектной областью, упорядоченный по
// имени метода.
//
// Глагол входит в класс ровно тогда, когда аннотация называет:
//   - конкретное поле области — не пустое и не подстановочное `*`: у пустого
//     поля объекта нет, у `*` вопрос задаётся о кластере, а не об объекте;
//   - без поля вида области: вид объекта у такого глагола выбирает сам запрос,
//     и правило формы обязано сперва решить, какая из двух пар полей — область
//     (§11.4 приёмки, вне класса);
//   - не `scope_filtered`: решение о доступе принимается над данными, а не
//     единичным вопросом об объекте;
//   - не исключение (`<exempt>` либо пустое отношение): дверь его не
//     спрашивает вовсе.
//
// Слушателя функция не знает: внутренний метод с конкретным полем в класс
// попадает, но двери, а с ней и звена формы, на внутреннем слушателе нет.
// Отбор по слушателю — дело того, кто монтирует (проба пересекает класс с
// методами публичного сервера корня).
func ObjectScopedRPCs() []ObjectScopedRPC {
	var out []ObjectScopedRPC
	catalogderive.RangeAnnotated(OwnDoorProtoPackages(),
		func(full string, _ protoreflect.MethodDescriptor, a catalogderive.Annotations) {
			field := a.ScopeFromRequestField
			switch {
			case field == "" || field == catalogderive.WildcardField,
				a.ScopeObjectTypeFromRequest != "",
				a.ScopeFiltered,
				a.Exempt():
				return
			}
			out = append(out, ObjectScopedRPC{Method: full, Field: field, ObjectType: a.ScopeObjectType})
		})
	sort.Slice(out, func(i, j int) bool { return out[i].Method < out[j].Method })
	return out
}
