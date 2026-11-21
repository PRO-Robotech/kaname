// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"errors"
	"regexp"
	"strings"
)

var userChildPathComponent = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

// MaxUserChildObjectKeyBytes ограничивает полный ключ типа и ID. В индексе
// фактов одной строкой хранятся ключи потомка и родителя вместе.
const MaxUserChildObjectKeyBytes = 512

// ErrUserChildRegistrationRefused обозначает предметный отказ регистрации.
// Внутреннюю причину сохраняет владелец транзакции.
var ErrUserChildRegistrationRefused = errors.New("user child registration refused")

// UserChildRegistrationTarget содержит серверные ключи объектов модели прав.
type UserChildRegistrationTarget struct {
	ChildObject  string
	ParentObject string
	ParentAction string
}

// UserChildPathPolicy описывает одну явно включённую форму идентификатора.
// Число сегментов родителя известно из политики типа до разбора запроса.
// Для каждого типа значение едино, поэтому префикс определяется без поиска
// среди зарегистрированных объектов и не зависит от их состояния.
type UserChildPathPolicy struct {
	ChildType      string
	ParentType     string
	ParentAction   string
	ParentSegments int
}

// Resolve разбирает канонический путь, не нормализуя и не декодируя его.
// Применитель вызывает этот разбор только для типов, явно принявших эту форму.
func (p UserChildPathPolicy) Resolve(id string) (UserChildRegistrationTarget, error) {
	if len(p.ChildType)+1+len(id) > MaxUserChildObjectKeyBytes ||
		p.ParentSegments <= 0 || !IsWellFormedObjectTypeName(p.ChildType) ||
		!IsWellFormedObjectTypeName(p.ParentType) ||
		!IsWellFormedObjectTypeName(p.ParentAction) {
		return UserChildRegistrationTarget{}, ErrUserChildRegistrationRefused
	}

	segments, index, parentEnd := 0, 0, 0
	for part := range strings.SplitSeq(id, "/") {
		if !userChildPathComponent.MatchString(part) {
			return UserChildRegistrationTarget{}, ErrUserChildRegistrationRefused
		}
		segments++
		index += len(part)
		if segments == p.ParentSegments {
			parentEnd = index
		}
		index++
	}
	if segments <= p.ParentSegments || len(p.ParentType)+1+parentEnd > MaxUserChildObjectKeyBytes {
		return UserChildRegistrationTarget{}, ErrUserChildRegistrationRefused
	}
	return UserChildRegistrationTarget{
		ChildObject:  p.ChildType + ":" + id,
		ParentObject: p.ParentType + ":" + id[:parentEnd],
		ParentAction: p.ParentAction,
	}, nil
}
