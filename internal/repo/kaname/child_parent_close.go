// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"
	"time"
)

// ChildParentCloseInput адресует текущую регистрацию родителя точной версией.
// Значение не содержит изменяемых коллекций, областей, актора или TX callback.
type ChildParentCloseInput struct {
	ResourceType  string
	ResourceID    string
	SourceVersion time.Time
}

// ChildParentCloseTransactions закрывает приём потомков до отдельного каскада.
// Личность модуля берётся из проверенного контекста. Время возвращается только
// после Commit; повтор закрытия возвращает первоначальный closed_at.
type ChildParentCloseTransactions interface {
	RunChildParentClose(context.Context, ChildParentCloseInput) (time.Time, error)
}
