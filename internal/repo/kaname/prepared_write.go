// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package kaname

import "context"

// PreparedWriteRepository явно владеет целой подготовленной мутацией.
// Callback не коммитит, не публикует внешние эффекты и не сохраняет writer.
type PreparedWriteRepository interface {
	RunPreparedWrite(context.Context, func(context.Context, Writer) error) error
}

// PreparedWriteExecutor принадлежит backend factory. Open выбирает конкретный
// настроенный prepared порт; повтор заново читает OLD и принимает authority.
type PreparedWriteExecutor interface {
	ExecutePreparedWrite(context.Context, func(context.Context) (Writer, error), func(context.Context, Writer) error) error
}
