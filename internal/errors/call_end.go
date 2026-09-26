// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package errors

import (
	"context"
	stderrors "errors"
	"fmt"
)

// OnEndedCall — отказ хранилища БЕЗ СОБСТВЕННОЙ ПРИЧИНЫ (`ErrInternal`,
// `ErrUnavailable`), пришедший, когда контекст вызова уже кончился, несёт конец
// контекста в цепочке (kaname#383, #423).
//
// Пул службы доводит отмену до сервера (`corelib/db.NewPool`), и оператор
// снимается там строкой состояния 57014 — без ошибки контекста в цепочке. Тот,
// кто судит отказ по цепочке (мост церемонии фундамента: срок и отмена вызова
// порта — временная недоступность, прочее — отказ сервера), иначе прочёл бы
// конец срока вызова поломкой. Различает их ровно один факт — кончился ли
// контекст, на котором шёл вызов, поэтому ctx — ТОТ контекст, на котором
// исполнялся вызов хранилища.
//
// Ответ, называющий свою причину (записи нет, ввод негоден, конфликт), о сроке
// не говорит и возвращается нетронутым; тот же 57014 на живом контексте —
// собственный потолок оператора — остаётся отказом хранилища.
func OnEndedCall(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	end := ctx.Err()
	switch {
	case end == nil,
		stderrors.Is(err, context.Canceled), stderrors.Is(err, context.DeadlineExceeded),
		!stderrors.Is(err, ErrInternal) && !stderrors.Is(err, ErrUnavailable):
		return err
	}
	return fmt.Errorf("%w: %w", end, err)
}
