// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
)

// errNoCutoffClock — построение полосы без источника моментов (kaname#589).
// Полоса, ставящая момент сессии или отсечки, без него не собирается: часы
// процесса этой реплики — ровно тот второй источник, который снят.
var errNoCutoffClock = errors.New("shared clock required (moments compared with the revoke-all cutoff)")

// sharedMoment — момент записи, которая сравнивается с отсечкой отзыва-всех
// (момент аутентификации сессии, сама отсечка): из ОБЩЕГО для всех реплик
// источника, в разрешении хранилища.
//
// Зовётся ДО открытия транзакции полосы: источник читается своим соединением,
// и чтение изнутри открытой транзакции брало бы второе соединение на запрос.
//
// Не ответил — ошибка; вызывающий отвечает своим отказом «не выполнено»
// ([ErrStoreUnavailable]) и ничего не пишет. В журнал — шаг и класс причины,
// без текста причины и без личных данных.
func sharedMoment(ctx context.Context, c revocationpolicy.Clock, logger *slog.Logger, verb string) (time.Time, error) {
	at, err := revocationpolicy.Moment(ctx, c)
	if err != nil {
		logger.ErrorContext(ctx, verb+": shared moment unavailable",
			"step", "shared-moment", "class", revocationpolicy.MomentFailureClass(err))
		return time.Time{}, err
	}
	return at.Truncate(time.Microsecond), nil
}
