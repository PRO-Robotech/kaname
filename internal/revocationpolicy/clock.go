// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package revocationpolicy

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Clock — ОДИН источник моментов, которые сравниваются с отсечкой отзыва-всех
// (задача kaname#589): отсечки «сейчас», выдачи долговременного удостоверения,
// аутентификации сессии. `iat` ставит подписант тем же источником через свой
// порт той же формы (`tokensigner.Clock`).
//
// Реплик службы больше одной. Часы процесса у каждой свои, и правило, судящее
// момент одной реплики отсечкой, записанной другой, судило бы их расхождение, а
// не порядок событий. Источник один на все реплики by construction — первичная
// база (`kanamepg.SharedClock`). Её же часами отсечку ставят схемные писатели
// (триггеры снятия клиента и деактивации владельца), поэтому второго источника
// у сравнения не остаётся.
//
// Вызов сетевой и потому может не ответить. Не ответил — это ОТКАЗ записи
// момента, а не подстановка часов процесса: момент от другого источника и есть
// дефект, который этот порт снимает. Запасного пути нет.
type Clock interface {
	// Now — момент источника. Ошибка не сворачивается в нулевой момент.
	Now(ctx context.Context) (time.Time, error)
}

// ErrNoClock — источник моментов не подан. Построение, получившее его, обязано
// отказать: полоса без источника не собирается, а не деградирует к часам
// процесса.
var ErrNoClock = errors.New("revocationpolicy: shared clock is not wired")

// ErrClockUnavailable — источник моментов не ответил. Несёт причину для
// журнала вызывающего; наружу не выходит.
var ErrClockUnavailable = errors.New("revocationpolicy: shared clock did not answer")

// ClockWithDeadline оборачивает источник собственным пределом на КАЖДЫЙ вызов —
// той же величиной, что читатель отсечки ([WithDeadline]): момент и отсечка
// читаются одним видом запроса к одной базе.
//
// Неположительный предел — отказ построения ([ErrLimitNotPositive]); неподанный
// источник — отказ построения ([ErrNoClock]): у источника моментов, в отличие
// от читателя отсечки, «не провязан» законным состоянием не бывает.
func ClockWithDeadline(inner Clock, timeout time.Duration) (Clock, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("%w, got %s", ErrLimitNotPositive, timeout)
	}
	if inner == nil {
		return nil, ErrNoClock
	}
	return deadlineClock{inner: inner, timeout: timeout}, nil
}

type deadlineClock struct {
	inner   Clock
	timeout time.Duration
}

func (d deadlineClock) Now(ctx context.Context) (time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.Now(ctx)
}

// Moment — момент источника для записи, сравниваемой с отсечкой.
//
// Ошибка — всегда [ErrClockUnavailable] (с причиной внутри); нулевой момент
// без ошибки — тоже она: нулевой момент правило читает как «возникло не позже
// любой отсечки» ([Forbids]), и записать его значило бы отозвать выданное в
// момент выдачи. Неподанный источник — [ErrNoClock].
func Moment(ctx context.Context, c Clock) (time.Time, error) {
	if c == nil {
		return time.Time{}, ErrNoClock
	}
	at, err := c.Now(ctx)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrClockUnavailable, err)
	}
	if at.IsZero() {
		return time.Time{}, fmt.Errorf("%w: zero moment", ErrClockUnavailable)
	}
	return at.UTC(), nil
}

// MomentFailureClass — класс отказа источника для журнала: «deadline»,
// «canceled», «unwired» или «store». Текст причины в журнал не идёт: ошибка
// драйвера несёт координаты соединения.
func MomentFailureClass(err error) string {
	switch {
	case errors.Is(err, ErrNoClock):
		return "unwired"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "store"
	}
}
