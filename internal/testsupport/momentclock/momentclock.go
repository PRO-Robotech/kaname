// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package momentclock — управляемые источники моментов для проб (kaname#589).
//
// Производственный источник моментов, сравниваемых с отсечкой, один — часы
// первичной базы (`kanamepg.SharedClock`), и подаёт его только корень. Пробам,
// которым база не нужна, нужен источник той же формы
// (`revocationpolicy.Clock`, `tokensigner.Clock`) с управляемым ответом — в том
// числе с отказом: путь «источник не ответил» обязан быть исполнимым в пробе.
//
// Пакет живёт в `testsupport` и в производственное дерево не провязывается:
// источник «часы процесса», поданный корнем, и есть дефект, который снят.
package momentclock

import (
	"context"
	"time"
)

// Func — источник, отвечающий показанием функции. `Func(time.Now)` — часы
// процесса пробы; `Func(func() time.Time { return at })` — застывшие часы.
type Func func() time.Time

// Now — показание функции; ошибки не бывает.
func (f Func) Now(context.Context) (time.Time, error) { return f(), nil }

// At — застывший источник: всегда отвечает at.
func At(at time.Time) Func { return func() time.Time { return at } }

// Failing — источник, который не отвечает: каждый вызов — err.
type Failing struct{ Err error }

// Now — всегда отказ.
func (f Failing) Now(context.Context) (time.Time, error) { return time.Time{}, f.Err }
