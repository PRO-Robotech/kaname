// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// pgmaperr_rate_test.go — отказ по ТЕМПУ заведения на мосту SQLSTATE→sentinel.
//
// ПРЕДМЕТ. Потолок темпа (миграция задачи #618) поднимает свои SQLSTATE'ы, отличные от
// тех, которыми отказывает потолок объёма. Мост, который их не знает, отправит
// отказ арендатора в последнюю ветвь — «неопознанный SQLSTATE» — и наружу уйдёт
// `INTERNAL "internal error"`: вызывающий увидит поломку платформы там, где она
// сработала ровно как задумано, и не узнает ни величины, ни окна.
//
// ПОЧЕМУ ТЕМП — СВОЙ SENTINEL, А ОТСУТСТВИЕ ВЕЛИЧИНЫ — ОБЩИЙ. Действия
// администратора у этих исходов разные, и различать надо именно их. «Окно полно»
// требует ПОДОЖДАТЬ — и это не то же, что «поднять предел объёма», поэтому
// sentinel свой. «Величина темпа не названа» требует ЗАВЕСТИ величину — ровно то
// же действие, что и при не названном пределе объёма, поэтому sentinel общий, а
// какую именно величину заводить, говорит текст производителя.

import (
	stderrors "errors"
	"strings"
	"testing"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// TestWrapPgErrClassifiesTheRateRefusal — оба SQLSTATE'а темпа опознаются, и
// каждый своим исходом.
func TestWrapPgErrClassifiesTheRateRefusal(t *testing.T) {
	const windowFull = "identity ext-42 has reached its admission rate of 3 iam.account per 3600 seconds"
	const rateNotStated = "identity ext-42 has no admission rate stated for iam.account"

	t.Run("KQ004 — окно полно", func(t *testing.T) {
		err := wrapPgErr(mkQuotaPgErr("KQ004", windowFull), "", "")
		if !stderrors.Is(err, iamerr.ErrQuotaRateExceeded) {
			t.Fatalf("отказ по темпу не опознан как ErrQuotaRateExceeded: %v", err)
		}
		if stderrors.Is(err, iamerr.ErrQuotaExceeded) {
			t.Error("отказ по темпу сведён с отказом по объёму: первый временен и лечится " +
				"ожиданием, второй терминален и лечится поднятием предела — свести их " +
				"значит отправить арендатора ждать того, что не наступит")
		}
		if got := iamerr.StripSentinel(err); got != windowFull {
			t.Errorf("текст производителя обязан доехать ДОСЛОВНО — он называет величину и "+
				"окно;\nполучено %q, ожидалось %q", got, windowFull)
		}
	})

	t.Run("KQ005 — величина темпа не названа", func(t *testing.T) {
		err := wrapPgErr(mkQuotaPgErr("KQ005", rateNotStated), "", "")
		if !stderrors.Is(err, iamerr.ErrQuotaNotProvisioned) {
			t.Fatalf("отсутствие величины темпа не опознано как ErrQuotaNotProvisioned: %v", err)
		}
		if stderrors.Is(err, iamerr.ErrQuotaRateExceeded) {
			t.Error("«величина не названа» сведена с «окно полно»: администратор пойдёт " +
				"поднимать то, чего не назначал")
		}
	})

	// Положительный контроль ПРОТИВОПОЛОЖНОЙ стороны: неопознанный SQLSTATE
	// по-прежнему уходит наружу непрозрачным. Без него проба выше зеленела бы на
	// мосту, объявляющем отказом учёта всё подряд.
	t.Run("чужой SQLSTATE остаётся непрозрачным", func(t *testing.T) {
		err := wrapPgErr(mkQuotaPgErr("XX000", "connection to 10.0.0.1:5432 failed"), "", "")
		if stderrors.Is(err, iamerr.ErrQuotaRateExceeded) || stderrors.Is(err, iamerr.ErrQuotaExceeded) {
			t.Fatalf("посторонний отказ объявлен отказом учёта: %v", err)
		}
		if strings.Contains(iamerr.StripSentinel(err), "10.0.0.1") {
			t.Error("координата хранилища утекла наружу вместе с текстом драйвера")
		}
	})
}
