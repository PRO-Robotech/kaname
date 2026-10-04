// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"fmt"
	"time"
)

// notifications.go — ФЛАГ ПОЧТЫ службы (замысел NTF-2 З2, приёмка NTF2-50).
//
// Значение трёхзначно НА ВХОДЕ и двузначно в процессе: «объявлено `true`»,
// «объявлено `false`» и «не объявлено». Третье — отказ старта с именем ключа, а
// не молча выбранное значение: `false` законно (почты у установки нет), и
// подставленное построением было бы выбором за оператора. Поэтому поле —
// указатель, умолчания в `defaults.go` нет, а привязка к окружению идёт строкой
// таблицы границ (`mail_bounds.go`), как у прочих ручек без умолчания.
//
// Наличие судится по указателю: декодер заводит его только для ключа, который
// дал какой-то слой — файл либо привязанная переменная, — то есть ровно тогда,
// когда `viper.IsSet` отвечает «да».

// NotificationsConfig — секция `notifications`.
type NotificationsConfig struct {
	// Enabled — включена ли почта службы. nil — ключ не объявлен.
	Enabled *bool `mapstructure:"enabled"`

	// CutoffGuard — полоса отсечки `notificationCutoffGuard` (приёмка NTF-1 Р5,
	// NTF1-F20): строка ленты, поставленная раньше отсечки последнего Restore
	// плюс полоса, — REVOKED. Часы источника и часы kaname разные, и строка,
	// поставленная до Restore по часам kaname, не проходит из-за опережающих
	// часов источника. Умолчания нет: nil — ключ не объявлен, и строитель
	// службы выдачи отказывает в старте с именем ключа; граница — [1s..10m].
	CutoffGuard *time.Duration `mapstructure:"cutoff-guard"`
}

// CutoffGuardKey — путь ключа полосы; его называет отказ строителя.
const CutoffGuardKey = "notifications.cutoff-guard"

// Границы полосы отсечки (Р5), включительно.
const (
	CutoffGuardMin = time.Second
	CutoffGuardMax = 10 * time.Minute
)

// CutoffGuardValue — полоса, судимая по объявлению и границе. Отказ называет
// ключ и границу.
func (n NotificationsConfig) CutoffGuardValue() (time.Duration, error) {
	g, err := Declared(n.CutoffGuard, CutoffGuardKey)
	if err != nil {
		return 0, fmt.Errorf("%w: полоса отсечки умолчания не имеет — объявите её в границах [%s..%s]",
			err, CutoffGuardMin, CutoffGuardMax)
	}
	if g < CutoffGuardMin || g > CutoffGuardMax {
		return 0, fmt.Errorf("%s (%s) = %s вне границ [%s..%s]", CutoffGuardKey, EnvNameOfKey(CutoffGuardKey),
			g, CutoffGuardMin, CutoffGuardMax)
	}
	return g, nil
}
