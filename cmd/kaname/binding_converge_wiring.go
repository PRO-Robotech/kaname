// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// binding_converge_wiring.go — величины сводящего прохода по выдачам: такт
// повтора и срок одного вызова (kaname#1006).
//
// # Что назначает такт
//
// Сводящий проход — единственный путь, которым у выдачи одному субъекту
// снимается лишний кортеж после смены вычисления (шапка
// `seed/binding_converge.go`). Такт и есть верхняя граница окна, в котором
// лишнее, записанное репликой прежней версии во время перекрытия выкатки, ещё
// действует после её ухода: интервал плюс длительность прохода. Умолчание —
// пять минут: проход читает реестр всех действующих выдач, и платить это чаще,
// чем обход по таймеру реконсайлера платит пересчёт выдач с селектором (30 с),
// незачем — расхождение рождается только выкаткой.
//
// # Что назначает срок
//
// Срок одного вызова ограничивает ожидание замка выдачи и саму сверку. Без него
// зависшее ожидание держало бы замок-одиночку прохода, и такты всех реплик
// пропускались бы. Выдача, не уложившаяся в срок, называется в переписи и в
// счётчике `kaname_binding_converge_total{outcome="failed"}` и повторяется
// следующим тактом.

import "time"

const (
	bindingConvergeIntervalKnob = "KANAME_BINDING_CONVERGE_INTERVAL_MS"
	bindingConvergeTimeoutKnob  = "KANAME_BINDING_CONVERGE_TIMEOUT_MS"
)

// Умолчания — величины, с которыми процесс работает без ручки посадки.
const (
	defaultBindingConvergeInterval = 5 * time.Minute
	defaultBindingConvergeTimeout  = 5 * time.Minute
)

// bindingConvergeWindows — величины, с которыми процесс БУДЕТ сводить выдачи.
type bindingConvergeWindows struct {
	// Interval — такт повтора сводящего прохода.
	Interval time.Duration
	// BindingTimeout — срок одного вызова сведения выдачи.
	BindingTimeout time.Duration
}

// readBindingConvergeWindows читает обе ручки один раз; пустое, нечисловое и
// неположительное значение — умолчание (форма `envDurationMS`).
func readBindingConvergeWindows() bindingConvergeWindows {
	return bindingConvergeWindows{
		Interval:       envDurationMS(bindingConvergeIntervalKnob, defaultBindingConvergeInterval),
		BindingTimeout: envDurationMS(bindingConvergeTimeoutKnob, defaultBindingConvergeTimeout),
	}
}
