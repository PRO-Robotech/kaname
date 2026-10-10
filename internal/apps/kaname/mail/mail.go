// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mail — постановка письма kaname на ленту notify (приёмка NTF-2;
// замысел issue-2917 З1–З3, З27).
//
// Пакет — ЕДИНСТВЕННЫЙ не-тестовый вызыватель порождённых функций Send*
// (`feedgen`, вывод notifygen): письмо собирается конструктором Letter своего
// шаблона и ставится портом Enqueuer в транзакции события вызывающего. Решение
// «ставить строку или нет» принимает только Enqueue: места вызова строку не
// решают. Держит это гейт дерева `mail_single_enqueuer`
// (internal/check/mail_single_enqueuer.go).
//
// Исходы Enqueue — закрытый тип Outcome; сторож ленты, кроме исчерпанного
// лимита шаблона, и ошибка хранилища — ошибка, и транзакция события
// откатывается (З1, О6). Корзины «прочее» нет.
package mail

import (
	"errors"
)

// EnabledKey — ключ конфигурации kaname, из которого корень разбирает флаг
// (З2). Им же отказ называет ключ.
const EnabledKey = "notifications.enabled"

// Enabled — флаг почты kaname, разобранный корнем один раз (З2, CX2-02 (а)).
// Закрытый тип: строит его только EnabledFrom, и нулевое значение («не
// разобрано») NewEnqueuer и приёмник метрики не принимают — false из
// незаданного неотличим от выключенной почты.
type Enabled struct {
	on, set bool
}

// EnabledFrom разбирает значение ключа notifications.enabled, прочитанное
// загрузчиком конфигурации как *bool: nil — ключ не объявлен, и это отказ, а
// не false (NTF2-50); false — законное значение.
func EnabledFrom(v *bool) (Enabled, error) {
	if v == nil {
		return Enabled{}, errors.New(EnabledKey + " must be declared")
	}
	return Enabled{on: *v, set: true}, nil
}

// On — значение флага.
func (e Enabled) On() bool { return e.on }

// Set — разобрано ли значение EnabledFrom.
func (e Enabled) Set() bool { return e.set }

// Сторожа пакета — различимы через errors.Is.
var (
	// ErrLetterInvalid — конструктор Letter отверг значение атрибута либо
	// адресата; текст называет шаблон и атрибут, значения не несёт.
	ErrLetterInvalid = errors.New("mail: письмо не собрано")
	// ErrLetterUnbuilt — Enqueue получил письмо, построенное мимо конструктора
	// (нулевой Letter): шаблона и постановки у него нет.
	ErrLetterUnbuilt = errors.New("mail: письмо построено мимо конструктора")
	// ErrFlagMismatch — флаг пакета включён, а источник ленты строку не записал:
	// флаг пакета и флаг источника ленты разошлись — дефект сборки корня.
	ErrFlagMismatch = errors.New("mail: флаг почты включён, а строка ленты не записана — флаг пакета и источника ленты разошлись")
)
