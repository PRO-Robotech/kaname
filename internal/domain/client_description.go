// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// client_description.go — описание клиента, каким его назвал запрос выдачи
// сессии (задача PRO-Robotech/kaname#634; приёмка
// `docs/engineering/acceptance/own-sessions-are-listed-and-ended-by-their-owner.md`,
// Р3).
//
// # Значение не разбирается и не толкуется
//
// Это заголовок `User-Agent` выдающего запроса в том виде, в каком его доставил
// край. Ни «браузер», ни «система» из него не выводятся: разбор строки клиента —
// эвристика, а неверное имя устройства хуже отсутствующего.
//
// # Приведение — два шага, в этом порядке, и ни один не отказывает
//
//  1. каждый байт, не входящий в допустимую последовательность UTF-8, — одна
//     руна U+FFFD (по руне на БАЙТ, а не на серию: `strings.ToValidUTF8`
//     свернула бы серию в одну руну);
//  2. из результата хранятся первые ClientDescriptionMaxRunes рун.
//
// Урезание по рунам не разрезает многобайтовую последовательность, поэтому
// хранимое значение — всегда допустимый UTF-8 не длиннее предела. Заголовок,
// который слушатель принял, вход не роняет: приведение не меняет исхода
// выдающего глагола.
//
// Руна U+0000 — та же замена, что у байта вне UTF-8: хранилище (текст Postgres)
// её не держит, и запись с ней уронила бы выдачу. Слушатель HTTP такой заголовок
// не доставляет вовсе (управляющий байт в значении — отказ разбора запроса),
// так что это ограда типа, а не правило полосы.
//
// # Отсутствие представимо отдельно от значения
//
// Заголовка нет либо он пуст — описания нет (IsZero). Пустого описания не
// бывает: ограничение схемы `human_sessions_user_agent_check` держит то же.

import (
	"strings"
	"unicode/utf8"
)

// ClientDescriptionMaxRunes — предел хранимого описания в рунах (Р3).
const ClientDescriptionMaxRunes = 512

// ClientDescription — приведённое описание клиента; нулевое значение — описания
// нет.
type ClientDescription struct {
	value string
}

// NewClientDescription — приведение сырого значения заголовка (шаги шапки).
// Пустой вход — отсутствие. Приведение идемпотентно: значение, прочитанное из
// записи, приводится в себя.
func NewClientDescription(raw string) ClientDescription {
	if raw == "" {
		return ClientDescription{}
	}
	var b strings.Builder
	b.Grow(len(raw))
	runes := 0
	for i := 0; i < len(raw) && runes < ClientDescriptionMaxRunes; {
		r, size := utf8.DecodeRuneInString(raw[i:])
		if r == utf8.RuneError && size <= 1 {
			// Байт вне допустимой последовательности: ровно одна замена на байт.
			size = 1
		}
		if r == 0 {
			r = utf8.RuneError
		}
		b.WriteRune(r)
		runes++
		i += size
	}
	return ClientDescription{value: b.String()}
}

// IsZero — описания нет.
func (c ClientDescription) IsZero() bool { return c.value == "" }

// Value — приведённое значение; у отсутствия — пустая строка.
func (c ClientDescription) Value() string { return c.value }
