// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package mail

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/corelib/notify/address"
	"github.com/PRO-Robotech/corelib/notify/feed"
	"github.com/PRO-Robotech/corelib/notify/form"
)

// Letter — письмо шаблона: шаблон, атрибуты и адресат, проверенные
// конструктором (letters.go). Закрытый тип: строит его только конструктор
// своего шаблона, и нулевой Letter Enqueue не принимает (ErrLetterUnbuilt).
type Letter struct {
	template string
	// put ставит письмо порождённым Send* шаблона в транзакции tx и отвечает
	// id записанной строки ленты и признаком, что строка записана.
	put func(ctx context.Context, tx pgx.Tx) (id string, queued bool, err error)
}

// Template — имя шаблона; у нулевого Letter — пусто.
func (l Letter) Template() string { return l.template }

// letterOf — письмо шаблона tmpl, которое ставит порождённая функция send.
func letterOf[A any](tmpl string, send func(context.Context, pgx.Tx, A) (feed.Queued, error), attrs A) Letter {
	return Letter{template: tmpl, put: func(ctx context.Context, tx pgx.Tx) (string, bool, error) {
		q, err := send(ctx, tx, attrs)
		if err != nil {
			return "", false, err
		}
		id, queued := q.ID()
		return id, queued, nil
	}}
}

// presence — состояние закрытого типа присутствия.
type presence uint8

const (
	// presenceUnset — нулевой литерал Optional{}: ни Present, ни Absent (УК48).
	presenceUnset presence = iota
	presenceGiven
	presenceAbsent
)

// Optional — значение optional атрибута шаблона (З1, З27): Present(v) либо
// Absent(). Отсутствие представимо отдельно от значения: пустая строка «нет
// значения» не означает, и Present("") конструктор отвергает так же, как нуль
// required. Нулевой литерал Optional{} — ни то ни другое, и конструктор его
// отвергает (УК48): иначе забытый аргумент молча стал бы «значения нет».
type Optional struct {
	v     string
	state presence
}

// Present — значение optional атрибута задано.
func Present(v string) Optional { return Optional{v: v, state: presenceGiven} }

// Absent — значения optional атрибута нет: письмо собирается без него.
func Absent() Optional { return Optional{state: presenceAbsent} }

// attrError — отказ конструктора: шаблон, атрибут и правило, без значения.
func attrError(tmpl, attr, rule string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%w: шаблон %s: атрибут %s: %s: %w", ErrLetterInvalid, tmpl, attr, rule, cause)
	}
	return fmt.Errorf("%w: шаблон %s: атрибут %s: %s", ErrLetterInvalid, tmpl, attr, rule)
}

// required — значение required атрибута: нуль своего вида — отказ с именем
// атрибута до Send*. Решение «нуль ли это» принимает form.Presence corelib —
// та же функция, которой судит лента.
func required(tmpl, attr string, kind form.Kind, raw any) error {
	_, present, err := form.Presence(kind, raw)
	if err != nil {
		return attrError(tmpl, attr, "значение вне формы", err)
	}
	if present == form.Absent {
		return attrError(tmpl, attr, "required без значения", nil)
	}
	return nil
}

// optionalValue — значение optional атрибута в форме поля Send*: Absent — нуль
// поля («не задан» у Send*), Present — значение, судимое как required.
func optionalValue(tmpl, attr string, kind form.Kind, o Optional) (string, error) {
	switch o.state {
	case presenceAbsent:
		return "", nil
	case presenceGiven:
		if err := required(tmpl, attr, kind, o.v); err != nil {
			return "", err
		}
		return o.v, nil
	case presenceUnset:
	}
	return "", attrError(tmpl, attr, "нулевой литерал Optional — ни Present, ни Absent", nil)
}

// addressRecipient — адресат формы address: значение address.Normalized; нуль
// — отказ с причиной address.ErrUnset.
func addressRecipient(tmpl string, to address.Normalized) (string, error) {
	v, err := to.Value()
	if err != nil {
		return "", attrError(tmpl, "to", "адресат формы address не задан", err)
	}
	return v, nil
}

// subjectUserPrefix — приставка адресата формы subject (NTF-3 Р27): user:<id>.
// Форму id судит лента (feed.Put, auth.InitiatorOf) — второго судьи здесь нет.
const subjectUserPrefix = "user:"

// subjectRecipient — адресат формы subject: id пользователя; пустой — отказ.
func subjectRecipient(tmpl, userID string) (string, error) {
	if userID == "" {
		return "", attrError(tmpl, "to", "адресат формы subject — пустой id пользователя", nil)
	}
	return subjectUserPrefix + userID, nil
}
