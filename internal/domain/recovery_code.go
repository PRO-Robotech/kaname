// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// recovery_code.go — КОД ВОССТАНОВЛЕНИЯ ДОСТУПА и его запись (фаза Ф5, задача
// PRO-Robotech/kacho#1271; приёмка `docs/engineering/acceptance/recovery-of-access.md`,
// решение Р1).
//
// # Код — предъявитель, и значение выходит РОВНО ДВУМЯ путями
//
// Обладание кодом даёт право сменить пароль (Р1). Поэтому значение устроено как
// носитель сессии (`SessionBearer`) и материал пароля (`LoginVerifier`): тип не
// печатается, не пишется в журнал и не сериализуется — общие пути вывода отдают
// заглушку либо отказ. Выходов два: `Digest` — в хранилище, `Letter` — в письмо.
//
// # Что хранится — свёртка, и почему этого достаточно для Ф5-07
//
// Хранилище знает SHA-256 значения, а не значение. Тот, кто видит хранимую
// строку, располагает свёрткой; предъявленная как код, она даёт свёртку свёртки
// и не совпадает ни с чем (Ф5-07). Срок кода — пять минут (Ф1 §4.1), применение
// однократно и решается одним оператором базы (Ф5-04, Ф5-05), число неверных
// предъявлений ограничено окном частоты (Ф5-08) — три рубежа сверх свёртки.
// Граница названа: свёртка без ключа обратима перебором пространства кода, и
// оно у нас 32¹⁰ ≈ 10¹⁵ — читающий базу и располагающий вычислительной
// мощностью может успеть за срок кода. Тот же читатель видит в очереди писем
// открытый код до сдачи письма узлу, поэтому второй рубеж против него — не
// свёртка, а срок и однократность, а сама очередь пустеет уборкой.
//
// # Форма — десять знаков алфавита Крокфорда, для человека две группы по пять
//
// Алфавит без I, L, O, U: знаки, которые путают с цифрами, при вводе приводятся
// к ним (I, L → 1; O → 0), регистр и разделители не значимы. Человек, набравший
// код с письма как прочитал, отказа за нашу же типографику не получает.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// RecoveryCodeID — идентификатор ПОТОКА восстановления: строка кода и ключ
// идемпотентности журнала завершений (Р4). Наружу не адресуется.
type RecoveryCodeID string

// CodeDigest — свёртка кода в хранилище (шестнадцатеричная запись SHA-256).
type CodeDigest string

// RecoveryCodeLength — длина кода в знаках алфавита без разделителя: 10 знаков
// по 5 бит — 50 бит случайности.
const RecoveryCodeLength = 10

// recoveryCodeAlphabet — алфавит Крокфорда: 32 знака без I, L, O, U.
const recoveryCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// recoveryCodeRedacted — заглушка на всяком общем пути вывода.
// #nosec G101 -- это ЗАМЕНА кода в выводе, а не сам код.
const recoveryCodeRedacted = "[redacted recovery code]"

// ErrRecoveryCodeNotSerializable — код не сериализуется ни в JSON, ни в текст:
// в письмо он уходит одним путём — `Letter` из писателя очереди.
var ErrRecoveryCodeNotSerializable = errors.New("recovery code is not serializable")

// RecoveryCodeValue — значение кода (Р1). Тип не печатается и не сериализуется;
// значение выходит ровно двумя методами: `Digest` (в хранилище) и `Letter`
// (в письмо).
type RecoveryCodeValue struct {
	box *recoveryCodeBox
}

type recoveryCodeBox struct {
	// canonical — знаки алфавита без разделителей, в верхнем регистре.
	canonical string
}

// NewRecoveryCodeValue — свежий код из криптографического источника
// случайности: каждый знак — независимый выбор из алфавита.
func NewRecoveryCodeValue() (RecoveryCodeValue, error) {
	var raw [RecoveryCodeLength]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return RecoveryCodeValue{}, fmt.Errorf("recovery code: random source: %w", err)
	}
	b := make([]byte, RecoveryCodeLength)
	for i, r := range raw {
		b[i] = recoveryCodeAlphabet[int(r)%len(recoveryCodeAlphabet)]
	}
	return RecoveryCodeValue{box: &recoveryCodeBox{canonical: string(b)}}, nil
}

// PresentedRecoveryCode — код, как его прислал человек: регистр и разделители
// (пробелы, дефисы) не значимы, знаки-двойники приводятся к своим. Пустое после
// нормализации — отсутствие кода.
func PresentedRecoveryCode(value string) RecoveryCodeValue {
	var b strings.Builder
	for _, r := range strings.ToUpper(value) {
		switch {
		case r == ' ' || r == '-' || r == '\t':
			continue
		case r == 'I' || r == 'L':
			b.WriteByte('1')
		case r == 'O':
			b.WriteByte('0')
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return RecoveryCodeValue{}
	}
	return RecoveryCodeValue{box: &recoveryCodeBox{canonical: b.String()}}
}

// IsZero — кода нет.
func (v RecoveryCodeValue) IsZero() bool { return v.box == nil || v.box.canonical == "" }

// Letter — форма для письма: две группы через дефис. Единственный выход к
// человеку.
func (v RecoveryCodeValue) Letter() string {
	if v.box == nil {
		return ""
	}
	c := v.box.canonical
	if len(c) != RecoveryCodeLength {
		return c
	}
	return c[:RecoveryCodeLength/2] + "-" + c[RecoveryCodeLength/2:]
}

// Digest — свёртка, по которой хранилище находит строку. Хранится и
// сравнивается только она.
func (v RecoveryCodeValue) Digest() CodeDigest {
	if v.box == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(v.box.canonical))
	return CodeDigest(hex.EncodeToString(sum[:]))
}

// String — заглушка.
func (v RecoveryCodeValue) String() string { return recoveryCodeRedacted }

// GoString — заглушка и для `%#v`.
func (v RecoveryCodeValue) GoString() string {
	return "domain.RecoveryCodeValue{" + recoveryCodeRedacted + "}"
}

// Format — заглушка на любом глаголе форматирования.
func (v RecoveryCodeValue) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, v.GoString())
		return
	}
	_, _ = io.WriteString(f, recoveryCodeRedacted)
}

// LogValue — заглушка для журнала.
func (v RecoveryCodeValue) LogValue() slog.Value { return slog.StringValue(recoveryCodeRedacted) }

// MarshalJSON — отказ.
func (v RecoveryCodeValue) MarshalJSON() ([]byte, error) { return nil, ErrRecoveryCodeNotSerializable }

// MarshalText — отказ.
func (v RecoveryCodeValue) MarshalText() ([]byte, error) { return nil, ErrRecoveryCodeNotSerializable }

// RecoveryCode — запись кода (Р1). Состав закрыт: личность, свёртка, момент
// выдачи, срок, момент применения.
type RecoveryCode struct {
	ID     RecoveryCodeID
	UserID UserID
	Digest CodeDigest
	// IssuedAt — момент чеканки (часы полосы).
	IssuedAt time.Time
	// ExpiresAt — абсолютный срок, ОДИН столбец; величина — настройка.
	ExpiresAt time.Time
	// ConsumedAt — момент применения; nil — не применён. Ставит его один
	// оператор базы (Ф5-05).
	ConsumedAt *time.Time
}

// Validate — запись, годная к выдаче: судится до базы то, что база держит
// ограничениями.
func (c RecoveryCode) Validate() error {
	if c.ID == "" {
		return fmt.Errorf("Illegal argument recovery_code.id: required")
	}
	if c.UserID == "" {
		return fmt.Errorf("Illegal argument recovery_code.user_id: required")
	}
	if len(c.Digest) != 64 || strings.Trim(string(c.Digest), "0123456789abcdef") != "" {
		return fmt.Errorf("Illegal argument recovery_code.code_digest: must be a hex SHA-256")
	}
	if c.IssuedAt.IsZero() {
		return fmt.Errorf("Illegal argument recovery_code.issued_at: required")
	}
	if !c.ExpiresAt.After(c.IssuedAt) {
		return fmt.Errorf("Illegal argument recovery_code.expires_at: must follow issued_at")
	}
	return nil
}

// Expired — истёк ли срок на данный момент. Граница включающая: в сам момент
// срока кода уже нет.
func (c RecoveryCode) Expired(now time.Time) bool { return !now.Before(c.ExpiresAt) }
