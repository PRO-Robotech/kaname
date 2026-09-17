// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// login_method.go — способ входа человека (фаза Ф2, задача `kacho#1268`).
//
// Способ — СТРОКА своей таблицы (`kaname.user_login_methods`), а не колонка в
// зеркале человека: второй вид способа тогда заводится правкой словаря, а не
// переносом каждой строки (F4d, Р4). Санкция: одобренная Ф1, ведомость §5,
// строка Ф2; F4d-13…F4d-15, причём F4d-13 — ЧАСТИЧНО.
//
// F4d-13 требует от строки «вид способа, проверочный материал, уровень доверия
// и состояние». Держатся вид, материал и — с фазы Ф12 (PRO-Robotech/kacho#1281,
// приёмка `second-factor-totp-and-recovery-codes.md`, Р1) — СОСТОЯНИЕ: `pending`
// (секрет чеканен, первый код не предъявлен) · `active` (подтверждён). Строка
// `pending` способом входа НЕ является: её не читает ни правило уровня, ни
// полоса входа. Уровень доверия в строке НЕ заведён и не будет: он есть функция
// предъявленного, а не способа (Ф11 Р1, PRO-Robotech/kacho#1280) — хранимый
// рядом, он был бы неверен для каждого предъявления, где сверки не было.
// Решение о составе строки — PRO-Robotech/kacho#1268 (комментарий 5680711802).
//
// Виды и их состояния: у `password` и `lookup_secret` состояние ровно одно —
// `active` (ограничение схемы `user_login_methods_pending_only_totp_check`);
// `pending` бывает только у `totp`. Сверх материала строка `totp` несёт
// ПОСЛЕДНИЙ ПРИНЯТЫЙ ШАГ (Ф12 Р5): состояние сверки, не секрет; код шага не
// старше него отвергается повтором.

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/assurance"
)

// LoginMethodKind — вид способа входа. Словарь ЗАКРЫТ и совпадает с
// ограничением таблицы `user_login_methods_kind_check`.
//
// ИМЕНА БЕРУТСЯ У СЛОВАРЯ СПОСОБОВ ПРЕДЪЯВЛЕНИЯ (`internal/assurance`, Ф11 Р8),
// а не пишутся здесь литералами: словарь объявлен ОДИН раз, и второе объявление
// перечня имён в прод-коде службы — находка гейта
// `TestAssuranceMethodVocabularyIsDeclaredOnce`. Видов три (Ф12 Р1):
// пароль · код по времени · набор запасных кодов; ключ доступа (`webauthn`)
// строкой этой таблицы не является — его хранилище заводит Ф7 своей приёмкой.
type LoginMethodKind string

// LoginMethodPassword — пароль: строка несёт его проверочный материал.
var LoginMethodPassword = LoginMethodKind(assurance.MethodPassword.String())

// LoginMethodTOTP — одноразовый код по времени (RFC 6238): строка несёт секрет
// ОБЁРНУТЫМ (Ф12 Р2) и последний принятый шаг.
var LoginMethodTOTP = LoginMethodKind(assurance.MethodTOTP.String())

// LoginMethodLookupSecret — набор запасных кодов: строка несёт проверочный
// материал набора, из которого значение кода не восстановимо (Ф12 Р6).
var LoginMethodLookupSecret = LoginMethodKind(assurance.MethodLookupSecret.String())

var loginMethodKinds = []LoginMethodKind{LoginMethodPassword, LoginMethodTOTP, LoginMethodLookupSecret}

// LoginMethodState — состояние строки способа (Ф12 Р1). Значений ровно два,
// закреплены ограничением схемы `user_login_methods_state_check`.
type LoginMethodState string

const (
	// LoginMethodStatePending — секрет чеканен, первый код не предъявлен.
	// Способом входа такая строка не является и живёт не дольше окна свежести
	// правки своих данных (Ф12 Р8); снимает её уборка либо новое заведение.
	LoginMethodStatePending LoginMethodState = "pending"
	// LoginMethodStateActive — подтверждён; единственное состояние `password`
	// и `lookup_secret`.
	LoginMethodStateActive LoginMethodState = "active"
)

// Validate — состояние из словаря.
func (s LoginMethodState) Validate() error {
	switch s {
	case LoginMethodStatePending, LoginMethodStateActive:
		return nil
	}
	return fmt.Errorf("Illegal argument login_method.state %q (allowed: %s|%s)", string(s),
		LoginMethodStatePending, LoginMethodStateActive)
}

// LoginMethodKinds — словарь видов; копия, чтобы вызывающий не мог его расширить.
func LoginMethodKinds() []LoginMethodKind {
	out := make([]LoginMethodKind, len(loginMethodKinds))
	copy(out, loginMethodKinds)
	return out
}

// ParseLoginMethodKind — вид из строки. Написание одно: регистр и пробелы не
// нормализуются, иначе вид становится несколькими значениями.
func ParseLoginMethodKind(s string) (LoginMethodKind, error) {
	k := LoginMethodKind(s)
	if err := k.Validate(); err != nil {
		return "", err
	}
	return k, nil
}

// Validate — вид из словаря.
func (k LoginMethodKind) Validate() error {
	for _, known := range loginMethodKinds {
		if k == known {
			return nil
		}
	}
	allowed := make([]string, len(loginMethodKinds))
	for i, known := range loginMethodKinds {
		allowed[i] = string(known)
	}
	return fmt.Errorf("Illegal argument login_method.kind %q (allowed: %s)", string(k), strings.Join(allowed, "|"))
}

// loginVerifierRedacted — то, что видит всякий путь вывода вместо материала.
const loginVerifierRedacted = "[redacted login verifier]"

// ErrLoginVerifierNotSerializable — материал не сериализуется. Отказ ГРОМКИЙ:
// молча выданное пустое читалось бы как «материала нет», то есть было бы ложью
// о строке.
var ErrLoginVerifierNotSerializable = errors.New("login verifier is not serializable")

// LoginVerifier — проверочный материал способа входа: хеш пароля в той форме, в
// какой его создала функция хеширования (прежнего поставщика либо наша). Это
// СЕКРЕТ: хеш не пароль, но перебор офлайн по нему возможен.
//
// Устройство выбрано так, чтобы материал не уезжал из процесса ни одним общим
// путём вывода:
//
//   - форматирование, журнал и `String` отдают заглушку;
//   - JSON и текстовая форма ОТКАЗЫВАЮТ;
//   - материал лежит ЗА УКАЗАТЕЛЕМ. Форматирование обходит неэкспортированное
//     поле, не вызывая методов типа, и печатает его содержимое сырым; указатель
//     на вложенной глубине печатается адресом, а не содержимым. Так тип
//     защищён и там, где его методы не спрашиваются.
//
// Выход у материала ОДИН — `Reveal`. Его вызывающих держит гейт дерева
// `internal/check` `TestLoginVerifierStaysInside`.
//
// Нулевое значение означает «материала нет» и в строку способа не проходит:
// отсутствие материала выражается ОТСУТСТВИЕМ строки.
//
// Сравнение через `==` сверяет указатели, а не материал. Сверка предъявленного с
// хранимым — дело проверяющего (часть П2), и только постоянным временем.
type LoginVerifier struct {
	box *loginVerifierBox
}

type loginVerifierBox struct {
	material string
}

// NewLoginVerifier — материал как есть, ДОСЛОВНО: без обрезки и нормализации.
// Перенесённый хеш держит вход прежним паролем ровно пока он побайтово тот же
// (Р1 Ф1). Пустой материал отвергается.
func NewLoginVerifier(material string) (LoginVerifier, error) {
	if material == "" {
		return LoginVerifier{}, fmt.Errorf("Illegal argument login_method.verifier: required")
	}
	return LoginVerifier{box: &loginVerifierBox{material: material}}, nil
}

// IsZero — материала нет.
func (v LoginVerifier) IsZero() bool { return v.box == nil || v.box.material == "" }

// Reveal — ЕДИНСТВЕННЫЙ выход материала. Звать его вправе только места,
// перечисленные гейтом `TestLoginVerifierStaysInside`.
func (v LoginVerifier) Reveal() string {
	if v.box == nil {
		return ""
	}
	return v.box.material
}

// String — заглушка.
func (v LoginVerifier) String() string { return loginVerifierRedacted }

// GoString — заглушка и для `%#v`.
func (v LoginVerifier) GoString() string {
	return "domain.LoginVerifier{" + loginVerifierRedacted + "}"
}

// Format — заглушка на ЛЮБОМ глаголе форматирования, включая `%x` и `%q`.
func (v LoginVerifier) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, v.GoString())
		return
	}
	_, _ = io.WriteString(f, loginVerifierRedacted)
}

// LogValue — заглушка для журнала.
func (v LoginVerifier) LogValue() slog.Value { return slog.StringValue(loginVerifierRedacted) }

// MarshalJSON — отказ.
func (v LoginVerifier) MarshalJSON() ([]byte, error) { return nil, ErrLoginVerifierNotSerializable }

// MarshalText — отказ.
func (v LoginVerifier) MarshalText() ([]byte, error) { return nil, ErrLoginVerifierNotSerializable }

// LoginMethod — строка способа входа.
//
// Ключ — пара (`UserID`, `Kind`): второй способ того же вида человеку
// отвергается базой. `UserID` — идентификатор ЧЕЛОВЕКА (`users.id`), а не
// внешний субъект и не почта: у приглашённого внешнего субъекта нет, почта
// изменяема.
type LoginMethod struct {
	UserID   UserID
	Kind     LoginMethodKind
	Verifier LoginVerifier
	// State — состояние строки (Ф12 Р1). Обязательно у всякого вида: значение,
	// подставленное молча, было бы вторым местом об одном предмете рядом с
	// умолчанием колонки.
	State LoginMethodState
	// AcceptedStep — последний принятый шаг кода по времени (Ф12 Р5);
	// StepAccepted отделяет «шага ещё не было» от значения: нулевой шаг —
	// законная величина оси, а не отсутствие.
	AcceptedStep int64
	StepAccepted bool
	// CreatedAt назначает запись. У строки `pending` — момент заведения, от
	// которого считается срок (Ф12 Р8); у `active` — момент подтверждения.
	CreatedAt time.Time
}

// Validate — строка, годная к записи. Отказ не несёт материала.
func (m LoginMethod) Validate() error {
	if m.UserID == "" {
		return fmt.Errorf("Illegal argument login_method.user_id: required")
	}
	if err := m.Kind.Validate(); err != nil {
		return err
	}
	if m.Verifier.IsZero() {
		return fmt.Errorf("Illegal argument login_method.verifier: required")
	}
	if err := m.State.Validate(); err != nil {
		return err
	}
	if m.State == LoginMethodStatePending && m.Kind != LoginMethodTOTP {
		return fmt.Errorf("Illegal argument login_method.state: %q is only a state of %q", m.State, LoginMethodTOTP)
	}
	if m.StepAccepted && m.Kind != LoginMethodTOTP {
		return fmt.Errorf("Illegal argument login_method.accepted_step: only %q carries one", LoginMethodTOTP)
	}
	return nil
}

// Enrolled — строка есть способ входа: заведён и подтверждён (Ф12 Р1).
func (m LoginMethod) Enrolled() bool { return m.State == LoginMethodStateActive }
