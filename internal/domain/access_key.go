// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// access_key.go — КЛЮЧ ДОСТУПА человека (WebAuthn) и ИСПЫТАНИЕ его церемоний
// (iam Ф7, PRO-Robotech/kacho#1273; приёмка
// `docs/engineering/acceptance/access-keys-are-ours.md`, Р1, Р6, Р10).
//
// # Ключ — строка СВОЕЙ таблицы, а не строка способа входа
//
// Человеку положено иметь несколько ключей; строка способа по построению одна
// на пару «человек, вид», и второго ключа она не выражает. Поэтому ключ —
// ресурс со своим `id`, своей таблицей и своим потолком (Р1, Р8). Строки вида
// `webauthn` в способах входа НЕТ; «умеет войти ключом» выводится из строк
// ключа.
//
// # Состав строки ЗАКРЫТ, и у каждой колонки назван читатель (Р1)
//
// `id` — адрес (Ф7-25, Ф7-47); человек — Ф7-14, Ф7-27; идентификатор
// удостоверения — уникальность (Ф7-05, Ф7-15) и поиск на утверждении (Ф7-08,
// Ф7-09); открытый ключ и алгоритм — сверка подписи (Ф7-07, Ф7-22); счётчик —
// Ф7-17…20; имя и описание — Ф7-01, Ф7-46, Ф7-50; момент заведения — Ф7-01;
// момент предъявления — Ф7-06, Ф7-07. Рукоятка — читатель Ф13 Р3 (полоса
// входа сверяет `userHandle` со строкой). Признака резервного копирования и
// проверки пользователя в строке НЕТ: различитель ступени берётся из флагов
// каждого утверждения, а не из памяти о регистрации (Ф11 Р3). Аттестации нет
// by construction (Р4).

import (
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

// PrefixAccessKey — префикс дефисной формы `ak-<17>`; сама константа канона —
// в фундаменте (`ids.PrefixAccessKeyHyphen`), здесь только имя для отказов и
// таблицы форм.
const PrefixAccessKey = "ak"

// AccessKeyID — платформенный идентификатор ключа (Р10). Единственное, чем
// ключ адресуется извне.
type AccessKeyID string

// accessKeyIDRe — форма `ak-<17 знаков crockford-base32>`, та же, что у
// ограничения схемы `user_access_keys_id_form_check`.
var accessKeyIDRe = regexp.MustCompile(`^ak-[0-9a-hjkmnp-tv-z]{17}$`)

// Validate — форма собственного идентификатора: то, что БУДЕТ ЗАПИСАНО.
func (id AccessKeyID) Validate() error {
	if !accessKeyIDRe.MatchString(string(id)) {
		return fmt.Errorf("Illegal argument access_key id: must match ^ak-[crockford-base32]{17}$")
	}
	return nil
}

// AccessKeyName — имя ключа одной формы дерева (DNS label RFC 1123). Форма —
// у фундамента; здесь тип для колонки, чтобы «что записывается» судилось
// тем же валидатором, что у всех именуемых ресурсов службы.
type AccessKeyName string

// Validate судит записываемое имя: пустое до записи не доживает
// (`corevalidate.NameOrDefault`), поэтому здесь оно негодно.
func (n AccessKeyName) Validate() error {
	// Строка ключа имя несёт ВСЕГДА (Р10: пустое заменяется умолчанием от `id`
	// до записи), поэтому судится каноном дерева, как шесть соседних типов:
	// пустое здесь — не законный вход, а дефект строки.
	return validateResourceName(string(n))
}

// AccessKeyDescriptionMax — предел описания в ЗНАКАХ, единица схемы
// (`CHECK (length(description) <= 256)`), как у удостоверений-соседей.
const AccessKeyDescriptionMax = 256

// AccessKeyDescription — описание ключа: свободный текст с пределом в ЗНАКАХ.
//
// Тип свой, а не `Description` соседей, потому что у них проверка входа считает
// БАЙТЫ (`len > 256`), а схема — знаки: на кириллической метке две формы
// расходятся — 200 знаков есть 400 байт. Здесь единица одна — знак, как у
// схемы и у фундаментного валидатора `corevalidate.Description` (Р10).
// Расхождение у соседей — их предмет, здесь оно только названо.
type AccessKeyDescription string

// Validate — предел в рунах.
func (d AccessKeyDescription) Validate() error {
	if utf8.RuneCountInString(string(d)) > AccessKeyDescriptionMax {
		return fmt.Errorf("Illegal argument description: length must be <= %d characters", AccessKeyDescriptionMax)
	}
	return nil
}

// AccessKeyChallengeBytes — длина случайного испытания: 32 байта = 256 бит,
// не меньше 16 требуемых нормой (§13.4.3).
const AccessKeyChallengeBytes = 32

// AccessKey — строка ключа.
type AccessKey struct {
	ID     AccessKeyID
	UserID UserID
	// CredentialID — идентификатор удостоверения WebAuthn: байты нормы,
	// глобально уникальны; наружу не выходят (Р10).
	CredentialID []byte
	// PublicKey — открытый ключ в форме COSE_Key, байт в байт как принят.
	PublicKey []byte
	// Algorithm — идентификатор алгоритма COSE.
	Algorithm int64
	// SignCount — сохранённое значение счётчика подписи (Р6).
	SignCount uint32
	// UserHandle — рукоятка `user.id` церемонии; у ключей Ф7 — платформенный
	// `id` человека как байты (Ф13 Р3). Пустая — источник переноса её не нёс.
	UserHandle  []byte
	Name        AccessKeyName
	Description AccessKeyDescription
	CreatedAt   time.Time
	// LastUsedAt — момент последнего успешного предъявления; нулевой указатель
	// — предъявлений не было.
	LastUsedAt *time.Time
}

// Validate — самопроверка записываемой строки (self-validating domain).
func (k AccessKey) Validate() error {
	if err := k.ID.Validate(); err != nil {
		return err
	}
	if k.UserID == "" {
		return fmt.Errorf("Illegal argument user_id: required")
	}
	if len(k.CredentialID) == 0 {
		return fmt.Errorf("Illegal argument credential_id: required")
	}
	if len(k.PublicKey) == 0 {
		return fmt.Errorf("Illegal argument public_key: required")
	}
	if k.Algorithm == 0 {
		return fmt.Errorf("Illegal argument algorithm: required")
	}
	if err := k.Name.Validate(); err != nil {
		return err
	}
	if err := k.Description.Validate(); err != nil {
		return err
	}
	if k.CreatedAt.IsZero() {
		return fmt.Errorf("Illegal argument created_at: required")
	}
	return nil
}

// AccessKeyChallengePurpose — процедура, для которой выдано испытание.
// Испытание регистрации утверждением не предъявить и наоборот: словарь закрыт
// ограничением схемы.
type AccessKeyChallengePurpose string

const (
	// ChallengeForRegistration — испытание церемонии регистрации (§7.1).
	ChallengeForRegistration AccessKeyChallengePurpose = "registration"
	// ChallengeForAssertion — испытание предъявления (§7.2).
	ChallengeForAssertion AccessKeyChallengePurpose = "assertion"
)

// AccessKeyChallengePurposes — закрытый перечень.
func AccessKeyChallengePurposes() []AccessKeyChallengePurpose {
	return []AccessKeyChallengePurpose{ChallengeForRegistration, ChallengeForAssertion}
}

// AccessKeyChallenge — выданное испытание: привязано к ВЫЗЫВАЮЩЕМУ (Р11),
// однократно (Ф7-03, Ф7-53) и срочно (Ф7-34, Ф7-54). Срок у обеих процедур —
// одна величина контракта (§7 инв. 5).
type AccessKeyChallenge struct {
	// Challenge — случайные байты; ключ строки.
	Challenge []byte
	// UserID — кому выдано: из чужой сессии испытание не находится (Ф7-55).
	UserID  UserID
	Purpose AccessKeyChallengePurpose
	// IssuedAt / ExpiresAt — момент выдачи и предел срока.
	IssuedAt  time.Time
	ExpiresAt time.Time
	// ConsumedAt — момент предъявления; нулевой указатель — не предъявлено.
	ConsumedAt *time.Time
}

// Validate — самопроверка записываемого испытания.
func (c AccessKeyChallenge) Validate() error {
	if len(c.Challenge) != AccessKeyChallengeBytes {
		return fmt.Errorf("Illegal argument challenge: must be %d bytes", AccessKeyChallengeBytes)
	}
	if c.UserID == "" {
		return fmt.Errorf("Illegal argument user_id: required")
	}
	switch c.Purpose {
	case ChallengeForRegistration, ChallengeForAssertion:
	default:
		return fmt.Errorf("Illegal argument purpose: must be one of %v", AccessKeyChallengePurposes())
	}
	if c.IssuedAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt) {
		return fmt.Errorf("Illegal argument expires_at: must be after issued_at")
	}
	return nil
}

// AccessKeyChallengeState — состояние испытания регистрации на момент
// предъявления: три различимых состояния (Ф7-34), плюс «выдано».
type AccessKeyChallengeState string

const (
	// ChallengeIssued — выдано, не предъявлено, срок не вышел.
	ChallengeIssued AccessKeyChallengeState = "issued"
	// ChallengeUnknown — служба такого не выдавала (Ф7-02).
	ChallengeUnknown AccessKeyChallengeState = "unknown"
	// ChallengeConsumed — уже предъявлено (Ф7-03).
	ChallengeConsumed AccessKeyChallengeState = "consumed"
	// ChallengeExpired — срок вышел (Ф7-34).
	ChallengeExpired AccessKeyChallengeState = "expired"
)

// StateAt — состояние испытания на момент `now`.
func (c AccessKeyChallenge) StateAt(now time.Time) AccessKeyChallengeState {
	switch {
	case c.ConsumedAt != nil:
		return ChallengeConsumed
	case !now.Before(c.ExpiresAt):
		return ChallengeExpired
	default:
		return ChallengeIssued
	}
}
