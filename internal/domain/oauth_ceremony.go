// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// oauth_ceremony.go — СОБСТВЕННАЯ ЦЕРЕМОНИЯ OAuth: код авторизации, семейство
// выданного по нему и обновляющий токен (kaname#313).
//
// Домен здесь описывает ЗНАЧЕНИЯ и ИСХОДЫ; хранение, свёртки и операторы живут
// у слоя доступа. Чистый Go, только stdlib.
//
// # Почему исходов обмена ТРИ, а не два
//
// «Не обменялось» — не исход, а корзина. Различать обязаны:
//
//   - ErrAuthorizationCodeUnknown — строки нет. Кода не выдавали, либо он уже
//     убран уборкой после истечения;
//   - ErrAuthorizationCodeReplayed — строка ЕСТЬ и неактивна. Это ПОВТОР, и по
//     нему отзывается ВСЁ семейство: кодом уже воспользовались, и второй
//     предъявитель — либо похититель, либо тот, у кого похитили;
//   - ErrAuthorizationCodeExpired — строка есть, активна, срок вышел. Отзыва
//     семейства не влечёт: истечение — не признак похищения.
//
// Слив их в один отказ сделал бы обнаружение повтора невыразимым: «неактивен» и
// «не найден» перестали бы различаться, а на этом различении стоит весь приём.
package domain

import (
	"errors"
	"fmt"
	"regexp"
)

// ── Исходы обмена и ротации ─────────────────────────────────────────────────

var (
	// ErrAuthorizationCodeUnknown — строки кода НЕТ.
	ErrAuthorizationCodeUnknown = errors.New("authorization code: unknown")
	// ErrAuthorizationCodeReplayed — строка есть и НЕАКТИВНА: повтор.
	ErrAuthorizationCodeReplayed = errors.New("authorization code: already redeemed")
	// ErrAuthorizationCodeExpired — строка активна, но срок вышел.
	ErrAuthorizationCodeExpired = errors.New("authorization code: expired")

	// ErrRefreshTokenUnknown — строки обновляющего токена НЕТ.
	ErrRefreshTokenUnknown = errors.New("refresh token: unknown")
	// ErrRefreshTokenReplayed — строка есть и НЕАКТИВНА: повтор отротированного.
	ErrRefreshTokenReplayed = errors.New("refresh token: already rotated")
	// ErrRefreshTokenExpired — строка активна, но срок вышел.
	ErrRefreshTokenExpired = errors.New("refresh token: expired")

	// ErrCeremonySessionUnknown — строки сессии, в которую заводится семейство,
	// НЕТ ВОВСЕ.
	//
	// Отдельно от «не жива», и это не педантизм: прежняя форма отвергала
	// отсутствующую сессию внешним ключом, называя его имя, — то есть
	// различение уже существовало, и слить его в отказ о живости значило бы
	// сделать опечатку в идентификаторе неотличимой от гонки с выходом.
	ErrCeremonySessionUnknown = errors.New("ceremony session: unknown")

	// ErrCeremonySessionNotLive — строка сессии ЕСТЬ, но сессия уже не жива:
	// снята выходом (своим либо принудительным) либо истекла.
	//
	// Состояний РОВНО ДВА, и оба сливаются намеренно: предъявителю они говорят
	// одно — «входа, в котором идёт церемония, больше нет». Третьего состояния
	// («сессии нет») здесь НЕТ — у него свой признак выше.
	//
	// Исход ЗАВЕДЕНИЯ, а не предъявления, поэтому он стоит отдельно от тройки
	// выше: там разбирается предъявленная строка, здесь — право завести новую.
	ErrCeremonySessionNotLive = errors.New("ceremony session: not live")
)

// ЗДЕСЬ СТОЯЛ ЧЕТВЁРТЫЙ ИСХОД — `ErrTokenFamilyRevoked`, «семейство отозвано».
// Он снят, и раздел выше («Почему исходов обмена ТРИ, а не два») теперь
// описывает то, что есть: исходов ровно три.
//
// Снят он не сокращением, а потому, что отдельным исходом быть перестал.
// Признак активности кода и обновляющего токена ПРОИЗВОДЕН от живости их
// семейства (`GENERATED ALWAYS … STORED` поверх `family_live`), поэтому
// отозванное семейство наблюдается предъявителю как неактивная строка — то есть
// как ПОВТОР, с отзывом семейства в качестве следствия. Производителей у
// четвёртого значения не осталось ни одного, а объявленный исход, которого
// никто не возвращает, читается вызывающим как возможный и не наступает ни при
// каком входе.

// IsAuthorizationCodeReplay — отвергнуто ли предъявление как ПОВТОР кода.
// Предикат, а не сравнение на месте: вызывающие обёртывают ошибку контекстом.
func IsAuthorizationCodeReplay(err error) bool {
	return errors.Is(err, ErrAuthorizationCodeReplayed)
}

// IsRefreshTokenReplay — отвергнуто ли предъявление как ПОВТОР обновляющего
// токена.
func IsRefreshTokenReplay(err error) bool { return errors.Is(err, ErrRefreshTokenReplayed) }

// ── Причины отзыва семейства ────────────────────────────────────────────────

// FamilyRevocationReason — причина отзыва семейства. Словарь ЗАКРЫТ и совпадает
// с ограничением `token_families_revoked_reason_ck`: корзины «прочее» у него
// нет, и значение вне перечня — наша ошибка, а не чужая. Совпадение в обе
// стороны держит проба живой схемы
// `TestIntegration_RevocationVocabularyAgreesWithTheDomain`.
type FamilyRevocationReason string

const (
	// FamilyRevokedByCodeReplay — повторное предъявление кода авторизации.
	FamilyRevokedByCodeReplay FamilyRevocationReason = "code-replay"
	// FamilyRevokedByRefreshReplay — повторное предъявление обновляющего токена.
	FamilyRevokedByRefreshReplay FamilyRevocationReason = "refresh-replay"
	// FamilyRevokedByLogout — человек вышел.
	FamilyRevokedByLogout FamilyRevocationReason = "logout"
	// FamilyRevokedBySessionEnd — сессия, в которой шла церемония, снята.
	FamilyRevokedBySessionEnd FamilyRevocationReason = "session-ended"
	// FamilyRevokedByClientRemoval — клиент снят.
	FamilyRevokedByClientRemoval FamilyRevocationReason = "client-removed"
)

// FamilyRevocationReasons — перечень целиком, КОПИЕЙ: вызывающий не может
// расширить его на месте.
func FamilyRevocationReasons() []FamilyRevocationReason {
	return []FamilyRevocationReason{
		FamilyRevokedByCodeReplay, FamilyRevokedByRefreshReplay, FamilyRevokedByLogout,
		FamilyRevokedBySessionEnd, FamilyRevokedByClientRemoval,
	}
}

// Validate — причина из словаря. Пустая причина исходом не является: отзыв без
// причины неотличим от неотозванного семейства в переписи.
func (r FamilyRevocationReason) Validate() error {
	for _, known := range FamilyRevocationReasons() {
		if r == known {
			return nil
		}
	}
	return fmt.Errorf("Illegal argument token_family.revoked_reason: %q is outside the vocabulary %v",
		string(r), FamilyRevocationReasons())
}

// ── Формы значений ──────────────────────────────────────────────────────────

// digestRe — свёртка SHA-256 шестнадцатерично: та же форма, что у
// `human_sessions.bearer_digest` и у ограничений
// `authorization_codes_digest_form_ck` / `refresh_tokens_digest_form_ck`.
var digestRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// pkceChallengeRe — испытание PKCE: 43 знака base64url без выравнивания
// (SHA-256 от верификатора, RFC 7636 §4.2).
var pkceChallengeRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// PKCEMethodS256 — ЕДИНСТВЕННЫЙ принимаемый метод испытания. `plain` не
// заводится: он сводит PKCE к передаче секрета в открытом виде, и колонка,
// допускающая его, была бы местом, куда он однажды ляжет.
const PKCEMethodS256 = "S256"

// ValidateCeremonyDigest — форма свёртки кода либо токена.
func ValidateCeremonyDigest(field, digest string) error {
	if digest == "" {
		return fmt.Errorf("Illegal argument %s: required", field)
	}
	if !digestRe.MatchString(digest) {
		return fmt.Errorf("Illegal argument %s: must match ^[0-9a-f]{64}$", field)
	}
	return nil
}

// ValidatePKCEChallenge — форма испытания и метода.
func ValidatePKCEChallenge(challenge, method string) error {
	if method != PKCEMethodS256 {
		return fmt.Errorf("Illegal argument code_challenge_method: only %q is accepted", PKCEMethodS256)
	}
	if !pkceChallengeRe.MatchString(challenge) {
		return fmt.Errorf("Illegal argument code_challenge: must match ^[A-Za-z0-9_-]{43}$")
	}
	return nil
}

// ── Значения церемонии ──────────────────────────────────────────────────────

// CeremonyContext — контекст церемонии: он один на семейство, код и всякий
// обновляющий токен семейства. Расхождение его копий отвергает СОСТАВНОЙ
// внешний ключ схемы, а не проверка писателя.
type CeremonyContext struct {
	FamilyID  string
	ClientID  string
	UserID    string
	SessionID string
	Scope     []string
}

// Validate — контекст заполнен целиком. Пустая область исходом не является:
// это не «все права», а отсутствие решения.
func (c CeremonyContext) Validate() error {
	for _, f := range []struct{ name, value string }{
		{"family_id", c.FamilyID}, {"client_id", c.ClientID},
		{"user_id", c.UserID}, {"session_id", c.SessionID},
	} {
		if f.value == "" {
			return fmt.Errorf("Illegal argument ceremony_context.%s: required", f.name)
		}
	}
	if len(c.Scope) == 0 {
		return fmt.Errorf("Illegal argument ceremony_context.scope: required")
	}
	for i, s := range c.Scope {
		if s == "" {
			return fmt.Errorf("Illegal argument ceremony_context.scope[%d]: must not be empty", i)
		}
	}
	return nil
}

// RedeemedCode — то, что вернул ОДИН оператор обмена: контекст церемонии и
// условия, под которыми код был выдан. Читается вызывающим для сверки
// верификатора PKCE и адреса возврата — сверка идёт ПОСЛЕ гашения, потому что
// гашение и есть то, что обязано быть неделимым.
type RedeemedCode struct {
	Context             CeremonyContext
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
}

// RotatedRefreshToken — то, что вернул ОДИН оператор ротации.
type RotatedRefreshToken struct {
	Context    CeremonyContext
	Generation int32
}
