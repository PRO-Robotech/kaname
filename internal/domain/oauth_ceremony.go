// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// oauth_ceremony.go — СОБСТВЕННАЯ ЦЕРЕМОНИЯ OAuth: код авторизации, семейство
// выданного по нему и обновляющий токен (kaname#313).
//
// Домен здесь описывает ЗНАЧЕНИЯ и ИСХОДЫ; хранение, свёртки и операторы живут
// у слоя доступа. Чистый Go, только stdlib.
//
// # Исходов ПРЕДЪЯВЛЕНИЯ здесь нет, и это не пропуск
//
// Обмен кода и оборот токена обновления исполняет движок фундамента
// (`corelib/oauthceremony`) над хранилищами слоя доступа, и исходы предъявления
// называет контракт его портов: «записи нет», погашен, обёрнут. Прежняя тройка
// исходов обмена и ротации принадлежала композициям слоя доступа, у которых
// прод-вызывающих не было, и снята вместе с ними (kaname#434). Здесь остаются
// исходы, которых у порта нет: заведение семейства в сессию, отсечка субъекта
// предъявленной строки, запись выпуска, занятость проверяющего секрета.
package domain

import (
	"errors"
	"fmt"
	"regexp"
)

// ── Исходы церемонии, которых нет у порта фундамента ───────────────────────

var (
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
	// Исход ЗАВЕДЕНИЯ, а не предъявления: разбирается не предъявленная строка,
	// а право завести новую.
	ErrCeremonySessionNotLive = errors.New("ceremony session: not live")

	// ErrCeremonySubjectCutOff — предъявленная строка (код либо токен
	// обновления) есть, активна и в сроке, но сессия, в которой она выдана,
	// аутентифицирована НЕ ПОЗЖЕ отсечки своего субъекта
	// (`user_token_revocations.revoke_before`).
	//
	// Исход ПРЕДЪЯВЛЕНИЯ, и у порта фундамента своего слова у него нет: это не
	// повтор — семейство по нему не отзывается, и журнал не называет атакой отзыв
	// доступа, — и не истечение. Порту он уходит «записи нет»
	// (`oauthceremony.ErrGrantNotFound`), причиной в цепочке: гранта, по которому
	// предъявитель пришёл, больше нет.
	ErrCeremonySubjectCutOff = errors.New("ceremony session: authenticated no later than its subject's cutoff")

	// ErrAccessTokenFamilyNotLive — выпуск токена доступа не записан: семейства,
	// в которое он заводится, нет либо оно отозвано (kaname#319).
	//
	// Исход ЗАВЕДЕНИЯ записи выпуска, а не предъявления. Два состояния сливаются
	// намеренно: выпуску говорят одно — «семейства, в котором идёт выдача, больше
	// нет», — и токен клиенту уезжать не должен. Различает их, если понадобится,
	// строка семейства, а не этот отказ.
	ErrAccessTokenFamilyNotLive = errors.New("access token: family is unknown or revoked")

	// ErrVerifierAtCapacity — проверяющий секрета занят: все места ёмкости
	// (`passwordverify`) заняты другими проверками. Отказ ПОВТОРЯЕМЫЙ и наш, а не
	// «секрет неверен»: несостоявшаяся сверка вердиктом не становится.
	ErrVerifierAtCapacity = errors.New("secret verifier: at capacity")
)

// ── Причины отзыва семейства ────────────────────────────────────────────────

// FamilyRevocationReason — причина отзыва семейства. Словарь ЗАКРЫТ и совпадает
// с ограничением `token_families_revoked_reason_ck`: корзины «прочее» у него
// нет, и значение вне перечня — наша ошибка, а не чужая. Совпадение в обе
// стороны держит проба живой схемы
// `TestIntegration_RevocationVocabularyAgreesWithTheDomain`, а то, что у
// каждого слова есть писатель, — гейт
// `TestFamilyRevocationVocabulary_KN_FRV_17_EveryWordHasAWriter`: слово, которого
// никто не пишет, перечень превращает в обещание (kaname#339).
type FamilyRevocationReason string

const (
	// FamilyRevokedByCodeReplay — повторное предъявление кода авторизации.
	FamilyRevokedByCodeReplay FamilyRevocationReason = "code-replay"
	// FamilyRevokedByRefreshReplay — повторное предъявление обновляющего токена.
	FamilyRevokedByRefreshReplay FamilyRevocationReason = "refresh-replay"
	// FamilyRevokedBySessionEnd — сессия, в которой шла церемония, снята.
	FamilyRevokedBySessionEnd FamilyRevocationReason = "session-ended"
	// FamilyRevokedByClientRevocation — клиент, которому выдан грант, сам
	// попросил отзыва (RFC 7009). Написание — дословно причина фундамента
	// `oauthceremony.RevocationClientRevoke`: адаптер порта отзыва сопрягает
	// словари ПО ЗНАЧЕНИЮ (`ceremonyport.FamilyReasonOf`), и другое написание
	// оставило бы причину без слова (kaname#406).
	FamilyRevokedByClientRevocation FamilyRevocationReason = "client-revoke"
)

// FamilyRevocationReasons — перечень целиком, КОПИЕЙ: вызывающий не может
// расширить его на месте.
func FamilyRevocationReasons() []FamilyRevocationReason {
	return []FamilyRevocationReason{
		FamilyRevokedByCodeReplay, FamilyRevokedByRefreshReplay, FamilyRevokedBySessionEnd,
		FamilyRevokedByClientRevocation,
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

// ValidateCeremonyLevel — уровень аутентификации гранта из той же закрытой оси,
// что у сессии (`assuranceLevelValues`, Ф11): семейство несёт СНИМОК уровня
// сессии на выдаче кода (миграция `20260925121413`), и второго словаря у этого
// предмета нет.
func ValidateCeremonyLevel(level string) error {
	for _, l := range assuranceLevelValues {
		if level == l {
			return nil
		}
	}
	return fmt.Errorf("Illegal argument token_family.acr: must be one of %v", assuranceLevelValues)
}

// CeremonyScopeOpenID — область интерактивного входа: её запрашивает
// первопартийный клиент (консоль, CLI), и она проецируется в утверждение
// `scope` выданного токена доступа (RFC 9068 §2.2.3).
//
// Прав область НЕ несёт: решение о доступе принимает модель (приёмка LINE-A-1
// Р9), и выданное по коду судится так же, как всякий наш токен. Токена личности
// церемония не выдаёт (`corelib/oauthceremony`, doc.go) — область называет вид
// гранта, а не обещание ID-токена.
const CeremonyScopeOpenID = "openid"

// CeremonyScopes — ЗАКРЫТЫЙ перечень областей, которые интерактивный клиент
// вправе запросить у точки авторизации. Копией: вызывающий не расширит его на
// месте. Область вне перечня отвергается движком церемонии (`invalid_scope`) —
// принять её и ничего по ней не сделать было бы «принято и проигнорировано».
func CeremonyScopes() []string { return []string{CeremonyScopeOpenID} }

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

// RotatedRefreshToken — то, что вернул ОДИН оператор ротации.
type RotatedRefreshToken struct {
	Context    CeremonyContext
	Generation int32
}
