// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// authorization_ceremony.go — величины и значения церемонии OAuth 2.1
// `authorization_code` нашими силами (под-фаза LINE-A-1, задача
// PRO-Robotech/kacho#2721; приёмка
// `sub-phase-LINE-A-1-own-authorization-endpoint-and-code-acceptance.md`,
// решения Р3, Р5, Р8, Р13).
//
// # Величины объявлены ЗДЕСЬ, одним местом, и ручками не являются
//
// Пол длины `state`, срок кода и окно, в котором предъявление уже
// потреблённого кода ещё узнаётся повтором, — НАШИ величины, и каждая
// объявлена ровно один раз: сверка зовёт это объявление, второго «как общее,
// но…» в дереве нет. Ручками они не заведены намеренно: величина, у которой
// нет законного второго значения, заведённая ручкой, получила бы умолчание —
// а умолчание стража старта мертвит (страж, требующий задания, зелен при
// любом входе). Срок обновляющего удостоверения здесь не объявлен вовсе: он
// равен сроку сессии, породившей авторизацию (своя ручка у той уже есть), —
// семейство не переживает вход, которым было выдано.
//
// # Код и обновляющее удостоверение — ПРЕДЪЯВИТЕЛЬСКИЕ значения
//
// Оба уходят клиенту ровно одним путём (перенаправлением и телом ответа
// токен-эндпоинта), а хранилище знает только их свёртку: копия таблицы не даёт
// ни одного годного кода. Тип значения не печатается и не сериализуется —
// попасть в журнал он не может ни одним общим путём вывода.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"time"
)

// AuthorizationStateFloor — пол длины параметра `state` запроса авторизации
// (Р13 п. 2): 22 — длина записи BASE64URL от 16 случайных байтов, самая
// короткая форма 128-битного значения. Сравнение — «не ниже» (≥).
//
// Единица счёта — знак алфавита VSCHAR (RFC 6749, прил. A.5: `%x20-7E`). Вне
// этого алфавита `state` отвергается ДО сравнения с полом, поэтому знак здесь
// равен байту, и на не-ASCII входе две законные реализации не расходятся.
const AuthorizationStateFloor = 22

// AuthorizationCodeTTL — срок кода от выдачи (Р5). Предикат срока исполняет
// БАЗА (`expires_at > now()` в операторе потребления), не сравнение в
// приложении; эта величина лишь назначает `expires_at` при выдаче.
//
// Минута — с запасом на перенаправление браузера и обмен бэк-каналом, которые
// исполняются машиной без участия человека.
const AuthorizationCodeTTL = time.Minute

// AuthorizationCodeReplayRetention — сколько запись кода живёт ПОСЛЕ своего
// срока. Потреблённый код, предъявленный повторно, отзывает семейство
// авторизации (Р8, 13), и узнать повтор можно лишь пока запись есть. Уборка
// снимает запись не раньше этого окна; после него повтор неотличим от
// неизвестного кода — и отказ у них один и тот же (Р10).
const AuthorizationCodeReplayRetention = time.Hour

// AuthorizationGrantIDPrefix — префикс идентификатора авторизации (семейства
// токенов, выданных по одному коду). Идентификатор наружу как адрес не
// выходит; в предъявителе он — ключ отсечки семейства.
const AuthorizationGrantIDPrefix = "agr"

// ClaimAuthorizationID — утверждение предъявителя, называющее авторизацию,
// которой он выдан. Читается правилом отзыва (`internal/tokenrevocation`) как
// ключ отсечки: отзыв семейства задевает ровно его предъявителей, а не всех
// живых удостоверений человека.
const ClaimAuthorizationID = "kaname_authorization_id"

// AuthorizationGrantID — идентификатор авторизации.
type AuthorizationGrantID string

// ceremonySecretBytes — длина случайной части кода и обновляющего
// удостоверения: 32 байта = 256 бит; в BASE64URL без выравнивания — 43 знака.
const ceremonySecretBytes = 32

// ceremonySecretRedacted — заглушка на всяком общем пути вывода.
// #nosec G101 -- это ЗАМЕНА значения в выводе, а не само значение.
const ceremonySecretRedacted = "[redacted ceremony credential]"

// ErrCeremonySecretNotSerializable — значение не сериализуется ни в JSON, ни в
// текст: наружу оно уходит одним путём, который пишет обработчик полосы.
var ErrCeremonySecretNotSerializable = fmt.Errorf("ceremony credential is not serializable")

// CeremonySecretDigest — свёртка кода либо обновляющего удостоверения
// (шестнадцатеричная запись SHA-256). Хранится и сравнивается только она.
type CeremonySecretDigest string

type ceremonySecretBox struct{ value string }

// CeremonySecret — непрозрачный предъявительский материал церемонии: код
// авторизации либо обновляющее удостоверение. Значение выходит ровно двумя
// методами: [CeremonySecret.Digest] (в хранилище) и [CeremonySecret.Deliver]
// (клиенту).
type CeremonySecret struct{ box *ceremonySecretBox }

// NewCeremonySecret — свежее значение из источника случайности.
func NewCeremonySecret() (CeremonySecret, error) {
	var raw [ceremonySecretBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return CeremonySecret{}, fmt.Errorf("ceremony credential: random source: %w", err)
	}
	return CeremonySecret{box: &ceremonySecretBox{value: base64.RawURLEncoding.EncodeToString(raw[:])}}, nil
}

// PresentedCeremonySecret — значение, как его прислал клиент. Не разбирается:
// единственное, что с ним делают, — берут свёртку. Пустое — отсутствие.
func PresentedCeremonySecret(value string) CeremonySecret {
	if value == "" {
		return CeremonySecret{}
	}
	return CeremonySecret{box: &ceremonySecretBox{value: value}}
}

// IsZero — значения нет.
func (s CeremonySecret) IsZero() bool { return s.box == nil || s.box.value == "" }

// Deliver — значение для провода клиенту. Единственный выход наружу.
func (s CeremonySecret) Deliver() string {
	if s.box == nil {
		return ""
	}
	return s.box.value
}

// Digest — свёртка значения.
func (s CeremonySecret) Digest() CeremonySecretDigest {
	if s.box == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(s.box.value))
	return CeremonySecretDigest(hex.EncodeToString(sum[:]))
}

// String — заглушка.
func (s CeremonySecret) String() string { return ceremonySecretRedacted }

// GoString — заглушка и для `%#v`.
func (s CeremonySecret) GoString() string {
	return "domain.CeremonySecret{" + ceremonySecretRedacted + "}"
}

// Format — заглушка на любом глаголе форматирования.
func (s CeremonySecret) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, s.GoString())
		return
	}
	_, _ = io.WriteString(f, ceremonySecretRedacted)
}

// LogValue — заглушка для журнала.
func (s CeremonySecret) LogValue() slog.Value { return slog.StringValue(ceremonySecretRedacted) }

// MarshalJSON — отказ.
func (s CeremonySecret) MarshalJSON() ([]byte, error) { return nil, ErrCeremonySecretNotSerializable }

// MarshalText — отказ.
func (s CeremonySecret) MarshalText() ([]byte, error) { return nil, ErrCeremonySecretNotSerializable }

// PKCEMethodS256 — единственный принимаемый метод преобразования PKCE (Р3).
const PKCEMethodS256 = "S256"

// pkceVerifierMin, pkceVerifierMax — границы длины `code_verifier`
// (RFC 7636 §4.1).
const (
	pkceVerifierMin = 43
	pkceVerifierMax = 128
)

// pkceChallengeLen — длина `code_challenge` метода S256: BASE64URL без
// выравнивания от 32 байтов SHA-256.
const pkceChallengeLen = 43

// ValidPKCEVerifier — `code_verifier` законной формы: 43…128 знаков
// алфавита unreserved (RFC 7636 §4.1).
func ValidPKCEVerifier(v string) bool {
	if len(v) < pkceVerifierMin || len(v) > pkceVerifierMax {
		return false
	}
	for i := 0; i < len(v); i++ {
		if !pkceUnreserved(v[i]) {
			return false
		}
	}
	return true
}

// ValidPKCEChallengeS256 — `code_challenge` формы метода S256: ровно 43 знака
// BASE64URL.
func ValidPKCEChallengeS256(c string) bool {
	if len(c) != pkceChallengeLen {
		return false
	}
	for i := 0; i < len(c); i++ {
		b := c[i]
		if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
			return false
		}
	}
	return true
}

// PKCEChallengeS256 — вызов, который даёт `code_verifier` методом S256:
// BASE64URL(SHA256(ASCII(verifier))) (RFC 7636 §4.2).
func PKCEChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func pkceUnreserved(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' ||
		b == '-' || b == '.' || b == '_' || b == '~'
}

// ValidOAuthState — `state` в алфавите VSCHAR (RFC 6749, прил. A.5) и не
// короче пола [AuthorizationStateFloor]. «Не прислан» даёт длину 0, а ноль
// меньше пола: обязательность наступает той же проверкой, отдельной ветки у
// неё нет (Р13 п. 1).
func ValidOAuthState(s string) bool {
	if len(s) < AuthorizationStateFloor {
		return false
	}
	return vscharOnly(s)
}

// ValidOAuthScope — `scope` формы RFC 6749 §3.3: токены через одиночный
// пробел, каждый из алфавита NQCHAR; пустая область законна (область не
// запрошена). Потолок длины — у хранилища.
func ValidOAuthScope(s string) bool {
	if s == "" {
		return true
	}
	prevSpace := true
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == ' ' {
			if prevSpace {
				return false
			}
			prevSpace = true
			continue
		}
		if b < 0x21 || b > 0x7e || b == '"' || b == '\\' {
			return false
		}
		prevSpace = false
	}
	return !prevSpace
}

// MaxOAuthScopeLen — потолок длины области; тот же объявлен CHECK базы.
const MaxOAuthScopeLen = 1024

func vscharOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
