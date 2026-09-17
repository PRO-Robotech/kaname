// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys

// refusals.go — отказы глаголов ключа: тексты и признаки — контракт.
//
// # Две полосы отказа, и форма у них РАЗНАЯ (§3.0, §10 п. 27)
//
// Полоса ЦЕРЕМОНИИ (регистрация) отказывает различимо: три состояния
// собственного испытания вызывающего (не выдавалось · уже предъявлено ·
// просрочено) называют ему следующий шаг, и это не оракул — все три о его
// же испытании (Ф7-34). Полоса УТВЕРЖДЕНИЯ отказывает ОДНИМ текстом и одним
// кодом на всё, что называет ключ, — четырнадцать полос §3.0: различимый
// текст сказал бы предъявителю, что подпись сверена и ключ признан, а
// недостаёт лишь одного (Ф7-49, Ф7-51, Ф7-52…55).

import (
	"errors"
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
)

// Тексты отказов — контракт.
const (
	// TextAssertionNotAccepted — ЕДИНЫЙ отказ аутентификации полосы утверждения.
	TextAssertionNotAccepted = "access key assertion is not accepted"
	TextSessionNotFresh      = "re-authentication required: present a credential again"
	TextChallengeUnknown     = "registration challenge was not issued: begin registration again"
	TextChallengeConsumed    = "registration challenge was already presented: begin registration again"
	TextChallengeExpired     = "registration challenge expired: begin registration again"
	TextOriginNotAllowed     = "credential origin is not in the declared list"
	TextRPIDMismatch         = "credential was created for another relying party"
	TextUserNotPresent       = "authenticator did not report user presence"
	TextAlgorithmNotAllowed  = "credential public key algorithm is not in the declared list"
	TextNotDiscoverable      = "credential is not discoverable: a discoverable credential is required"
	TextMalformedCredential  = "credential result is malformed"
	TextLastSignInMethod     = "last sign-in method cannot be revoked: enrol another sign-in method first"
	TextUserNotActive        = "user %s is not active and cannot register an access key"
	TextAccessKeyNotFound    = "AccessKey %s not found"
	TextCeilingNextStep      = "revoke an access key you no longer need, or raise own-ceilings.access-keys-per-user"
)

// Признаки (`ErrorInfo.reason`) — закрытый перечень.
const (
	ReasonSessionNotFresh     = "SESSION_NOT_FRESH"
	ReasonChallengeUnknown    = "CHALLENGE_NOT_ISSUED"
	ReasonChallengeConsumed   = "CHALLENGE_ALREADY_PRESENTED"
	ReasonChallengeExpired    = "CHALLENGE_EXPIRED"
	ReasonOriginNotAllowed    = "ORIGIN_NOT_ALLOWED"
	ReasonRPIDMismatch        = "RP_ID_MISMATCH"
	ReasonUserNotPresent      = "USER_NOT_PRESENT"
	ReasonAlgorithmNotAllowed = "ALGORITHM_NOT_ALLOWED"
	ReasonNotDiscoverable     = "CREDENTIAL_NOT_DISCOVERABLE"
	ReasonLastSignInMethod    = "LAST_SIGN_IN_METHOD"
)

// ErrAssertionNotAccepted — ОДИН отказ на четырнадцать полос §3.0.
var ErrAssertionNotAccepted = errors.New(TextAssertionNotAccepted)

// assertionRefusal — единственный производитель отказа полосы утверждения:
// один текст, один код, без подробностей.
func assertionRefusal() error {
	return status.Error(codes.InvalidArgument, TextAssertionNotAccepted)
}

// withReason — отказ с признаком полосы для машинного различения.
func withReason(code codes.Code, reason, text string) error {
	st := status.New(code, text)
	info := &errdetails.ErrorInfo{Reason: reason, Domain: refusaldomain.For(refusaldomain.ServiceIAM)}
	if with, err := st.WithDetails(info); err == nil {
		return with.Err()
	}
	return st.Err()
}

// sessionNotFresh — отказ окна свежести, называющий следующий шаг (Ф7-04, Ф7-36).
func sessionNotFresh() error {
	return withReason(codes.FailedPrecondition, ReasonSessionNotFresh, TextSessionNotFresh)
}

// fieldRequired / fieldRule — отказ формы с именем поля.
func fieldRequired(field string) error {
	return status.Errorf(codes.InvalidArgument, "Illegal argument %s: required", field)
}

func fieldRule(field, rule string) error {
	return status.Errorf(codes.InvalidArgument, "Illegal argument %s: %s", field, rule)
}

// invalidAccessKeyID — негодная форма собственного идентификатора (Ф7-47):
// контракт-тон `invalid <res> id '<X>'`.
func invalidAccessKeyID(raw string) error {
	return status.Errorf(codes.InvalidArgument, "invalid access key id '%s'", raw)
}

// notFound — полоса отсутствия: чужой ключ и несуществующий побайтово равны (Ф7-27).
func notFound(id string) error {
	return status.Errorf(codes.NotFound, TextAccessKeyNotFound, id)
}

// notFoundUser — человека, названного областью, нет.
func notFoundUser(id domain.UserID) error {
	return status.Errorf(codes.NotFound, "User %s not found", id)
}

// userNotActive — ключ заводится только активному: состояние решает владелец.
func userNotActive(id domain.UserID) error {
	return status.Errorf(codes.FailedPrecondition, TextUserNotActive, id)
}

// lastSignInMethod — единственный способ входа не снимается (Ф7-26).
func lastSignInMethod() error {
	return withReason(codes.FailedPrecondition, ReasonLastSignInMethod, TextLastSignInMethod)
}

// Lane — полоса, на которой наблюдается отказ (клетки счётчика).
type Lane string

const (
	LaneRegistration Lane = "registration"
	LaneAssertion    Lane = "assertion"
	LaneRevoke       Lane = "revoke"
)

// Lanes — закрытый перечень.
func Lanes() []Lane { return []Lane{LaneRegistration, LaneAssertion, LaneRevoke} }

// Refusal — причина отказа для наблюдателя; наружу на полосе утверждения не
// выходит.
type Refusal string

const (
	RefusalSessionNotFresh     Refusal = "session-not-fresh"
	RefusalChallengeUnknown    Refusal = "challenge-not-issued"
	RefusalChallengeConsumed   Refusal = "challenge-consumed"
	RefusalChallengeExpired    Refusal = "challenge-expired"
	RefusalMalformed           Refusal = "malformed"
	RefusalOriginNotAllowed    Refusal = "origin-not-allowed"
	RefusalRPIDMismatch        Refusal = "rp-id-mismatch"
	RefusalUserNotPresent      Refusal = "user-not-present"
	RefusalAlgorithmNotAllowed Refusal = "algorithm-not-allowed"
	RefusalNotDiscoverable     Refusal = "not-discoverable"
	RefusalSignature           Refusal = "signature"
	RefusalUnknownCredential   Refusal = "unknown-credential"
	RefusalForeignKey          Refusal = "foreign-key"
	RefusalUserHandle          Refusal = "user-handle-mismatch"
	RefusalCounter             Refusal = "counter"
	RefusalCounterRace         Refusal = "counter-race"
	RefusalLastSignInMethod    Refusal = "last-sign-in-method"
	RefusalNotFound            Refusal = "not-found"
	RefusalForm                Refusal = "form"
)

// Refusals — закрытый перечень причин.
func Refusals() []Refusal {
	return []Refusal{RefusalSessionNotFresh, RefusalChallengeUnknown, RefusalChallengeConsumed, RefusalChallengeExpired,
		RefusalMalformed, RefusalOriginNotAllowed, RefusalRPIDMismatch, RefusalUserNotPresent, RefusalAlgorithmNotAllowed,
		RefusalNotDiscoverable, RefusalSignature, RefusalUnknownCredential, RefusalForeignKey, RefusalUserHandle,
		RefusalCounter, RefusalCounterRace, RefusalLastSignInMethod, RefusalNotFound, RefusalForm}
}

// Event — событие ключа для наблюдателя.
type Event string

const (
	EventRegistrationChallengeIssued Event = "registration-challenge-issued"
	EventRegistered                  Event = "registered"
	EventAssertionChallengeIssued    Event = "assertion-challenge-issued"
	EventAsserted                    Event = "asserted"
	EventRevoked                     Event = "revoked"
	EventTransferred                 Event = "transferred"
)

// Events — закрытый перечень.
func Events() []Event {
	return []Event{EventRegistrationChallengeIssued, EventRegistered, EventAssertionChallengeIssued, EventAsserted, EventRevoked, EventTransferred}
}

// storeUnavailable — хранилище не ответило: фиксированный текст, без причины.
func storeUnavailable(verb string) error {
	return status.Error(codes.Unavailable, fmt.Sprintf("%s temporarily unavailable", verb))
}
