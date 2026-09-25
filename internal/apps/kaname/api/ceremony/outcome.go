// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremony

import "sync"

// Outcome — исход одного запроса церемонии. Словарь ЗАКРЫТ, и перепись
// заводится по нему целиком до первого запроса: счётчик, появляющийся при
// первом отказе, не отличает «ноль отказов» от «исхода без счётчика».
//
// Наружу отказы после именования кода неразличимы (Р10), отказы до доверия
// цели — тоже (04/05); различимость для нас — здесь, в журнале и в счётчике.
type Outcome string

// Исходы эндпоинта авторизации.
const (
	AuthorizeIssued               Outcome = "authorize.issued"
	AuthorizeTargetParamInvalid   Outcome = "authorize.target-param-invalid"
	AuthorizeClientUnknown        Outcome = "authorize.client-unknown"
	AuthorizeClientNotActive      Outcome = "authorize.client-not-active"
	AuthorizeRedirectUnregistered Outcome = "authorize.redirect-unregistered"
	AuthorizeParamRepeated        Outcome = "authorize.param-repeated"
	AuthorizeResponseTypeMissing  Outcome = "authorize.response-type-missing"
	AuthorizeResponseTypeRefused  Outcome = "authorize.response-type-unsupported"
	AuthorizeStateAbsent          Outcome = "authorize.state-absent"
	AuthorizeStateRefused         Outcome = "authorize.state-refused"
	AuthorizePKCERefused          Outcome = "authorize.pkce-refused"
	AuthorizeScopeRefused         Outcome = "authorize.scope-refused"
	AuthorizeACRValuesRefused     Outcome = "authorize.acr-values-refused"
	AuthorizeUnauthenticated      Outcome = "authorize.unauthenticated"
	AuthorizeStepUpRequired       Outcome = "authorize.step-up-required"
	AuthorizeIssueRaced           Outcome = "authorize.issue-condition-lost"
	AuthorizeUnavailable          Outcome = "authorize.unavailable"
)

// Исходы полос обмена токен-эндпоинта.
const (
	ExchangeCodeAccepted          Outcome = "exchange.code-accepted"
	ExchangeRefreshRotated        Outcome = "exchange.refresh-rotated"
	ExchangeFormInvalid           Outcome = "exchange.form-invalid"
	ExchangeClientMissing         Outcome = "exchange.client-credentials-missing"
	ExchangeClientUnknown         Outcome = "exchange.client-unknown"
	ExchangeClientNotActive       Outcome = "exchange.client-not-active"
	ExchangeClientNoSecret        Outcome = "exchange.client-secret-absent"
	ExchangeClientSecretWrong     Outcome = "exchange.client-secret-mismatch"
	ExchangeClientSecretBroken    Outcome = "exchange.client-secret-unreadable"
	ExchangeVerifierBusy          Outcome = "exchange.secret-verifier-capacity-exhausted"
	ExchangeCodeUnknown           Outcome = "exchange.code-unknown"
	ExchangeCodeReplayed          Outcome = "exchange.code-replayed"
	ExchangeCodeExpired           Outcome = "exchange.code-expired"
	ExchangeCodeClientMismatch    Outcome = "exchange.code-client-mismatch"
	ExchangeCodeRedirectMismatch  Outcome = "exchange.code-redirect-mismatch"
	ExchangeCodeVerifierMismatch  Outcome = "exchange.code-verifier-mismatch"
	ExchangeCodeSessionEnded      Outcome = "exchange.code-session-ended"
	ExchangeRefreshUnknown        Outcome = "exchange.refresh-unknown"
	ExchangeRefreshReplayed       Outcome = "exchange.refresh-replayed"
	ExchangeRefreshRevoked        Outcome = "exchange.refresh-family-revoked"
	ExchangeRefreshClientMismatch Outcome = "exchange.refresh-client-mismatch"
	ExchangeRefreshSessionEnded   Outcome = "exchange.refresh-session-ended"
	ExchangeScopeRefused          Outcome = "exchange.scope-refused"
	ExchangeUnavailable           Outcome = "exchange.unavailable"
)

var outcomes = []Outcome{
	AuthorizeIssued, AuthorizeTargetParamInvalid, AuthorizeClientUnknown, AuthorizeClientNotActive,
	AuthorizeRedirectUnregistered, AuthorizeParamRepeated, AuthorizeResponseTypeMissing,
	AuthorizeResponseTypeRefused, AuthorizeStateAbsent, AuthorizeStateRefused, AuthorizePKCERefused, AuthorizeScopeRefused,
	AuthorizeACRValuesRefused, AuthorizeUnauthenticated, AuthorizeStepUpRequired, AuthorizeIssueRaced,
	AuthorizeUnavailable,
	ExchangeCodeAccepted, ExchangeRefreshRotated, ExchangeFormInvalid, ExchangeClientMissing,
	ExchangeClientUnknown, ExchangeClientNotActive, ExchangeClientNoSecret, ExchangeClientSecretWrong,
	ExchangeClientSecretBroken, ExchangeVerifierBusy, ExchangeCodeUnknown, ExchangeCodeReplayed,
	ExchangeCodeExpired, ExchangeCodeClientMismatch, ExchangeCodeRedirectMismatch,
	ExchangeCodeVerifierMismatch, ExchangeCodeSessionEnded, ExchangeRefreshUnknown,
	ExchangeRefreshReplayed, ExchangeRefreshRevoked, ExchangeRefreshClientMismatch,
	ExchangeRefreshSessionEnded, ExchangeScopeRefused, ExchangeUnavailable,
}

// Outcomes — копия словаря: вызывающий не может его расширить.
func Outcomes() []Outcome {
	out := make([]Outcome, len(outcomes))
	copy(out, outcomes)
	return out
}

// OutcomeNames — имена исходов строками: набор клеток витрины выводится из
// того же словаря, которым засеяна перепись.
func OutcomeNames() []string {
	out := make([]string, 0, len(outcomes))
	for _, o := range outcomes {
		out = append(out, string(o))
	}
	return out
}

// Census — перепись исходов, засеянная целиком по словарю.
type Census struct {
	mu     sync.Mutex
	counts map[Outcome]uint64
}

// NewCensus — перепись с клеткой на каждый объявленный исход.
func NewCensus() *Census {
	c := &Census{counts: make(map[Outcome]uint64, len(outcomes))}
	for _, o := range outcomes {
		c.counts[o] = 0
	}
	return c
}

// Count — один исход.
func (c *Census) Count(o Outcome) {
	c.mu.Lock()
	c.counts[o]++
	c.mu.Unlock()
}

// Snapshot — перепись строками для читателя величин.
func (c *Census) Snapshot() map[string]uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]uint64, len(c.counts))
	for o, n := range c.counts {
		out[string(o)] = n
	}
	return out
}
