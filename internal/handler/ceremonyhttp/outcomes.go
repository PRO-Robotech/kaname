// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyhttp

import "sync"

// Outcome — исход обращения к поверхности церемонии. Словарь ЗАКРЫТ: у каждого
// значения свой счётчик, заведённый при сборке (Census), — «ноль отказов за всю
// жизнь полосы» обязан отличаться от «полоса не исполнялась ни разу».
//
// Наружу отказы после именования кода неразличимы (приёмка Р10), а отказы до
// доверия цели — неразличимы между собой (Р4). Различимость для нас живёт
// здесь и в журнале.
type Outcome string

// Исходы эндпоинта авторизации.
const (
	OutcomeAuthorizeMethodNotAllowed     Outcome = "authorize-method-not-allowed"
	OutcomeAuthorizeRequestMalformed     Outcome = "authorize-request-malformed"
	OutcomeAuthorizeClientUnknown        Outcome = "authorize-client-unknown"
	OutcomeAuthorizeRedirectUnregistered Outcome = "authorize-redirect-unregistered"
	OutcomeAuthorizeStateBelowFloor      Outcome = "authorize-state-below-floor"
	OutcomeAuthorizeProtocolRefused      Outcome = "authorize-protocol-refused"
	OutcomeAuthorizeLoginRequired        Outcome = "authorize-login-required"
	OutcomeAuthorizeStepUpRequired       Outcome = "authorize-step-up-required"
	OutcomeAuthorizeUnavailable          Outcome = "authorize-unavailable"
	OutcomeAuthorizeIssued               Outcome = "authorize-code-issued"
)

// Исходы полос обмена токен-эндпоинта.
const (
	OutcomeExchangeRequestRefused Outcome = "token-request-refused"
	OutcomeExchangeClientRefused  Outcome = "token-client-refused"
	OutcomeExchangeGrantRefused   Outcome = "token-grant-refused"
	OutcomeExchangeUnavailable    Outcome = "token-unavailable"
	OutcomeExchangeCodeExchanged  Outcome = "token-code-exchanged"
	OutcomeExchangeRefreshed      Outcome = "token-refreshed"
)

// Outcomes — словарь целиком, КОПИЕЙ.
func Outcomes() []Outcome {
	return []Outcome{
		OutcomeAuthorizeMethodNotAllowed, OutcomeAuthorizeRequestMalformed, OutcomeAuthorizeClientUnknown,
		OutcomeAuthorizeRedirectUnregistered, OutcomeAuthorizeStateBelowFloor, OutcomeAuthorizeProtocolRefused,
		OutcomeAuthorizeLoginRequired, OutcomeAuthorizeStepUpRequired, OutcomeAuthorizeUnavailable,
		OutcomeAuthorizeIssued,
		OutcomeExchangeRequestRefused, OutcomeExchangeClientRefused, OutcomeExchangeGrantRefused,
		OutcomeExchangeUnavailable, OutcomeExchangeCodeExchanged, OutcomeExchangeRefreshed,
	}
}

// DeclaredOutcomes — словарь строками: читателю величин набор рядов витрины
// обязан совпадать с набором клеток переписи by construction.
func DeclaredOutcomes() []string {
	declared := Outcomes()
	out := make([]string, 0, len(declared))
	for _, o := range declared {
		out = append(out, string(o))
	}
	return out
}

// Census — перепись исходов, засеянная ЦЕЛИКОМ по словарю при сборке.
type Census struct {
	mu     sync.Mutex
	counts map[Outcome]uint64
}

// NewCensus — перепись с нулём у каждого объявленного исхода.
func NewCensus() *Census {
	c := &Census{counts: make(map[Outcome]uint64, len(Outcomes()))}
	for _, o := range Outcomes() {
		c.counts[o] = 0
	}
	return c
}

func (c *Census) count(o Outcome) {
	c.mu.Lock()
	c.counts[o]++
	c.mu.Unlock()
}

// Read — снимок переписи строками. Читается сборщиком метрик.
func (c *Census) Read() map[string]uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]uint64, len(c.counts))
	for k, v := range c.counts {
		out[string(k)] = v
	}
	return out
}
