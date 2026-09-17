// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// password_rule.go — ЕДИНСТВЕННОЕ объявление правила пароля (Р11, Ф1-38,
// Ф3-32): минимальная длина · схожесть с адресом · проверка по базе утечек.
// Регистрация (Ф4) и восстановление (Ф5) ЗОВУТ это правило; второе объявление
// в дереве — находка гейта `TestPasswordRuleIsDeclaredOnce`.
//
// Исход Ф1-35 записан решением (Р11): авторитет утечек объявлен и недоступен —
// пароль принимается по остальным правилам, несостоявшаяся проверка сосчитана и
// записана в журнал уровня error. Настроен не туда (ответ не по протоколу) —
// ОТКАЗ операции: иначе проверка в никуда была бы присутствующей и никогда не
// отказывающей.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// BreachVerdict — что ответил авторитет утечек.
type BreachVerdict int

const (
	// BreachNotFound — пароля в базе нет.
	BreachNotFound BreachVerdict = iota
	// BreachFound — пароль в базе есть; число здесь не несётся и наружу не
	// выходит (Ф1-34: «без числа»).
	BreachFound
)

// ErrBreachAuthorityUnavailable — отказ сети либо 5xx: третья категория, а не
// вердикт; исход — проход громко (Ф1-35, Р11).
var ErrBreachAuthorityUnavailable = errors.New("breach check authority unavailable")

// BreachChecker — порт авторитета утечек. Реализация — адаптер по k-анонимности
// (`internal/clients/breachcheck`); дублёр в пробах.
type BreachChecker interface {
	// Check — вердикт; ошибка ErrBreachAuthorityUnavailable — недоступность,
	// ErrBreachAuthorityMisconfigured — по адресу не тот эндпоинт, прочее —
	// как недоступность.
	Check(ctx context.Context, password string) (BreachVerdict, error)
}

// PasswordRule — правило, объявленное один раз.
type PasswordRule struct {
	// MinLength — минимальная длина в РУНАХ; без умолчания (Ф1 §7 инв. 4).
	MinLength int
	// Breach — авторитет утечек; nil — проверка выключена словом (Ф1-36).
	Breach   BreachChecker
	observer Observer
	logger   *slog.Logger
}

// NewPasswordRule — правило с наблюдателем и журналом.
func NewPasswordRule(minLength int, breach BreachChecker, observer Observer, logger *slog.Logger) (*PasswordRule, error) {
	if minLength <= 0 {
		return nil, fmt.Errorf("password rule: min length must be positive")
	}
	if observer == nil {
		observer = NopObserver{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &PasswordRule{MinLength: minLength, Breach: breach, observer: observer, logger: logger}, nil
}

// Тексты правил — часть отказа `Illegal argument newPassword: <правило>`.
const (
	RuleTooShort       = "shorter than the declared minimum length"
	RuleResemblesEmail = "must not resemble the e-mail address"
	RuleBreached       = "appears in a known breach corpus"
)

// Judge — годен ли пароль для адреса email. Отказ — *FieldError с полем
// `newPassword` и правилом; ErrBreachAuthorityMisconfigured — отказ операции.
func (r *PasswordRule) Judge(ctx context.Context, email, password string) error {
	if password == "" {
		return FieldRequired("newPassword")
	}
	if len([]rune(password)) < r.MinLength {
		return &FieldError{Field: "newPassword", Rule: RuleTooShort}
	}
	if resemblesEmail(email, password) {
		return &FieldError{Field: "newPassword", Rule: RuleResemblesEmail}
	}
	if r.Breach == nil {
		r.observer.BreachCheckObserved(BreachCheckDisabled)
		return nil
	}
	verdict, err := r.Breach.Check(ctx, password)
	switch {
	case errors.Is(err, ErrBreachAuthorityMisconfigured):
		r.observer.BreachCheckObserved(BreachCheckMisconfigured)
		r.logger.Error("password breach check: the declared address does not answer the protocol — refusing the operation",
			"err", err.Error())
		return ErrBreachAuthorityMisconfigured
	case err != nil:
		r.observer.BreachCheckObserved(BreachCheckUnavailable)
		r.logger.Error("password breach check did not happen: authority unavailable — password accepted by the remaining rules (Ф1-35)",
			"err", err.Error())
		return nil
	case verdict == BreachFound:
		r.observer.BreachCheckObserved(BreachCheckFound)
		return &FieldError{Field: "newPassword", Rule: RuleBreached}
	}
	r.observer.BreachCheckObserved(BreachCheckClean)
	return nil
}

// resemblesEmail — пароль совпадает с адресом, содержит его целиком либо
// содержит локальную часть длиной от четырёх знаков; регистр не различается.
func resemblesEmail(email, password string) bool {
	e := strings.ToLower(strings.TrimSpace(email))
	p := strings.ToLower(password)
	if e == "" {
		return false
	}
	if p == e || strings.Contains(p, e) {
		return true
	}
	local, _, ok := strings.Cut(e, "@")
	if ok && len([]rune(local)) >= 4 && strings.Contains(p, local) {
		return true
	}
	return false
}
