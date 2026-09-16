// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// rate.go — ограничение частоты неверных предъявлений (Р10): два окна — по
// адресу и по источнику; величины — настройка без умолчания.
//
// Что считается попыткой — ВСЕ отказы входа Ф3-02 и неподошедшее подтверждение
// смены пароля. Что не считается: отказ формы, отказ по частоте, исчерпание
// ёмкости проверяющего (PWV-15.3), успешный вход (он обнуляет счёт по адресу).
// Считает ВЫЗЫВАЮЩИЙ (полоса), здесь — только окна и вопрос «исчерпано ли».

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Limits — четыре величины Р10. Незаданная — отказ старта (страж настройки, не
// здесь); здесь — отказ построения, чтобы полоса без величин не собралась.
type Limits struct {
	AddressAttempts int
	AddressWindow   time.Duration
	SourceAttempts  int
	SourceWindow    time.Duration
}

// Validate — все четыре положительны.
func (l Limits) Validate() error {
	switch {
	case l.AddressAttempts <= 0:
		return fmt.Errorf("login rate limit: address attempts must be positive")
	case l.AddressWindow <= 0:
		return fmt.Errorf("login rate limit: address window must be positive")
	case l.SourceAttempts <= 0:
		return fmt.Errorf("login rate limit: source attempts must be positive")
	case l.SourceWindow <= 0:
		return fmt.Errorf("login rate limit: source window must be positive")
	}
	return nil
}

// LongestWindow — порог уборки следов: старше самого длинного окна ни одна ось
// не считает.
func (l Limits) LongestWindow() time.Duration {
	if l.AddressWindow > l.SourceWindow {
		return l.AddressWindow
	}
	return l.SourceWindow
}

// AddressKey — нормализованный ключ почты (нижний регистр, без краевых
// пробелов — F4d-52): регистр букв не удваивает окно.
func AddressKey(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

// attemptGate — вопрос «исчерпано ли» по обеим осям; source пуст — ось
// источника не спрашивается (вызывающего без адреса к полосе не бывает — Р16, но
// пробы уровня I зовут полосу и без него).
type attemptGate struct {
	store  Store
	limits Limits
	now    func() time.Time
}

func (g attemptGate) check(ctx context.Context, addressKey, source string) (*TooManyAttemptsError, error) {
	now := g.now()
	if hit, err := g.exhausted(ctx, FailureByAddress, addressKey, g.limits.AddressAttempts, g.limits.AddressWindow, now); err != nil || hit != nil {
		return hit, err
	}
	if source == "" {
		return nil, nil
	}
	return g.exhausted(ctx, FailureBySource, source, g.limits.SourceAttempts, g.limits.SourceWindow, now)
}

func (g attemptGate) exhausted(ctx context.Context, scope FailureScope, key string, attempts int, window time.Duration, now time.Time) (*TooManyAttemptsError, error) {
	if key == "" {
		return nil, nil
	}
	since := now.Add(-window)
	n, err := g.store.CountFailures(ctx, scope, key, since)
	if err != nil {
		return nil, err
	}
	if n < attempts {
		return nil, nil
	}
	oldest, found, err := g.store.OldestFailureSince(ctx, scope, key, since)
	if err != nil {
		return nil, err
	}
	retry := window
	if found {
		retry = oldest.Add(window).Sub(now)
		if retry <= 0 {
			retry = time.Second
		}
	}
	return &TooManyAttemptsError{Scope: scope, RetryAfter: retry}, nil
}

// recordFailure — след по обеим осям одной транзакцией.
func recordFailure(ctx context.Context, w Writer, addressKey, source string, at time.Time) error {
	if addressKey != "" {
		if err := w.RecordFailure(ctx, FailureByAddress, addressKey, at); err != nil {
			return err
		}
	}
	if source != "" {
		if err := w.RecordFailure(ctx, FailureBySource, source, at); err != nil {
			return err
		}
	}
	return nil
}
