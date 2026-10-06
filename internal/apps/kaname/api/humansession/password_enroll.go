// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// password_enroll.go — ЗАВЕДЕНИЕ ПЕРВОГО ПАРОЛЯ из живой сессии (задача
// PRO-Robotech/kaname#213; приёмка
// `docs/engineering/acceptance/first-password-from-a-live-session.md`,
// отпечаток 72825c63…, Р1…Р7).
//
// # Заведение — не смена
//
// Основание — живая СВЕЖАЯ сессия самого человека (Р2), а не текущий пароль:
// его у человека нет (он входит ключом, Ф13 Р7). Строка «пароль» уже есть —
// отказ состояния (Р3), и решает его ключ строки хранилища, а не проверка
// перед вставкой: из двух одновременных заведений проходит одно.
//
// # Исход — строка и событие одной транзакцией; сессии не трогаются (Р5)
//
// Ни один прежний материал не стал негодным — способ добавлен, — поэтому
// прочие сессии живут, отсечки нет, носитель не перевыпускается, уровень и
// момент последнего предъявления не меняются (заведение — не предъявление,
// Ф11 Р2). Счёт неверных предъявлений глагол не трогает (Р7): секрета он не
// предъявляет.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// AuditPasswordEnrolled — событие заведения первого пароля (Р5).
const AuditPasswordEnrolled = "iam.user.password_enrolled"

// Отказ состояния заведения (Р3): тот же код и статус, что у «второй фактор
// уже заведён» на этой полосе — один предмет «способ уже заведён».
const (
	TextPasswordAlreadySet   = "password is already set; change it with the current password"
	ReasonPasswordAlreadySet = "PASSWORD_ALREADY_SET"
)

// ErrPasswordAlreadySet — строка «пароль» у человека уже есть.
var ErrPasswordAlreadySet = errors.New(TextPasswordAlreadySet)

// EnrollPasswordDeps — зависимости глагола; все обязательны, кроме журнала.
type EnrollPasswordDeps struct {
	Store  Store
	Hasher Hasher
	Rule   *PasswordRule
	// Freshness — окно свежести правки своих данных (Ф1 §4.1): та же
	// величина, что у второго фактора.
	Freshness time.Duration
	Observer  Observer
	Now       func() time.Time
	Logger    *slog.Logger
}

// EnrollPasswordInput — носитель сессии и новый пароль.
type EnrollPasswordInput struct {
	Bearer      domain.SessionBearer
	NewPassword string
}

// EnrollPasswordOutput — сессия, как она есть: глагол её не меняет (Р5, Р6).
type EnrollPasswordOutput struct {
	View SessionView
}

// EnrollPasswordUseCase — заведение первого пароля.
type EnrollPasswordUseCase struct{ deps EnrollPasswordDeps }

// NewEnrollPasswordUseCase — построение с проверкой зависимостей.
func NewEnrollPasswordUseCase(d EnrollPasswordDeps) (*EnrollPasswordUseCase, error) {
	switch {
	case d.Store == nil:
		return nil, fmt.Errorf("password enroll: session store required")
	case d.Hasher == nil:
		return nil, fmt.Errorf("password enroll: hasher required")
	case d.Rule == nil:
		return nil, fmt.Errorf("password enroll: password rule required")
	case d.Freshness <= 0:
		return nil, fmt.Errorf("password enroll: freshness window must be positive")
	}
	if d.Observer == nil {
		d.Observer = NopObserver{}
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return &EnrollPasswordUseCase{deps: d}, nil
}

// Execute — порядок: сессия → свежесть → правило → значение → строка и
// событие одним исходом.
func (uc *EnrollPasswordUseCase) Execute(ctx context.Context, in EnrollPasswordInput) (EnrollPasswordOutput, error) {
	now := uc.deps.Now().UTC()
	if in.Bearer.IsZero() {
		return EnrollPasswordOutput{}, ErrAuthenticationFailed
	}
	resolved, reason, err := uc.deps.Store.Resolve(ctx, in.Bearer.Digest(), now)
	if err != nil {
		return EnrollPasswordOutput{}, ErrStoreUnavailable
	}
	if reason != SessionFound {
		uc.deps.Observer.NoSessionObserved(reason)
		return EnrollPasswordOutput{}, ErrAuthenticationFailed
	}
	// Свежесть — граница включена: ровно окно — свежая (Р2).
	if now.Sub(resolved.Session.LastPresentedAt) > uc.deps.Freshness {
		return EnrollPasswordOutput{}, ErrSessionNotFresh
	}
	user := resolved.User
	if err := uc.deps.Rule.Judge(ctx, string(user.Email), in.NewPassword); err != nil {
		return EnrollPasswordOutput{}, err
	}
	material, err := uc.deps.Hasher.Hash(in.NewPassword)
	if err != nil {
		uc.deps.Logger.Error("password enroll: hasher refused", "err", err.Error())
		return EnrollPasswordOutput{}, ErrStoreUnavailable
	}
	w, err := uc.deps.Store.Writer(ctx)
	if err != nil {
		return EnrollPasswordOutput{}, ErrStoreUnavailable
	}
	defer func() { _ = w.Rollback(ctx) }()
	enrolled, err := w.EnrollLoginMethod(ctx, domain.LoginMethod{
		UserID: user.ID, Kind: domain.LoginMethodPassword, Verifier: material, State: domain.LoginMethodStateActive,
	})
	if err != nil {
		return EnrollPasswordOutput{}, ErrStoreUnavailable
	}
	if !enrolled {
		return EnrollPasswordOutput{}, ErrPasswordAlreadySet
	}
	if err := w.EmitAudit(ctx, outboxtypes.AuditEvent{
		EventType:       AuditPasswordEnrolled,
		TenantAccountID: string(user.AccountID),
		Payload: map[string]any{
			"user_id":    string(user.ID),
			"session_id": string(resolved.Session.ID),
			"methods":    resolved.Session.PresentedMethods,
		},
	}); err != nil {
		return EnrollPasswordOutput{}, ErrStoreUnavailable
	}
	if err := w.Commit(ctx); err != nil {
		return EnrollPasswordOutput{}, ErrStoreUnavailable
	}
	return EnrollPasswordOutput{View: SessionView{User: user, Session: resolved.Session, EmailVerified: resolved.EmailVerified}}, nil
}
