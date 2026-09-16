// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// change_password.go — СМЕНА ПАРОЛЯ (Р6; Ф3-19…23): подтверждение текущим
// паролем (это предъявление — тем же проверяющим и тем же счётом попыток, что
// вход), новый — по правилу пароля, и ЧЕТЫРЕ записи одним исходом: новый
// материал · записи всех прочих сессий сняты · отсечка тем же моментом, что у
// выхода, с причиной `password-change` · событие. Сверх того — носитель
// перевыпущен (Ф11 Р5), требование сменить пароль снято (Ф5-24).
//
// Отказов два, и они разные (F4d-19): подтверждение не прислано — поле;
// прислано и не подошло — тот же отказ, что на входе.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/loginmethod"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// AuditPasswordChanged — событие смены (Р14).
const AuditPasswordChanged = "iam.user.password_changed"

// ChangePasswordInput — форма смены.
type ChangePasswordInput struct {
	Bearer          domain.SessionBearer
	CurrentPassword string
	NewPassword     string
	Source          string
}

// ChangePasswordOutput — состав ответа и НОВЫЙ носитель той же сессии.
type ChangePasswordOutput struct {
	View   SessionView
	Bearer domain.SessionBearer
}

// ChangePasswordUseCase — смена пароля.
type ChangePasswordUseCase struct {
	store    Store
	methods  loginmethod.Store
	verifier Verifier
	hasher   Hasher
	rule     *PasswordRule
	observer Observer
	now      func() time.Time
	logger   *slog.Logger
	gate     attemptGate
}

// ChangePasswordDeps — зависимости.
type ChangePasswordDeps struct {
	Store    Store
	Methods  loginmethod.Store
	Verifier Verifier
	Hasher   Hasher
	Rule     *PasswordRule
	Limits   Limits
	Observer Observer
	Now      func() time.Time
	Logger   *slog.Logger
}

// NewChangePasswordUseCase — построение с проверкой зависимостей.
func NewChangePasswordUseCase(d ChangePasswordDeps) (*ChangePasswordUseCase, error) {
	switch {
	case d.Store == nil:
		return nil, fmt.Errorf("change password: session store required")
	case d.Methods == nil:
		return nil, fmt.Errorf("change password: login method store required")
	case d.Verifier == nil:
		return nil, fmt.Errorf("change password: password verifier required")
	case d.Hasher == nil:
		return nil, fmt.Errorf("change password: password hasher required")
	case d.Rule == nil:
		return nil, fmt.Errorf("change password: password rule required")
	}
	if err := d.Limits.Validate(); err != nil {
		return nil, err
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
	return &ChangePasswordUseCase{
		store: d.Store, methods: d.Methods, verifier: d.Verifier, hasher: d.Hasher, rule: d.Rule,
		observer: d.Observer, now: d.Now, logger: d.Logger,
		gate: attemptGate{store: d.Store, limits: d.Limits, now: d.Now, observer: d.Observer},
	}, nil
}

// Execute — смена пароля из сессии носителя.
func (uc *ChangePasswordUseCase) Execute(ctx context.Context, in ChangePasswordInput) (ChangePasswordOutput, error) {
	if in.CurrentPassword == "" {
		return ChangePasswordOutput{}, FieldRequired("currentPassword")
	}
	if in.NewPassword == "" {
		return ChangePasswordOutput{}, FieldRequired("newPassword")
	}
	now := uc.now().UTC()

	// Сессия — по записи (Р16: отсечку читает край до нас).
	if in.Bearer.IsZero() {
		return ChangePasswordOutput{}, ErrAuthenticationFailed
	}
	resolved, reason, err := uc.store.Resolve(ctx, in.Bearer.Digest(), now)
	if err != nil {
		return ChangePasswordOutput{}, ErrStoreUnavailable
	}
	if reason != SessionFound {
		uc.observer.NoSessionObserved(reason)
		return ChangePasswordOutput{}, ErrAuthenticationFailed
	}
	user := resolved.User
	addressKey := AddressKey(string(user.Email))

	// Частота — тот же счёт, что у входа (F4d-19: смена — не обход счётчика).
	if hit, err := uc.gate.check(ctx, addressKey, in.Source); err != nil {
		return ChangePasswordOutput{}, ErrStoreUnavailable
	} else if hit != nil {
		uc.observer.RateLimitObserved(hit.Scope)
		return ChangePasswordOutput{}, hit
	}

	// Подтверждение текущим — предъявление тем же проверяющим.
	m, err := uc.methods.Get(ctx, user.ID, domain.LoginMethodPassword)
	var stored domain.LoginVerifier
	switch {
	case err == nil:
		stored = m.Verifier
	case errors.Is(err, iamerr.ErrNotFound):
	default:
		return ChangePasswordOutput{}, ErrStoreUnavailable
	}
	res := uc.verifier.Verify(stored, in.CurrentPassword)
	switch res.Outcome {
	case passwordverify.OutcomeMatched:
	case passwordverify.OutcomeCapacityExhausted:
		return ChangePasswordOutput{}, ErrAuthenticationFailed
	default:
		if res.Outcome.IsOurError() {
			uc.logger.Error("change password: stored material could not be checked — our data, not the caller's input",
				"outcome", string(res.Outcome))
		}
		if werr := uc.recordFailure(ctx, addressKey, in.Source, now); werr != nil {
			uc.logger.Error("change password: failed attempt not recorded", "err", werr.Error())
		}
		return ChangePasswordOutput{}, ErrAuthenticationFailed
	}

	// Новый пароль — по правилу (Ф1-32…38).
	if err := uc.rule.Judge(ctx, string(user.Email), in.NewPassword); err != nil {
		return ChangePasswordOutput{}, err
	}
	fresh, err := uc.hasher.Hash(in.NewPassword)
	if err != nil {
		uc.logger.Error("change password: hasher refused", "err", err.Error())
		return ChangePasswordOutput{}, ErrStoreUnavailable
	}
	bearer, err := domain.NewSessionBearer()
	if err != nil {
		return ChangePasswordOutput{}, ErrStoreUnavailable
	}

	// Четыре записи одним исходом (Р6).
	w, err := uc.store.Writer(ctx)
	if err != nil {
		return ChangePasswordOutput{}, ErrStoreUnavailable
	}
	defer func() { _ = w.Rollback(ctx) }()
	replaced, err := w.ReplaceLoginVerifier(ctx, domain.LoginMethod{UserID: user.ID, Kind: domain.LoginMethodPassword, Verifier: fresh})
	if err != nil {
		return ChangePasswordOutput{}, ErrStoreUnavailable
	}
	if !replaced {
		// Проверка прошла, а строки способа нет: гонка со снятием способа.
		return ChangePasswordOutput{}, ErrAuthenticationFailed
	}
	if _, err := w.EndOtherSessions(ctx, user.ID, resolved.Session.ID, now, domain.RevokeReasonPasswordChange); err != nil {
		return ChangePasswordOutput{}, ErrStoreUnavailable
	}
	cutoff, err := revocationMoment(ctx, w, resolved.Session, uc.logger)
	if err != nil {
		return ChangePasswordOutput{}, ErrStoreUnavailable
	}
	if err := w.UpsertCutoff(ctx, domain.UserTokenRevocation{
		UserID: user.ID, RevokeBefore: cutoff, Reason: domain.RevokeReasonPasswordChange,
	}, user.ID); err != nil {
		return ChangePasswordOutput{}, ErrStoreUnavailable
	}
	if err := w.RotateBearer(ctx, resolved.Session.ID, bearer.Digest(), now); err != nil {
		return ChangePasswordOutput{}, ErrStoreUnavailable
	}
	if resolved.Session.PasswordChangeRequired {
		if err := w.ClearPasswordChangeRequired(ctx, resolved.Session.ID); err != nil {
			return ChangePasswordOutput{}, ErrStoreUnavailable
		}
	}
	if err := w.EmitAudit(ctx, outboxtypes.AuditEvent{
		EventType:       AuditPasswordChanged,
		TenantAccountID: string(user.AccountID),
		Payload: map[string]any{
			"user_id":    string(user.ID),
			"session_id": string(resolved.Session.ID),
			"methods":    resolved.Session.PresentedMethods,
		},
	}); err != nil {
		return ChangePasswordOutput{}, ErrStoreUnavailable
	}
	if err := w.Commit(ctx); err != nil {
		return ChangePasswordOutput{}, ErrStoreUnavailable
	}

	s := resolved.Session
	s.LastPresentedAt = now
	s.PasswordChangeRequired = false
	// Уровень — пересчёт правилом от множества предъявленного, а не константа.
	if level, ok := assurance.LevelOf(presentationsOf(s.PresentedMethods)); ok {
		s.AssuranceLevel = level.String()
	}
	return ChangePasswordOutput{
		View:   SessionView{User: user, Session: s, EmailVerified: resolved.EmailVerified},
		Bearer: bearer,
	}, nil
}

func (uc *ChangePasswordUseCase) recordFailure(ctx context.Context, addressKey, source string, at time.Time) error {
	w, err := uc.store.Writer(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = w.Rollback(ctx) }()
	if err := recordFailure(ctx, w, addressKey, source, at); err != nil {
		return err
	}
	return w.Commit(ctx)
}

// presentationsOf — слова записи → предъявления правила уровня. Слова вне
// словаря пропускаются: база их не пропускает by construction.
func presentationsOf(methods []string) []assurance.Presentation {
	out := make([]assurance.Presentation, 0, len(methods))
	for _, m := range methods {
		switch m {
		case assurance.MethodPassword.String():
			out = append(out, assurance.PasswordPresented())
		case assurance.MethodTOTP.String():
			out = append(out, assurance.TOTPPresented())
		case assurance.MethodLookupSecret.String():
			out = append(out, assurance.LookupSecretPresented())
		case assurance.MethodRecoveryCode.String():
			out = append(out, assurance.RecoveryCodePresented())
		case assurance.MethodWebAuthn.String():
			out = append(out, assurance.KeyAssertion(false, true))
		}
	}
	return out
}
