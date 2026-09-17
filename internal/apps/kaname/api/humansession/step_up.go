// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// step_up.go — ЦЕРЕМОНИЯ ПОВЫШЕНИЯ внутри живой сессии (Ф11 §6 «серверная
// операция и её ответ»; адрес и форму заводит Ф12 Р4 — `POST /iam/v1/auth/step-up`;
// Ф11-08, Ф11-09, Ф11-11, Ф11-29, Ф11-30; Ф12-10, Ф12-15…22).
//
// Глагол ОДИН на три ветви, способ называет клиент: `password` (ветвь Ф11 —
// сверка текущего пароля тем же проверяющим, что вход), `totp`, `lookup_secret`
// (ветви Ф12 — `sf_present.go`). Второго адреса церемонии — на способ — не
// заводится: консоль звала бы два адреса об одном предмете.
//
// Всякое успешное предъявление — предъявление в смысле Ф11: способ кладётся в
// множество, уровень пересчитывается правилом (монотонно: понижения нет),
// носитель перевыпускается, момент последнего предъявления сдвигается; момент
// аутентификации не двигает ничто. Неудачное предъявление сессию не гасит и не
// понижает (Ф11-30). Ответ называет достигнутый уровень и чего не хватает.

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// StepUpInput — предъявление одного способа внутри сессии.
type StepUpInput struct {
	Bearer domain.SessionBearer
	Method assurance.Method
	// Password — у способа `password`; Code — у `totp` и `lookup_secret`.
	Password string
	Code     string
	Source   string
}

// StepUpOutput — сессия после предъявления, новый носитель, вид `assurance`.
type StepUpOutput struct {
	View      SessionView
	Bearer    domain.SessionBearer
	Assurance AssuranceView
	// BackupCodesRemaining — только в ответе, потребившем запасной код (Р4).
	BackupCodesRemaining *int
}

// StepUpUseCase — церемония.
type StepUpUseCase struct {
	deps SecondFactorDeps
	gate attemptGate
}

// NewStepUpUseCase — построение с проверкой зависимостей.
func NewStepUpUseCase(d SecondFactorDeps) (*StepUpUseCase, error) {
	d, err := d.validate("step-up")
	if err != nil {
		return nil, err
	}
	return &StepUpUseCase{deps: d, gate: d.gate()}, nil
}

// Execute — порядок: форма → сессия → частота → (у кода) состояние → сверка →
// предъявление одним исходом с журналом повышения.
func (uc *StepUpUseCase) Execute(ctx context.Context, in StepUpInput) (StepUpOutput, error) {
	switch in.Method {
	case assurance.MethodPassword:
		if in.Password == "" {
			return StepUpOutput{}, FieldRequired("password")
		}
	case assurance.MethodTOTP, assurance.MethodLookupSecret:
		if err := JudgeCodeForm("code", SecondFactorPresentation{Method: in.Method, Code: in.Code}); err != nil {
			return StepUpOutput{}, err
		}
	default:
		return StepUpOutput{}, &FieldError{Field: "method", Rule: "must be one of password|totp|lookup_secret"}
	}
	now := uc.deps.Now().UTC()
	resolved, err := resolveLiveSession(ctx, uc.deps, in.Bearer, now)
	if err != nil {
		return StepUpOutput{}, err
	}
	user := resolved.User
	addressKey := AddressKey(string(user.Email))
	if hit, err := uc.gate.check(ctx, addressKey, in.Source); err != nil {
		return StepUpOutput{}, ErrStoreUnavailable
	} else if hit != nil {
		uc.deps.Observer.RateLimitObserved(hit.Scope)
		return StepUpOutput{}, hit
	}

	var (
		p          = presenter{deps: uc.deps}
		pr         preparedPresentation
		passwordOK bool
	)
	if in.Method == assurance.MethodPassword {
		outcome, err := uc.verifyPassword(ctx, user.ID, in.Password)
		if err != nil {
			return StepUpOutput{}, ErrStoreUnavailable
		}
		switch outcome {
		case passwordverify.OutcomeMatched:
			passwordOK = true
		case passwordverify.OutcomeCapacityExhausted:
			// Преходящий исход: попыткой не считается (PWV-15.3), наружу — тот же отказ.
			return StepUpOutput{}, ErrAuthenticationFailed
		default:
			if werr := recordFailureTx(ctx, uc.deps.Store, addressKey, in.Source, now); werr != nil {
				uc.deps.Logger.Error("step-up: failed attempt not recorded", "err", werr.Error())
			}
			return StepUpOutput{}, ErrAuthenticationFailed
		}
	} else {
		pr, err = p.prepare(ctx, user.ID, SecondFactorPresentation{Method: in.Method, Code: in.Code})
		if err != nil {
			return StepUpOutput{}, ErrStoreUnavailable
		}
		if pr.verdict != verdictMatched {
			st, _ := p.settle(ctx, nil, pr, false)
			p.observe(pr, st)
			return StepUpOutput{}, uc.refuse(ctx, pr.verdict, addressKey, in.Source, now)
		}
	}

	bearer, err := domain.NewSessionBearer()
	if err != nil {
		return StepUpOutput{}, ErrStoreUnavailable
	}
	methods := withMethod(resolved.Session.PresentedMethods, in.Method)
	level, err := levelOf(methods)
	if err != nil {
		uc.deps.Logger.Error("step-up: level not derived", "err", err.Error())
		return StepUpOutput{}, ErrStoreUnavailable
	}

	w, err := uc.deps.Store.Writer(ctx)
	if err != nil {
		return StepUpOutput{}, ErrStoreUnavailable
	}
	defer func() { _ = w.Rollback(ctx) }()
	var st settledPresentation
	if !passwordOK {
		st, err = p.settle(ctx, w, pr, true)
		if err != nil {
			return StepUpOutput{}, ErrStoreUnavailable
		}
		if st.verdict != verdictMatched {
			_ = w.Rollback(ctx)
			p.observe(pr, st)
			return StepUpOutput{}, uc.refuse(ctx, st.verdict, addressKey, in.Source, now)
		}
	}
	if err := w.PresentInSession(ctx, resolved.Session.ID, methods, level, bearer.Digest(), now); err != nil {
		return StepUpOutput{}, ErrStoreUnavailable
	}
	if err := w.ResetFailures(ctx, FailureByAddress, addressKey); err != nil {
		return StepUpOutput{}, ErrStoreUnavailable
	}
	if err := emitStepUpJournal(ctx, w, user, resolved.Session, in.Method, level); err != nil {
		return StepUpOutput{}, ErrStoreUnavailable
	}
	if err := w.Commit(ctx); err != nil {
		return StepUpOutput{}, ErrStoreUnavailable
	}
	if !passwordOK {
		p.observe(pr, st)
	}

	s := resolved.Session
	s.PresentedMethods, s.AssuranceLevel, s.LastPresentedAt = methods, level, now
	out := StepUpOutput{
		View:      SessionView{User: user, Session: s, EmailVerified: resolved.EmailVerified},
		Bearer:    bearer,
		Assurance: assuranceAfter(ctx, uc.deps, user.ID, methods),
	}
	if st.consumed {
		remaining := st.remaining
		out.BackupCodesRemaining = &remaining
	}
	return out, nil
}

// verifyPassword — ветвь пароля (Ф11-09): тем же проверяющим, что вход; исход
// проверяющего наружу не выходит.
func (uc *StepUpUseCase) verifyPassword(ctx context.Context, userID domain.UserID, password string) (passwordverify.Outcome, error) {
	var stored domain.LoginVerifier
	m, err := uc.deps.Methods.Get(ctx, userID, domain.LoginMethodPassword)
	switch {
	case err == nil:
		stored = m.Verifier
	case isNotFound(err):
	default:
		return "", err
	}
	res := uc.deps.Verifier.Verify(stored, password)
	if res.Outcome.IsOurError() {
		uc.deps.Logger.Error("step-up: stored password material could not be checked — our data, not the caller's input",
			"outcome", string(res.Outcome))
	}
	return res.Outcome, nil
}

func (uc *StepUpUseCase) refuse(ctx context.Context, v presentVerdict, addressKey, source string, at time.Time) error {
	if countsAsAttempt(v) {
		if werr := recordFailureTx(ctx, uc.deps.Store, addressKey, source, at); werr != nil {
			uc.deps.Logger.Error("step-up: failed attempt not recorded", "err", werr.Error())
		}
	}
	return refusalOf(v)
}
