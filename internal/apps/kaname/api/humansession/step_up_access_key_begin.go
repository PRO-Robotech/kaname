// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// step_up_access_key_begin.go — ВЫДАЧА ИСПЫТАНИЯ ПОВЫШЕНИЯ ключом доступа под
// живой сессией (`POST /iam/v1/auth/step-up/access-key/begin`; задача
// PRO-Robotech/kaname#827, приёмка
// `docs/engineering/acceptance/step-up-with-any-enrolled-method.md`, Р2, Р5, Р7;
// замысел §2.1, §2.6).
//
// # Порядок
//
//	признак формы и положение (транспорт) → сессия → «ключи выключены» →
//	удостоверения человека → ноль — отказ «ключа нет» → испытание → выдача
//
// Испытание принадлежит ЗАПИСИ СЕССИИ и одно живое на неё: новая выдача
// сменяет прежнее одним оператором хранилища, и прежнее значение предъявить
// больше нельзя — оно читается «не выдавалось». Частоты у выдачи нет (Р2): рост
// хранилища ограничен одним живым испытанием на сессию и уборкой; счёт
// попыток выдача не спрашивает и не пишет — ни отказ состояния, ни выдача
// попыткой не являются.

import (
	"context"
	"crypto/rand"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
)

// StepUpAccessKeyBeginInput — сессия, под которой испытание выдаётся.
type StepUpAccessKeyBeginInput struct {
	Bearer domain.SessionBearer
}

// StepUpAccessKeyBeginOutput — испытание в форме параметров предъявления
// браузерного интерфейса: удостоверения человека — в `allowCredentials`.
type StepUpAccessKeyBeginOutput struct {
	Challenge        []byte
	RPID             string
	UserVerification string
	// Timeout — срок испытания, как его назовёт браузеру транспорт.
	Timeout time.Duration
	// AllowCredentials — удостоверения человека в порядке `(created_at, id)`.
	AllowCredentials [][]byte
}

// StepUpAccessKeyBeginUseCase — выдача испытания повышения.
type StepUpAccessKeyBeginUseCase struct {
	deps SecondFactorDeps
}

// NewStepUpAccessKeyBeginUseCase — построение с проверкой зависимостей.
func NewStepUpAccessKeyBeginUseCase(d SecondFactorDeps) (*StepUpAccessKeyBeginUseCase, error) {
	d, err := d.validate("step-up access key begin")
	if err != nil {
		return nil, err
	}
	return &StepUpAccessKeyBeginUseCase{deps: d}, nil
}

// Execute — испытание записи сессии носителя.
func (uc *StepUpAccessKeyBeginUseCase) Execute(ctx context.Context, in StepUpAccessKeyBeginInput) (_ StepUpAccessKeyBeginOutput, err error) {
	// Выдача — первая половина церемонии повышения: её сбой хранилища — клетка
	// того же глагола, а не своего.
	defer func() { err = observeStoreFailure(uc.deps.Observer, StoreFailureStepUp, err) }()
	now := uc.deps.Now().UTC()
	resolved, err := resolveLiveSession(ctx, uc.deps, in.Bearer, now)
	if err != nil {
		return StepUpAccessKeyBeginOutput{}, err
	}
	keys := uc.deps.Keys
	// «Выключено» — до чтения удостоверений и до выдачи (Р7): испытание,
	// которое нечем принять, не выдаётся.
	if keys.Binding.Disabled() {
		uc.deps.Observer.SecondFactorRefusalObserved(RefusalAccessKeysDisabled)
		return StepUpAccessKeyBeginOutput{}, webauthnverify.ErrKeysDisabled
	}
	allow, err := keys.Store.CredentialIDsOf(ctx, resolved.User.ID)
	if err != nil {
		return StepUpAccessKeyBeginOutput{}, ErrStoreUnavailable
	}
	if len(allow) == 0 {
		// Ключей ноль — отказ состояния, не попытка (Р5): испытания нет.
		uc.deps.Observer.SecondFactorRefusalObserved(RefusalAccessKeyNotRegistered)
		return StepUpAccessKeyBeginOutput{}, ErrAccessKeyNotRegistered
	}
	raw := make([]byte, domain.AccessKeyChallengeBytes)
	if _, err := rand.Read(raw); err != nil {
		uc.deps.Logger.ErrorContext(ctx, "step-up access key begin: random source refused a challenge", "err", err.Error())
		return StepUpAccessKeyBeginOutput{}, ErrStoreUnavailable
	}
	if err := keys.Store.IssueStepUpChallenge(ctx, domain.StepUpChallenge{
		Challenge: raw, SessionID: resolved.Session.ID, IssuedAt: now, ExpiresAt: now.Add(keys.ChallengeTTL),
	}); err != nil {
		return StepUpAccessKeyBeginOutput{}, ErrStoreUnavailable
	}
	uc.deps.Observer.StepUpAccessKeyObserved(AccessKeyLoginChallengeIssued)
	return StepUpAccessKeyBeginOutput{
		Challenge: raw, RPID: keys.Binding.RPID, UserVerification: keys.UserVerification,
		Timeout: keys.ChallengeTTL, AllowCredentials: allow,
	}, nil
}
