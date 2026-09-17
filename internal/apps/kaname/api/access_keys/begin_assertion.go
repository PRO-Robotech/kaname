// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys

// begin_assertion.go — ВЫДАЧА ИСПЫТАНИЯ ПРЕДЪЯВЛЕНИЯ вызывающему (Ф7-42, Р11):
// требование проверки пользователя — литерал контракта; `allowCredentials` —
// удостоверения вызывающего, а не чьи-либо ещё; испытание находится потом
// только из его сессии (Ф7-55). Свежести здесь нет: предъявление ключа —
// то, что окно свежести ОТКРЫВАЕТ (Ф11 Р6), требовать её от него нельзя.

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// BeginAssertionInput — вызывающий.
type BeginAssertionInput struct{ UserID domain.UserID }

// BeginAssertionOutput — испытание в форме `PublicKeyCredentialRequestOptions`.
type BeginAssertionOutput struct {
	Challenge        []byte
	ExpiresAt        time.Time
	RPID             string
	UserVerification string
	AllowCredentials [][]byte
}

// BeginAssertionUseCase — выдача испытания предъявления.
type BeginAssertionUseCase struct{ deps Deps }

// NewBeginAssertionUseCase — построение с проверкой зависимостей.
func NewBeginAssertionUseCase(d Deps) (*BeginAssertionUseCase, error) {
	d, err := d.validate("access key begin assertion")
	if err != nil {
		return nil, err
	}
	return &BeginAssertionUseCase{deps: d}, nil
}

// Execute — испытание вызывающему.
func (uc *BeginAssertionUseCase) Execute(ctx context.Context, in BeginAssertionInput) (BeginAssertionOutput, error) {
	if in.UserID == "" {
		return BeginAssertionOutput{}, fieldRequired("user_id")
	}
	now := uc.deps.Now().UTC()
	creds, err := uc.deps.Store.CredentialIDsOf(ctx, in.UserID)
	if err != nil {
		return BeginAssertionOutput{}, mapStoreErr(uc.deps, "access_keys.BeginAssertion.credentials", err)
	}
	ch, err := issueChallenge(ctx, uc.deps, in.UserID, domain.ChallengeForAssertion, now)
	if err != nil {
		return BeginAssertionOutput{}, err
	}
	uc.deps.Observer.AccessKeyEventObserved(EventAssertionChallengeIssued)
	return BeginAssertionOutput{
		Challenge: ch.Challenge, ExpiresAt: ch.ExpiresAt, RPID: uc.deps.Binding.RPID,
		UserVerification: UserVerificationAssertion, AllowCredentials: creds,
	}, nil
}
