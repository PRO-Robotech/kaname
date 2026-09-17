// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys

// begin_registration.go — ВЫДАЧА ИСПЫТАНИЯ РЕГИСТРАЦИИ (Ф7-40): шесть величин
// контракта в испытании, запрос расширения свойств удостоверения, срок —
// литерал контракта. Действие — в окне свежести (Р5, Ф7-04): испытание,
// выданное несвежей сессии, было бы результатом церемонии, собранным без
// доказательства, что человек — он.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
)

// BeginRegistrationInput — кому заводится ключ и кто зовёт.
type BeginRegistrationInput struct {
	// UserID — человек, которому заводится ключ (область записи каталога).
	UserID domain.UserID
	// Actor — вызывающий; окно свежести судится о нём.
	Actor domain.UserID
}

// BeginRegistrationOutput — выданное испытание с шестью величинами контракта
// (Ф7-40) и запросом расширения свойств удостоверения.
type BeginRegistrationOutput struct {
	Challenge     []byte
	ExpiresAt     time.Time
	RPID          string
	RPDisplayName string
	// User — человек глазами аутентификатора: имя и отображаемое имя.
	User domain.User
	// UserHandle — `user.id` церемонии: платформенный `id` человека как байты.
	UserHandle       []byte
	Algorithms       []int64
	UserVerification string
	ResidentKey      string
	Attestation      string
	CredProps        bool
}

// ContractValuesInRegistrationChallenge — перепись пары «величин контракта,
// попадающих в испытание регистрации · названных выданным испытанием» (Ф7-40).
func ContractValuesInRegistrationChallenge(o BeginRegistrationOutput) (named, total int) {
	total = 6
	for _, present := range []bool{
		o.RPID != "", len(o.Algorithms) > 0, o.RPDisplayName != "",
		o.UserVerification != "", o.ResidentKey != "", o.Attestation != "",
	} {
		if present {
			named++
		}
	}
	return named, total
}

// BeginRegistrationUseCase — выдача испытания регистрации.
type BeginRegistrationUseCase struct{ deps Deps }

// NewBeginRegistrationUseCase — построение с проверкой зависимостей.
func NewBeginRegistrationUseCase(d Deps) (*BeginRegistrationUseCase, error) {
	d, err := d.validate("access key begin registration")
	if err != nil {
		return nil, err
	}
	return &BeginRegistrationUseCase{deps: d}, nil
}

// Execute — свежесть → человек → испытание.
func (uc *BeginRegistrationUseCase) Execute(ctx context.Context, in BeginRegistrationInput) (BeginRegistrationOutput, error) {
	if in.UserID == "" {
		return BeginRegistrationOutput{}, fieldRequired("user_id")
	}
	now := uc.deps.Now().UTC()
	if err := requireFresh(ctx, uc.deps, LaneRegistration, in.Actor, now); err != nil {
		return BeginRegistrationOutput{}, err
	}
	user, err := activeUser(ctx, uc.deps, in.UserID, "begin registration")
	if err != nil {
		return BeginRegistrationOutput{}, err
	}
	ch, err := issueChallenge(ctx, uc.deps, in.UserID, domain.ChallengeForRegistration, now)
	if err != nil {
		return BeginRegistrationOutput{}, err
	}
	uc.deps.Observer.AccessKeyEventObserved(EventRegistrationChallengeIssued)
	return BeginRegistrationOutput{
		Challenge: ch.Challenge, ExpiresAt: ch.ExpiresAt,
		RPID: uc.deps.Binding.RPID, RPDisplayName: RPDisplayName,
		User: user, UserHandle: []byte(in.UserID),
		Algorithms:       algorithmsOf(uc.deps.Binding.Algorithms),
		UserVerification: UserVerificationRegistration, ResidentKey: ResidentKey,
		Attestation: Attestation, CredProps: true,
	}, nil
}

func algorithmsOf(algs []webauthnverify.Algorithm) []int64 {
	out := make([]int64, 0, len(algs))
	for _, a := range algs {
		out = append(out, int64(a))
	}
	return out
}

// requireFresh — окно свежести правки своих данных от момента последнего
// предъявления вызывающего (Ф11 Р6, Р5): не предъявлял либо предъявлял давно —
// отказ, называющий следующий шаг.
func requireFresh(ctx context.Context, d Deps, lane Lane, actor domain.UserID, now time.Time) error {
	if actor == "" {
		d.Observer.AccessKeyRefusalObserved(lane, RefusalSessionNotFresh)
		return sessionNotFresh()
	}
	at, found, err := d.Freshness.LastPresentedAt(ctx, actor)
	if err != nil {
		d.Logger.Error("access keys: freshness unreadable", "lane", string(lane), "err", err.Error())
		return storeUnavailable()
	}
	if !found || now.Sub(at) > d.FreshnessWindow {
		d.Observer.AccessKeyRefusalObserved(lane, RefusalSessionNotFresh)
		return sessionNotFresh()
	}
	return nil
}

// activeUser — человек ОДНИМ чтением; только ACTIVE заводит ключ: состояние
// решает владелец ключа, как у удостоверений-соседей.
func activeUser(ctx context.Context, d Deps, id domain.UserID, verb string) (domain.User, error) {
	user, err := d.Store.UserOf(ctx, id)
	if err != nil {
		if errors.Is(err, iamerr.ErrNotFound) {
			return domain.User{}, notFoundUser(id)
		}
		d.Logger.Error("access keys: user unreadable", "verb", verb, "err", err.Error())
		return domain.User{}, storeUnavailable()
	}
	if !user.InviteStatus.MayAuthenticate() {
		return domain.User{}, userNotActive(id)
	}
	return user, nil
}

// issueChallenge — случайное испытание, привязанное к вызывающему и
// процедуре, своей транзакцией.
func issueChallenge(ctx context.Context, d Deps, userID domain.UserID, purpose domain.AccessKeyChallengePurpose, now time.Time) (domain.AccessKeyChallenge, error) {
	raw := make([]byte, domain.AccessKeyChallengeBytes)
	if _, err := rand.Read(raw); err != nil {
		d.Logger.Error("access keys: challenge not minted", "err", err.Error())
		return domain.AccessKeyChallenge{}, storeUnavailable()
	}
	ch := domain.AccessKeyChallenge{Challenge: raw, UserID: userID, Purpose: purpose, IssuedAt: now, ExpiresAt: now.Add(ChallengeTTL)}
	if err := ch.Validate(); err != nil {
		return domain.AccessKeyChallenge{}, fmt.Errorf("access keys: challenge: %w", err)
	}
	w, err := d.Store.Writer(ctx)
	if err != nil {
		return domain.AccessKeyChallenge{}, storeUnavailable()
	}
	defer func() { _ = w.Rollback(ctx) }()
	if err := w.InsertChallenge(ctx, ch); err != nil {
		d.Logger.Error("access keys: challenge not stored", "err", err.Error())
		return domain.AccessKeyChallenge{}, storeUnavailable()
	}
	if err := w.Commit(ctx); err != nil {
		return domain.AccessKeyChallenge{}, storeUnavailable()
	}
	return ch, nil
}
