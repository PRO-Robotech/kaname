// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys

// finish_assertion.go — ПРОВЕРКА УТВЕРЖДЕНИЯ ключа вызывающего (Ф7-06…12,
// Ф7-17…20, Ф7-28…30, Ф7-49, Ф7-51…55).
//
// # Один отказ на всё, что называет ключ (§3.0, §7 инв. 4)
//
// Снаружи все четырнадцать полос отказа — один текст и один код, без
// подробностей; внутри причина различима клеткой наблюдателя. Порядок сверок
// внутри контрактом не является (§11 п. 2) и наружу не течёт.
//
// # Порядок здесь
//
// клиентские данные → испытание вызывающего этой процедуры (не выдавалось ·
// чужое · предъявлено · просрочено — одно состояние снаружи) → строка по
// идентификатору удостоверения → принадлежность вызывающему (Ф7-51) →
// рукоятка, если прислана → сверка байтов проверяющим (подпись, происхождение,
// хэш имени, присутствие) → счётчик (Р6) → ОДНОЙ транзакцией: потребление
// испытания и атомарный сдвиг счётчика с моментом предъявления.
//
// # Неразличимость по времени (Ф7-09)
//
// Работа по неизвестному идентификатору выполняется наравне с работой по
// известному: проверяющий гоняется над ключом-приманкой того же алгоритма, что
// у первого объявленного, и над той же подписью — отказ приходит после той же
// стоимости.

import (
	"bytes"
	"context"
	"errors"

	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
)

// FinishAssertionInput — утверждение в байтах браузера и вызывающий.
type FinishAssertionInput struct {
	UserID            domain.UserID
	CredentialID      []byte
	ClientDataJSON    []byte
	AuthenticatorData []byte
	Signature         []byte
	UserHandle        []byte
}

// FinishAssertionOutput — что утверждение сообщило: человек, равный
// вызывающему, ключ и предъявление в виде, который читает правило Ф11 (§3.8).
type FinishAssertionOutput struct {
	UserID       domain.UserID
	AccessKeyID  domain.AccessKeyID
	Flags        webauthnverify.Flags
	Presentation assurance.Presentation
}

// FinishAssertionUseCase — проверка утверждения.
type FinishAssertionUseCase struct {
	deps  Deps
	decoy webauthnverify.DecoyKey
}

// NewFinishAssertionUseCase — построение с проверкой зависимостей и
// ключом-приманкой выравнивания времени.
func NewFinishAssertionUseCase(d Deps) (*FinishAssertionUseCase, error) {
	d, err := d.validate("access key finish assertion")
	if err != nil {
		return nil, err
	}
	decoy, err := webauthnverify.NewDecoyKey(d.Binding.Algorithms[0])
	if err != nil {
		return nil, err
	}
	return &FinishAssertionUseCase{deps: d, decoy: decoy}, nil
}

// Execute — сверка.
func (uc *FinishAssertionUseCase) Execute(ctx context.Context, in FinishAssertionInput) (FinishAssertionOutput, error) {
	if in.UserID == "" {
		return FinishAssertionOutput{}, fieldRequired("user_id")
	}
	if len(in.CredentialID) == 0 {
		return FinishAssertionOutput{}, fieldRequired("credential.id")
	}
	if len(in.ClientDataJSON) == 0 {
		return FinishAssertionOutput{}, fieldRequired("credential.client_data_json")
	}
	if len(in.AuthenticatorData) == 0 {
		return FinishAssertionOutput{}, fieldRequired("credential.authenticator_data")
	}
	if len(in.Signature) == 0 {
		return FinishAssertionOutput{}, fieldRequired("credential.signature")
	}
	now := uc.deps.Now().UTC()
	cd, err := webauthnverify.ParseClientData(in.ClientDataJSON)
	if err != nil {
		return uc.refuse(RefusalMalformed)
	}
	ch, found, err := uc.deps.Store.Challenge(ctx, cd.Challenge, in.UserID, domain.ChallengeForAssertion)
	if err != nil {
		return FinishAssertionOutput{}, mapStoreErr(uc.deps, "access_keys.FinishAssertion.challenge", err)
	}
	// Состояние испытания — одно снаружи (§10 п. 27); сверка байтов идёт и на
	// негодном испытании, чтобы отказ пришёл после той же работы.
	challengeReason := Refusal("")
	if !found {
		challengeReason = RefusalChallengeUnknown
	} else {
		switch ch.StateAt(now) {
		case domain.ChallengeConsumed:
			challengeReason = RefusalChallengeConsumed
		case domain.ChallengeExpired:
			challengeReason = RefusalChallengeExpired
		}
	}

	key, known, err := uc.deps.Store.KeyByCredentialID(ctx, in.CredentialID)
	if err != nil {
		return FinishAssertionOutput{}, mapStoreErr(uc.deps, "access_keys.FinishAssertion.key", err)
	}
	pub, alg := key.PublicKey, webauthnverify.Algorithm(key.Algorithm)
	if !known {
		pub, alg = uc.decoy.Public(), uc.decoy.Algorithm()
	}
	res, verr := webauthnverify.VerifyAssertion(webauthnverify.AssertionInput{
		Challenge: cd.Challenge, Binding: uc.deps.Binding,
		ClientDataJSON: in.ClientDataJSON, AuthenticatorData: in.AuthenticatorData, Signature: in.Signature,
		PublicKey: pub, Algorithm: alg,
	})
	switch {
	case challengeReason != "":
		return uc.refuse(challengeReason)
	case !known:
		return uc.refuse(RefusalUnknownCredential)
	case key.UserID != in.UserID:
		return uc.refuse(RefusalForeignKey)
	case len(in.UserHandle) > 0 && !bytes.Equal(in.UserHandle, key.UserHandle):
		return uc.refuse(RefusalUserHandle)
	case verr != nil:
		return uc.refuse(verifyRefusalOf(verr))
	}
	// Счётчик: чтение классифицирует, инвариант держит оператор (Р6).
	switch webauthnverify.JudgeCounter(key.SignCount, res.SignCount) {
	case webauthnverify.CounterRegressed:
		uc.deps.Observer.SignCountRegressionObserved()
		return uc.refuse(RefusalCounter)
	}
	w, err := uc.deps.Store.Writer(ctx)
	if err != nil {
		return FinishAssertionOutput{}, mapStoreErr(uc.deps, "access_keys.FinishAssertion.writer", err)
	}
	defer func() { _ = w.Rollback(ctx) }()
	consumed, err := w.ConsumeChallenge(ctx, ch.Challenge, in.UserID, domain.ChallengeForAssertion, now)
	if err != nil {
		return FinishAssertionOutput{}, mapStoreErr(uc.deps, "access_keys.FinishAssertion.consume", err)
	}
	if !consumed {
		return uc.refuse(RefusalChallengeConsumed)
	}
	advanced, err := w.AdvanceSignCount(ctx, key.ID, key.SignCount, res.SignCount, now)
	if err != nil {
		return FinishAssertionOutput{}, mapStoreErr(uc.deps, "access_keys.FinishAssertion.advance", err)
	}
	if !advanced {
		// Проигравший конкуренции (Ф7-20, ветвь б): сдвиг перехвачен другим
		// утверждением того же ключа — отказ БЕЗ сигнала клонирования (Р6).
		return uc.refuse(RefusalCounterRace)
	}
	if err := w.Commit(ctx); err != nil {
		return FinishAssertionOutput{}, mapStoreErr(uc.deps, "access_keys.FinishAssertion.commit", err)
	}
	uc.deps.Observer.AccessKeyEventObserved(EventAsserted)
	return FinishAssertionOutput{
		UserID: key.UserID, AccessKeyID: key.ID, Flags: res.Flags,
		Presentation: assurance.KeyAssertion(res.Flags.UserVerified, res.Flags.BackupEligible),
	}, nil
}

func (uc *FinishAssertionUseCase) refuse(reason Refusal) (FinishAssertionOutput, error) {
	uc.deps.Observer.AccessKeyRefusalObserved(LaneAssertion, reason)
	return FinishAssertionOutput{}, assertionRefusal()
}

func verifyRefusalOf(err error) Refusal {
	var r *webauthnverify.Refusal
	if !errors.As(err, &r) {
		return RefusalMalformed
	}
	switch r.Reason {
	case webauthnverify.ReasonSignature:
		return RefusalSignature
	case webauthnverify.ReasonOriginNotAllowed:
		return RefusalOriginNotAllowed
	case webauthnverify.ReasonRPIDHashMismatch:
		return RefusalRPIDMismatch
	case webauthnverify.ReasonUserNotPresent:
		return RefusalUserNotPresent
	case webauthnverify.ReasonAlgorithmNotAllowed:
		return RefusalAlgorithmNotAllowed
	default:
		return RefusalMalformed
	}
}
