// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys

// finish_registration.go — ПРИЁМ РЕЗУЛЬТАТА ЦЕРЕМОНИИ и заведение ключа
// (Ф7-01…05, Ф7-34, Ф7-35, Ф7-41, Ф7-44…46, Ф7-48).
//
// # Порядок — несущий
//
// форма имени и описания (синхронно, первым стейтментом, испытания не гасит —
// Ф7-46) → свежесть (Ф7-04) → человек → испытание по клиентским данным
// (не выдавалось · предъявлено · просрочено — три различимых состояния, Ф7-34)
// → сверка результата шестью осями проверяющим → расширение свойств (Ф7-41)
// → операция. Внутри операции ОДНОЙ транзакцией: потребление испытания
// (условный оператор — второе предъявление проигрывает), строка ключа (её
// уникальность и слот потолка судит база), событие аудита.
//
// Испытание потребляется на УСПЕХЕ: отказ по сроку, происхождению, хэшу имени,
// алгоритму, присутствию или форме оставляет его выданным — «тот же результат с
// годным полем проходит» есть положительный контроль внутри каждого из этих
// сценариев. Повтор после успеха отвергает условный оператор (Ф7-03).

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	corevalidate "github.com/PRO-Robotech/corelib/validate"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
)

// FinishRegistrationInput — результат церемонии в байтах браузера.
type FinishRegistrationInput struct {
	UserID      domain.UserID
	Actor       domain.UserID
	Name        string
	Description string
	// CredentialID — `rawId`.
	CredentialID      []byte
	ClientDataJSON    []byte
	AttestationObject []byte
	// Discoverable — `clientExtensionResults.credProps.rk`; nil — не сообщено.
	Discoverable *bool
}

// FinishRegistrationUseCase — приём результата церемонии.
type FinishRegistrationUseCase struct {
	deps Deps
	ops  operations.Repo
}

// NewFinishRegistrationUseCase — построение с проверкой зависимостей.
func NewFinishRegistrationUseCase(d Deps, ops operations.Repo) (*FinishRegistrationUseCase, error) {
	d, err := d.validate("access key finish registration")
	if err != nil {
		return nil, err
	}
	if ops == nil {
		return nil, errors.New("access key finish registration: operations repo required")
	}
	return &FinishRegistrationUseCase{deps: d, ops: ops}, nil
}

// Execute — синхронные сверки, затем операция.
func (uc *FinishRegistrationUseCase) Execute(ctx context.Context, in FinishRegistrationInput) (*operations.Operation, error) {
	if in.UserID == "" {
		return nil, fieldRequired("user_id")
	}
	// Форма — ПЕРВЫМ стейтментом (Ф7-46): пустое имя законно и заменится
	// умолчанием от id; описание судится в знаках фундаментным валидатором.
	if err := corevalidate.NameOnCreate("name", in.Name); err != nil {
		return nil, err
	}
	// Единица предела — знак, как у схемы; валидатор фундамента называет поле
	// и правило в `BadRequest.field_violations` — той же формой, что у имени.
	if err := corevalidate.Description("description", in.Description); err != nil {
		return nil, err
	}
	if len(in.CredentialID) == 0 {
		return nil, fieldRequired("credential.id")
	}
	if len(in.ClientDataJSON) == 0 {
		return nil, fieldRequired("credential.client_data_json")
	}
	if len(in.AttestationObject) == 0 {
		return nil, fieldRequired("credential.attestation_object")
	}
	now := uc.deps.Now().UTC()
	if err := requireFresh(ctx, uc.deps, LaneRegistration, in.Actor, now); err != nil {
		return nil, err
	}
	user, err := activeUser(ctx, uc.deps, in.UserID, "finish registration")
	if err != nil {
		return nil, err
	}
	// Испытание находится по клиентским данным и судится ДО остального:
	// результат, собранный не на выданном, до сверки байтов не доходит.
	cd, err := webauthnverify.ParseClientData(in.ClientDataJSON)
	if err != nil {
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRegistration, RefusalMalformed)
		return nil, fieldRule("credential.client_data_json", TextMalformedCredential)
	}
	ch, found, err := uc.deps.Store.Challenge(ctx, cd.Challenge, in.UserID, domain.ChallengeForRegistration)
	if err != nil {
		uc.deps.Logger.Error("access keys: challenge unreadable", "err", err.Error())
		return nil, storeUnavailable("access key registration")
	}
	if !found {
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRegistration, RefusalChallengeUnknown)
		return nil, withReason(codes.FailedPrecondition, ReasonChallengeUnknown, TextChallengeUnknown)
	}
	switch ch.StateAt(now) {
	case domain.ChallengeConsumed:
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRegistration, RefusalChallengeConsumed)
		return nil, withReason(codes.FailedPrecondition, ReasonChallengeConsumed, TextChallengeConsumed)
	case domain.ChallengeExpired:
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRegistration, RefusalChallengeExpired)
		return nil, withReason(codes.FailedPrecondition, ReasonChallengeExpired, TextChallengeExpired)
	}
	res, err := webauthnverify.VerifyRegistration(webauthnverify.RegistrationInput{
		Challenge: ch.Challenge, Binding: uc.deps.Binding, ClientDataJSON: in.ClientDataJSON, AttestationObject: in.AttestationObject,
	})
	if err != nil {
		return nil, uc.ceremonyRefusal(err)
	}
	if !bytesEqual(res.CredentialID, in.CredentialID) {
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRegistration, RefusalMalformed)
		return nil, fieldRule("credential.id", "does not match the attested credential id")
	}
	// Расширение свойств удостоверения: три стороны (Ф7-41).
	if in.Discoverable != nil && !*in.Discoverable {
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRegistration, RefusalNotDiscoverable)
		return nil, withReason(codes.InvalidArgument, ReasonNotDiscoverable, TextNotDiscoverable)
	}

	keyID := domain.AccessKeyID(ids.NewHyphenID(ids.PrefixAccessKeyHyphen))
	key := domain.AccessKey{
		ID: keyID, UserID: in.UserID, CredentialID: res.CredentialID, PublicKey: res.PublicKey,
		Algorithm: int64(res.Algorithm), SignCount: res.SignCount, UserHandle: []byte(in.UserID),
		Name:        domain.AccessKeyName(corevalidate.NameOrDefault(in.Name, string(keyID))),
		Description: domain.AccessKeyDescription(in.Description), CreatedAt: now,
	}
	if err := key.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	op, err := operations.NewFromContext(ctx, domain.PrefixOperationIAM,
		fmt.Sprintf("Register access key for %s", in.UserID),
		&iamv1.RegisterAccessKeyMetadata{UserId: string(in.UserID), AccessKeyId: string(keyID), AccountId: string(user.AccountID)})
	if err != nil {
		return nil, err
	}
	if err := uc.ops.Create(ctx, op); err != nil {
		return nil, err
	}
	actor := string(in.Actor)
	challenge := ch.Challenge
	operations.Run(ctx, uc.ops, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return uc.commit(ctx, key, user.AccountID, challenge, actor, now)
	})
	return &op, nil
}

// commit — ОДНА транзакция: потребление испытания, строка, событие.
func (uc *FinishRegistrationUseCase) commit(ctx context.Context, key domain.AccessKey, account domain.AccountID, challenge []byte, actor string, now time.Time) (*anypb.Any, error) {
	w, err := uc.deps.Store.Writer(ctx)
	if err != nil {
		return nil, mapStoreErr(uc.deps, "access_keys.FinishRegistration.writer", err)
	}
	defer func() { _ = w.Rollback(ctx) }()
	consumed, err := w.ConsumeChallenge(ctx, challenge, key.UserID, domain.ChallengeForRegistration, now)
	if err != nil {
		return nil, mapStoreErr(uc.deps, "access_keys.FinishRegistration.consume", err)
	}
	if !consumed {
		// Проигравший второго предъявления того же испытания (Ф7-03): отвечает
		// состоянием, как синхронная ветвь.
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRegistration, RefusalChallengeConsumed)
		return nil, withReason(codes.FailedPrecondition, ReasonChallengeConsumed, TextChallengeConsumed)
	}
	persisted, err := w.InsertKey(ctx, key)
	if err != nil {
		return nil, mapStoreErr(uc.deps, "access_keys.FinishRegistration.insert", err)
	}
	if err := emitKeyAudit(ctx, w, AuditAccessKeyRegistered, persisted, account, actor); err != nil {
		return nil, mapStoreErr(uc.deps, "access_keys.FinishRegistration.audit", err)
	}
	if err := w.Commit(ctx); err != nil {
		return nil, mapStoreErr(uc.deps, "access_keys.FinishRegistration.commit", err)
	}
	uc.deps.Observer.AccessKeyEventObserved(EventRegistered)
	return anypb.New(&iamv1.RegisterAccessKeyResponse{AccessKey: keyToProto(persisted)})
}

// ceremonyRefusal — отказ проверяющего на полосе церемонии: причина названа
// вызывающему (все — о его собственном результате), клетка наблюдателю.
func (uc *FinishRegistrationUseCase) ceremonyRefusal(err error) error {
	var r *webauthnverify.Refusal
	if !errors.As(err, &r) {
		return status.Errorf(codes.Internal, "access key registration failed")
	}
	switch r.Reason {
	case webauthnverify.ReasonOriginNotAllowed:
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRegistration, RefusalOriginNotAllowed)
		return withReason(codes.InvalidArgument, ReasonOriginNotAllowed, TextOriginNotAllowed)
	case webauthnverify.ReasonRPIDHashMismatch:
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRegistration, RefusalRPIDMismatch)
		return withReason(codes.InvalidArgument, ReasonRPIDMismatch, TextRPIDMismatch)
	case webauthnverify.ReasonUserNotPresent:
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRegistration, RefusalUserNotPresent)
		return withReason(codes.InvalidArgument, ReasonUserNotPresent, TextUserNotPresent)
	case webauthnverify.ReasonAlgorithmNotAllowed:
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRegistration, RefusalAlgorithmNotAllowed)
		return withReason(codes.InvalidArgument, ReasonAlgorithmNotAllowed, TextAlgorithmNotAllowed)
	case webauthnverify.ReasonChallengeMismatch:
		// Испытание уже найдено по тем же клиентским данным; расхождение здесь
		// означает подмену байтов между разбором и сверкой — форма.
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRegistration, RefusalMalformed)
		return fieldRule("credential.client_data_json", TextMalformedCredential)
	default:
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRegistration, RefusalMalformed)
		return fieldRule("credential", TextMalformedCredential)
	}
}

// mapStoreErr — отказ хранилища на пути операции: семейство `internal/errors`
// переводится в gRPC общим преобразователем; отказ потолка получает следующий
// шаг (Ф7-37), текст производителя доезжает дословно.
func mapStoreErr(d Deps, site string, err error) error {
	if errors.Is(err, iamerr.ErrQuotaExceeded) {
		// Текст производителя (триггера) доезжает дословно, следующий шаг
		// дописывается; признак полосы (`ErrorInfo`) сохраняется.
		mapped := shared.MapRepoErr(err)
		st, _ := status.FromError(mapped)
		pb := st.Proto()
		pb.Message += "; WAY OUT: " + TextCeilingNextStep
		return status.FromProto(pb).Err()
	}
	return shared.LogMappedErr(context.Background(), d.Logger, site, err, shared.MapRepoErr(err))
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
