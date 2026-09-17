// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys

// handler.go — gRPC-транспорт `kaname.cloud.iam.v1.AccessKeyService` (Ф7,
// kacho#1273): разбор запроса → сценарий → форма ответа. Логики здесь нет.
//
// # Вызывающий — из принципала, никогда из тела
//
// Область записи каталога (`user_id`) судит дверь; окно свежести судится о
// ВЫЗЫВАЮЩЕМ (Р5), и его имя берётся из принципала запроса. У освобождённых
// глаголов утверждения (Р11: `<exempt>`, `SELF_SERVICE`) освобождение — от
// проверки права, а не от аутентификации: без принципала они отвечают тем же
// отказом, что и четыре глагола под правом.
//
// # Форма испытаний — форма церемонии браузера
//
// Испытание регистрации отдаётся в форме `PublicKeyCredentialCreationOptions`,
// испытание предъявления — `PublicKeyCredentialRequestOptions`: клиент
// подставляет их в `navigator.credentials.create/get` без пересборки. Тип
// удостоверения — литерал нормы `public-key`, единственный у WebAuthn L2.

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/operations"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// CredentialTypePublicKey — единственный тип удостоверения WebAuthn L2 §5.8.2.
const CredentialTypePublicKey = "public-key"

// Handler — реализация службы.
type Handler struct {
	iamv1.UnimplementedAccessKeyServiceServer
	beginRegistration  *BeginRegistrationUseCase
	finishRegistration *FinishRegistrationUseCase
	list               *ListUseCase
	revoke             *RevokeUseCase
	beginAssertion     *BeginAssertionUseCase
	finishAssertion    *FinishAssertionUseCase
}

// NewHandler собирает шесть сценариев над одними зависимостями; отказ
// построения любого — отказ сборки службы.
func NewHandler(d Deps, ops operations.Repo) (*Handler, error) {
	beginReg, err := NewBeginRegistrationUseCase(d)
	if err != nil {
		return nil, err
	}
	finishReg, err := NewFinishRegistrationUseCase(d, ops)
	if err != nil {
		return nil, err
	}
	list, err := NewListUseCase(d)
	if err != nil {
		return nil, err
	}
	revoke, err := NewRevokeUseCase(d, ops)
	if err != nil {
		return nil, err
	}
	beginAssert, err := NewBeginAssertionUseCase(d)
	if err != nil {
		return nil, err
	}
	finishAssert, err := NewFinishAssertionUseCase(d)
	if err != nil {
		return nil, err
	}
	return &Handler{
		beginRegistration: beginReg, finishRegistration: finishReg, list: list, revoke: revoke,
		beginAssertion: beginAssert, finishAssertion: finishAssert,
	}, nil
}

// caller — принципал запроса; пусто — отказ той же формы, что у остальных
// служб (анонимный вызов до сценария не доходит).
func caller(ctx context.Context) (domain.UserID, error) {
	if authzguard.PrincipalUserID(ctx) == "" {
		return "", authzguard.PermissionDenied()
	}
	// Окно свежести и предъявление судятся о ЧЕЛОВЕКЕ: машина сессии не
	// имеет, и её вызов сценарий отвергает как не свежий (Р5), а не молча.
	return domain.UserID(authzguard.HumanUserID(ctx)), nil
}

// BeginRegistration — испытание регистрации (Ф7-40).
func (h *Handler) BeginRegistration(ctx context.Context, req *iamv1.BeginAccessKeyRegistrationRequest) (*iamv1.AccessKeyRegistrationChallenge, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	out, err := h.beginRegistration.Execute(ctx, BeginRegistrationInput{UserID: domain.UserID(req.GetUserId()), Actor: actor})
	if err != nil {
		return nil, err
	}
	params := make([]*iamv1.PublicKeyCredentialParameters, 0, len(out.Algorithms))
	for _, alg := range out.Algorithms {
		params = append(params, &iamv1.PublicKeyCredentialParameters{Type: CredentialTypePublicKey, Alg: alg})
	}
	return &iamv1.AccessKeyRegistrationChallenge{
		Challenge: out.Challenge,
		Rp:        &iamv1.RelyingParty{Id: out.RPID, Name: out.RPDisplayName},
		User: &iamv1.CeremonyUser{
			Id: out.UserHandle, Name: string(out.User.Email), DisplayName: ceremonyDisplayName(out.User),
		},
		PubKeyCredParams: params,
		AuthenticatorSelection: &iamv1.AuthenticatorSelection{
			ResidentKey: out.ResidentKey, RequireResidentKey: out.ResidentKey == ResidentKey, UserVerification: out.UserVerification,
		},
		Attestation: out.Attestation,
		Extensions:  &iamv1.CeremonyExtensions{CredProps: out.CredProps},
		ExpiresAt:   timestamppb.New(out.ExpiresAt),
	}, nil
}

// ceremonyDisplayName — отображаемое имя церемонии: имя человека, а при его
// отсутствии адрес (аутентификатор показывает его при выборе удостоверения;
// пустая строка там читалась бы как «без имени»).
func ceremonyDisplayName(u domain.User) string {
	if u.DisplayName != "" {
		return string(u.DisplayName)
	}
	return string(u.Email)
}

// FinishRegistration — приём результата церемонии (Ф7-01); удостоверение
// обязательно, форма имени и описания судится сценарием первым стейтментом.
func (h *Handler) FinishRegistration(ctx context.Context, req *iamv1.FinishAccessKeyRegistrationRequest) (*operationpb.Operation, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	cred := req.GetCredential()
	if cred == nil {
		return nil, fieldRequired("credential")
	}
	in := FinishRegistrationInput{
		UserID: domain.UserID(req.GetUserId()), Actor: actor,
		Name: req.GetName(), Description: req.GetDescription(),
		CredentialID: cred.GetId(), ClientDataJSON: cred.GetClientDataJson(), AttestationObject: cred.GetAttestationObject(),
	}
	if cred.GetDiscoverable() != nil {
		v := cred.GetDiscoverable().GetValue()
		in.Discoverable = &v
	}
	op, err := h.finishRegistration.Execute(ctx, in)
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

// List — перечень ключей человека; формат страницы судится ДО чтения.
func (h *Handler) List(ctx context.Context, req *iamv1.ListAccessKeysRequest) (*iamv1.ListAccessKeysResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	if err := shared.ValidateRawPagination(req.GetPageToken(), req.GetPageSize()); err != nil {
		return nil, err
	}
	if _, err := caller(ctx); err != nil {
		return nil, err
	}
	keys, next, err := h.list.Execute(ctx, ListInput{
		UserID: domain.UserID(req.GetUserId()), PageSize: int32(req.GetPageSize()), PageToken: req.GetPageToken(), // #nosec G115 -- величина уже в [0..1000]
	})
	if err != nil {
		return nil, err
	}
	out := &iamv1.ListAccessKeysResponse{AccessKeys: make([]*iamv1.AccessKey, 0, len(keys)), NextPageToken: next}
	for _, k := range keys {
		pb, err := KeyToProto(k)
		if err != nil {
			return nil, status.Error(codes.Internal, "internal error")
		}
		out.AccessKeys = append(out.AccessKeys, pb)
	}
	return out, nil
}

// Revoke — снятие ключа (Ф7-25); форма `id` судится сценарием первым
// стейтментом (Ф7-47).
func (h *Handler) Revoke(ctx context.Context, req *iamv1.RevokeAccessKeyRequest) (*operationpb.Operation, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	op, err := h.revoke.Execute(ctx, RevokeInput{UserID: domain.UserID(req.GetUserId()), Actor: actor, AccessKeyID: req.GetAccessKeyId()})
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

// BeginAssertion — испытание предъявления вызывающему (Ф7-42).
func (h *Handler) BeginAssertion(ctx context.Context, req *iamv1.BeginAccessKeyAssertionRequest) (*iamv1.AccessKeyAssertionChallenge, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	out, err := h.beginAssertion.Execute(ctx, BeginAssertionInput{UserID: actor})
	if err != nil {
		return nil, err
	}
	allow := make([]*iamv1.PublicKeyCredentialDescriptor, 0, len(out.AllowCredentials))
	for _, id := range out.AllowCredentials {
		allow = append(allow, &iamv1.PublicKeyCredentialDescriptor{Type: CredentialTypePublicKey, Id: id})
	}
	return &iamv1.AccessKeyAssertionChallenge{
		Challenge: out.Challenge, RpId: out.RPID, UserVerification: out.UserVerification,
		AllowCredentials: allow, ExpiresAt: timestamppb.New(out.ExpiresAt),
	}, nil
}

// FinishAssertion — проверка утверждения (Ф7-06): ответ называет человека,
// равного вызывающему, ключ и флаги предъявления.
func (h *Handler) FinishAssertion(ctx context.Context, req *iamv1.FinishAccessKeyAssertionRequest) (*iamv1.FinishAccessKeyAssertionResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	actor, err := caller(ctx)
	if err != nil {
		return nil, err
	}
	cred := req.GetCredential()
	if cred == nil {
		return nil, fieldRequired("credential")
	}
	out, err := h.finishAssertion.Execute(ctx, FinishAssertionInput{
		UserID: actor, CredentialID: cred.GetId(), ClientDataJSON: cred.GetClientDataJson(),
		AuthenticatorData: cred.GetAuthenticatorData(), Signature: cred.GetSignature(), UserHandle: cred.GetUserHandle(),
	})
	if err != nil {
		return nil, err
	}
	return &iamv1.FinishAccessKeyAssertionResponse{
		UserId: string(out.UserID), AccessKeyId: string(out.AccessKeyID),
		Flags: &iamv1.AssertionFlags{
			UserPresent: out.Flags.UserPresent, UserVerified: out.Flags.UserVerified,
			BackupEligible: out.Flags.BackupEligible, BackupState: out.Flags.BackupState,
		},
	}, nil
}
