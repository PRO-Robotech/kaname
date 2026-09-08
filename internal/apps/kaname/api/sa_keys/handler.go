// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// handler.go — gRPC handler for kaname.cloud.iam.v1.SAKeyService.
package sa_keys

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Handler — gRPC server impl.
type Handler struct {
	iamv1.UnimplementedSAKeyServiceServer
	issue  *IssueSAKeyUseCase
	revoke *RevokeSAKeyUseCase
	list   *ListSAKeysUseCase
}

// NewHandler constructs.
func NewHandler(issue *IssueSAKeyUseCase, revoke *RevokeSAKeyUseCase, list *ListSAKeysUseCase) *Handler {
	return &Handler{issue: issue, revoke: revoke, list: list}
}

// Issue implements SAKeyService.Issue.
//
// Identity-spoofing guard: `created_by_user_id` MUST come from the
// authenticated principal; request-body value is only accepted when it matches
// the principal (strict reject per OQ-3 — silent-override hides client bugs).
// The rule itself lives in ONE place for both credential-issuing lanes —
// `shared.CreatedByLane`; only what makes THIS lane different is named here.
func (h *Handler) Issue(ctx context.Context, req *iamv1.IssueSAKeyRequest) (*operationpb.Operation, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	principal := authzguard.PrincipalUserID(ctx)
	if principal == "" {
		return nil, authzguard.PermissionDenied()
	}
	// Admin/seed path (#60 SA-key analog): a service-account principal caller (the
	// acr-exempt #58 bootstrap-admin SA, or any system_admin SA the gateway
	// FGA-authorized for v_update@iam_service_account) is not a users(id) row, so it
	// cannot itself be the created_by — forcing created_by=principal would fail the
	// created_by FK (23503) as an opaque async code-9 (issue #60). For an SA caller
	// the use-case records created_by = the target SA's account OWNER (a valid users
	// row, deterministic — never a request-body value, so no spoofing), while the
	// REAL actor (the SA) is still captured in the durable audit_outbox event.
	callerIsServiceAccount := operations.PrincipalFromContext(ctx).Type == "service_account"
	// ОТЛИЧИЕ ЭТОЙ ПОЛОСЫ, названное решением, а не оставленное молчаливым: для
	// вызывающей машины ответственный резолвится ВНУТРИ use-case из владельца
	// аккаунта целевой учётки, и краю это значение недоступно — сверить
	// присланное нечем, поэтому любое непустое отвергается. У полосы
	// персонального токена записываемое значение названо самим запросом
	// (`user_id`), поэтому совпавшее там принимается. Сверку полос между собой
	// держит shared/created_by_lane_parity_test.go.
	if err := shared.CreatedByLaneForSAKey(principal, callerIsServiceAccount).
		ValidateRequested(req.GetCreatedByUserId()); err != nil {
		return nil, err
	}
	// Phase 3b: federated trusted-subjects passthrough. nil/empty slice keeps
	// Phase 3a private_key_jwt behaviour intact (no schema change for
	// existing callers).
	//
	// ВСЕ ЧЕТЫРЕ поля переносятся, и это не полнота ради полноты. Перечень
	// доверенных издателей — наша таблица (#1124), и подпись внешнего утверждения
	// сверяется с записанным здесь ключом. Ключ и его алгоритм объявлены
	// обязательными и на проводе, и в домене; транспорт, переносивший только пару
	// (issuer, subject_pattern), делал федеративную выдачу неисполнимой ни при
	// каком входе: домен отвергал КАЖДЫЙ запрос, называя негодными ровно те поля,
	// которые вызывающий прислал.
	var ts []domain.TrustedSubject
	if raw := req.GetTrustedSubjects(); len(raw) > 0 {
		ts = make([]domain.TrustedSubject, 0, len(raw))
		for _, r := range raw {
			if r == nil {
				continue
			}
			ts = append(ts, domain.TrustedSubject{
				Issuer:         r.GetIssuer(),
				SubjectPattern: r.GetSubjectPattern(),
				PublicKeyPEM:   r.GetPublicKeyPem(),
				KeyAlgorithm:   r.GetKeyAlgorithm(),
			})
		}
	}
	op, err := h.issue.Execute(ctx, IssueInput{
		ServiceAccountID:       domain.ServiceAccountID(req.GetServiceAccountId()),
		Description:            req.GetDescription(),
		TTLSeconds:             req.GetTtlSeconds(),
		CreatedByUserID:        principal,
		CallerIsServiceAccount: callerIsServiceAccount,
		TrustedSubjects:        ts,
		// Create-only metadata: name + labels are set on Issue and immutable
		// (the resource carries only Issue/List/Revoke — no Update).
		Name:   req.GetName(),
		Labels: labelsFromProto(req.GetLabels()),
		// Вид удостоверения. Не назван — прежнее поведение дословно.
		CredentialKind: CredentialKindFromProto(req.GetCredentialKind()),
		// Federation OUT — caller-supplied external audience(s).
		// Empty → use-case falls back to AudiencePrefix (kacho-internal).
		Audience: req.GetAudience(),
	})
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

// Revoke implements SAKeyService.Revoke.
func (h *Handler) Revoke(ctx context.Context, req *iamv1.RevokeSAKeyRequest) (*operationpb.Operation, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	op, err := h.revoke.Execute(ctx, RevokeInput{
		ServiceAccountID: domain.ServiceAccountID(req.GetServiceAccountId()),
		KeyID:            domain.SAOAuthClientID(req.GetKeyId()),
	})
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

// List implements SAKeyService.List.
//
// Формат страницы судится по СЫРОМУ запросу: сужение int64→int32 ниже насыщающее,
// и отрицательный page_size превратился бы в 0 («умолчание») до того, как его
// кто-либо увидит. Здесь это была единственная проверка формата на всём пути —
// ниже по потоку страницу не судил никто.
func (h *Handler) List(ctx context.Context, req *iamv1.ListSAKeysRequest) (*iamv1.ListSAKeysResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	if err := shared.ValidateRawPagination(req.GetPageToken(), req.GetPageSize()); err != nil {
		return nil, err
	}
	rows, nextToken, err := h.list.Execute(ctx, ListInput{
		ServiceAccountID: domain.ServiceAccountID(req.GetServiceAccountId()),
		PageSize:         safeconv.ClampNonNegInt32(req.GetPageSize()),
		PageToken:        req.GetPageToken(),
	})
	if err != nil {
		return nil, mapPGErr(err)
	}
	out := make([]*iamv1.ServiceAccountOAuthClient, 0, len(rows))
	for _, c := range rows {
		pb, err := saClientToProto(c)
		if err != nil {
			return nil, status.Error(codes.Internal, "internal error")
		}
		out = append(out, pb)
	}
	return &iamv1.ListSAKeysResponse{Keys: out, NextPageToken: nextToken}, nil
}
