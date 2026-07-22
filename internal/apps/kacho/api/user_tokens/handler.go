// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// handler.go — gRPC handler для kacho.cloud.iam.v1.UserTokenService.
package user_tokens

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// Handler — gRPC server impl.
type Handler struct {
	iamv1.UnimplementedUserTokenServiceServer
	issue  *IssueUserTokenUseCase
	revoke *RevokeUserTokenUseCase
	list   *ListUserTokensUseCase
}

// NewHandler конструирует.
func NewHandler(issue *IssueUserTokenUseCase, revoke *RevokeUserTokenUseCase, list *ListUserTokensUseCase) *Handler {
	return &Handler{issue: issue, revoke: revoke, list: list}
}

// Issue implements UserTokenService.Issue.
//
// Identity-spoofing guard: `created_by_user_id` ОБЯЗАН приходить из
// аутентифицированного принципала; значение из тела запроса принимается только если
// совпадает с принципалом (strict reject — silent-override прячет клиентские баги).
//
// Admin/seed path (#60): a ServiceAccount principal (the acr-exempt #58
// bootstrap-admin SA, or any system_admin SA the gateway FGA-authorized for
// v_update@iam_user) cannot itself be the created_by — its `sva…` id is not a
// users(id) row, so forcing created_by=principal would fail the created_by FK
// (23503) as an opaque async code-9 (issue #60). For an SA caller the token is
// recorded with created_by = the TARGET user (self, always a valid user row).
// This never lets the SA spoof an arbitrary created_by — it is forced to the
// request's user_id — and the REAL actor (the SA) is still captured in the
// durable audit_outbox event (usecases.go doIssue actor=PrincipalUserID).
func (h *Handler) Issue(ctx context.Context, req *iamv1.IssueUserTokenRequest) (*operationpb.Operation, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	principal := authzguard.PrincipalUserID(ctx)
	if principal == "" {
		return nil, authzguard.PermissionDenied()
	}
	createdBy := principal
	if operations.PrincipalFromContext(ctx).Type == "service_account" {
		// SA caller — record created_by = the target user (self). The gateway FGA
		// Check already authorized this SA for v_update on the target user object.
		createdBy = req.GetUserId()
	} else if rv := req.GetCreatedByUserId(); rv != "" && rv != principal {
		// user/system caller — anti-spoofing: a request-body created_by must match
		// the authenticated principal (or be empty).
		return nil, status.Error(codes.InvalidArgument,
			"Illegal argument created_by_user_id: must match authenticated principal or be empty")
	}
	op, err := h.issue.Execute(ctx, IssueInput{
		UserID:          domain.UserID(req.GetUserId()),
		Description:     req.GetDescription(),
		TTLSeconds:      req.GetTtlSeconds(),
		CreatedByUserID: createdBy,
		// Create-only метаданные: name + labels выставляются на Issue и immutable
		// (ресурс несёт только Issue/List/Revoke — нет Update).
		Name:   req.GetName(),
		Labels: labelsFromProto(req.GetLabels()),
	})
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

// Revoke implements UserTokenService.Revoke.
func (h *Handler) Revoke(ctx context.Context, req *iamv1.RevokeUserTokenRequest) (*operationpb.Operation, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	op, err := h.revoke.Execute(ctx, RevokeInput{
		UserID:  domain.UserID(req.GetUserId()),
		TokenID: domain.UserOAuthClientID(req.GetTokenId()),
	})
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

// List implements UserTokenService.List.
func (h *Handler) List(ctx context.Context, req *iamv1.ListUserTokensRequest) (*iamv1.ListUserTokensResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	rows, nextToken, err := h.list.Execute(ctx, ListInput{
		UserID:    domain.UserID(req.GetUserId()),
		PageSize:  safeconv.ClampNonNegInt32(req.GetPageSize()),
		PageToken: req.GetPageToken(),
	})
	if err != nil {
		return nil, mapPGErr(err)
	}
	out := make([]*iamv1.UserOAuthClient, 0, len(rows))
	for _, c := range rows {
		pb, err := userTokenToProto(c)
		if err != nil {
			return nil, status.Error(codes.Internal, "marshal user token")
		}
		out = append(out, pb)
	}
	return &iamv1.ListUserTokensResponse{Tokens: out, NextPageToken: nextToken}, nil
}
