// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// handler.go — gRPC handler для kacho.cloud.iam.v1.UserTokenService.
package user_tokens

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/safeconv"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

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
func (h *Handler) Issue(ctx context.Context, req *iamv1.IssueUserTokenRequest) (*operationpb.Operation, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "empty request")
	}
	principal := authzguard.PrincipalUserID(ctx)
	if principal == "" {
		return nil, authzguard.PermissionDenied()
	}
	if rv := req.GetCreatedByUserId(); rv != "" && rv != principal {
		return nil, status.Error(codes.InvalidArgument,
			"Illegal argument created_by_user_id: must match authenticated principal or be empty")
	}
	op, err := h.issue.Execute(ctx, IssueInput{
		UserID:          domain.UserID(req.GetUserId()),
		Description:     req.GetDescription(),
		TTLSeconds:      req.GetTtlSeconds(),
		CreatedByUserID: principal,
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
