// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package user — UserService (public CRUD + Invite) + InternalUserService
// (UpsertFromIdentity / Get).
package user

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repouser "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
)

// Handler — публичный UserService (Get/List/Invite/Update/Delete).
type Handler struct {
	iamv1.UnimplementedUserServiceServer

	get    *GetUserUseCase
	list   *ListUsersUseCase
	update *UpdateUserUseCase
	delete *DeleteUserUseCase
	invite *InviteUserUseCase
	listOp *shared.ListOperationsUseCase
}

func NewHandler(g *GetUserUseCase, l *ListUsersUseCase, u *UpdateUserUseCase, d *DeleteUserUseCase, i *InviteUserUseCase) *Handler {
	return &Handler{get: g, list: l, update: u, delete: d, invite: i}
}

// WithListOperations wires the per-resource operation-listing use-case.
// Mirrors Account/Project/Role/Group/ServiceAccount.
func (h *Handler) WithListOperations(uc *shared.ListOperationsUseCase) *Handler {
	h.listOp = uc
	return h
}

// ListOperations — sync read of the operations recorded for the user
// (resource_id=usr-…, e.g. Delete + Invite ops). Malformed id →
// InvalidArgument (first statement); well-formed-but-no-ops → empty list, not
// NotFound (parity with the existing five, D-6). Viewer-tier authz is enforced
// by the api-gateway permission-catalog (acceptance 1.2-05).
func (h *Handler) ListOperations(ctx context.Context, req *iamv1.ListUserOperationsRequest) (*iamv1.ListUserOperationsResponse, error) {
	if err := shared.ValidateResourceID(req.GetUserId(), domain.PrefixUser, "user"); err != nil {
		return nil, err
	}
	ops, next, err := h.listOp.Execute(ctx, req.GetUserId(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := make([]*operationpb.Operation, 0, len(ops))
	for i := range ops {
		out = append(out, shared.OperationToProto(&ops[i]))
	}
	return &iamv1.ListUserOperationsResponse{Operations: out, NextPageToken: next}, nil
}

func (h *Handler) Get(ctx context.Context, req *iamv1.GetUserRequest) (*iamv1.User, error) {
	u, err := h.get.Execute(ctx, domain.UserID(req.GetUserId()))
	if err != nil {
		return nil, err
	}
	pb, err := userToPb(u)
	if err != nil {
		return nil, status.Error(codes.Internal, "marshal user")
	}
	return pb, nil
}

func (h *Handler) List(ctx context.Context, req *iamv1.ListUsersRequest) (*iamv1.ListUsersResponse, error) {
	filter := repouser.ListFilter{
		PageSize:  safeconv.ClampNonNegInt32(req.GetPageSize()),
		PageToken: req.GetPageToken(),
		Filter:    req.GetFilter(),
		AccountID: domain.AccountID(req.GetAccountId()),
	}
	rows, next, err := h.list.Execute(ctx, filter)
	if err != nil {
		return nil, err
	}
	out := make([]*iamv1.User, 0, len(rows))
	for _, u := range rows {
		pb, err := userToPb(u)
		if err != nil {
			return nil, status.Error(codes.Internal, "marshal user")
		}
		out = append(out, pb)
	}
	return &iamv1.ListUsersResponse{Users: out, NextPageToken: next}, nil
}

// Update — публичный UpdateUser RPC. Тонкий transport: parse → use-case →
// format. Request — flat-форма: единственное mutable-поле `labels` лежит на
// верхнем уровне (паритет с UpdateRole/ServiceAccount/AccessBinding). labels-
// валидация и update_mask discipline — в use-case. Async → Operation.
func (h *Handler) Update(ctx context.Context, req *iamv1.UpdateUserRequest) (*operationpb.Operation, error) {
	in := UpdateUserInput{
		ID: domain.UserID(req.GetUserId()),
	}
	if labels := req.GetLabels(); labels != nil {
		in.Labels = labelsFromProto(labels)
	}
	if mask := req.GetUpdateMask(); mask != nil {
		in.UpdateMask = append([]string{}, mask.GetPaths()...)
	}
	op, err := h.update.Execute(ctx, in)
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) Delete(ctx context.Context, req *iamv1.DeleteUserRequest) (*operationpb.Operation, error) {
	op, err := h.delete.Execute(ctx, domain.UserID(req.GetUserId()))
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

// Invite — invite-or-bind use-case. Возвращает Operation (LRO).
func (h *Handler) Invite(ctx context.Context, req *iamv1.InviteUserRequest) (*operationpb.Operation, error) {
	in := InviteUserInput{
		AccountID:   domain.AccountID(req.GetAccountId()),
		Email:       domain.Email(req.GetEmail()),
		DisplayName: domain.DisplayName(req.GetDisplayName()),
		ProjectID:   domain.ProjectID(req.GetProjectId()),
		RoleID:      domain.RoleID(req.GetRoleId()),
	}
	op, err := h.invite.Execute(ctx, in)
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

// NOTE: `UserService.Create` is deprecated. Текущий iam/v1 proto НЕ содержит
// `Create` RPC (его никогда не было; `Invite` создан с нуля), поэтому
// отдельный deprecated-handler не нужен. Если в будущем какой-то клиент
// ожидает `Create` — добавь RPC в proto с `option deprecated = true` и
// handler вернет FailedPrecondition с подсказкой использовать `Invite`.

// InternalHandler — InternalUserService (UpsertFromIdentity / Get /
// OnRecoveryCompleted).
type InternalHandler struct {
	iamv1.UnimplementedInternalUserServiceServer

	upsert     *UpsertFromIdentityUseCase
	get        *GetUserUseCase
	onRecovery *OnRecoveryCompletedUseCase
}

func NewInternalHandler(u *UpsertFromIdentityUseCase, g *GetUserUseCase, r *OnRecoveryCompletedUseCase) *InternalHandler {
	return &InternalHandler{upsert: u, get: g, onRecovery: r}
}

func (h *InternalHandler) UpsertFromIdentity(ctx context.Context, req *iamv1.UpsertFromIdentityRequest) (*operationpb.Operation, error) {
	in := UpsertFromIdentityInput{
		ExternalID:  domain.ExternalSubject(req.GetExternalId()),
		Email:       domain.Email(req.GetEmail()),
		DisplayName: domain.DisplayName(req.GetDisplayName()),
	}
	op, err := h.upsert.Execute(ctx, in)
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *InternalHandler) Get(ctx context.Context, req *iamv1.GetUserRequest) (*iamv1.User, error) {
	u, err := h.get.Execute(ctx, domain.UserID(req.GetUserId()))
	if err != nil {
		return nil, err
	}
	pb, err := userToPb(u)
	if err != nil {
		return nil, status.Error(codes.Internal, "marshal user")
	}
	return pb, nil
}

// OnRecoveryCompleted — Kratos password-recovery webhook. Mutation → async Operation.
func (h *InternalHandler) OnRecoveryCompleted(ctx context.Context, req *iamv1.OnRecoveryCompletedRequest) (*operationpb.Operation, error) {
	op, err := h.onRecovery.Execute(ctx, OnRecoveryCompletedInput{
		ExternalID:  domain.ExternalSubject(req.GetExternalId()),
		RecoveryJTI: req.GetRecoveryJti(),
		Email:       domain.Email(req.GetEmail()),
	})
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

// ---- shared ----

func userToPb(u domain.User) (*iamv1.User, error) {
	any, err := marshalUser(u)
	if err != nil {
		return nil, err
	}
	var pb iamv1.User
	if err := any.UnmarshalTo(&pb); err != nil {
		return nil, err
	}
	return &pb, nil
}
