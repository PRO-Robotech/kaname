// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package handler — thin gRPC transport layer для kacho-iam: parses request,
// delegates to service use-case, formats response.
//
// Resource-specific handlers (Account / Project / User / ServiceAccount /
// Group / Role / AccessBinding) живут под internal/apps/kacho/api/<resource>/;
// этот пакет держит только общий OperationHandler — единый envelope для всех
// IAM long-running operations.
package handler

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
)

// OperationHandler реализует operationpb.OperationServiceServer — единый
// envelope для всех IAM long-running operations (parity с kacho-vpc).
type OperationHandler struct {
	operationpb.UnimplementedOperationServiceServer
	repo operations.Repo
}

// NewOperationHandler создает OperationHandler.
func NewOperationHandler(repo operations.Repo) *OperationHandler {
	return &OperationHandler{repo: repo}
}

func (h *OperationHandler) Get(ctx context.Context, req *operationpb.GetOperationRequest) (*operationpb.Operation, error) {
	if req.OperationId == "" {
		return nil, status.Error(codes.InvalidArgument, "operation_id required")
	}
	op, err := h.repo.Get(ctx, req.OperationId)
	if err != nil {
		if errors.Is(err, operations.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "operation %s not found", req.OperationId)
		}
		// Generic Internal без leak'а pgx-detail (host / dsn в тексте
		// raw err — категорически нельзя пропускать наружу).
		return nil, status.Error(codes.Internal, "operation get failed")
	}
	// Hide other principals' operations: anti-info-leak returns NotFound
	// rather than PermissionDenied. Anonymous principals are rejected FIRST;
	// then IsSelf is checked for known principals. The inverted order is
	// load-bearing — a naive `!IsAnonymous(ctx) && !IsSelf(...)` guard
	// short-circuits to `false` for anonymous callers, letting anyone GET
	// any operation by id (including JIT/AB/SA mutations whose response
	// carries the principal-owner).
	if authzguard.IsAnonymous(ctx) {
		return nil, status.Errorf(codes.NotFound, "operation %s not found", req.OperationId)
	}
	if !authzguard.IsSelf(ctx, op.Principal.ID) {
		return nil, status.Errorf(codes.NotFound, "operation %s not found", req.OperationId)
	}
	return operationToProto(op), nil
}

func (h *OperationHandler) Cancel(ctx context.Context, req *operationpb.CancelOperationRequest) (*operationpb.Operation, error) {
	if req.OperationId == "" {
		return nil, status.Error(codes.InvalidArgument, "operation_id required")
	}
	// Prevent cancel of someone else's operation. Anonymous → NotFound first
	// (anti-info-leak); then IsSelf for known principals. Same inversion
	// rationale as Get.
	if existing, err := h.repo.Get(ctx, req.OperationId); err == nil {
		if authzguard.IsAnonymous(ctx) {
			return nil, status.Errorf(codes.NotFound, "operation %s not found", req.OperationId)
		}
		if !authzguard.IsSelf(ctx, existing.Principal.ID) {
			return nil, status.Errorf(codes.NotFound, "operation %s not found", req.OperationId)
		}
	}
	if err := h.repo.Cancel(ctx, req.OperationId); err != nil {
		if errors.Is(err, operations.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "operation %s not found", req.OperationId)
		}
		if errors.Is(err, operations.ErrAlreadyDone) {
			return nil, status.Errorf(codes.FailedPrecondition, "operation %s already completed", req.OperationId)
		}
		return nil, status.Error(codes.Internal, "operation cancel failed")
	}
	op, err := h.repo.Get(ctx, req.OperationId)
	if err != nil {
		if errors.Is(err, operations.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "operation %s not found", req.OperationId)
		}
		return nil, status.Error(codes.Internal, "operation reload after cancel failed")
	}
	return operationToProto(op), nil
}
