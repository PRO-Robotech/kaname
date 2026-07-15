// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package conditions — ConditionsService gRPC handler.
package conditions

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/condition"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// Handler — gRPC server.
type Handler struct {
	iamv1.UnimplementedConditionsServiceServer
	svc *service.ConditionsCRUDService
}

// NewHandler — builder.
func NewHandler(svc *service.ConditionsCRUDService) *Handler {
	return &Handler{svc: svc}
}

// Get — see iamv1.ConditionsServiceServer.
func (h *Handler) Get(ctx context.Context, req *iamv1.GetConditionRequest) (*iamv1.Condition, error) {
	c, err := h.svc.Get(ctx, domain.ConditionID(req.GetConditionId()))
	if err != nil {
		return nil, mapErr(err)
	}
	return service.ConditionToProto(c), nil
}

// List — see iamv1.ConditionsServiceServer.
func (h *Handler) List(ctx context.Context, req *iamv1.ListConditionsRequest) (*iamv1.ListConditionsResponse, error) {
	rows, next, err := h.svc.List(ctx, condition.ListFilter{
		FolderID:  req.GetFolderId(),
		PageSize:  safeconv.ClampNonNegInt32(req.GetPageSize()),
		PageToken: req.GetPageToken(),
		Filter:    req.GetFilter(),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	pbs := make([]*iamv1.Condition, 0, len(rows))
	for _, r := range rows {
		pbs = append(pbs, service.ConditionToProto(r))
	}
	return &iamv1.ListConditionsResponse{Conditions: pbs, NextPageToken: next}, nil
}

// Create — see iamv1.ConditionsServiceServer.
func (h *Handler) Create(ctx context.Context, req *iamv1.CreateConditionRequest) (*operationpb.Operation, error) {
	if req.GetFolderId() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument folder_id: required")
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument name: required")
	}
	if req.GetExpression() == "" {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument expression: required")
	}
	var paramsRaw []byte
	if s := req.GetParametersSchema(); s != nil {
		b, err := s.MarshalJSON()
		if err == nil {
			paramsRaw = b
		}
	}
	op, err := h.svc.Create(ctx, service.CreateConditionRequest{
		FolderID:         req.GetFolderId(),
		Name:             req.GetName(),
		Description:      req.GetDescription(),
		Labels:           req.GetLabels(),
		Expression:       req.GetExpression(),
		ParametersSchema: json.RawMessage(paramsRaw),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return shared.OperationToProto(op), nil
}

// Update — see iamv1.ConditionsServiceServer.
func (h *Handler) Update(ctx context.Context, req *iamv1.UpdateConditionRequest) (*operationpb.Operation, error) {
	var paramsRaw []byte
	if s := req.GetParametersSchema(); s != nil {
		b, err := s.MarshalJSON()
		if err == nil {
			paramsRaw = b
		}
	}
	mask := []string{}
	if m := req.GetUpdateMask(); m != nil {
		mask = m.GetPaths()
	}
	op, err := h.svc.Update(ctx, service.UpdateConditionRequest{
		ID:               domain.ConditionID(req.GetConditionId()),
		UpdateMask:       mask,
		Description:      req.GetDescription(),
		Labels:           req.GetLabels(),
		Expression:       req.GetExpression(),
		ParametersSchema: json.RawMessage(paramsRaw),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return shared.OperationToProto(op), nil
}

// Delete — see iamv1.ConditionsServiceServer.
func (h *Handler) Delete(ctx context.Context, req *iamv1.DeleteConditionRequest) (*operationpb.Operation, error) {
	op, err := h.svc.Delete(ctx, domain.ConditionID(req.GetConditionId()))
	if err != nil {
		return nil, mapErr(err)
	}
	return shared.OperationToProto(op), nil
}

// Evaluate — see iamv1.ConditionsServiceServer.
func (h *Handler) Evaluate(ctx context.Context, req *iamv1.EvaluateConditionRequest) (*iamv1.EvaluateConditionResponse, error) {
	if req.GetContext() == nil {
		return nil, status.Error(codes.InvalidArgument, "Illegal argument context: required")
	}
	res, err := h.svc.Evaluate(ctx, service.EvaluateConditionRequest{
		ID:      domain.ConditionID(req.GetConditionId()),
		Context: structToMap(req.GetContext()),
		Params:  structToMap(req.GetParams()),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return &iamv1.EvaluateConditionResponse{
		Allowed:     res.Allowed,
		Trace:       res.Trace,
		EvaluatedAt: shared.TimestampProto(res.EvaluatedAt),
	}, nil
}

// ── helpers ──

func structToMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}

// mapErr — domain/iamerr → gRPC status.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	// Already a gRPC status (the in-service authz guards return
	// codes.PermissionDenied directly) — pass through unchanged rather than
	// re-wrapping as Internal.
	if _, ok := status.FromError(err); ok {
		return err
	}
	if stderrors.Is(err, iamerr.ErrNotFound) {
		return status.Error(codes.NotFound, iamerr.StripSentinel(err))
	}
	if stderrors.Is(err, iamerr.ErrAlreadyExists) {
		return status.Error(codes.AlreadyExists, iamerr.StripSentinel(err))
	}
	if stderrors.Is(err, iamerr.ErrFailedPrecondition) {
		return status.Error(codes.FailedPrecondition, iamerr.StripSentinel(err))
	}
	if stderrors.Is(err, iamerr.ErrInvalidArg) {
		return status.Error(codes.InvalidArgument, iamerr.StripSentinel(err))
	}
	if strings.HasPrefix(err.Error(), "Illegal argument") {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	// NOTE: the "Condition … is in use by … AccessBindings" precondition is now
	// returned wrapped in iamerr.ErrFailedPrecondition by the use-case and is
	// caught by the ErrFailedPrecondition sentinel branch above — no error-string
	// substring match here (robust to rewording).
	//
	// SEC (audit r2): any UNMAPPED error is opaque INTERNAL — never echo err.Error()
	// to the tenant (an un-sentineled pgx/DB error would leak driver/connection text:
	// host/port/user/db). Matches shared.MapRepoErr / grpcmw recovery fixed-string.
	return status.Error(codes.Internal, "internal error")
}
