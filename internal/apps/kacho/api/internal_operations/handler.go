// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_operations

// handler.go — thin gRPC transport for InternalOperationsService.
//
// Запрет #6: registered ONLY on the internal listener (:9091), never on the
// external TLS endpoint. Business logic (admin gate + filter) lives in the
// use-case; the handler only parses the request and formats the response.

import (
	"context"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
)

// Handler implements iamv1.InternalOperationsServiceServer.
type Handler struct {
	iamv1.UnimplementedInternalOperationsServiceServer

	list *ListIamOperationsUseCase
}

// NewHandler assembles the Handler. Composition root: cmd/kacho-iam/wiring.go.
func NewHandler(list *ListIamOperationsUseCase) *Handler {
	return &Handler{list: list}
}

// ListIamOperations — cluster-wide admin feed (optional account_id filter).
func (h *Handler) ListIamOperations(ctx context.Context, req *iamv1.ListIamOperationsRequest) (*iamv1.ListIamOperationsResponse, error) {
	ops, next, err := h.list.Execute(ctx, req.GetAccountId(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := make([]*operationpb.Operation, 0, len(ops))
	for i := range ops {
		out = append(out, shared.OperationToProto(&ops[i]))
	}
	return &iamv1.ListIamOperationsResponse{Operations: out, NextPageToken: next}, nil
}
