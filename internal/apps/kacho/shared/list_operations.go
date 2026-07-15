// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package shared — list_operations.go: ListOperationsUseCase backs the
// per-resource ListOperations RPC of RoleService / GroupService /
// ProjectService / ServiceAccountService.
//
// All four resources list operations identically — filter the common
// `operations` table by the denormalized `resource_id` column with
// (created_at, id) cursor pagination (corelib operations.Repo). The query lives
// in the repo layer (corelib); this use-case is the thin reuse point so the four
// handlers stay transport-only (architecture.md clean-arch) and the no-op
// placeholders are replaced by one shared implementation.
package shared

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// ListOperationsUseCase lists the operations recorded for a single resource id.
type ListOperationsUseCase struct {
	opsRepo operations.Repo
}

// NewListOperationsUseCase wires the use-case to the operations repo.
func NewListOperationsUseCase(opsRepo operations.Repo) *ListOperationsUseCase {
	return &ListOperationsUseCase{opsRepo: opsRepo}
}

// Execute returns the resource's operations (cursor-paginated) and the
// next_page_token.
//
// Error mapping (api-conventions.md):
//   - a List failure with a non-empty pageToken is a malformed opaque cursor →
//     InvalidArgument (garbage token → InvalidArgument, never INTERNAL);
//   - a List failure with an empty pageToken can only be a server/DB fault →
//     Internal with fixed text (no pgx/SQL leak).
func (u *ListOperationsUseCase) Execute(ctx context.Context, resourceID string, pageSize int64, pageToken string) ([]operations.Operation, string, error) {
	ops, next, err := u.opsRepo.List(ctx, operations.ListFilter{
		ResourceID: resourceID,
		PageSize:   pageSize,
		PageToken:  pageToken,
	})
	if err != nil {
		if pageToken != "" {
			return nil, "", status.Error(codes.InvalidArgument, "invalid page_token")
		}
		return nil, "", status.Error(codes.Internal, "list operations failed")
	}
	return ops, next, nil
}
