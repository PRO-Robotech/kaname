// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package shared — list_operations.go: ListOperationsUseCase backs the
// per-resource ListOperations RPC of RoleService / GroupService /
// ProjectService / ServiceAccountService, plus MapOperationsListErr — the
// single classifier every IAM operations feed uses to decide whether a listing
// failure belongs to the caller or to the store.
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
// next_page_token. Failures are classified by MapOperationsListErr.
func (u *ListOperationsUseCase) Execute(ctx context.Context, resourceID string, pageSize int64, pageToken string) ([]operations.Operation, string, error) {
	ops, next, err := operations.ListForCaller(ctx, u.opsRepo, operations.ListFilter{
		ResourceID: resourceID,
		PageSize:   pageSize,
		PageToken:  pageToken,
	})
	if err != nil {
		return nil, "", MapOperationsListErr(err)
	}
	return ops, next, nil
}

// MapOperationsListErr classifies a failure of operations.Repo.List by WHAT THE
// STORE ANSWERED, never by what the caller happened to send.
//
// The operations repo validates the caller's page format itself and reports it
// as a gRPC InvalidArgument naming the field — a page_token it could not decode,
// a page_size outside [0..1000] (corevalidate.PageSize). That classification is
// authoritative and passes through unchanged, field violations included.
// Everything else the repo returns is a store failure and gets the fixed
// INTERNAL text (never the pgx/SQL text).
//
// The shape this replaces keyed on "was a page_token supplied", which is not a
// fact about the failure at all. It mislabelled in both directions: a database
// that was down was reported as a malformed cursor — sending the operator to fix
// a client that was fine — and a page_size out of range on the FIRST page (no
// token yet) was reported as an internal fault, filing a caller's mistake as an
// outage. Both are now decided by the store's own answer.
func MapOperationsListErr(err error) error {
	if err == nil {
		return nil
	}
	if st, ok := status.FromError(err); ok && st.Code() == codes.InvalidArgument {
		return err
	}
	return status.Error(codes.Internal, "list operations failed")
}
