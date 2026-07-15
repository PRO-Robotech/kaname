// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package account — use-case-структура AccountService.
//
// Slice-per-RPC layout: create.go / update.go / delete.go / get.go / list.go —
// каждый use-case в своем файле. Handler — тонкий transport-слой (parse request
// → uc.Execute() → format response). The reference impl for the other IAM
// resources (Project / User / SA / Group / Role / AccessBinding) mirrors
// the same shape.
package account

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
)

// Handler реализует iamv1.AccountServiceServer. Тонкий transport-слой: parse
// proto request → domain → uc.Execute() → format proto response.
type Handler struct {
	iamv1.UnimplementedAccountServiceServer

	create    *CreateAccountUseCase
	update    *UpdateAccountUseCase
	delete    *DeleteAccountUseCase
	get       *GetAccountUseCase
	list      *ListAccountsUseCase
	listOp    *shared.ListOperationsUseCase
	listAllOp *ListAllOperationsUseCase
}

// NewHandler собирает Handler из готовых use-case'ов. Composition root —
// `cmd/kacho-iam/main.go::buildServices`.
func NewHandler(c *CreateAccountUseCase, u *UpdateAccountUseCase, d *DeleteAccountUseCase, g *GetAccountUseCase, l *ListAccountsUseCase) *Handler {
	return &Handler{create: c, update: u, delete: d, get: g, list: l}
}

// WithListOperations wires the per-resource operation-listing use-case.
func (h *Handler) WithListOperations(uc *shared.ListOperationsUseCase) *Handler {
	h.listOp = uc
	return h
}

// WithListAllOperations wires the account-scoped aggregated operation feed
// (AccountService.ListAllOperations).
func (h *Handler) WithListAllOperations(uc *ListAllOperationsUseCase) *Handler {
	h.listAllOp = uc
	return h
}

// Create — sync-validation + create Operation + spawn worker.
func (h *Handler) Create(ctx context.Context, req *iamv1.CreateAccountRequest) (*operationpb.Operation, error) {
	a := domain.Account{
		Name:        domain.AccountName(req.GetName()),
		Description: domain.Description(req.GetDescription()),
		Labels:      labelsFromProto(req.GetLabels()),
		OwnerUserID: domain.UserID(req.GetOwnerUserId()),
	}
	op, err := h.create.Execute(ctx, a)
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

// Update — sync mask validation + create Operation + spawn worker.
func (h *Handler) Update(ctx context.Context, req *iamv1.UpdateAccountRequest) (*operationpb.Operation, error) {
	in := UpdateAccountInput{
		ID: domain.AccountID(req.GetAccountId()),
	}
	if name := req.GetName(); name != "" {
		n := domain.AccountName(name)
		in.Name = &n
	}
	if desc := req.GetDescription(); desc != "" {
		d := domain.Description(desc)
		in.Description = &d
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

// Delete — sync id-validation + create Operation + spawn worker.
func (h *Handler) Delete(ctx context.Context, req *iamv1.DeleteAccountRequest) (*operationpb.Operation, error) {
	op, err := h.delete.Execute(ctx, domain.AccountID(req.GetAccountId()))
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

// Get — sync read.
func (h *Handler) Get(ctx context.Context, req *iamv1.GetAccountRequest) (*iamv1.Account, error) {
	a, err := h.get.Execute(ctx, domain.AccountID(req.GetAccountId()))
	if err != nil {
		return nil, err
	}
	pb, err := accountToPb(a)
	if err != nil {
		return nil, status.Error(codes.Internal, "marshal account")
	}
	return pb, nil
}

// List — sync read with pagination.
func (h *Handler) List(ctx context.Context, req *iamv1.ListAccountsRequest) (*iamv1.ListAccountsResponse, error) {
	filter := account.ListFilter{
		PageSize:  safeconv.ClampNonNegInt32(req.GetPageSize()),
		PageToken: req.GetPageToken(),
		Filter:    req.GetFilter(),
	}
	rows, next, err := h.list.Execute(ctx, filter)
	if err != nil {
		return nil, err
	}
	out := make([]*iamv1.Account, 0, len(rows))
	for _, a := range rows {
		pb, err := accountToPb(a)
		if err != nil {
			return nil, status.Error(codes.Internal, "marshal account")
		}
		out = append(out, pb)
	}
	return &iamv1.ListAccountsResponse{Accounts: out, NextPageToken: next}, nil
}

// ListOperations — sync read of the operations recorded for the account.
// Delegates to the shared ListOperationsUseCase (same shape as Role / Group /
// Project / ServiceAccount). Malformed id → InvalidArgument (first statement);
// well-formed-but-no-ops → empty list, not NotFound.
func (h *Handler) ListOperations(ctx context.Context, req *iamv1.ListAccountOperationsRequest) (*iamv1.ListAccountOperationsResponse, error) {
	if err := shared.ValidateResourceID(req.GetAccountId(), domain.PrefixAccount, "account"); err != nil {
		return nil, err
	}
	ops, next, err := h.listOp.Execute(ctx, req.GetAccountId(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := make([]*operationpb.Operation, 0, len(ops))
	for i := range ops {
		out = append(out, shared.OperationToProto(&ops[i]))
	}
	return &iamv1.ListAccountOperationsResponse{Operations: out, NextPageToken: next}, nil
}

// ListAllOperations — sync read of ALL IAM operations scoped to the account
// (filtered by the denormalized account_id column). Distinct from
// ListOperations (per-resource resource_id filter). Malformed id →
// InvalidArgument (first statement); missing / forbidden account →
// PermissionDenied (existence hiding). Viewer-on-account is enforced both by the
// api-gateway permission-catalog (distinct FQN iam.account_operationses.listAll)
// and the use-case requireAccountViewAuthority.
func (h *Handler) ListAllOperations(ctx context.Context, req *iamv1.ListAllAccountOperationsRequest) (*iamv1.ListAllAccountOperationsResponse, error) {
	ops, next, err := h.listAllOp.Execute(ctx, req.GetAccountId(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := make([]*operationpb.Operation, 0, len(ops))
	for i := range ops {
		out = append(out, shared.OperationToProto(&ops[i]))
	}
	return &iamv1.ListAllAccountOperationsResponse{Operations: out, NextPageToken: next}, nil
}

// labelsFromProto — proto map[string]string → domain.Labels.
func labelsFromProto(m map[string]string) domain.Labels {
	if len(m) == 0 {
		return domain.Labels{}
	}
	out := make(domain.Labels, len(m))
	for k, v := range m {
		out[domain.LabelKey(k)] = domain.LabelVal(v)
	}
	return out
}

// accountToPb — обертка над dto.Transfer для удобства handler'а.
func accountToPb(a domain.Account) (*iamv1.Account, error) {
	pb, err := marshalAccountToPb(a)
	if err != nil {
		return nil, err
	}
	return pb, nil
}

// marshalAccountToPb — helper, использует DTO-реестр. Тоже что marshalAccount
// в helpers.go, но возвращает *iamv1.Account, а не *anypb.Any (нужно для Get / List).
func marshalAccountToPb(a domain.Account) (*iamv1.Account, error) {
	any, err := marshalAccount(a)
	if err != nil {
		return nil, err
	}
	var pb iamv1.Account
	if err := any.UnmarshalTo(&pb); err != nil {
		return nil, err
	}
	return &pb, nil
}
