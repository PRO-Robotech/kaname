// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package service_account — ServiceAccountService.
// Key-credentials (key/secret create) — отдельный pipeline (через Ory Hydra
// client_credentials grant, OAuth2 token endpoint).
package service_account

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	reposa "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
)

type Handler struct {
	iamv1.UnimplementedServiceAccountServiceServer

	create *CreateServiceAccountUseCase
	update *UpdateServiceAccountUseCase
	delete *DeleteServiceAccountUseCase
	get    *GetServiceAccountUseCase
	list   *ListServiceAccountsUseCase
	listOp *shared.ListOperationsUseCase
}

func NewHandler(c *CreateServiceAccountUseCase, u *UpdateServiceAccountUseCase, d *DeleteServiceAccountUseCase,
	g *GetServiceAccountUseCase, l *ListServiceAccountsUseCase) *Handler {
	return &Handler{create: c, update: u, delete: d, get: g, list: l}
}

// WithListOperations wires the per-resource operation-listing use-case.
func (h *Handler) WithListOperations(uc *shared.ListOperationsUseCase) *Handler {
	h.listOp = uc
	return h
}

func (h *Handler) Create(ctx context.Context, req *iamv1.CreateServiceAccountRequest) (*operationpb.Operation, error) {
	sa := domain.ServiceAccount{
		AccountID:   domain.AccountID(req.GetAccountId()),
		Name:        domain.SvcAccountName(req.GetName()),
		Description: domain.Description(req.GetDescription()),
		Labels:      labelsFromProto(req.GetLabels()),
	}
	op, err := h.create.Execute(ctx, sa)
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) Update(ctx context.Context, req *iamv1.UpdateServiceAccountRequest) (*operationpb.Operation, error) {
	in := UpdateServiceAccountInput{
		ID: domain.ServiceAccountID(req.GetServiceAccountId()),
	}
	if name := req.GetName(); name != "" {
		n := domain.SvcAccountName(name)
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

func (h *Handler) Delete(ctx context.Context, req *iamv1.DeleteServiceAccountRequest) (*operationpb.Operation, error) {
	op, err := h.delete.Execute(ctx, domain.ServiceAccountID(req.GetServiceAccountId()))
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

func (h *Handler) Get(ctx context.Context, req *iamv1.GetServiceAccountRequest) (*iamv1.ServiceAccount, error) {
	sa, err := h.get.Execute(ctx, domain.ServiceAccountID(req.GetServiceAccountId()))
	if err != nil {
		return nil, err
	}
	pb, err := saToPb(sa)
	if err != nil {
		return nil, status.Error(codes.Internal, "marshal service account")
	}
	return pb, nil
}

func (h *Handler) List(ctx context.Context, req *iamv1.ListServiceAccountsRequest) (*iamv1.ListServiceAccountsResponse, error) {
	filter := reposa.ListFilter{
		AccountID: domain.AccountID(req.GetAccountId()),
		PageSize:  safeconv.ClampNonNegInt32(req.GetPageSize()),
		PageToken: req.GetPageToken(),
		Filter:    req.GetFilter(),
	}
	rows, next, err := h.list.Execute(ctx, filter)
	if err != nil {
		return nil, err
	}
	out := make([]*iamv1.ServiceAccount, 0, len(rows))
	for _, sa := range rows {
		pb, err := saToPb(sa)
		if err != nil {
			return nil, status.Error(codes.Internal, "marshal service account")
		}
		out = append(out, pb)
	}
	return &iamv1.ListServiceAccountsResponse{ServiceAccounts: out, NextPageToken: next}, nil
}

func (h *Handler) ListOperations(ctx context.Context, req *iamv1.ListServiceAccountOperationsRequest) (*iamv1.ListServiceAccountOperationsResponse, error) {
	if err := shared.ValidateResourceID(req.GetServiceAccountId(), domain.PrefixServiceAccount, "service account"); err != nil {
		return nil, err
	}
	ops, next, err := h.listOp.Execute(ctx, req.GetServiceAccountId(), req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, err
	}
	out := make([]*operationpb.Operation, 0, len(ops))
	for i := range ops {
		out = append(out, shared.OperationToProto(&ops[i]))
	}
	return &iamv1.ListServiceAccountOperationsResponse{Operations: out, NextPageToken: next}, nil
}

// ----- shared utils -----

func saToPb(sa domain.ServiceAccount) (*iamv1.ServiceAccount, error) {
	any, err := marshalSA(sa)
	if err != nil {
		return nil, err
	}
	var pb iamv1.ServiceAccount
	if err := any.UnmarshalTo(&pb); err != nil {
		return nil, err
	}
	return &pb, nil
}
