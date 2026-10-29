// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grant_delegation

// handler.go — тонкий транспорт службы GrantDelegationService: разбор запроса →
// use-case → проекция ответа. Решений здесь нет.

import (
	"context"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Handler — служба делегирований права выдавать.
type Handler struct {
	iamv1.UnimplementedGrantDelegationServiceServer
	create *CreateGrantDelegationUseCase
	get    *GetGrantDelegationUseCase
	list   *ListGrantDelegationsUseCase
	revoke *RevokeGrantDelegationUseCase
}

// NewHandler — службу собирает корень (`cmd/kaname/wiring.go`).
func NewHandler(c *CreateGrantDelegationUseCase, g *GetGrantDelegationUseCase,
	l *ListGrantDelegationsUseCase, r *RevokeGrantDelegationUseCase) *Handler {
	return &Handler{create: c, get: g, list: l, revoke: r}
}

// Create — заведение делегирования.
func (h *Handler) Create(ctx context.Context, req *iamv1.CreateGrantDelegationRequest) (*operationpb.Operation, error) {
	in := CreateInput{
		AccountID:   req.GetAccountId(),
		DelegateID:  req.GetDelegate().GetId(),
		RoleIDs:     req.GetRoleIds(),
		TargetTypes: req.GetTargetTypes(),
	}
	if req.GetDelegate() != nil {
		in.DelegateType = req.GetDelegate().GetType().String()
	}
	for _, t := range req.GetSubjectTypes() {
		in.SubjectTypes = append(in.SubjectTypes, t.String())
	}
	op, err := h.create.Execute(ctx, in)
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}

// Get — чтение делегирования.
func (h *Handler) Get(ctx context.Context, req *iamv1.GetGrantDelegationRequest) (*iamv1.GrantDelegation, error) {
	d, err := h.get.Execute(ctx, domain.GrantDelegationID(req.GetGrantDelegationId()))
	if err != nil {
		return nil, err
	}
	pb, err := ToProto(d)
	if err != nil {
		return nil, shared.MapRepoErr(err)
	}
	return pb, nil
}

// List — делегирования аккаунта.
func (h *Handler) List(ctx context.Context, req *iamv1.ListGrantDelegationsRequest) (*iamv1.ListGrantDelegationsResponse, error) {
	rows, next, err := h.list.Execute(ctx, ListInput{
		AccountID: req.GetAccountId(),
		PageSize:  req.GetPageSize(),
		PageToken: req.GetPageToken(),
	})
	if err != nil {
		return nil, err
	}
	out := &iamv1.ListGrantDelegationsResponse{
		GrantDelegations: make([]*iamv1.GrantDelegation, 0, len(rows)),
		NextPageToken:    next,
	}
	for _, d := range rows {
		pb, perr := ToProto(d)
		if perr != nil {
			return nil, shared.MapRepoErr(perr)
		}
		out.GrantDelegations = append(out.GrantDelegations, pb)
	}
	return out, nil
}

// Revoke — отзыв делегирования и выданного по нему.
func (h *Handler) Revoke(ctx context.Context, req *iamv1.RevokeGrantDelegationRequest) (*operationpb.Operation, error) {
	op, err := h.revoke.Execute(ctx, domain.GrantDelegationID(req.GetGrantDelegationId()))
	if err != nil {
		return nil, err
	}
	return shared.OperationToProto(op), nil
}
