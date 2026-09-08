// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package limit

// handler.go — thin gRPC transport for InternalLimitService.
//
// Ban #6: registered ONLY on the internal listener (:9091), never on the external
// TLS endpoint. No business logic here — parse, delegate, format.

import (
	"context"

	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Handler implements iamv1.InternalLimitServiceServer.
type Handler struct {
	iamv1.UnimplementedInternalLimitServiceServer

	get     *GetUseCase
	list    *ListUseCase
	create  *CreateUseCase
	update  *UpdateUseCase
	del     *DeleteUseCase
	resolve *ResolveUseCase
	changed *ListChangedUseCase
}

// NewHandler assembles the Handler. Composition root: cmd/kaname/wiring.go.
func NewHandler(
	g *GetUseCase, l *ListUseCase, c *CreateUseCase, u *UpdateUseCase, d *DeleteUseCase,
	r *ResolveUseCase, ch *ListChangedUseCase,
) *Handler {
	return &Handler{get: g, list: l, create: c, update: u, del: d, resolve: r, changed: ch}
}

// Get — sync read of one limit.
func (h *Handler) Get(ctx context.Context, req *iamv1.GetLimitRequest) (*iamv1.Limit, error) {
	l, err := h.get.Execute(ctx, req.GetLimitId())
	if err != nil {
		return nil, err
	}
	return toProto(l), nil
}

// List — sync cursor-paginated read.
func (h *Handler) List(ctx context.Context, req *iamv1.ListLimitsRequest) (*iamv1.ListLimitsResponse, error) {
	res, err := h.list.Execute(ctx, req.GetPageSize(), req.GetPageToken(), domain.LimitFilter{
		Scope:   scopeFromProto(req.GetScope()),
		ScopeID: req.GetScopeId(),
		Kind:    domain.LimitKind(req.GetKind()),
	})
	if err != nil {
		return nil, err
	}
	out := &iamv1.ListLimitsResponse{
		Limits:        make([]*iamv1.Limit, 0, len(res.Limits)),
		NextPageToken: res.NextPageToken,
	}
	for _, l := range res.Limits {
		out.Limits = append(out.Limits, toProto(l))
	}
	return out, nil
}

// Create — async; returns the Operation envelope.
func (h *Handler) Create(ctx context.Context, req *iamv1.CreateLimitRequest) (*operationpb.Operation, error) {
	return h.create.Execute(ctx, req)
}

// Update — async; returns the Operation envelope.
func (h *Handler) Update(ctx context.Context, req *iamv1.UpdateLimitRequest) (*operationpb.Operation, error) {
	return h.update.Execute(ctx, req)
}

// Delete — async; returns the Operation envelope.
func (h *Handler) Delete(ctx context.Context, req *iamv1.DeleteLimitRequest) (*operationpb.Operation, error) {
	return h.del.Execute(ctx, req.GetLimitId())
}

// Resolve — sync read of the ceilings in force for one scope object.
func (h *Handler) Resolve(ctx context.Context, req *iamv1.ResolveLimitsRequest) (*iamv1.ResolveLimitsResponse, error) {
	eff, err := h.resolve.Execute(ctx, req.GetScopeId(), req.GetService())
	if err != nil {
		return nil, err
	}
	out := &iamv1.ResolveLimitsResponse{Limits: make([]*iamv1.EffectiveLimit, 0, len(eff))}
	for _, e := range eff {
		out.Limits = append(out.Limits, effectiveToProto(e))
	}
	return out, nil
}

// ListChangedSince — sync read of the delta after the caller's cursor.
func (h *Handler) ListChangedSince(
	ctx context.Context, req *iamv1.ListChangedLimitsRequest,
) (*iamv1.ListChangedLimitsResponse, error) {
	res, err := h.changed.Execute(ctx, req.GetCursor(), req.GetPageSize())
	if err != nil {
		return nil, err
	}
	out := &iamv1.ListChangedLimitsResponse{
		Changes:    make([]*iamv1.LimitChange, 0, len(res.Changes)),
		NextCursor: res.NextCursor,
	}
	for _, l := range res.Changes {
		out.Changes = append(out.Changes, changeToProto(l))
	}
	return out, nil
}
