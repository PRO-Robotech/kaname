// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package interactiveclient

// handler.go — thin gRPC transport for InternalInteractiveClientService.
//
// Ban #6: registered ONLY on the internal listener (:9091), never on the
// external TLS endpoint. No business logic here — parse, delegate, format.

import (
	"context"

	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)

// Handler implements iamv1.InternalInteractiveClientServiceServer.
type Handler struct {
	iamv1.UnimplementedInternalInteractiveClientServiceServer

	get    *GetUseCase
	list   *ListUseCase
	create *CreateUseCase
	update *UpdateUseCase
	del    *DeleteUseCase
}

// NewHandler assembles the Handler. Composition root: cmd/kaname/wiring.go.
func NewHandler(g *GetUseCase, l *ListUseCase, c *CreateUseCase, u *UpdateUseCase, d *DeleteUseCase) *Handler {
	return &Handler{get: g, list: l, create: c, update: u, del: d}
}

// Get — sync read of one client.
func (h *Handler) Get(ctx context.Context, req *iamv1.GetInteractiveClientRequest) (*iamv1.InteractiveClient, error) {
	c, err := h.get.Execute(ctx, req.GetInteractiveClientId())
	if err != nil {
		return nil, err
	}
	return toProto(c), nil
}

// List — sync cursor-paginated read.
func (h *Handler) List(ctx context.Context, req *iamv1.ListInteractiveClientsRequest) (*iamv1.ListInteractiveClientsResponse, error) {
	res, err := h.list.Execute(ctx, req.GetPageSize(), req.GetPageToken(), req.GetFilter())
	if err != nil {
		return nil, err
	}
	out := &iamv1.ListInteractiveClientsResponse{
		InteractiveClients: make([]*iamv1.InteractiveClient, 0, len(res.Clients)),
		NextPageToken:      res.NextPageToken,
	}
	for _, c := range res.Clients {
		out.InteractiveClients = append(out.InteractiveClients, toProto(c))
	}
	return out, nil
}

// Create — async; returns the Operation envelope.
func (h *Handler) Create(ctx context.Context, req *iamv1.CreateInteractiveClientRequest) (*operationpb.Operation, error) {
	return h.create.Execute(ctx, req)
}

// Update — async; returns the Operation envelope.
func (h *Handler) Update(ctx context.Context, req *iamv1.UpdateInteractiveClientRequest) (*operationpb.Operation, error) {
	return h.update.Execute(ctx, req)
}

// Delete — async; returns the Operation envelope.
func (h *Handler) Delete(ctx context.Context, req *iamv1.DeleteInteractiveClientRequest) (*operationpb.Operation, error) {
	return h.del.Execute(ctx, req.GetInteractiveClientId())
}
