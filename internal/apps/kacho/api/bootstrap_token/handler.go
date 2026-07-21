// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// handler.go — thin gRPC transport for InternalBootstrapTokenService.
//
// ban #6: registered ONLY on the cluster-internal listener (:9091), never on the
// external TLS endpoint (the `Internal…Service` name is 404'd on the public
// listener by HasInternalSuffix). No business logic here — parse → use-case → format.
package bootstrap_token

import (
	"context"

	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// Handler implements iamv1.InternalBootstrapTokenServiceServer.
type Handler struct {
	iamv1.UnimplementedInternalBootstrapTokenServiceServer

	mint *MintUseCase
}

// NewHandler assembles the handler. Composition root: cmd/kacho-iam/wiring.go.
func NewHandler(mint *MintUseCase) *Handler { return &Handler{mint: mint} }

// MintBootstrapToken mints the bootstrap RS256 Bearer (synchronous — not an
// Operation, D-2).
func (h *Handler) MintBootstrapToken(ctx context.Context, req *iamv1.MintBootstrapTokenRequest) (*iamv1.MintBootstrapTokenResponse, error) {
	res, err := h.mint.Execute(ctx, req.GetTtlSeconds())
	if err != nil {
		return nil, err
	}
	return &iamv1.MintBootstrapTokenResponse{
		AccessToken: res.AccessToken,
		TokenType:   res.TokenType,
		ExpiresIn:   res.ExpiresIn,
		ExpiresAt:   timestamppb.New(res.ExpiresAt),
		PrincipalId: res.PrincipalID,
		IssuedAt:    timestamppb.New(res.IssuedAt),
	}, nil
}
