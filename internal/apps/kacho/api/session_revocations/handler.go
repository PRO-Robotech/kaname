// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package session_revocations — InternalSessionRevocationsService
// (kacho-only, gRPC port :9091).
//
// Ban #6 (Internal.* not on external endpoint): internal-only service. Registered
// ONLY on the internal listener (port 9091). gRPC-direct only.
//
// Revocation sources that drive Revoke:
//   - User-initiated logout (api-gateway OAuth2 logout handler — fronts Revoke).
//   - Admin force-logout (InternalIAMService.ForceLogout — uses the same writer).
//   - Back-channel logout from Hydra.
//
// Methods:
//   - Revoke    — async (Operation): write a session_revocations row, NOTIFY.
//   - IsRevoked — sync hot-path lookup (api-gateway cache-miss / refresh-hook).
//   - ListByUser— sync admin/audit enumeration.
//
// Why this exists: before this handler the api-gateway logout called Revoke but
// kacho-iam never registered the service → codes.Unimplemented → token
// revocation was INERT (the refresh-hook IsRevoked gate had nothing written to
// it). This handler closes that loop.
package session_revocations

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// revoker — narrow write port. Implemented by
// *RevokeUseCase. Kept as an interface so the handler is mock-testable.
type revoker interface {
	Execute(ctx context.Context, in RevokeInput) (*operationpb.Operation, error)
}

// reader — narrow read port (CQRS-split). Implemented by an adapter over the
// SessionRevocationRepo (pool-scoped). nil when the read stack is not wired —
// IsRevoked / ListByUser then fail-closed Unavailable.
type reader interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
	GetByJTI(ctx context.Context, jti string) (domain.SessionRevocation, error)
	ListByUser(ctx context.Context, userID string, limit int32) ([]domain.SessionRevocation, error)
}

// Handler — gRPC server for InternalSessionRevocationsService.
type Handler struct {
	iamv1.UnimplementedInternalSessionRevocationsServiceServer

	revoke revoker
	read   reader
}

// NewHandler — builder. `revoke` carries the RevokeUseCase; `read` is the
// read-side adapter (may be nil in degraded/dev — reads then fail-closed).
func NewHandler(revoke revoker, read reader) *Handler {
	return &Handler{revoke: revoke, read: read}
}

// Revoke — record a token revocation. Async per the proto envelope: the row is
// written synchronously inside the use-case and an Operation (done=true) is
// returned. Idempotent on token_jti (ON CONFLICT DO UPDATE in the repo).
func (h *Handler) Revoke(ctx context.Context, req *iamv1.RevokeRequest) (*operationpb.Operation, error) {
	if strings.TrimSpace(req.GetUserId()) == "" {
		return nil, shared.InvalidArg("user_id", "required")
	}
	// Without a jti AND without the bulk flag there is nothing to revoke.
	if strings.TrimSpace(req.GetTokenJti()) == "" && !req.GetRevokeAllUserTokens() {
		return nil, shared.InvalidArg("token_jti",
			"required unless revoke_all_user_tokens is set")
	}
	if h.revoke == nil {
		return nil, status.Error(codes.Unavailable, "session revocation writer not configured")
	}

	var ttl *timestamppb.Timestamp
	if t := req.GetTtlExpiresAt(); t != nil {
		ttl = t
	}
	return h.revoke.Execute(ctx, RevokeInput{
		TokenJTI:            strings.TrimSpace(req.GetTokenJti()),
		UserID:              strings.TrimSpace(req.GetUserId()),
		Reason:              strings.TrimSpace(req.GetReason()),
		TTLExpiresAt:        ttl,
		RevokeAllUserTokens: req.GetRevokeAllUserTokens(),
	})
}

// IsRevoked — sync hot-path lookup. Called by api-gateway on cache-miss and by
// the Hydra refresh-hook. fail-closed Unavailable when the read stack is unwired.
func (h *Handler) IsRevoked(ctx context.Context, req *iamv1.IsRevokedRequest) (*iamv1.IsRevokedResponse, error) {
	jti := strings.TrimSpace(req.GetTokenJti())
	if jti == "" {
		return nil, shared.InvalidArg("token_jti", "required")
	}
	if h.read == nil {
		return nil, status.Error(codes.Unavailable, "session revocation reader not configured")
	}
	revoked, err := h.read.IsRevoked(ctx, jti)
	if err != nil {
		return nil, status.Error(codes.Internal, "session revocation lookup failed")
	}
	resp := &iamv1.IsRevokedResponse{Revoked: revoked}
	if revoked {
		// Best-effort enrichment of revoked_at / reason; a lookup miss here is
		// not fatal — the boolean is the contract.
		if rev, gerr := h.read.GetByJTI(ctx, jti); gerr == nil {
			resp.RevokedAt = shared.TimestampProto(rev.RevokedAt)
			resp.Reason = rev.Reason
		}
	}
	return resp, nil
}

// ListByUser — sync admin/audit enumeration of active revocations for a user.
func (h *Handler) ListByUser(ctx context.Context, req *iamv1.ListByUserRequest) (*iamv1.ListByUserResponse, error) {
	userID := strings.TrimSpace(req.GetUserId())
	if userID == "" {
		return nil, shared.InvalidArg("user_id", "required")
	}
	if h.read == nil {
		return nil, status.Error(codes.Unavailable, "session revocation reader not configured")
	}
	limit := safeconv.ClampNonNegInt32(req.GetPageSize())
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := h.read.ListByUser(ctx, userID, limit)
	if err != nil {
		return nil, status.Error(codes.Internal, "session revocation list failed")
	}
	resp := &iamv1.ListByUserResponse{}
	for _, r := range rows {
		resp.Revocations = append(resp.Revocations, toProto(r))
	}
	return resp, nil
}

// toProto maps a domain SessionRevocation to the wire message.
func toProto(r domain.SessionRevocation) *iamv1.SessionRevocation {
	out := &iamv1.SessionRevocation{
		TokenJti: r.TokenJTI,
		UserId:   string(r.UserID),
		Reason:   r.Reason,
	}
	if !r.RevokedAt.IsZero() {
		out.RevokedAt = shared.TimestampProto(r.RevokedAt)
	}
	if !r.TTLExpiresAt.IsZero() {
		out.TtlExpiresAt = shared.TimestampProto(r.TTLExpiresAt)
	}
	return out
}
