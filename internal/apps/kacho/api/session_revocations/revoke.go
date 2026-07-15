// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// revoke.go — RevokeUseCase: record a session revocation.
//
// Writes one session_revocations row via the existing SessionRevocationsWriter
// adapter (RevokeWithAdmin → ON CONFLICT (token_jti) DO UPDATE — idempotent,
// ban #10 within-DB invariant on the table PK) and returns a synchronous
// Operation (done=true). No async worker is needed: the write is a single fast
// upsert and the LISTEN/NOTIFY fan-out to api-gateway pods is driven by the
// table trigger, not by an LRO worker.
package session_revocations

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// defaultRevocationTTL — fallback retention when the caller omits ttl_expires_at.
// Must be ≥ the token's exp so the cache stays authoritative for the token's
// lifetime; 30d mirrors the proto docstring + the api-gateway logout handler.
const defaultRevocationTTL = 30 * 24 * time.Hour

// eventSessionAllRevoked — audit_outbox taxonomy value for the
// revoke-all session path. Defined locally so the use-case stays free of a
// repo/pg import (clean-arch boundary); it must match the pg-side session
// taxonomy + audit_outbox_event_type CHECK. The single-jti path's event_type
// (iam.session.revoked) is owned by the tx-scoped RevokeTx adapter (always the
// same value, so it is not threaded through the port).
const eventSessionAllRevoked = "iam.session.all_revoked"

// sessionRevocationWriter — narrow write port. Implemented
// by *repo/kacho/pg.SessionRevocationsAdapter (the SAME adapter the refresh-hook
// reads through), so writer and reader share one table.
//
// Both methods are the tx-scoped *Tx variants — they commit the
// revocation AND the durable audit_outbox compliance row in ONE transaction
// (commit-together-or-rollback-together, запрет #10). eventType selects the
// audit taxonomy value (revoked / all_revoked).
//
//   - RevokeTx              — per-jti session_revocations row (single-token logout)
//   - iam.session.revoked audit row, atomically.
//   - RevokeAllUserTokensTx — per-user revoke-all cutoff (user_token_revocations)
//   - iam.session.all_revoked audit row, atomically. The cutoff is the gate the
//     refresh-hook enforces against the token's session auth_time.
type sessionRevocationWriter interface {
	RevokeTx(ctx context.Context, rev domain.SessionRevocation, revokedBy domain.UserID) error
	RevokeAllUserTokensTx(ctx context.Context, userID domain.UserID, revokeBefore time.Time, reason string, revokedBy domain.UserID, eventType string) error
}

// RevokeInput — transport-agnostic input the handler passes to the use-case.
type RevokeInput struct {
	TokenJTI            string
	UserID              string
	Reason              string
	TTLExpiresAt        *timestamppb.Timestamp
	RevokeAllUserTokens bool

	// RevokedBy — admin/actor who triggered the revocation (audit). "" for
	// user-self logout / system paths.
	RevokedBy string
}

// RevokeUseCase — orchestrates the single-row revocation write + Operation.
type RevokeUseCase struct {
	writer sessionRevocationWriter
	now    func() time.Time
}

// NewRevokeUseCase — constructor. writer may be nil; the handler guards against
// a nil writer (fail-closed Unavailable) before calling Execute.
func NewRevokeUseCase(writer sessionRevocationWriter) *RevokeUseCase {
	return &RevokeUseCase{writer: writer, now: time.Now}
}

// Execute validates, writes the revocation(s), and returns a done Operation.
//
//   - revoke_all_user_tokens=true → write a per-user revoke-all cutoff
//     (revoke_before = now). This denies ALL the user's currently-live tokens at
//     refresh (the refresh-hook compares the token's session auth_time against
//     the cutoff). Previously the flag was silently ignored and one empty-jti
//     row was written (revoked_count=0) → a no-op reported as success.
//   - a per-jti token revoke (token_jti set) → write the single
//     session_revocations row, as before. Both may be set together.
func (uc *RevokeUseCase) Execute(ctx context.Context, in RevokeInput) (*operationpb.Operation, error) {
	if uc.writer == nil {
		// Defensive: an unwired writer must fail closed, never panic.
		return nil, status.Error(codes.Unavailable, "session revocation writer not configured")
	}
	now := uc.now().UTC()
	revokedBy := domain.UserID(in.RevokedBy)

	reason := in.Reason
	if reason == "" {
		if in.RevokeAllUserTokens {
			reason = "admin-revoke"
		} else {
			reason = "user-logout"
		}
	}

	revokedCount := int32(0)

	// User-level revoke-all cutoff — the gate the refresh-hook actually enforces.
	if in.RevokeAllUserTokens {
		marker := domain.UserTokenRevocation{
			UserID:       domain.UserID(in.UserID),
			RevokeBefore: now,
			Reason:       reason,
		}
		if err := marker.Validate(); err != nil {
			return nil, shared.InvalidArg("user_token_revocation", err.Error())
		}
		if err := uc.writer.RevokeAllUserTokensTx(ctx, marker.UserID, marker.RevokeBefore, marker.Reason, revokedBy, eventSessionAllRevoked); err != nil {
			return nil, shared.MapRepoErr(err)
		}
		// A user-level revoke-all is a real, non-no-op revocation. Report ≥1 so
		// the metadata reflects reality (not the inert 0-with-success).
		revokedCount++
	}

	// Per-jti revoke — single-token logout path.
	if in.TokenJTI != "" {
		ttl := now.Add(defaultRevocationTTL)
		if in.TTLExpiresAt != nil {
			if t := in.TTLExpiresAt.AsTime(); t.After(now) {
				ttl = t.UTC()
			}
		}
		rev := domain.SessionRevocation{
			TokenJTI:     in.TokenJTI,
			RevokedAt:    now,
			Reason:       reason,
			UserID:       domain.UserID(in.UserID),
			TTLExpiresAt: ttl,
		}
		if err := rev.Validate(); err != nil {
			return nil, shared.InvalidArg("session_revocation", err.Error())
		}
		if err := uc.writer.RevokeTx(ctx, rev, revokedBy); err != nil {
			return nil, shared.MapRepoErr(err)
		}
		revokedCount++
	}

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Revoke session for user %s", in.UserID),
		&iamv1.RevokeMetadata{RevokedCount: revokedCount, UserId: in.UserID},
	)
	if err != nil {
		return nil, fmt.Errorf("build revoke operation: %w", err)
	}
	op.Done = true
	return shared.OperationToProto(&op), nil
}
