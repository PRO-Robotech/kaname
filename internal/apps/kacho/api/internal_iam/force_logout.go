// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// force_logout.go — InternalIAMService.ForceLogout + GetJWKSStatus.
//
// ForceLogout — admin force-logout: records a USER-LEVEL revoke-all cutoff
// (user_token_revocations.revoke_before = now) for the target subject so the
// refresh-hook denies ALL of the user's currently-live tokens (it compares the
// token's session auth_time against the cutoff). Reuses the SAME adapter as the
// user-logout / Revoke(revoke_all) paths. Async per the proto envelope (returns
// Operation, done=true). The earlier per-jti synthetic-jti write was inert — a
// synthetic jti can never match the target's real live-token jti.
//
// GetJWKSStatus — admin observability over oidc_jwks_keys: per-alg current key
// id, age, and a rotation-overdue flag. Read-only; never serialises the
// encrypted private key (infra-sensitive material stays internal).
//
// Both were advertised (caller_policy + permission_catalog) but Unimplemented
// before this fix — an advertised-but-Unimplemented RPC is a contract gap.
package internal_iam

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/safeconv"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// sessionRevoker — narrow write port for ForceLogout.
// Implemented by *repo/kacho/pg.SessionRevocationsAdapter — the SAME adapter
// the user-logout Revoke path and the refresh-hook share.
//
// ForceLogout writes a USER-LEVEL revoke-all cutoff (the gate the refresh-hook
// actually enforces against the token's real session auth_time), NOT a per-jti
// row. The previous per-jti synthetic-jti approach was inert: the synthetic
// "force-logout:<user>:<unixnano>" never equals the target's real live-token
// jti, so the refresh-hook jti gate (WHERE token_jti=$1) never matched.
//
// The tx-scoped RevokeAllUserTokensTx commits the cutoff AND the durable
// iam.session.force_logout audit_outbox row in ONE transaction
// (commit-together-or-rollback-together, запрет #10). eventType selects the
// audit taxonomy value (force_logout for this RPC).
type sessionRevoker interface {
	RevokeAllUserTokensTx(ctx context.Context, userID domain.UserID, revokeBefore time.Time, reason string, revokedBy domain.UserID, eventType string) error
}

// eventSessionForceLogout — audit_outbox taxonomy value for ForceLogout.
// Defined locally to keep the use-case free of a repo/pg import; must match the
// pg-side session taxonomy + audit_outbox_event_type CHECK.
const eventSessionForceLogout = "iam.session.force_logout"

// jwksStatusReader — narrow read port for GetJWKSStatus. Implemented by
// *repo/kacho/pg.OIDCJwksKeyRepo (ListCurrent).
type jwksStatusReader interface {
	ListCurrent(ctx context.Context) ([]domain.OIDCJwksKey, error)
}

// WithSessionRevoker — attaches the session-revocation writer used by
// ForceLogout. Composition-root only (cmd/kacho-iam/wiring.go).
func (h *Handler) WithSessionRevoker(r sessionRevoker) *Handler {
	h.sessionRevoker = r
	return h
}

// WithAdminChecker — attaches the defense-in-depth ReBAC system_admin@cluster
// gate enforced on ForceLogout. Composition-root only. nil checker stays
// fail-closed (requireSystemAdmin denies).
func (h *Handler) WithAdminChecker(c authzguard.RelationChecker) *Handler {
	h.adminCheck = c
	return h
}

// requireSystemAdmin — defense-in-depth in-iam gate for the privileged admin
// RPCs. Requires an authenticated principal holding system_admin@cluster in
// ReBAC. Additive to the gateway caller-policy (AuthN+AuthZ on every RPC,
// internal included, runs its own per-RPC Check — the caller-policy only proves
// WHO dialed :9091, not that the END USER is a cluster admin).
//
// Fail-closed everywhere: anonymous / empty principal, nil checker, backend
// error, or not-allowed → PermissionDenied (verbatim, non-leaking).
//
// acr step-up (required_acr_min) is enforced separately by the internal acr-floor
// (authzguard.ACRFloor) chained on the :9091 listener BEFORE this handler: when
// ForceLogout's catalog acr_min>0 (latent-until-policy today), the trusted
// forwarded acr (corelib grpcsrv x-kacho-token-acr) must satisfy it or the call
// is rejected with a step-up signal. This gate stays the per-user ReBAC Check;
// acr is no longer a gap on the internal route.
func (h *Handler) requireSystemAdmin(ctx context.Context) error {
	principal := authzguard.PrincipalUserID(ctx)
	if principal == "" || authzguard.IsAnonymous(ctx) {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	if h.adminCheck == nil {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	allowed, err := h.adminCheck.Check(ctx,
		"user:"+principal, "system_admin", "cluster:"+domain.ClusterSingletonID)
	if err != nil || !allowed {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	return nil
}

// WithJWKSStatus — attaches the JWKS read port + the configured rotation
// interval used by GetJWKSStatus.
func (h *Handler) WithJWKSStatus(r jwksStatusReader, rotationInterval time.Duration) *Handler {
	h.jwksReader = r
	h.jwksRotation = rotationInterval
	return h
}

// ForceLogout — record a user-level revoke-all cutoff for the target subject so
// the refresh-hook denies ALL of the user's currently-live tokens.
//
// We set revoke_before = now(): the refresh-hook denies any token whose session
// authenticated at or before this cutoff (compared against the Hydra session
// auth_time). Once the user re-authenticates, auth_time advances past the cutoff
// and new sessions are allowed again (no permanent lockout). This actually
// denies live tokens — unlike the old per-jti synthetic-jti row, which was inert
// (a synthetic jti never matches the target's real token jti).
func (h *Handler) ForceLogout(ctx context.Context, req *iamv1.ForceLogoutRequest) (*operationpb.Operation, error) {
	// Defense-in-depth authZ FIRST: require an authenticated principal holding
	// system_admin@cluster (fail-closed). This RPC was previously ungated
	// (catalog `<exempt>`) — relying solely on the gateway caller-policy.
	if err := h.requireSystemAdmin(ctx); err != nil {
		return nil, err
	}
	userID := strings.TrimSpace(req.GetUserId())
	if userID == "" {
		return nil, shared.InvalidArg("user_id", "required")
	}
	if h.sessionRevoker == nil {
		return nil, status.Error(codes.Unavailable, "session revocation writer not configured")
	}

	reason := strings.TrimSpace(req.GetReason())
	if reason == "" {
		reason = "admin-force-logout"
	}
	now := time.Now().UTC()

	marker := domain.UserTokenRevocation{
		UserID:       domain.UserID(userID),
		RevokeBefore: now,
		Reason:       reason,
	}
	if err := marker.Validate(); err != nil {
		return nil, shared.InvalidArg("user_token_revocation", err.Error())
	}

	// Audit actor (revoked_by) is sourced from the VERIFIED principal — never
	// from req.GetActorId(), which is client-supplied and spoofable. A non-empty
	// body actor_id that disagrees with the verified principal is a spoof
	// attempt → reject (InvalidArgument), rather than silently recording a
	// falsified audit actor. The gate above already guarantees a non-empty
	// authenticated principal.
	actor := authzguard.PrincipalUserID(ctx)
	if bodyActor := strings.TrimSpace(req.GetActorId()); bodyActor != "" && bodyActor != actor {
		return nil, status.Error(codes.InvalidArgument,
			"actor_id must match the authenticated principal")
	}
	revokedBy := domain.UserID(actor)
	if err := h.sessionRevoker.RevokeAllUserTokensTx(ctx, marker.UserID, marker.RevokeBefore, marker.Reason, revokedBy, eventSessionForceLogout); err != nil {
		return nil, shared.MapRepoErr(err)
	}

	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Force logout user %s", userID),
		&iamv1.ForceLogoutMetadata{UserId: userID},
	)
	if err != nil {
		return nil, fmt.Errorf("build force-logout operation: %w", err)
	}
	op.Done = true
	return shared.OperationToProto(&op), nil
}

// GetJWKSStatus — per-alg status of the current signing keys.
func (h *Handler) GetJWKSStatus(ctx context.Context, _ *emptypb.Empty) (*iamv1.JWKSStatusResponse, error) {
	if h.jwksReader == nil {
		return nil, status.Error(codes.Unavailable, "jwks status reader not configured")
	}
	keys, err := h.jwksReader.ListCurrent(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, "jwks status lookup failed")
	}

	intervalDays := safeconv.ClampNonNegInt32(int64(h.jwksRotation / (24 * time.Hour)))
	now := time.Now().UTC()

	resp := &iamv1.JWKSStatusResponse{}
	for _, k := range keys {
		// ClampNonNegInt32 also floors a future-dated key (negative age) at 0.
		ageDays := safeconv.ClampNonNegInt32(int64(now.Sub(k.CreatedAt) / (24 * time.Hour)))
		alg := &iamv1.JWKSAlgStatus{
			Alg:                  string(k.Alg),
			CurrentKid:           k.KID,
			CurrentAgeDays:       ageDays,
			RotationIntervalDays: intervalDays,
			RotationOverdue:      intervalDays > 0 && ageDays >= intervalDays,
		}
		if !k.CreatedAt.IsZero() {
			alg.CurrentCreatedAt = shared.TimestampProto(k.CreatedAt)
		}
		resp.Algorithms = append(resp.Algorithms, alg)
	}
	return resp, nil
}
