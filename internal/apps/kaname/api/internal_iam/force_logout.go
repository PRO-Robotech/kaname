// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// force_logout.go — InternalIAMService.ForceLogout.
//
// ForceLogout — admin force-logout: records a USER-LEVEL revoke-all cutoff
// (user_token_revocations.revoke_before = now) for the target subject so the
// refresh-hook denies ALL of the user's currently-live tokens (it compares the
// token's session auth_time against the cutoff). Reuses the SAME adapter as the
// user-logout / Revoke(revoke_all) paths. Async per the proto envelope (returns
// Operation, done=true). The earlier per-jti synthetic-jti write was inert — a
// synthetic jti can never match the target's real live-token jti.
//
// ForceLogout was advertised (caller_policy + permission_catalog) but
// Unimplemented before this fix — an advertised-but-Unimplemented RPC is a
// contract gap.
package internal_iam

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// sessionRevoker — narrow write port for ForceLogout.
// Implemented by *repo/kaname/pg.SessionRevocationsAdapter — the SAME adapter
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

// forceLogoutOperationRepo — Operation-порт ForceLogout. Шире operations.Repo
// ровно на MetadataFinalizer: op-строку обязано создавать ДО мутации (иначе
// сбой Create оставляет закоммиченный cutoff без pollable операции), а
// объявленный контрактом ответ `ForceLogoutResult` известен только после
// записи. `MarkDone` третьим параметром берёт RESPONSE и metadata не трогает.
type forceLogoutOperationRepo interface {
	operations.Repo
	operations.MetadataFinalizer
}

// eventSessionForceLogout — audit_outbox taxonomy value for ForceLogout.
// Defined locally to keep the use-case free of a repo/pg import; must match the
// pg-side session taxonomy + audit_outbox_event_type CHECK.
const eventSessionForceLogout = "iam.session.force_logout"

// providerSessions — the identity provider's login-session surface.
//
// Force-logout writes a cutoff that stops tokens from being ISSUED. That is the
// authoritative half, and on its own it leaves the person's browser holding a
// live session: when that session asks again it presents its ORIGINAL
// authentication instant, which the cutoff refuses — correctly, and forever,
// with nothing prompting the re-authentication that would clear it. Ending the
// session is what turns a standing refusal into a logout.
//
// Implemented by *clients.HydraAdminClient. nil when the provider-admin surface
// is not configured: the cutoff is still recorded and still enforced.
type providerSessions interface {
	DeleteLoginSessions(ctx context.Context, subject string) error
}

// externalIDResolver maps a kacho user id to the identity the provider knows.
//
// The two are different namespaces and neither substitutes for the other:
// force-logout names a `users.id`, the provider keys its sessions on the
// subject it issued. Passing one where the other belongs would delete nothing
// and report success.
type externalIDResolver interface {
	ExternalIDOf(ctx context.Context, id domain.UserID) (string, error)
}

// WithProviderSessions — attaches the provider's login-session surface and the
// resolver that names a user to it. Both or neither: a teardown that cannot
// resolve its subject is not a teardown.
func (h *Handler) WithProviderSessions(p providerSessions, r externalIDResolver) *Handler {
	if p == nil || r == nil {
		return h
	}
	h.providerSessions = p
	h.externalIDs = r
	return h
}

// WithSessionRevoker — attaches the session-revocation writer used by
// ForceLogout. Composition-root only (cmd/kaname/wiring.go).
func (h *Handler) WithSessionRevoker(r sessionRevoker) *Handler {
	h.sessionRevoker = r
	return h
}

// WithOperations — attaches the Operation repository ForceLogout persists its
// operation row in. Composition-root only. A nil repo stays fail-closed
// (ForceLogout returns Unavailable): handing back an operation id that names no
// row is the very defect this wiring exists to prevent, so a wiring omission
// must refuse rather than answer with an unqueryable id.
func (h *Handler) WithOperations(r forceLogoutOperationRepo) *Handler {
	h.operations = r
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
// Fail-closed everywhere — the revoke never runs unless the model said yes; the
// ANSWER still says what happened: anonymous / empty principal, nil checker or
// not-allowed → PermissionDenied; a checker that could not be reached →
// Unavailable (nothing was decided, an identical retry is worth making). Both are
// verbatim and non-leaking.
//
// acr step-up (required_acr_min) is enforced separately by the internal acr-floor
// (authzguard.ACRFloor) chained on the :9091 listener BEFORE this handler: when
// ForceLogout's catalog acr_min>0 (latent-until-policy today), the trusted
// forwarded acr (corelib grpcsrv x-kacho-token-acr) must satisfy it or the call
// is rejected with a step-up signal. This gate stays the per-user ReBAC Check;
// acr is no longer a gap on the internal route.
// The subject is named by SubjectFromPrincipal, not by joining "user:" to the id.
// `PrincipalUserID` deliberately admits `service_account` and `system` as well as
// `user`, so prefixing its result with "user:" asked the store about a subject that
// cannot exist whenever the caller was non-interactive — a machine cluster-admin was
// refused by construction, however it was granted. Found by census of this class
// after the same spelling was fixed in the invite gate; no e2e case covers this
// route, which is why it survived there.
func (h *Handler) requireSystemAdmin(ctx context.Context) error {
	subject, ok := authzguard.PrincipalSubject(ctx)
	if !ok {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	if h.adminCheck == nil {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	allowed, err := h.adminCheck.Check(ctx,
		subject, "system_admin", "cluster:"+domain.ClusterSingletonID)
	if err != nil {
		return authzguard.AuthzBackendUnavailable()
	}
	if !allowed {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	return nil
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
	if h.operations == nil {
		return nil, status.Error(codes.Unavailable, "operation repository not configured")
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

	// Persist the Operation (done=false) BEFORE the mutation — mirroring every
	// other mutation in this service, so the operation id the admin receives is
	// ALWAYS durably queryable. It used to be built in memory, stamped
	// done=true and returned without ever reaching the operations table: the
	// force-logout was invisible to OperationService.Get, to every operation
	// list and to every audit that reads operations.
	op, err := operations.NewFromContext(ctx,
		domain.PrefixOperationIAM,
		fmt.Sprintf("Force logout user %s", userID),
		&iamv1.ForceLogoutMetadata{UserId: userID},
	)
	if err != nil {
		return nil, fmt.Errorf("build force-logout operation: %w", err)
	}
	if err := h.operations.Create(ctx, op); err != nil {
		return nil, fmt.Errorf("persist operation: %w", err)
	}

	if err := h.sessionRevoker.RevokeAllUserTokensTx(ctx, marker.UserID, marker.RevokeBefore, marker.Reason, revokedBy, eventSessionForceLogout); err != nil {
		// Record the terminal failure on the already-persisted op so a poll sees
		// a real error, not NotFound; still surface the gRPC error to the caller.
		gerr := shared.MapRepoErr(err)
		if merr := h.operations.MarkError(ctx, op.ID, status.Convert(gerr).Proto()); merr != nil {
			slog.ErrorContext(ctx, "ForceLogout: operation error-mark failed",
				"operation_id", op.ID, "err", merr.Error())
		}
		return nil, gerr
	}

	// End the session at the provider, now that the cutoff is durable.
	//
	// Order is deliberate. The cutoff goes first because it is the half that
	// holds without anyone's cooperation; the teardown follows because it is the
	// half that makes the refusal recoverable. If the provider cannot be reached
	// the cutoff STAYS — it is protective and idempotent — but the call reports
	// failure: an administrator told "logged out" while the session is still
	// standing is worse off than one told to retry. Retrying re-applies the same
	// cutoff and re-attempts the same teardown, both idempotent.
	if h.providerSessions != nil {
		if err := h.endProviderSession(ctx, marker.UserID); err != nil {
			gerr := status.Error(codes.Unavailable, "could not end the session at the identity provider")
			slog.ErrorContext(ctx, "ForceLogout: provider session teardown failed",
				"operation_id", op.ID, "user_id", userID, "err", err.Error())
			if merr := h.operations.MarkError(ctx, op.ID, status.Convert(gerr).Proto()); merr != nil {
				slog.ErrorContext(ctx, "ForceLogout: operation error-mark failed",
					"operation_id", op.ID, "err", merr.Error())
			}
			return nil, gerr
		}
	}

	// Complete the Operation: done=true, metadata + the declared response.
	//
	// revoked_count counts the revocation records this call committed — one
	// user-level cutoff, which denies every live token of the subject. It is
	// deliberately not 0: an inert 0-with-success is how the earlier
	// synthetic-jti implementation reported doing nothing, and the sibling
	// Revoke(revoke_all) path counts its cutoff the same way for the same reason.
	//
	// KNOWN, NOT FIXED HERE: the field's proto comment still describes the
	// per-jti model it was written for ("session_revocations rows newly
	// inserted"). Under the cutoff model no such row is inserted and the number
	// of tokens denied is not knowable at all — it is "every live one". Making
	// the comment say that is a proto edit with stub regeneration and a catalog
	// re-check behind it, which is its own change; leaving the response unwritten
	// to dodge the question would recreate the defect this fixes.
	meta, resp, merr := forceLogoutOperationPayload(userID)
	if merr != nil {
		return nil, merr
	}
	if err := h.operations.MarkDoneWithMetadata(ctx, op.ID, meta, resp); err != nil {
		// Non-fatal for the caller: the cutoff committed and the row exists, so
		// a poll answers (done=false) and never NotFound. Nothing finishes it
		// afterwards, so it is logged loudly, never swallowed (CWE-390).
		slog.ErrorContext(ctx, "ForceLogout: operation complete failed",
			"operation_id", op.ID, "err", err.Error())
	}
	op.Done = true
	op.Metadata = meta
	op.Response = resp

	return shared.OperationToProto(&op), nil
}

// forceLogoutOperationPayload — the terminal (metadata, response) pair declared
// by `InternalIAMService.ForceLogout` (metadata: ForceLogoutMetadata,
// response: ForceLogoutResult).
func forceLogoutOperationPayload(userID string) (meta, resp *anypb.Any, err error) {
	meta, err = anypb.New(&iamv1.ForceLogoutMetadata{UserId: userID})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal force-logout metadata: %w", err)
	}
	resp, err = anypb.New(&iamv1.ForceLogoutResult{RevokedCount: 1})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal force-logout response: %w", err)
	}
	return meta, resp, nil
}

// endProviderSession resolves the target to the identity the provider knows and
// ends every login session it holds for them.
//
// A subject that cannot be resolved is an error, not a skip: silently doing
// nothing here is exactly the shape of the defect this closes.
func (h *Handler) endProviderSession(ctx context.Context, userID domain.UserID) error {
	subject, err := h.externalIDs.ExternalIDOf(ctx, userID)
	if err != nil {
		return fmt.Errorf("resolve external subject of %s: %w", userID, err)
	}
	if subject == "" {
		return fmt.Errorf("user %s has no external subject to end sessions for", userID)
	}
	return h.providerSessions.DeleteLoginSessions(ctx, subject)
}
