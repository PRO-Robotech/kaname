// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// refresh_hook_handler.go — Hydra refresh_token webhook.
//
// POST /iam/v1/hooks/refresh
//
// Hydra (configured oauth2.refresh_token_hook.url) вызывает этот endpoint
// каждый раз при refresh-token-rotation. Handler:
//
//  1. Проверяет shared-secret.
//  2. Lookup user; если admin force-blocked (user.invite_status == BLOCKED) —
//     возвращает 403 user_disabled → Hydra пропагирует как invalid_grant.
//  3. Требует jti; пустой jti → 403 invalid_grant (revocation-gate не skippable).
//  4. Проверяет session_revocations cache — если jti revoked → reject.
//  5. Re-injects ext_claims (same as token_hook).
//  6. Audit emit `authn.refresh.issued` (либо `authn.refresh.denied`).
package iamhooks

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// RefreshHookConfig — runtime config.
type RefreshHookConfig struct {
	HookSharedSecret string
	Domain           string
	HydraIssuer      string
}

// RefreshHookHandler — HTTP handler.
type RefreshHookHandler struct {
	cfg         RefreshHookConfig
	users       UserLookupPort
	revocations SessionRevocationsWriter
	audit       AuditEmitter
	logger      *slog.Logger
	now         func() time.Time
}

// NewRefreshHookHandler — constructor.
func NewRefreshHookHandler(
	cfg RefreshHookConfig,
	users UserLookupPort,
	revocations SessionRevocationsWriter,
	audit AuditEmitter,
	logger *slog.Logger,
) *RefreshHookHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &RefreshHookHandler{
		cfg:         cfg,
		users:       users,
		revocations: revocations,
		audit:       audit,
		logger:      logger,
		now:         time.Now,
	}
}

// hydraRefreshHookRequest — payload от Hydra.
type hydraRefreshHookRequest struct {
	Subject string `json:"subject"`
	Session struct {
		ClientID string `json:"client_id"`
		ACR      string `json:"acr"`
		// AuthTime — session authentication time (unix seconds). Carried by the
		// Hydra session envelope (same field the token_hook reads). The
		// user-level revoke-all gate compares this against the per-user
		// revoke_before cutoff: a session that authenticated at-or-before the
		// cutoff is denied; a re-auth past the cutoff is allowed.
		AuthTime int64 `json:"auth_time"`
		Cnf      struct {
			Jkt     string `json:"jkt"`
			X5tS256 string `json:"x5t#S256"`
		} `json:"cnf"`
	} `json:"session"`
	Request struct {
		ClientID        string   `json:"client_id"`
		GrantedScopes   []string `json:"granted_scopes"`
		GrantedAudience []string `json:"granted_audience"`
	} `json:"request"`
	AccessTokenClaims struct {
		Jti string `json:"jti"`
	} `json:"access_token_claims"`
}

// hydraRefreshHookResponse — успешный ответ.
type hydraRefreshHookResponse struct {
	Session struct {
		AccessToken map[string]any `json:"access_token"`
	} `json:"session"`
}

// ServeHTTP реализует http.Handler.
func (h *RefreshHookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if !requireHookAuth(w, r, h.cfg.HookSharedSecret) {
		return
	}

	var payload hydraRefreshHookRequest
	if !decodeHookBody(w, r, &payload, h.logger, "refresh_hook") {
		return
	}
	defer func() { _ = r.Body.Close() }()

	if payload.Subject == "" {
		http.Error(w, `{"error":"missing_subject"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// 1. Lookup user; reject if blocked.
	users, err := h.users.FindActiveByExternalID(ctx, domain.ExternalSubject(payload.Subject))
	if err != nil {
		h.logger.Error("refresh_hook: user lookup failed", "subject", payload.Subject, "err", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	if len(users) == 0 {
		h.denyAndAudit(ctx, payload, "user_not_found")
		http.Error(w, `{"error":"user_disabled"}`, http.StatusForbidden)
		return
	}
	primary := users[0]
	if primary.InviteStatus == domain.InviteStatusBlocked {
		h.denyAndAudit(ctx, payload, "user_blocked")
		http.Error(w, `{"error":"user_disabled"}`, http.StatusForbidden)
		return
	}

	// 2. Require a jti on the refresh path. The per-jti revocation gate (step 3)
	// keys on access_token_claims.jti; an empty jti previously SKIPPED that gate
	// entirely (fail-OPEN) — a token minted/refreshed without a jti would never
	// be subject to revocation. Treat a missing jti as unverifiable and deny
	// (fail-closed), the same 403 invalid_grant shape used for a revoked jti.
	if h.revocations != nil && payload.AccessTokenClaims.Jti == "" {
		h.denyAndAudit(ctx, payload, "missing_jti")
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusForbidden)
		return
	}

	// 3. Check session_revocations cache. This is an authoritative revocation
	// gate, so it MUST fail-closed: a lookup error means we cannot prove the
	// jti is NOT revoked, so we deny (never fall through and mint a refreshed
	// token). Both a revoked jti and a check error reject with 403 invalid_grant.
	if h.revocations != nil {
		revoked, err := h.revocations.IsRevoked(ctx, payload.AccessTokenClaims.Jti)
		if err != nil {
			h.logger.Error("refresh_hook: revocation check failed — failing closed",
				"subject", payload.Subject, "jti", payload.AccessTokenClaims.Jti, "err", err)
			h.denyAndAudit(ctx, payload, "revocation_check_failed")
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusForbidden)
			return
		}
		if revoked {
			h.denyAndAudit(ctx, payload, "jti_revoked")
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusForbidden)
			return
		}
	}

	// 4. User-level revoke-all gate (admin ForceLogout / Revoke(revoke_all)).
	// Deny if ANY of the identity's user-rows has a revoke_before cutoff at-or-
	// after the session auth_time: the token's session predates the revoke-all,
	// so it must not be refreshed. Same fail-closed discipline as the jti gate:
	// a lookup error denies. If auth_time is absent (0) but a cutoff exists, we
	// cannot prove the token post-dates the revoke-all → fail-safe deny (never a
	// silent allow).
	if h.revocations != nil {
		if denied, reason, derr := h.userLevelRevoked(ctx, users, payload.Session.AuthTime); derr != nil {
			h.logger.Error("refresh_hook: user-level revocation check failed — failing closed",
				"subject", payload.Subject, "err", derr)
			h.denyAndAudit(ctx, payload, "revocation_check_failed")
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusForbidden)
			return
		} else if denied {
			h.denyAndAudit(ctx, payload, reason)
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusForbidden)
			return
		}
	}

	// 5. Re-inject ext_claims.
	claims, err := h.refreshClaims(primary, &payload)
	if err != nil {
		if errors.Is(err, iamerr.ErrNotFound) {
			http.Error(w, `{"error":"user_disabled"}`, http.StatusForbidden)
			return
		}
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	resp := hydraRefreshHookResponse{}
	resp.Session.AccessToken = map[string]any{
		"ext_claims": claims,
	}

	// 6. Audit emit success. Log-and-continue on failure (mirrors
	// token_hook.authn.token.issued): a failing/backpressured audit sink must
	// not be invisible — swallowing the error silently drops the authn audit
	// record with zero operator signal (OWASP A09 / CWE-778).
	if h.audit != nil {
		if emitErr := h.audit.Emit(ctx, AuditEvent{
			EventType:       "authn.refresh.issued",
			TenantAccountID: string(primary.AccountID),
			Payload: map[string]any{
				"subject":   payload.Subject,
				"user_id":   string(primary.ID),
				"client_id": payload.Request.ClientID,
				"jti":       payload.AccessTokenClaims.Jti,
				"jkt":       payload.Session.Cnf.Jkt,
				"x5t_s256":  payload.Session.Cnf.X5tS256,
			},
		}); emitErr != nil {
			h.logger.Warn("refresh_hook: audit emit failed",
				"event_type", "authn.refresh.issued", "err", emitErr)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Warn("refresh_hook: encode response failed", "err", err)
	}
}

// userLevelRevoked reports whether the token must be denied by a per-user
// revoke-all cutoff. It checks every user-row of the identity (robust across
// multi-account membership) and returns (denied, auditReason, err).
//
//   - A token is denied when a cutoff exists with revoke_before >= the session
//     auth_time (the session was established at-or-before the revoke-all).
//   - auth_time == 0 (absent) + an existing cutoff → fail-safe deny: we cannot
//     prove the token post-dates the revoke-all.
//   - Any lookup error is returned so the caller fails closed.
func (h *RefreshHookHandler) userLevelRevoked(ctx context.Context, users []domain.User, authTimeUnix int64) (bool, string, error) {
	var authTime time.Time
	if authTimeUnix > 0 {
		authTime = time.Unix(authTimeUnix, 0).UTC()
	}
	for _, u := range users {
		cutoff, found, err := h.revocations.UserRevokedBefore(ctx, string(u.ID))
		if err != nil {
			return false, "", err
		}
		if !found {
			continue
		}
		// No auth_time to compare → cannot prove the token post-dates the
		// revoke-all → deny (fail-safe), never a silent allow.
		if authTime.IsZero() {
			return true, "user_revoked", nil
		}
		// Session authenticated at-or-before the cutoff → deny.
		if !authTime.After(cutoff) {
			return true, "user_revoked", nil
		}
	}
	return false, "", nil
}

// refreshClaims builds the enriched ID/access-token claim set from the resolved
// user + the Hydra refresh payload. It performs no context-propagated work
// (groups enrichment is not yet wired), so it takes no ctx — a caller that later
// adds a DB/FGA lookup here must re-introduce ctx and thread it to that call.
func (h *RefreshHookHandler) refreshClaims(u domain.User, p *hydraRefreshHookRequest) (map[string]any, error) {
	claims := map[string]any{
		"kacho_external_id":       string(u.ExternalID),
		"kacho_user_id":           string(u.ID),
		"kacho_active_account":    string(u.AccountID),
		"kacho_groups":            []string{},
		"kacho_principal_type":    "user",
		"kacho_device_compliance": "unknown",
		"kacho_jkt":               p.Session.Cnf.Jkt,
		"kacho_x5t_s256":          p.Session.Cnf.X5tS256,
		"kacho_acr":               p.Session.ACR,
		"kacho_audience":          h.cfg.Domain,
		"kacho_issuer":            h.cfg.HydraIssuer,
		"kacho_issued_at":         h.now().Unix(),
	}
	for _, sc := range p.Request.GrantedScopes {
		if sc == "webauthn" || sc == "passkey" {
			claims["kacho_device_compliance"] = "attested"
			break
		}
	}
	return claims, nil
}

func (h *RefreshHookHandler) denyAndAudit(ctx context.Context, p hydraRefreshHookRequest, reason string) {
	if h.audit == nil {
		return
	}
	// Log-and-continue on emit failure: a dropped "authn.refresh.denied" record
	// must be observable (OWASP A09 / CWE-778), not silently swallowed.
	if emitErr := h.audit.Emit(ctx, AuditEvent{
		EventType: "authn.refresh.denied",
		Payload: map[string]any{
			"subject":   p.Subject,
			"reason":    reason,
			"client_id": p.Request.ClientID,
			"jti":       p.AccessTokenClaims.Jti,
		},
	}); emitErr != nil {
		h.logger.Warn("refresh_hook: audit emit failed",
			"event_type", "authn.refresh.denied", "err", emitErr)
	}
}
