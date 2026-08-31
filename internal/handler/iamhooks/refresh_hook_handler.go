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
//  2. Читает строки субъекта КАК ЕСТЬ и выносит вердикт по состоянию
//     (domain.InviteStatus.MayAuthenticate): ни одной строки → 403
//     user_disabled с причиной user_not_found; строки есть, но ни одна не
//     вправе аутентифицироваться → 403 user_disabled с причиной user_blocked.
//     Hydra пропагирует оба как invalid_grant. Тот же вердикт применяет
//     token-hook, поэтому разойтись они больше не могут.
//  3. Применяет user-level revoke-all cutoff (ForceLogout / Revoke(revoke_all) /
//     восстановление пароля), сверяя его с моментом аутентификации сессии.
//  4. Re-injects ext_claims (same as token_hook).
//  5. Audit emit `authn.refresh.issued` (либо `authn.refresh.denied`).
//
// Пер-jti гейта здесь НЕТ, и это не упущение: тело этого хука вообще не несёт
// claims предъявленного токена (см. testdata/README.md), поэтому гейт,
// ключевавшийся на jti, ни разу не выполнился по существу — он отклонял
// КАЖДОЕ обновление за отсутствием поля, у которого нет источника, и делал
// недостижимым всё, что стояло за ним. Отзыв конкретного токена проверяется
// там, где предъявленный токен есть: на краю, интроспекцией, плюс
// `InternalSessionRevocationsService.IsRevoked`.
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
	revocations UserRevocationLookup
	audit       AuditEmitter
	logger      *slog.Logger
	now         func() time.Time
}

// NewRefreshHookHandler — constructor.
func NewRefreshHookHandler(
	cfg RefreshHookConfig,
	users UserLookupPort,
	revocations UserRevocationLookup,
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
//
// This is NOT the token hook's body, and the two differ in every place this
// type used to assume they matched. Taken from a captured refresh of the
// provider at the version this stand runs (testdata/README.md):
//
//   - the subject IS top-level here (the token hook has none);
//   - the session's authentication instant and assurance level sit at
//     `session.id_token.id_token_claims`, as an RFC3339 string — not at the top
//     of the session and not as a number;
//   - the exchange is described by `requester`, plus a top-level `client_id` /
//     `granted_scopes` / `granted_audience`. There is no `request` object, so
//     reading one left a blank client id in every audit record this hook wrote
//     and no granted scopes for the device-compliance derivation;
//   - there is NO token-claims object of any kind. `access_token_claims` does
//     not occur anywhere in the provider binary.
type hydraRefreshHookRequest struct {
	Subject string `json:"subject"`
	Session struct {
		ClientID string `json:"client_id"`
		IDToken  struct {
			// Claims — the session's OIDC claim set. AuthTime is what the
			// revoke-all gate weighs the cutoff against: a session that
			// authenticated at or before the cutoff is denied; one that
			// authenticated after it is a re-authentication and is allowed.
			Claims struct {
				AuthTime time.Time `json:"auth_time"`
				ACR      string    `json:"acr"`
			} `json:"id_token_claims"`
		} `json:"id_token"`
		Cnf struct {
			Jkt     string `json:"jkt"`
			X5tS256 string `json:"x5t#S256"`
		} `json:"cnf"`
	} `json:"session"`
	// Requester — the exchange, as this hook's body names it.
	Requester struct {
		ClientID        string   `json:"client_id"`
		GrantedScopes   []string `json:"granted_scopes"`
		GrantedAudience []string `json:"granted_audience"`
	} `json:"requester"`
	// The same three are ALSO stated top-level. Both are read, `requester`
	// first: the provider fills both today and names neither as authoritative,
	// so a reader that picks only one is one release away from being blank
	// again — which is the defect this type is being corrected for.
	ClientID      string   `json:"client_id"`
	GrantedScopes []string `json:"granted_scopes"`
}

// clientID — the OAuth client this refresh ran for.
func (p hydraRefreshHookRequest) clientID() string {
	if p.Requester.ClientID != "" {
		return p.Requester.ClientID
	}
	return p.ClientID
}

// grantedScopes — the scopes granted to the refreshed token.
func (p hydraRefreshHookRequest) grantedScopes() []string {
	if len(p.Requester.GrantedScopes) > 0 {
		return p.Requester.GrantedScopes
	}
	return p.GrantedScopes
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
	if !requireHookAuth(w, r, h.cfg.HookSharedSecret, h.logger, "refresh_hook") {
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

	// 1. Look the subject up AS IT IS, then judge its state.
	//
	// This used to resolve through the ACTIVE-only query, which meant a blocked
	// user arrived here as an EMPTY result and was refused as "not found". The
	// refusal was right; the recorded reason was not — it named a state the row
	// does not have — and the blocked branch below was unreachable code that
	// only a fake could enter. The issuance hook read the very same emptiness as
	// "the mirror has not committed yet" and issued. One state, one verdict.
	users, err := h.users.FindByExternalID(ctx, domain.ExternalSubject(payload.Subject))
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
	// A membership set may mix states across accounts; the first row that may
	// authenticate is the default active account. None means the subject exists
	// and is refused — a different verdict from absent, and audited as such.
	var primary domain.User
	var found bool
	for _, u := range users {
		if u.InviteStatus.MayAuthenticate() {
			primary, found = u, true
			break
		}
	}
	if !found {
		h.denyAndAudit(ctx, payload, "user_blocked")
		http.Error(w, `{"error":"user_disabled"}`, http.StatusForbidden)
		return
	}

	// 2. User-level revoke-all gate (admin ForceLogout / Revoke(revoke_all) /
	// password recovery). Deny if ANY of the identity's user-rows has a cutoff at
	// or after the session's authentication instant: the token's session predates
	// the revoke-all, so it must not be refreshed. Fail-closed on a lookup error.
	// An absent instant with a cutoff present is also a denial — we cannot show
	// the token post-dates the revoke-all, and an unprovable claim is not a
	// permission.
	//
	// This is now THE gate on this path rather than the last of three: the per-jti
	// gate that used to precede it keyed on a field this body does not carry, so
	// it refused every refresh and this block was never reached.
	if h.revocations != nil {
		if denied, reason, derr := h.userLevelRevoked(ctx, users, payload.Session.IDToken.Claims.AuthTime); derr != nil {
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

	// 3. Re-inject ext_claims.
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

	// 4. Audit emit success. Log-and-continue on failure (mirrors
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
				"client_id": payload.clientID(),
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
//   - A token is denied when a cutoff exists at or after the session's
//     authentication instant (the session was established at-or-before the
//     revoke-all).
//   - An absent instant + an existing cutoff → fail-safe deny: we cannot prove
//     the token post-dates the revoke-all.
//   - Any lookup error is returned so the caller fails closed.
func (h *RefreshHookHandler) userLevelRevoked(ctx context.Context, users []domain.User, authTime time.Time) (bool, string, error) {
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
		"kacho_acr":               p.Session.IDToken.Claims.ACR,
		"kacho_audience":          h.cfg.Domain,
		"kacho_issuer":            h.cfg.HydraIssuer,
		"kacho_issued_at":         h.now().Unix(),
	}
	for _, sc := range p.grantedScopes() {
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
			"client_id": p.clientID(),
		},
	}); emitErr != nil {
		h.logger.Warn("refresh_hook: audit emit failed",
			"event_type", "authn.refresh.denied", "err", emitErr)
	}
}
