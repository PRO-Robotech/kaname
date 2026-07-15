// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// token_hook_handler.go — Hydra access_token webhook.
//
// POST /iam/v1/hooks/token
//
// Hydra (configured oauth2.token_hook.url) вызывает этот endpoint каждый раз
// перед выдачей access_token. Payload содержит session+request; ответ
// обогащает session.access_token.ext_claims с kacho-specific полями.
package iamhooks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// TokenHookConfig — runtime config для token hook.
type TokenHookConfig struct {
	HookSharedSecret string
	Domain           string
	HydraIssuer      string
}

// TokenEnricher — service-layer use-case the handler delegates claims
// assembly to. Clean Architecture: the handler stays a thin transport shim;
// claims assembly / device-compliance heuristics / mfa_at derivation live in
// the service layer. Implemented by *service.TokenEnrichmentService.
type TokenEnricher interface {
	EnrichClaims(ctx context.Context, subject string, hookCtx service.TokenHookContext) (map[string]any, error)
	MinimalClaims(subject string) map[string]any
}

// TokenHookHandler — HTTP handler.
type TokenHookHandler struct {
	cfg      TokenHookConfig
	enricher TokenEnricher
	audit    AuditEmitter
	logger   *slog.Logger
}

// NewTokenHookHandler — constructor.
func NewTokenHookHandler(
	cfg TokenHookConfig,
	enricher TokenEnricher,
	audit AuditEmitter,
	logger *slog.Logger,
) *TokenHookHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &TokenHookHandler{
		cfg:      cfg,
		enricher: enricher,
		audit:    audit,
		logger:   logger,
	}
}

// hydraTokenHookRequest — payload от Hydra (subset per Hydra v2 hook contract).
type hydraTokenHookRequest struct {
	Session struct {
		ClientID string `json:"client_id"`
		AuthTime int64  `json:"auth_time"`
		AMR      []any  `json:"amr"`
		ACR      string `json:"acr"`
		Subject  string `json:"subject"`
		Cnf      struct {
			Jkt     string `json:"jkt"`
			X5tS256 string `json:"x5t#S256"`
		} `json:"cnf"`
		Extra map[string]any `json:"extra"`
	} `json:"session"`
	Request struct {
		ClientID        string              `json:"client_id"`
		GrantedScopes   []string            `json:"granted_scopes"`
		GrantedAudience []string            `json:"granted_audience"`
		Payload         map[string][]string `json:"payload"`
		RequestedAt     string              `json:"requested_at"`
	} `json:"request"`
	Subject string `json:"subject"`
}

// hydraTokenHookResponse — Hydra ожидает session.access_token.ext_claims в
// результате (per https://www.ory.sh/docs/hydra/guides/claims-at-refresh).
type hydraTokenHookResponse struct {
	Session struct {
		AccessToken map[string]any `json:"access_token"`
		IDToken     map[string]any `json:"id_token,omitempty"`
	} `json:"session"`
}

// ServeHTTP реализует http.Handler.
func (h *TokenHookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if !requireHookAuth(w, r, h.cfg.HookSharedSecret) {
		return
	}

	var payload hydraTokenHookRequest
	if !decodeHookBody(w, r, &payload, h.logger, "token_hook") {
		return
	}
	defer func() { _ = r.Body.Close() }()

	subject := payload.Subject
	if subject == "" {
		subject = payload.Session.Subject
	}
	// client_credentials (RFC 6749 §4.4) не несёт end-user subject — Hydra
	// отдаёт его пустым. kacho-принципал такого токена — ServiceAccount за
	// OAuth2-клиентом, поэтому fallback на client_id (session, затем request);
	// enricher резолвит его в SA через LookupByOAuthClientID и штампует
	// kacho_principal_id = SA-id.
	if subject == "" {
		subject = payload.Session.ClientID
		if subject == "" {
			subject = payload.Request.ClientID
		}
	}
	if subject == "" {
		http.Error(w, `{"error":"missing_subject"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	grantType := firstFormValue(payload.Request.Payload, "grant_type")
	assertionIssuer := ""
	if grantType == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		assertionIssuer = decodeAssertionIssuer(firstFormValue(payload.Request.Payload, "assertion"))
	}
	hookCtx := service.TokenHookContext{
		GrantedScopes:  payload.Request.GrantedScopes,
		AuthTime:       payload.Session.AuthTime,
		ACR:            payload.Session.ACR,
		CnfJkt:         payload.Session.Cnf.Jkt,
		CnfX5tS256:     payload.Session.Cnf.X5tS256,
		OAuthClientID:  payload.Request.ClientID,
		GrantType:      grantType,
		ExternalIssuer: assertionIssuer,
	}
	enriched, err := h.enricher.EnrichClaims(ctx, subject, hookCtx)
	if err != nil {
		// User not found — это не fail; Hydra может вызывать для guest-token
		// (client_credentials flow); возвращаем minimum ext_claims.
		if errors.Is(err, iamerr.ErrNotFound) {
			h.logger.Info("token_hook: subject not found in users; emitting minimal claims",
				"subject", subject)
			enriched = h.enricher.MinimalClaims(subject)
		} else {
			h.logger.Error("token_hook: enrich failed", "subject", subject, "err", err)
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
	}

	resp := hydraTokenHookResponse{}
	resp.Session.AccessToken = map[string]any{
		"ext_claims": enriched,
	}
	if h.audit != nil {
		// Routine token-issued trail — log-and-continue (audit_outbox is the
		// durable record; the token is already minted at this point).
		if emitErr := h.audit.Emit(ctx, AuditEvent{
			EventType:       "authn.token.issued",
			TenantAccountID: getString(enriched, "kacho_active_account"),
			Payload: map[string]any{
				"subject":          subject,
				"client_id":        payload.Request.ClientID,
				"granted_scopes":   payload.Request.GrantedScopes,
				"granted_audience": payload.Request.GrantedAudience,
				"acr":              payload.Session.ACR,
				"jkt":              payload.Session.Cnf.Jkt,
				"x5t_s256":         payload.Session.Cnf.X5tS256,
			},
		}); emitErr != nil {
			h.logger.Warn("token_hook: audit emit failed",
				"event_type", "authn.token.issued", "err", emitErr)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Warn("token_hook: encode response failed", "err", err)
	}
}

func getString(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// firstFormValue returns the first occurrence of key in the Hydra-shaped
// form-payload map (`map[string][]string`), or "" when absent.
func firstFormValue(m map[string][]string, key string) string {
	if v, ok := m[key]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

// decodeAssertionIssuer extracts the `iss` claim from an unverified JWT
// assertion. Hydra has ALREADY validated the assertion's signature against
// the configured trusted-issuer JWKS by the time it calls the token-hook;
// kacho-iam only needs the issuer to disambiguate which external IdP this
// federated SA-token was minted for so the (iss, sub) lookup can target the
// right `trusted_subjects` row. Failure returns "" — caller falls through to
// the non-federated paths.
//
// We deliberately do NOT re-validate the signature here (Hydra already did;
// re-fetching JWKS in-process would be a needless dependency and an attack
// surface for SSRF on misconfigured issuer URLs).
func decodeAssertionIssuer(assertion string) string {
	if assertion == "" {
		return ""
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return ""
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some IdPs emit padded base64url; try the std variant.
		body, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(body, &claims); err != nil {
		return ""
	}
	return claims.Iss
}
