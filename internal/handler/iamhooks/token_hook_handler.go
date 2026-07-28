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

// OAuth2 grants in which the credential presented IS the client registration —
// there is no end user in the exchange (RFC 6749 §4.4, RFC 7523 §2.1).
const (
	grantTypeClientCredentials = "client_credentials"
	grantTypeJWTBearer         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// hydraTokenHookRequest — payload от Hydra (subset per Hydra v2 hook contract).
//
// The body of THIS hook is `{session, request}` — it has no top-level subject.
// The identity of the human the exchange is for lives inside the token-shaped
// part of the session (`session.id_token.subject`), which is why it is read
// from there and from nowhere else: a field with no producer is silently empty
// forever, and here that emptiness reads as "no end user", which is the very
// question the machine-credential refusal turns on. The sibling refresh hook
// DOES carry a top-level subject — a different body, decoded by its own type.
type hydraTokenHookRequest struct {
	Session struct {
		ClientID string `json:"client_id"`
		AuthTime int64  `json:"auth_time"`
		AMR      []any  `json:"amr"`
		ACR      string `json:"acr"`
		IDToken  struct {
			Subject string `json:"subject"`
		} `json:"id_token"`
		Cnf struct {
			Jkt     string `json:"jkt"`
			X5tS256 string `json:"x5t#S256"`
		} `json:"cnf"`
		Extra map[string]any `json:"extra"`
	} `json:"session"`
	Request struct {
		ClientID        string   `json:"client_id"`
		GrantedScopes   []string `json:"granted_scopes"`
		GrantedAudience []string `json:"granted_audience"`
		// GrantTypes — the grants the exchange ran under, stated by the provider
		// from the request it executed. See grantType.
		GrantTypes []string            `json:"grant_types"`
		Payload    map[string][]string `json:"payload"`
	} `json:"request"`
}

// grantType names the grant this exchange ran under.
//
// The provider states it twice and the two are not equally trustworthy. The
// authoritative statement is the request's own grant list, filled from the
// grant the provider actually executed. The other is the client's submitted
// form, which reaches us only for as long as the provider chooses to forward
// that parameter — the set it forwards is its decision, it sanitises the form
// before sending, and the day that set narrows the form copy becomes silently
// empty. Reading the authoritative field first is what keeps this signal alive
// through such a change; the form stays as a fallback because it is populated
// today and costs nothing.
//
// Load-bearing: this is the ONLY signal that identifies the federated machine
// grant (see isMachineCredentialRequest), so an empty answer there is not a
// missing hint but a missing refusal.
func (p hydraTokenHookRequest) grantType() string {
	for _, gt := range p.Request.GrantTypes {
		if gt != "" {
			return gt
		}
	}
	return firstFormValue(p.Request.Payload, "grant_type")
}

// isMachineCredentialRequest reports whether this token request has no human
// behind it — the credential being presented is the OAuth client itself.
//
// It reads three independent signals because no single one is guaranteed to be
// present, and each covers the others' blind spot:
//
//  1. the grant NAMES a machine flow. The primary signal, and the only one that
//     catches jwt-bearer (whose subject is the external assertion's `sub`, so it
//     resembles an end-user subject);
//  2. the payload carried NO end-user subject at all, so `subject` above had to
//     be recovered from the client id. Reaching that fallback is itself proof
//     there is no human;
//  3. the subject IS the client id. This is the shape Hydra sends for
//     client_credentials, and it holds even when the form payload — which the
//     provider is under no obligation to forward — reaches us without a
//     grant_type. An end-user identity is never equal to a client registration
//     id, so this cannot capture an interactive request.
//
// Deliberately a question about the REQUEST, not about the outcome of any
// lookup: the answer must not change with the state of the mapping stores.
func (p hydraTokenHookRequest) isMachineCredentialRequest(subject, endUserSubject, grantType string) bool {
	if grantType == grantTypeClientCredentials || grantType == grantTypeJWTBearer {
		return true
	}
	if endUserSubject == "" {
		return true
	}
	if p.Session.ClientID != "" && subject == p.Session.ClientID {
		return true
	}
	return p.Request.ClientID != "" && subject == p.Request.ClientID
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

	// endUserSubject — the identity of the human this token is for, as the
	// provider stated it. Empty means the request has no end user at all.
	endUserSubject := payload.Session.IDToken.Subject
	subject := endUserSubject
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
	grantType := payload.grantType()
	assertionIssuer := ""
	if grantType == grantTypeJWTBearer {
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
		// The credential behind this request is past its stated expiry. Deny —
		// 403 is the only status Hydra reads as "refuse this token request"
		// (any other non-2xx becomes a server error), the same lever the
		// refresh hook pulls for a revoked session. The body is the diagnostic
		// Hydra surfaces to operators; `invalid_client` per RFC 6749 §5.2,
		// because what failed is client authentication, not the grant.
		//
		// Checked BEFORE the not-found branch on purpose: for an INTERACTIVE
		// request that branch still falls back to MinimalClaims and mints, so an
		// expired credential must never be able to arrive there.
		if errors.Is(err, service.ErrCredentialExpired) {
			h.denyExpired(ctx, subject, payload)
			http.Error(w, `{"error":"invalid_client"}`, http.StatusForbidden)
			return
		}
		if errors.Is(err, iamerr.ErrNotFound) {
			// Nothing in kacho answers to this subject. What that means — and
			// therefore what we owe the caller — depends entirely on whether a
			// human is behind the request.
			//
			// MACHINE request: the credential presented IS the OAuth client, and
			// every client kacho recognises was registered by this service
			// together with its mapping row (SA key, personal token, bootstrap,
			// federated subject). No row therefore means "not a kacho
			// credential", and there is no principal to mint for. Refusing here
			// is also what makes key revocation take effect at commit: revoke
			// deletes the row first and asks the provider to delete the client
			// second, so a client that outlives that second step arrives here and
			// is turned away — with no dependence on the provider being reachable.
			//
			// INTERACTIVE request: a human authenticated at the identity
			// provider and their kacho mirror is provisioned ASYNCHRONOUSLY (the
			// provision hook returns once the Operation is accepted; the User row
			// commits after). Their first token can legitimately be requested
			// before that row exists, so it is minted with the reduced claim set
			// and the mirror catches up. Refusing them would break first login.
			if payload.isMachineCredentialRequest(subject, endUserSubject, grantType) {
				h.denyUnmappedClient(ctx, subject, payload)
				http.Error(w, `{"error":"invalid_client"}`, http.StatusForbidden)
				return
			}
			h.logger.Info("token_hook: identity has no kacho mirror yet; emitting minimal claims",
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

// denyExpired records the refusal of a credential past its stated expiry.
func (h *TokenHookHandler) denyExpired(ctx context.Context, subject string, payload hydraTokenHookRequest) {
	h.logger.WarnContext(ctx, "token_hook: credential expired — token request denied",
		"subject", subject, "client_id", payload.Request.ClientID)
	h.auditDenied(ctx, subject, payload, "credential_expired")
}

// denyUnmappedClient records the refusal of a machine credential that resolves
// to no kacho principal — its client is not a kacho credential, so there is no
// principal to mint for.
//
// This record is also the standing signal for a provider-side registration that
// outlived its kacho row (a revoke whose provider-delete failed): it can no
// longer mint, and every attempt it makes says so by name.
func (h *TokenHookHandler) denyUnmappedClient(ctx context.Context, subject string, payload hydraTokenHookRequest) {
	h.logger.WarnContext(ctx, "token_hook: oauth client resolves to no kacho principal — token request denied",
		"subject", subject, "client_id", payload.Request.ClientID)
	h.auditDenied(ctx, subject, payload, "principal_not_found")
}

// auditDenied writes the refusal to the durable trail. The reason distinguishes
// WHY the credential was turned away — an expired key and one that resolves to
// nothing call for different operator responses. Log-and-continue on an emit
// failure, mirroring the issued-trail: a dropped authn record must be visible
// (OWASP A09 / CWE-778), never silently swallowed. No key material or PII is
// carried — the client_id and subject correlate the event.
func (h *TokenHookHandler) auditDenied(ctx context.Context, subject string, payload hydraTokenHookRequest, reason string) {
	if h.audit == nil {
		return
	}
	if emitErr := h.audit.Emit(ctx, AuditEvent{
		EventType: "authn.token.denied",
		Payload: map[string]any{
			"subject":   subject,
			"reason":    reason,
			"client_id": payload.Request.ClientID,
		},
	}); emitErr != nil {
		h.logger.Warn("token_hook: audit emit failed",
			"event_type", "authn.token.denied", "err", emitErr)
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
