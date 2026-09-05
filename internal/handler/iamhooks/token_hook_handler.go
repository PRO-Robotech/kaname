// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"time"

	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
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
	EnrichClaims(ctx context.Context, subject string, hookCtx service.TokenHookContext) (map[string]any, service.ResolvedPrincipal, error)
	MinimalClaims(subject string) map[string]any
}

// TokenHookHandler — HTTP handler.
type TokenHookHandler struct {
	cfg         TokenHookConfig
	enricher    TokenEnricher
	revocations UserRevocationLookup
	audit       AuditEmitter
	logger      *slog.Logger
}

// NewTokenHookHandler — constructor.
//
// revocations is what makes "log this person out of everything" mean anything
// at the moment a token is MINTED. Without it the cutoff had three writers and
// one reader, on the path taken only when an EXISTING token is refreshed — so
// an administrator's force-logout returned success while the subject's live
// session kept obtaining fresh tokens on demand, and a personal access token,
// whose grant has no refresh hook at all, was never re-examined even once.
//
// A nil reader is accepted so an in-process fixture can wire the hook without a
// revocation store; the composition root has no branch that leaves it out.
func NewTokenHookHandler(
	cfg TokenHookConfig,
	enricher TokenEnricher,
	revocations UserRevocationLookup,
	audit AuditEmitter,
	logger *slog.Logger,
) *TokenHookHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &TokenHookHandler{
		cfg:         cfg,
		enricher:    enricher,
		revocations: revocations,
		audit:       audit,
		logger:      logger,
	}
}

// OAuth2 grants in which the credential presented IS the client registration —
// there is no end user in the exchange (RFC 6749 §4.4, RFC 7523 §2.1).
const (
	grantTypeClientCredentials = "client_credentials"
	// #nosec G101 -- это идентификатор типа гранта из RFC 7523 §2.1, а не секрет: значение
	// фиксировано стандартом и обязано совпадать байт-в-байт с тем, что присылает провайдер.
	// Правило срабатывает на подстроку "bearer" в имени константы.
	grantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
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
//
// The session's authentication time, assurance level and methods sit DEEPER
// still — among the OIDC claims of that same token-shaped part, at
// `session.id_token.id_token_claims` — and `auth_time` is an RFC3339 STRING
// there, not a unix integer. They used to be declared at the top of the session
// and typed as a number, which has no producer at all: both readings were empty
// on every real request, so the assurance claims derived from them were blank
// forever and the session's authentication instant — the thing a revoke-all
// cutoff is weighed against — was permanently zero.
//
// This placement is not inferred from the provider's types. It is taken from
// captured bodies of the provider at the version this stand runs; see
// testdata/README.md, which also records how to re-take them.
type hydraTokenHookRequest struct {
	Session struct {
		ClientID string `json:"client_id"`
		IDToken  struct {
			Subject string `json:"subject"`
			// Claims — the session's OIDC claim set. The provider sends the zero
			// instant ("0001-01-01T00:00:00Z") for a session it never
			// authenticated, so "absent" and "never authenticated" are the same
			// observation here and every reader below treats them alike.
			Claims struct {
				AuthTime time.Time `json:"auth_time"`
				ACR      string    `json:"acr"`
				AMR      []any     `json:"amr"`
			} `json:"id_token_claims"`
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
// It reads three signals because no single one is guaranteed to be present.
// They do NOT all cover each other:
//
//  1. the grant NAMES a machine flow. The primary signal, and for jwt-bearer the
//     ONLY one — that grant's subject is the external assertion's `sub`, so it
//     is neither absent (2) nor equal to a client id (3), and neither can fire.
//     Lose this reading and a federated assertion belonging to nobody we trust
//     is indistinguishable from an interactive first login. See grantType for
//     why it is taken from the provider's own field rather than the client's
//     submitted form;
//  2. the request carried NO end-user subject at all, so `subject` above had to
//     be recovered from the client id. Reaching that fallback is itself proof
//     there is no human;
//  3. the subject IS the client id. This is the shape Hydra sends for
//     client_credentials, so for THAT grant it is a second reading independent
//     of the grant name. An end-user identity is never equal to a client
//     registration id, so this cannot capture an interactive request.
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
	if !requireHookAuth(w, r, h.cfg.HookSharedSecret, h.logger, "token_hook") {
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
	sessionAuthTime := payload.Session.IDToken.Claims.AuthTime
	hookCtx := service.TokenHookContext{
		GrantedScopes:  payload.Request.GrantedScopes,
		AuthTime:       unixOrZero(sessionAuthTime),
		ACR:            payload.Session.IDToken.Claims.ACR,
		CnfJkt:         payload.Session.Cnf.Jkt,
		CnfX5tS256:     payload.Session.Cnf.X5tS256,
		OAuthClientID:  payload.Request.ClientID,
		GrantType:      grantType,
		ExternalIssuer: assertionIssuer,
	}
	enriched, principal, err := h.enricher.EnrichClaims(ctx, subject, hookCtx)
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
		// The subject is a kacho user whose state forbids authentication.
		//
		// Checked BEFORE the not-found branch, and for a sharper reason than the
		// expiry above: this refusal used to BE that branch. The user resolution
		// filtered on ACTIVE, so a blocked user came back empty, was taken for an
		// identity whose mirror had not committed yet, and was issued the reduced
		// claim set — a 200. Same diagnostic as the refresh hook returns for the
		// same state: one subject state, one answer, whichever hook is asked.
		if errors.Is(err, service.ErrSubjectNotActive) {
			h.denyNotActive(ctx, subject, payload)
			http.Error(w, `{"error":"user_disabled"}`, http.StatusForbidden)
			return
		}
		// The subject is a kacho SERVICE ACCOUNT whose state forbids
		// authentication. Same refusal, different words on purpose: what failed
		// is client authentication (`invalid_client`, RFC 6749 §5.2, as for an
		// expired key on this same path), and the subject is not a person — so
		// the human's diagnostic would send an operator searching the wrong
		// table for a subject that is not in it.
		//
		// Also checked BEFORE the not-found branch, for the reason that branch
		// documents: it still mints for an interactive identity whose mirror has
		// not committed, and a refusal that reached it would be answered with a
		// token.
		if errors.Is(err, service.ErrServiceAccountDisabled) {
			h.denyServiceAccountDisabled(ctx, subject, payload)
			http.Error(w, `{"error":"invalid_client"}`, http.StatusForbidden)
			return
		}
		if errors.Is(err, iamerr.ErrNotFound) {
			// Nothing in kacho answers to this subject. What that means — and
			// therefore what we owe the caller — depends entirely on whether a
			// human is behind the request.
			//
			// MACHINE request: the credential presented IS the OAuth client, and
			// the mapping row is what makes a client a kacho credential — it is
			// the authority every issuance is checked against (SA key, personal
			// token, bootstrap, federated subject). No row therefore means "not a
			// kacho credential", and there is no principal to mint for. Note the
			// registration and its row are NOT written atomically — the provider
			// call is a separate, earlier step — so a registration without a row
			// is a state that genuinely occurs; that is precisely the case this
			// branch answers, rather than one it assumes away. Refusing here
			// is also what stops a revoked key from obtaining anything further at
			// commit: revoke deletes the row first and asks the provider to delete
			// the client second, so a client that outlives that second step
			// arrives here and is turned away — with no dependence on the provider
			// being reachable. Tokens ALREADY minted are self-contained and are
			// not reached from here; they lapse with their own lifetime.
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

	// The subject may have been logged out of everything since they last
	// authenticated. That is a question about the SAME row the enricher just
	// read, asked with the identifier this service keys it on — which is why it
	// is asked here, with the resolved principal, rather than from the
	// provider's subject (an external identity or a client registration,
	// neither of which the cutoff is keyed on).
	//
	// Asked at ISSUANCE, which is the point. The cutoff had three writers and
	// one reader, on the path taken only when an existing token is refreshed.
	if denied, reason := h.revokedAtIssuance(ctx, principal, sessionAuthTime); denied {
		h.denyRevoked(ctx, subject, payload, reason)
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusForbidden)
		return
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
				"acr":              payload.Session.IDToken.Claims.ACR,
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

// denyNotActive records the refusal of a subject whose state forbids
// authentication. Mirrors the refresh hook's own deny trail so the two hooks
// leave one recognisable account of the same verdict.
func (h *TokenHookHandler) denyNotActive(ctx context.Context, subject string, payload hydraTokenHookRequest) {
	h.logger.WarnContext(ctx, "token_hook: subject not active — token request denied",
		"subject", subject, "client_id", payload.Request.ClientID)
	h.auditDenied(ctx, subject, payload, "user_blocked")
}

// denyServiceAccountDisabled records the refusal of a service account whose
// state forbids authentication. The reason is its own, not the user one: an
// operator responds to a disabled service account by looking at that account,
// and calling it a blocked user would send them to a table it is not in.
func (h *TokenHookHandler) denyServiceAccountDisabled(ctx context.Context, subject string, payload hydraTokenHookRequest) {
	h.logger.WarnContext(ctx, "token_hook: service account disabled — token request denied",
		"subject", subject, "client_id", payload.Request.ClientID)
	h.auditDenied(ctx, subject, payload, "service_account_disabled")
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
// The record is where a provider-side registration that outlived its kacho row
// (a revoke whose provider-delete failed) becomes visible: it can no longer
// mint, and every attempt it makes is written down. The reason is the shared
// one for the whole class, so it does NOT single that case out — a client this
// service never registered is recorded identically. Telling the two apart is
// the operator's job and needs the client id against the mapping store; what
// this record affords on its own is noticing that some registration is trying.
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

// unixOrZero converts an instant to unix seconds, keeping the zero instant a
// zero. The service-layer context carries this as a number and reads 0 as "not
// stated", so the zero instant must not arrive there as 62135596800.
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// revokedAtIssuance reports whether a revoke-all cutoff forbids minting for this
// principal, and the reason to record.
//
// What the cutoff is weighed against depends on what the exchange presented,
// and the three cases are genuinely different questions:
//
//   - a MACHINE credential (service account) is not a person's session. A user
//     logged out of everything says nothing about a service account that merely
//     shares an account with them, and treating it as if it did would take
//     machine credentials offline as a side effect of an unrelated
//     administrative act. Its own lifetime bounds it, enforced on its own path;
//   - an INTERACTIVE session states when it authenticated. At or before the
//     cutoff is exactly what the cutoff names; after it is the subject proving
//     themselves again, which is what stops a force-logout from being a
//     permanent lockout;
//   - a STANDING personal credential has no session and never re-authenticates,
//     so its anchor is when it was minted. This is the case with no other point
//     of enforcement anywhere: its grant has no refresh hook, so a token minted
//     through it is never re-examined after issuance.
//
// Two unknowns are refusals, not permissions. A cutoff with no instant to weigh
// against cannot be shown to be satisfied, and an unavailable revocation store
// is not an answer of "no" — this is an authoritative gate and fails closed,
// the same discipline the refresh path states for the same read.
func (h *TokenHookHandler) revokedAtIssuance(ctx context.Context, p service.ResolvedPrincipal, sessionAuthTime time.Time) (bool, string) {
	if h.revocations == nil || p.Kind != service.PrincipalUser || p.UserID == "" {
		return false, ""
	}
	cutoff, found, err := h.revocations.UserRevokedBefore(ctx, p.UserID)
	if err != nil {
		h.logger.ErrorContext(ctx, "token_hook: revoke-all lookup failed — failing closed",
			"user_id", p.UserID, "err", err)
		return true, "revocation_check_failed"
	}
	if !found {
		return false, ""
	}
	anchor := issuanceAnchor(p, sessionAuthTime)
	if anchor.IsZero() || !anchor.After(cutoff) {
		return true, "user_revoked"
	}
	return false, ""
}

// issuanceAnchor returns the instant this exchange's authority dates from: the
// standing credential's issuance when there is one, otherwise the session's own
// authentication instant. A zero result means the exchange stated neither.
func issuanceAnchor(p service.ResolvedPrincipal, sessionAuthTime time.Time) time.Time {
	if p.StandingCredentialIssuedAt != nil {
		return *p.StandingCredentialIssuedAt
	}
	return sessionAuthTime
}

// denyRevoked records the refusal of a subject logged out of everything.
// `invalid_grant`, not `invalid_client`: what is no longer good is the authority
// behind the request, not the client's authentication — and it is the word the
// refresh path answers for the same state, so one question asked at two doors
// cannot come back as two different verdicts.
func (h *TokenHookHandler) denyRevoked(ctx context.Context, subject string, payload hydraTokenHookRequest, reason string) {
	h.logger.WarnContext(ctx, "token_hook: subject revoked — token request denied",
		"subject", subject, "client_id", payload.Request.ClientID, "reason", reason)
	h.auditDenied(ctx, subject, payload, reason)
}
