// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// token_enrichment_service.go — use-case: assemble kacho-specific ext_claims
// for an OAuth2 access_token.
//
// Clean Architecture requires the Hydra token-hook HTTP handler
// (handler/iamhooks/token_hook_handler.go) to stay a thin transport shim —
// claims assembly, device-compliance heuristics and mfa_at derivation are
// domain decisions and belong in the service layer.
package service

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// TokenEnrichmentUserPort — read-side dependency: resolve a User mirror by its
// external identity subject (Kratos `sub`).
type TokenEnrichmentUserPort interface {
	// FindActiveByExternalID returns all ACTIVE User rows for an identity
	// across every Account. The first row is the default active account.
	FindActiveByExternalID(ctx context.Context, externalID domain.ExternalSubject) ([]domain.User, error)
}

// TokenEnrichmentSAPort — read-side dependency: resolve a ServiceAccount and
// its OAuth-client mapping. Used for the Phase 3a SA-token path
// (`client_credentials` → Hydra mints a token whose `subject` is the Hydra
// client id; we map it back to the kacho SA and stamp principal_type/id/
// account_id claims) AND the Phase 3b federation-IN path (Hydra forwards an
// external OIDC assertion `(iss, sub)` plus its own `client_id`; we recover
// the SA mapping by matching `trusted_subjects[*].issuer` + regex on `sub`).
type TokenEnrichmentSAPort interface {
	// LookupByOAuthClientID resolves the kacho-iam SA + OAuth-client mapping
	// from a Hydra `client_id`. Returns iamerr.ErrNotFound when the client
	// id is unknown (e.g. legacy Hydra registration outside kacho-iam).
	LookupByOAuthClientID(ctx context.Context, hydraClientID domain.OAuthClientID) (domain.ServiceAccountOAuthClient, error)
	// GetServiceAccount fetches the SA referenced by a mapping row.
	GetServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error)
	// FindByExternalSubject resolves the Phase 3b federated SA mapping by
	// (external OIDC issuer, external sub). Returns iamerr.ErrNotFound when
	// no `trusted_subjects` entry matches.
	FindByExternalSubject(ctx context.Context, issuer, sub string) (domain.ServiceAccountOAuthClient, error)
}

// TokenEnrichmentUserTokenPort — read-side dependency: resolve a User + its
// personal-access-token (UserOAuthClient) mapping from a Hydra `client_id`.
// Used for the User-token path (`client_credentials` → Hydra mints a token whose
// `subject` is the Hydra client id; we map it back to the kacho User and stamp
// principal_type=user + principal_id/account_id claims — the net-new mapping that
// lets a personal token authenticate as `user:<id>` rather than a service account).
type TokenEnrichmentUserTokenPort interface {
	// LookupByOAuthClientID resolves the kacho-iam User-token (UserOAuthClient)
	// mapping from a Hydra `client_id`. Returns iamerr.ErrNotFound when the
	// client id is not a User-token client.
	LookupByOAuthClientID(ctx context.Context, hydraClientID domain.OAuthClientID) (domain.UserOAuthClient, error)
	// GetUser fetches the User referenced by a mapping row.
	GetUser(ctx context.Context, id domain.UserID) (domain.User, error)
}

// TokenEnrichmentConfig — static issuer/audience metadata stamped into claims.
type TokenEnrichmentConfig struct {
	// Domain — public Kachō audience.
	Domain string
	// HydraIssuer — token issuer URL.
	HydraIssuer string
}

// TokenHookContext — transport-agnostic projection of the inbound token-hook
// request. The handler maps the Hydra wire payload onto this struct so the
// service never depends on the HTTP/Hydra contract.
type TokenHookContext struct {
	// GrantedScopes — OAuth2 scopes granted for this token.
	GrantedScopes []string
	// AuthTime — session auth_time (unix seconds); 0 when unknown.
	AuthTime int64
	// ACR — Authentication Context Class Reference.
	ACR string
	// CnfJkt — DPoP confirmation thumbprint (RFC 9449).
	CnfJkt string
	// CnfX5tS256 — mTLS certificate confirmation thumbprint (RFC 8705).
	CnfX5tS256 string
	// OAuthClientID — `request.client_id` as Hydra knows it. For
	// client_credentials this equals `subject`; for jwt-bearer (Phase 3b
	// federation IN) this is the kacho-iam-issued client_id while `subject`
	// is the EXTERNAL assertion sub (e.g. `repo:acme/infra:ref:refs/heads/
	// main`). Empty when the handler cannot recover it.
	OAuthClientID string
	// GrantType — OAuth2 grant exercised. Used to disambiguate the
	// federated path (`urn:ietf:params:oauth:grant-type:jwt-bearer`) from
	// `client_credentials`. Empty when not provided by Hydra.
	GrantType string
	// ExternalIssuer — `iss` of the external assertion in the jwt-bearer
	// flow, populated by the handler when it can decode the form payload.
	// Empty for the non-federated paths.
	ExternalIssuer string
}

// TokenEnrichmentService — use-case for token-hook claims assembly.
type TokenEnrichmentService struct {
	cfg        TokenEnrichmentConfig
	users      TokenEnrichmentUserPort
	sas        TokenEnrichmentSAPort        // optional; nil → SA enrichment disabled
	userTokens TokenEnrichmentUserTokenPort // optional; nil → User-token enrichment disabled
	now        func() time.Time
}

// NewTokenEnrichmentService — constructor. A nil now-func defaults to
// time.Now.
func NewTokenEnrichmentService(cfg TokenEnrichmentConfig, users TokenEnrichmentUserPort) *TokenEnrichmentService {
	return &TokenEnrichmentService{cfg: cfg, users: users, now: time.Now}
}

// WithSAPort wires the ServiceAccount lookup port enabling Phase 3a SA-token
// enrichment (`kacho_principal_type=service_account` + principal_id +
// account_id claims). Returning the receiver keeps the constructor chainable
// and lets test wiring stay nil.
func (s *TokenEnrichmentService) WithSAPort(p TokenEnrichmentSAPort) *TokenEnrichmentService {
	s.sas = p
	return s
}

// WithUserTokenPort wires the User-token lookup port enabling personal-access-token
// enrichment (`kacho_principal_type=user` + principal_id + account_id claims for a
// token minted from a UserOAuthClient client_credentials client). Returning the
// receiver keeps the constructor chainable; nil-wiring keeps User-token enrichment
// disabled.
func (s *TokenEnrichmentService) WithUserTokenPort(p TokenEnrichmentUserTokenPort) *TokenEnrichmentService {
	s.userTokens = p
	return s
}

// EnrichClaims assembles the kacho-specific ext_claims map for an access_token.
//
// Resolution order:
//  1. Federated SA (Phase 3b): `GrantType == urn:ietf:params:oauth:grant-
//     type:jwt-bearer` AND `(ExternalIssuer, subject)` matches a
//     `trusted_subjects` entry on a SA-OAuth-client mapping.
//  2. SA by Hydra client_id (Phase 3a `client_credentials`). For federated
//     tokens this is also tried as a fallback using `OAuthClientID`.
//  3. User-token by Hydra client_id (personal-access-token `client_credentials`):
//     `subject` is the client_id of a UserOAuthClient; mapped back to the owning
//     User → `principal_type=user`. Tried after the SA lookup (a client_id is
//     either an SA-key or a User-token client, never both). Skipped when the
//     User-token port is unwired.
//  4. User by external_id (interactive Kratos sessions).
//  5. iamerr.ErrNotFound — caller falls back to MinimalClaims.
func (s *TokenEnrichmentService) EnrichClaims(ctx context.Context, subject string, hookCtx TokenHookContext) (map[string]any, error) {
	// 1. Federated SA path (Phase 3b). `subject` here is the EXTERNAL
	//    assertion sub; `hookCtx.OAuthClientID` is the kacho-issued client.
	//    We only enter this branch when Hydra signalled jwt-bearer — falling
	//    back to user/SA paths otherwise keeps Phase 3a behaviour intact for
	//    callers whose handler does not yet populate the new fields.
	if s.sas != nil && hookCtx.GrantType == "urn:ietf:params:oauth:grant-type:jwt-bearer" && hookCtx.ExternalIssuer != "" {
		soc, err := s.sas.FindByExternalSubject(ctx, hookCtx.ExternalIssuer, subject)
		if err == nil {
			sa, saErr := s.sas.GetServiceAccount(ctx, soc.SvaID)
			if saErr != nil && !stderrors.Is(saErr, iamerr.ErrNotFound) {
				return nil, fmt.Errorf("get sa %s: %w", soc.SvaID, saErr)
			}
			return s.federatedClaims(soc, sa, subject, hookCtx), nil
		}
		if !stderrors.Is(err, iamerr.ErrNotFound) {
			return nil, fmt.Errorf("lookup federated sa (iss=%s, sub=%s): %w", hookCtx.ExternalIssuer, subject, err)
		}
		// fall through — maybe a misconfigured assertion; treat the
		// `OAuthClientID` as a bare SA token below.
	}

	// 2. ServiceAccount path (Phase 3a). `subject` for client_credentials is
	//    the Hydra client_id. For the federated fallthrough above we instead
	//    try `OAuthClientID` so a misconfigured assertion still produces
	//    deterministic claims tied to the kacho SA.
	if s.sas != nil {
		lookupID := subject
		if hookCtx.OAuthClientID != "" && hookCtx.GrantType == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			lookupID = hookCtx.OAuthClientID
		}
		soc, err := s.sas.LookupByOAuthClientID(ctx, domain.OAuthClientID(lookupID))
		if err == nil {
			sa, saErr := s.sas.GetServiceAccount(ctx, soc.SvaID)
			if saErr != nil && !stderrors.Is(saErr, iamerr.ErrNotFound) {
				return nil, fmt.Errorf("get sa %s: %w", soc.SvaID, saErr)
			}
			// sa may be zero-value when the mapping outlives the SA (SA
			// deleted, OAuth client cleanup pending); still emit
			// principal_type/id, omit account_id in that case.
			return s.saClaims(soc, sa, lookupID, hookCtx), nil
		}
		if !stderrors.Is(err, iamerr.ErrNotFound) {
			return nil, fmt.Errorf("lookup sa oauth client %s: %w", lookupID, err)
		}
	}

	// 2b. User-token path (client_credentials with a personal access token).
	//     `subject` is the Hydra client_id of a UserOAuthClient; map it back to
	//     the owning User so the minted token's principal is `user:<id>` (net-new
	//     relative to SA-keys, which map to serviceAccount:<id>). Tried after the
	//     SA lookup (a client_id is either an SA-key or a User-token client, never
	//     both — the UNIQUE hydra_client_id spans both tables via distinct rows).
	if s.userTokens != nil {
		uoc, err := s.userTokens.LookupByOAuthClientID(ctx, domain.OAuthClientID(subject))
		if err == nil {
			u, uErr := s.userTokens.GetUser(ctx, uoc.UserID)
			if uErr != nil && !stderrors.Is(uErr, iamerr.ErrNotFound) {
				return nil, fmt.Errorf("get user %s: %w", uoc.UserID, uErr)
			}
			return s.userTokenClaims(uoc, u, subject, hookCtx), nil
		}
		if !stderrors.Is(err, iamerr.ErrNotFound) {
			return nil, fmt.Errorf("lookup user-token oauth client %s: %w", subject, err)
		}
	}

	// 3. User path (interactive sessions).
	users, err := s.users.FindActiveByExternalID(ctx, domain.ExternalSubject(subject))
	if err != nil {
		return nil, fmt.Errorf("find users by external_id: %w", err)
	}
	if len(users) > 0 {
		return s.userClaims(users[0], subject, hookCtx), nil
	}

	return nil, iamerr.Wrapf(iamerr.ErrNotFound, "subject %s not found (neither user nor service-account oauth client)", subject)
}

// userClaims assembles the ext_claims map for a User subject.
func (s *TokenEnrichmentService) userClaims(primary domain.User, subject string, hookCtx TokenHookContext) map[string]any {
	claims := map[string]any{
		"kacho_external_id":       subject,
		"kacho_user_id":           string(primary.ID),
		"kacho_active_account":    string(primary.AccountID),
		"kacho_groups":            []string{},
		"kacho_principal_type":    "user",
		"kacho_principal_id":      string(primary.ID),
		"kacho_account_id":        string(primary.AccountID),
		"kacho_device_compliance": "unknown",
		"kacho_mfa_at":            int64(0),
		"kacho_jkt":               hookCtx.CnfJkt,
		"kacho_x5t_s256":          hookCtx.CnfX5tS256,
		"kacho_acr":               hookCtx.ACR,
		"kacho_audience":          s.cfg.Domain,
		"kacho_issuer":            s.cfg.HydraIssuer,
		"kacho_issued_at":         s.now().Unix(),
	}

	// Device compliance: a webauthn/passkey scope ⇒ attested device.
	for _, sc := range hookCtx.GrantedScopes {
		if sc == "webauthn" || sc == "passkey" {
			claims["kacho_device_compliance"] = "attested"
			break
		}
	}
	// MFA timestamp: session auth_time when positive.
	if hookCtx.AuthTime > 0 {
		claims["kacho_mfa_at"] = hookCtx.AuthTime
	}

	return claims
}

// saClaims assembles the ext_claims map for a ServiceAccount-issued token
// (Phase 3a client_credentials).
//
// Permission resolution is intentionally OUT OF SCOPE here: per-RPC
// authorization stays in the api-gateway authz-gate (`internal/authzguard`
// + `internal_authorize.Check`), which has the live FGA tuple-store as
// source of truth. Stamping a `kacho_permissions: [...]` claim into the
// token would freeze a snapshot at issuance time and silently bypass
// revocations until token expiry — exactly the failure mode the FGA-based
// gate exists to prevent.
func (s *TokenEnrichmentService) saClaims(soc domain.ServiceAccountOAuthClient, sa domain.ServiceAccount, subject string, hookCtx TokenHookContext) map[string]any {
	claims := map[string]any{
		"kacho_external_id":       subject,
		"kacho_hydra_client_id":   subject,
		"kacho_principal_type":    "service_account",
		"kacho_principal_id":      string(soc.SvaID),
		"kacho_sa_key_id":         string(soc.ID),
		"kacho_device_compliance": "unknown",
		"kacho_jkt":               hookCtx.CnfJkt,
		"kacho_x5t_s256":          hookCtx.CnfX5tS256,
		"kacho_acr":               hookCtx.ACR,
		"kacho_audience":          s.cfg.Domain,
		"kacho_issuer":            s.cfg.HydraIssuer,
		"kacho_issued_at":         s.now().Unix(),
	}
	if sa.ID != "" {
		claims["kacho_account_id"] = string(sa.AccountID)
		claims["kacho_active_account"] = string(sa.AccountID)
		if sa.ProjectID != "" {
			claims["kacho_project_id"] = string(sa.ProjectID)
		}
	}
	return claims
}

// federatedClaims assembles the ext_claims map for a Phase 3b federated SA
// token. The token-hook resolves the SA via `(ExternalIssuer, sub)` against
// `trusted_subjects`; we stamp the external identity alongside the kacho
// principal id so api-gateway audit + authz can correlate. Permission
// resolution stays out-of-band (FGA gate, same as Phase 3a).
func (s *TokenEnrichmentService) federatedClaims(soc domain.ServiceAccountOAuthClient, sa domain.ServiceAccount, externalSub string, hookCtx TokenHookContext) map[string]any {
	claims := map[string]any{
		// kacho_external_id stays the external assertion sub for audit.
		"kacho_external_id":        externalSub,
		"kacho_hydra_client_id":    hookCtx.OAuthClientID,
		"kacho_principal_type":     "service_account",
		"kacho_principal_id":       string(soc.SvaID),
		"kacho_sa_key_id":          string(soc.ID),
		"kacho_federation_issuer":  hookCtx.ExternalIssuer,
		"kacho_federation_subject": externalSub,
		"kacho_federation_mode":    "jwt-bearer",
		"kacho_device_compliance":  "unknown",
		"kacho_jkt":                hookCtx.CnfJkt,
		"kacho_x5t_s256":           hookCtx.CnfX5tS256,
		"kacho_acr":                hookCtx.ACR,
		"kacho_audience":           s.cfg.Domain,
		"kacho_issuer":             s.cfg.HydraIssuer,
		"kacho_issued_at":          s.now().Unix(),
	}
	if sa.ID != "" {
		claims["kacho_account_id"] = string(sa.AccountID)
		claims["kacho_active_account"] = string(sa.AccountID)
		if sa.ProjectID != "" {
			claims["kacho_project_id"] = string(sa.ProjectID)
		}
	}
	return claims
}

// userTokenClaims assembles the ext_claims map for a personal-access-token-issued
// token (UserOAuthClient client_credentials). The principal is the OWNING User —
// `kacho_principal_type=user` + principal_id/account_id — so downstream authZ treats
// the token exactly like an interactive session of that user. Permission resolution
// stays out-of-band (FGA gate, same as the SA / interactive paths).
func (s *TokenEnrichmentService) userTokenClaims(uoc domain.UserOAuthClient, u domain.User, subject string, hookCtx TokenHookContext) map[string]any {
	claims := map[string]any{
		"kacho_external_id":       subject,
		"kacho_hydra_client_id":   subject,
		"kacho_principal_type":    "user",
		"kacho_principal_id":      string(uoc.UserID),
		"kacho_user_id":           string(uoc.UserID),
		"kacho_user_token_id":     string(uoc.ID),
		"kacho_device_compliance": "unknown",
		"kacho_jkt":               hookCtx.CnfJkt,
		"kacho_x5t_s256":          hookCtx.CnfX5tS256,
		"kacho_acr":               hookCtx.ACR,
		"kacho_audience":          s.cfg.Domain,
		"kacho_issuer":            s.cfg.HydraIssuer,
		"kacho_issued_at":         s.now().Unix(),
	}
	if u.ID != "" {
		claims["kacho_account_id"] = string(u.AccountID)
		claims["kacho_active_account"] = string(u.AccountID)
	}
	return claims
}

// MinimalClaims returns the reduced ext_claims set for a subject without an
// active User or SA mapping (legacy / unknown client_credentials clients).
func (s *TokenEnrichmentService) MinimalClaims(subject string) map[string]any {
	return map[string]any{
		"kacho_external_id":       subject,
		"kacho_principal_type":    "service_account",
		"kacho_device_compliance": "unknown",
		"kacho_issuer":            s.cfg.HydraIssuer,
		"kacho_audience":          s.cfg.Domain,
		"kacho_issued_at":         s.now().Unix(),
	}
}
