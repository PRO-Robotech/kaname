// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_enrichment_service.go — use-case: assemble kaname-specific ext_claims
// for an access token minted by one of this service's own issuance lanes.
//
// Claims assembly is a domain decision and belongs in the service layer, not in
// the transport of whichever lane mints. The external identity provider's token
// hooks used to be the first such transport; they are gone with the provider
// (kaname#363), and the own lanes enter through ClaimsForAssertionClient
// (token_enrichment_own_lane.go).
package service

import (
	"context"
	stderrors "errors"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ErrSubjectNotActive — the subject behind this token request IS a kacho user,
// and its state forbids authentication.
//
// It is deliberately NOT an iamerr sentinel: "blocked" and "not found" are
// different verdicts and the lane owes them different answers. A blocked user
// collapsing into not-found once reached a surviving branch of the provider's
// token hook and was ISSUED a token — precisely the defect this sentinel exists
// to make impossible.
var ErrSubjectNotActive = stderrors.New("subject not active")

// ErrServiceAccountDisabled — the subject behind this token request IS a kacho
// service account, and `service_accounts.enabled` forbids it from
// authenticating.
//
// Separate from ErrSubjectNotActive above, which carries the same fact about a
// USER, because the lane owes the two different answers: what fails for a
// machine credential is client authentication (RFC 6749 §5.2 `invalid_client`),
// and the operator reading the trail needs to know which table to look in.
// Nothing distinguishes them further down — a personal access token is a
// machine request whose subject is a person — so the distinction has to be made
// here, where the kind of subject is known.
//
// Also separate from iamerr.ErrNotFound: a mapping that resolves to no account
// is refused through its own branch, and reporting an account that exists as
// missing would send whoever is debugging it looking for a row that is right
// there.
var ErrServiceAccountDisabled = stderrors.New("service account disabled")

// TokenEnrichmentSAPort — read-side dependency of the service-account lane: the
// owning ServiceAccount of a key row, whose state the lane judges before it
// mints.
//
// It used to resolve the key row as well — by client id for the provider's
// `client_credentials` exchange and by `(external issuer, sub)` for its
// federation-IN exchange. Both lookups were the provider's token hook's (gone,
// kaname#363); the own lane reads the row by OUR id
// ([TokenEnrichmentOwnClientPort]).
type TokenEnrichmentSAPort interface {
	// GetServiceAccount fetches the SA referenced by a mapping row.
	GetServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error)
}

// TokenEnrichmentUserTokenPort — read-side dependency of the personal-token
// lane: the owning User of a personal access token, whose state the lane judges
// before it mints.
//
// It used to resolve the token row as well, by the name the previous external
// issuer gave its client. That lookup is gone with the column it read
// (kaname#362): the issuer registers no personal token, so there was no row it
// could find. The row is read by OUR id on the own lane
// ([TokenEnrichmentOwnClientPort]).
type TokenEnrichmentUserTokenPort interface {
	// GetUser fetches the User referenced by a mapping row.
	GetUser(ctx context.Context, id domain.UserID) (domain.User, error)
}

// TokenEnrichmentConfig — static metadata stamped into claims.
//
// It carries the audience and nothing about the issuer. An issuer claim used to
// ride here, filled with the address of the provider this service is retiring:
// nothing in the service, the platform or the foundation ever read it, and on a
// landing without that provider it named a server that answers nothing. The
// token's own `iss` is the signer's, stated by whichever lane signs.
type TokenEnrichmentConfig struct {
	// Domain — public Kachō audience.
	Domain string
}

// TokenHookContext — transport-agnostic projection of what the minting lane
// knows about the exchange: the confirmation it binds the token to and the
// assurance level it states. The name is historical — the first transport was
// the provider's token hook (gone, kaname#363); the own lanes fill it now.
//
// Fields only that hook wrote or only its branches read (granted scopes, the
// session instant, the grant type, the provider's client id, the external
// assertion issuer) left together with it.
type TokenHookContext struct {
	// ACR — Authentication Context Class Reference.
	ACR string
	// CnfJkt — DPoP confirmation thumbprint (RFC 9449).
	CnfJkt string
	// CnfX5tS256 — mTLS certificate confirmation thumbprint (RFC 8705).
	CnfX5tS256 string
}

// PrincipalKind names WHOSE authority a token carries, as the enricher resolved
// it. Not a claim and not a copy of one: it is what a caller needs in order to
// ask a FURTHER question about the same row the enricher just read.
type PrincipalKind string

const (
	// PrincipalUnresolved — nothing in kacho answers to this subject: the zero
	// value, returned together with an error.
	PrincipalUnresolved PrincipalKind = ""
	// PrincipalUser — a person, whether they authenticated interactively or
	// presented a personal access token they had issued earlier.
	PrincipalUser PrincipalKind = "user"
	// PrincipalServiceAccount — a machine credential. Not a person's session, so
	// a person's revoke-all cutoff says nothing about it.
	PrincipalServiceAccount PrincipalKind = "service_account"
)

// ResolvedPrincipal — who the enricher decided the token is for, expressed in
// the identifiers this service's own tables are keyed on rather than in the
// terms of the claim set.
//
// It exists because the subject the provider states is NOT such an identifier:
// interactively it is the external identity from the login provider, and for a
// machine-shaped exchange it is an OAuth client registration. The revoke-all
// cutoff is keyed on `users.id`, and until this type existed only the claim
// assembly ever learned that id — so a caller wanting to weigh the cutoff had
// either to resolve the subject a second time or to scrape the answer back out
// of the claims it had just been handed.
type ResolvedPrincipal struct {
	// Kind — whose authority the token carries.
	Kind PrincipalKind
	// UserID — `users.id`. Set only when Kind is PrincipalUser.
	UserID string
	// StandingCredentialIssuedAt — when the long-lived credential behind this
	// exchange was issued, for the exchanges that HAVE one (a personal access
	// token). nil for an interactive exchange, where the session states its own
	// authentication instant and that is the instant to weigh.
	//
	// The distinction is the whole reason this field exists. A person forced out
	// re-authenticates and their session moves past the cutoff; a standing
	// credential never re-authenticates, so its anchor is the moment it was
	// minted — one minted after the cutoff is authority the subject established
	// since, and one minted before it is exactly what "log this person out
	// everywhere" is about.
	StandingCredentialIssuedAt *time.Time
}

// TokenEnrichmentService — use-case for claims assembly of the own issuance lanes.
type TokenEnrichmentService struct {
	cfg        TokenEnrichmentConfig
	sas        TokenEnrichmentSAPort        // optional; nil → SA enrichment disabled
	userTokens TokenEnrichmentUserTokenPort // optional; nil → User-token enrichment disabled
	// ownClients — чтение строки реестра по НАШЕМУ идентификатору (задача
	// #898). Опционален: пока наш токен-эндпоинт не провязан, вход в состав
	// утверждений остаётся один.
	ownClients TokenEnrichmentOwnClientPort
	now        func() time.Time
}

// NewTokenEnrichmentService — constructor. The clock defaults to time.Now.
func NewTokenEnrichmentService(cfg TokenEnrichmentConfig) *TokenEnrichmentService {
	return &TokenEnrichmentService{cfg: cfg, now: time.Now}
}

// WithClock injects the clock this service stamps `kaname_issued_at` from. A nil
// func keeps time.Now.
//
// It exists because the claim set carries a value derived from the clock, and
// a probe comparing the claim sets of two lanes on one principal BYTE FOR BYTE
// needs both to read one clock. Two clocks would let that one value diverge —
// and the divergence would be a property of the probe, not of the product.
func (s *TokenEnrichmentService) WithClock(now func() time.Time) *TokenEnrichmentService {
	if now != nil {
		s.now = now
	}
	return s
}

// WithSAPort wires the owner read of the service-account lane
// (`kaname_principal_type=service_account` + principal_id + account_id claims).
// Returning the receiver keeps the constructor chainable and lets test wiring
// stay nil.
func (s *TokenEnrichmentService) WithSAPort(p TokenEnrichmentSAPort) *TokenEnrichmentService {
	s.sas = p
	return s
}

// WithUserTokenPort wires the owner read of the personal-token lane
// (`kaname_principal_type=user` + principal_id + account_id claims for a token
// exchanged by a UserOAuthClient). Returning the receiver keeps the constructor
// chainable; without it the own lane refuses a personal token rather than mint
// for an owner it could not judge.
func (s *TokenEnrichmentService) WithUserTokenPort(p TokenEnrichmentUserTokenPort) *TokenEnrichmentService {
	s.userTokens = p
	return s
}

// saClaims assembles the ext_claims map for a ServiceAccount-issued token.
//
// Permission resolution is intentionally OUT OF SCOPE here: per-RPC
// authorization stays in the api-gateway authz-gate (`internal/authzguard`
// + `internal_authorize.Check`), which has the live FGA tuple-store as
// source of truth. Stamping a `kaname_permissions: [...]` claim into the
// token would freeze a snapshot at issuance time and silently bypass
// revocations until token expiry — exactly the failure mode the FGA-based
// gate exists to prevent.
func (s *TokenEnrichmentService) saClaims(soc domain.ServiceAccountOAuthClient, sa domain.ServiceAccount, subject string, hookCtx TokenHookContext) map[string]any {
	claims := map[string]any{
		"kaname_external_id":       subject,
		domain.ClaimPrincipalType:  "service_account",
		domain.ClaimPrincipalID:    string(soc.SvaID),
		"kaname_sa_key_id":         string(soc.ID),
		"kaname_device_compliance": "unknown",
		"kaname_jkt":               hookCtx.CnfJkt,
		"kaname_x5t_s256":          hookCtx.CnfX5tS256,
		"kaname_acr":               hookCtx.ACR,
		"kaname_audience":          s.cfg.Domain,
		"kaname_issued_at":         s.now().Unix(),
	}
	if sa.ID != "" {
		claims["kaname_account_id"] = string(sa.AccountID)
		claims["kaname_active_account"] = string(sa.AccountID)
	}
	return claims
}

// userTokenClaims assembles the ext_claims map for a personal-access-token-issued
// token (UserOAuthClient client_credentials). The principal is the OWNING User —
// `kaname_principal_type=user` + principal_id/account_id — so downstream authZ treats
// the token exactly like an interactive session of that user. Permission resolution
// stays out-of-band (FGA gate, same as the SA / interactive paths).
func (s *TokenEnrichmentService) userTokenClaims(uoc domain.UserOAuthClient, u domain.User, subject string, hookCtx TokenHookContext) map[string]any {
	claims := map[string]any{
		"kaname_external_id":       subject,
		domain.ClaimPrincipalType:  "user",
		domain.ClaimPrincipalID:    string(uoc.UserID),
		"kaname_user_id":           string(uoc.UserID),
		"kaname_user_token_id":     string(uoc.ID),
		"kaname_device_compliance": "unknown",
		"kaname_jkt":               hookCtx.CnfJkt,
		"kaname_x5t_s256":          hookCtx.CnfX5tS256,
		"kaname_acr":               hookCtx.ACR,
		"kaname_audience":          s.cfg.Domain,
		"kaname_issued_at":         s.now().Unix(),
	}
	if u.ID != "" {
		claims["kaname_account_id"] = string(u.AccountID)
		claims["kaname_active_account"] = string(u.AccountID)
	}
	return claims
}
