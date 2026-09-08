// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// ErrCredentialExpired — the OAuth2 client behind this token request maps to a
// kacho credential (SA key / personal access token) whose stated expiry has
// passed. The token hook translates it into a 403, which is how Hydra is told
// to deny the token request.
//
// It is deliberately NOT an iamerr sentinel. "Expired" and "not found" are
// different verdicts and the hook owes them different answers: not-found is
// refused for a machine credential but still mints the reduced claim set for an
// interactive identity whose mirror has not committed yet. An expired credential
// collapsing into "not found" would therefore be able to reach that surviving
// branch, and the gate would be defeated for exactly the requests it exists for.
var ErrCredentialExpired = stderrors.New("credential expired")

// ErrSubjectNotActive — the subject behind this token request IS a kacho user,
// and its state forbids authentication. Both hooks translate it into a 403.
//
// Like ErrCredentialExpired it is deliberately NOT an iamerr sentinel, and for
// the same reason, sharpened by what actually happened: "blocked" and "not
// found" are different verdicts and the hook owes them different answers.
// Not-found still mints the reduced claim set for an interactive identity whose
// mirror has not committed yet — that is first login. A blocked user collapsing
// into not-found therefore reached that surviving branch and was ISSUED a token,
// which is precisely the defect this sentinel exists to make impossible.
var ErrSubjectNotActive = stderrors.New("subject not active")

// ErrServiceAccountDisabled — the subject behind this token request IS a kacho
// service account, and `service_accounts.enabled` forbids it from
// authenticating. The token hook translates it into a 403.
//
// Separate from ErrSubjectNotActive above, which carries the same fact about a
// USER, because the hook owes the two different answers: what fails for a
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

// TokenEnrichmentUserPort — read-side dependency: resolve a User mirror by its
// external identity subject (Kratos `sub`).
type TokenEnrichmentUserPort interface {
	// FindByExternalID returns EVERY User row for an identity across every
	// Account, whatever its state. The first row that may authenticate is the
	// default active account.
	//
	// An ACTIVE-filtering variant is deliberately absent. That filter answers
	// "give me the usable rows", which is the wrong question here: a blocked
	// user comes back as an empty result, indistinguishable from an identity
	// that has no mirror yet — and the reduced claim set that exists for the
	// latter was therefore minted for the former. Reading the rows as they are
	// lets the state be judged instead of inferred from an absence.
	FindByExternalID(ctx context.Context, externalID domain.ExternalSubject) ([]domain.User, error)
}

// TokenEnrichmentSAPort — read-side dependency: resolve a ServiceAccount and
// its OAuth-client mapping. Used for the Phase 3a SA-token path
// (`client_credentials` → Hydra mints a token whose `subject` is the Hydra
// client id; we map it back to the kacho SA and stamp principal_type/id/
// account_id claims) AND the Phase 3b federation-IN path (Hydra forwards an
// external OIDC assertion `(iss, sub)` plus its own `client_id`; we recover
// the SA mapping by matching `trusted_subjects[*].issuer` + regex on `sub`).
type TokenEnrichmentSAPort interface {
	// LookupByOAuthClientID resolves the kaname SA + OAuth-client mapping
	// from a Hydra `client_id`. Returns iamerr.ErrNotFound when the client
	// id is unknown (e.g. legacy Hydra registration outside kaname).
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
	// LookupByOAuthClientID resolves the kaname User-token (UserOAuthClient)
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
	// federation IN) this is the kaname-issued client_id while `subject`
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

// PrincipalKind names WHOSE authority a token carries, as the enricher resolved
// it. Not a claim and not a copy of one: it is what a caller needs in order to
// ask a FURTHER question about the same row the enricher just read.
type PrincipalKind string

const (
	// PrincipalUnresolved — nothing in kacho answers to this subject. Only the
	// reduced claim set can be minted, and there is no identifier to look
	// anything else up by.
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

// TokenEnrichmentService — use-case for token-hook claims assembly.
type TokenEnrichmentService struct {
	cfg        TokenEnrichmentConfig
	users      TokenEnrichmentUserPort
	sas        TokenEnrichmentSAPort        // optional; nil → SA enrichment disabled
	userTokens TokenEnrichmentUserTokenPort // optional; nil → User-token enrichment disabled
	// ownClients — чтение строки реестра по НАШЕМУ идентификатору (задача
	// #898). Опционален: пока наш токен-эндпоинт не провязан, вход в состав
	// утверждений остаётся один.
	ownClients TokenEnrichmentOwnClientPort
	now        func() time.Time
}

// NewTokenEnrichmentService — constructor. A nil now-func defaults to
// time.Now.
func NewTokenEnrichmentService(cfg TokenEnrichmentConfig, users TokenEnrichmentUserPort) *TokenEnrichmentService {
	return &TokenEnrichmentService{cfg: cfg, users: users, now: time.Now}
}

// WithClock injects the clock this service stamps `kaname_issued_at` from. A nil
// func keeps time.Now.
//
// It exists because the claim set carries a value derived from the clock, and
// the two issuance lanes (the provider's token hook and its refresh hook) must
// be comparable BYTE FOR BYTE on one principal. Two clocks would let that one
// value diverge — and the divergence would be a property of the probe, not of
// the product, which is the shape of a check that cannot tell the two apart.
// One instance, one clock, both lanes: whatever still differs belongs to the
// lanes.
func (s *TokenEnrichmentService) WithClock(now func() time.Time) *TokenEnrichmentService {
	if now != nil {
		s.now = now
	}
	return s
}

// UserClaims assembles the claim set for a User subject the CALLER has already
// resolved.
//
// This is the same producer EnrichClaims uses on its user branch, exported so
// the refresh lane can reach it. The refresh hook resolves the subject itself —
// it has to, its revoke-all gate weighs EVERY row of the identity — and used to
// assemble the claim set itself as well. That second assembly was a second place
// about one subject: a change to the device-compliance derivation in the service
// would not have reached the refresh lane, and one person would have been handed
// different claims at issuance and at renewal, with each lane's own probe green.
func (s *TokenEnrichmentService) UserClaims(u domain.User, subject string, hookCtx TokenHookContext) map[string]any {
	return s.userClaims(u, subject, hookCtx)
}

// WithSAPort wires the ServiceAccount lookup port enabling Phase 3a SA-token
// enrichment (`kaname_principal_type=service_account` + principal_id +
// account_id claims). Returning the receiver keeps the constructor chainable
// and lets test wiring stay nil.
func (s *TokenEnrichmentService) WithSAPort(p TokenEnrichmentSAPort) *TokenEnrichmentService {
	s.sas = p
	return s
}

// WithUserTokenPort wires the User-token lookup port enabling personal-access-token
// enrichment (`kaname_principal_type=user` + principal_id + account_id claims for a
// token minted from a UserOAuthClient client_credentials client). Returning the
// receiver keeps the constructor chainable; nil-wiring keeps User-token enrichment
// disabled.
func (s *TokenEnrichmentService) WithUserTokenPort(p TokenEnrichmentUserTokenPort) *TokenEnrichmentService {
	s.userTokens = p
	return s
}

// EnrichClaims assembles the kacho-specific ext_claims map for an access_token,
// and states WHO it resolved the subject to.
//
// The second return is not a summary of the first. The claim set is what the
// provider will stamp into a token; the ResolvedPrincipal is what this service
// knows the subject to be, in identifiers the claim set does not fully carry —
// a standing credential's issuance instant is not a claim and must not become
// one. A caller needing to ask a further question about the subject asks it
// with this.
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
//  5. iamerr.ErrNotFound — nothing answers to this subject. What the caller does
//     with that depends on the request: the token hook refuses a MACHINE
//     credential (its client is not a kacho credential) and falls back to
//     MinimalClaims only for an interactive identity whose mirror has not
//     committed yet.
func (s *TokenEnrichmentService) EnrichClaims(ctx context.Context, subject string, hookCtx TokenHookContext) (map[string]any, ResolvedPrincipal, error) {
	// 1. Federated SA path (Phase 3b). `subject` here is the EXTERNAL
	//    assertion sub; `hookCtx.OAuthClientID` is the kacho-issued client.
	//    We only enter this branch when Hydra signalled jwt-bearer — falling
	//    back to user/SA paths otherwise keeps Phase 3a behaviour intact for
	//    callers whose handler does not yet populate the new fields.
	if s.sas != nil && hookCtx.GrantType == "urn:ietf:params:oauth:grant-type:jwt-bearer" && hookCtx.ExternalIssuer != "" {
		soc, err := s.sas.FindByExternalSubject(ctx, hookCtx.ExternalIssuer, subject)
		if err == nil {
			// Terminal on expiry — never fall through to the bare-SA branch
			// below, which would mint for a credential we just refused.
			if s.expired(soc.ExpiresAt) {
				return nil, ResolvedPrincipal{}, fmt.Errorf("federated sa-key %s: %w", soc.ID, ErrCredentialExpired)
			}
			sa, saErr := s.sas.GetServiceAccount(ctx, soc.SvaID)
			if saErr != nil && !stderrors.Is(saErr, iamerr.ErrNotFound) {
				return nil, ResolvedPrincipal{}, fmt.Errorf("get sa %s: %w", soc.SvaID, saErr)
			}
			// Federation-in reaches the same account by another door, so it owes
			// the same answer: a state that stops one branch and not the other is
			// not a state, it is a suggestion.
			if saErr == nil && !sa.MayAuthenticate() {
				return nil, ResolvedPrincipal{}, fmt.Errorf("federated sa-key %s: service account %s: %w",
					soc.ID, soc.SvaID, ErrServiceAccountDisabled)
			}
			return s.federatedClaims(soc, sa, subject, hookCtx),
				ResolvedPrincipal{Kind: PrincipalServiceAccount}, nil
		}
		if !stderrors.Is(err, iamerr.ErrNotFound) {
			return nil, ResolvedPrincipal{}, fmt.Errorf("lookup federated sa (iss=%s, sub=%s): %w", hookCtx.ExternalIssuer, subject, err)
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
			if s.expired(soc.ExpiresAt) {
				return nil, ResolvedPrincipal{}, fmt.Errorf("sa-key %s: %w", soc.ID, ErrCredentialExpired)
			}
			sa, saErr := s.sas.GetServiceAccount(ctx, soc.SvaID)
			if saErr != nil && !stderrors.Is(saErr, iamerr.ErrNotFound) {
				return nil, ResolvedPrincipal{}, fmt.Errorf("get sa %s: %w", soc.SvaID, saErr)
			}
			// The account states whether it may authenticate at all, and this is
			// where a token stops being issued to one that may not. The check is
			// on the row that was READ: `Enabled` is false in a zero value too,
			// so judging an unresolved account by the same field would refuse
			// every mapping whose account read missed — a different verdict
			// wearing this one's clothes.
			if saErr == nil && !sa.MayAuthenticate() {
				return nil, ResolvedPrincipal{}, fmt.Errorf("sa-key %s: service account %s: %w",
					soc.ID, soc.SvaID, ErrServiceAccountDisabled)
			}
			// sa may be zero-value when the mapping outlives the SA (SA
			// deleted, OAuth client cleanup pending); still emit
			// principal_type/id, omit account_id in that case.
			return s.saClaims(soc, sa, lookupID, hookCtx),
				ResolvedPrincipal{Kind: PrincipalServiceAccount}, nil
		}
		if !stderrors.Is(err, iamerr.ErrNotFound) {
			return nil, ResolvedPrincipal{}, fmt.Errorf("lookup sa oauth client %s: %w", lookupID, err)
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
			if s.expired(uoc.ExpiresAt) {
				return nil, ResolvedPrincipal{}, fmt.Errorf("user-token %s: %w", uoc.ID, ErrCredentialExpired)
			}
			u, uErr := s.userTokens.GetUser(ctx, uoc.UserID)
			if uErr != nil && !stderrors.Is(uErr, iamerr.ErrNotFound) {
				return nil, ResolvedPrincipal{}, fmt.Errorf("get user %s: %w", uoc.UserID, uErr)
			}
			// A personal token is its owner's authority, so it cannot outlive
			// the owner's ability to authenticate. This path resolves the owner
			// BY ID, which applies no state filter at all — so before this check
			// a blocked user's personal token minted the FULL claim set,
			// principal id and account included: strictly more than the
			// interactive path handed the same user.
			if uErr == nil && !u.InviteStatus.MayAuthenticate() {
				return nil, ResolvedPrincipal{}, fmt.Errorf("user-token %s owner %s: %w", uoc.ID, uoc.UserID, ErrSubjectNotActive)
			}
			// A personal token carries no session, so the instant its authority
			// dates from is its own issuance.
			issued := uoc.CreatedAt
			return s.userTokenClaims(uoc, u, subject, hookCtx), ResolvedPrincipal{
				Kind:                       PrincipalUser,
				UserID:                     string(uoc.UserID),
				StandingCredentialIssuedAt: &issued,
			}, nil
		}
		if !stderrors.Is(err, iamerr.ErrNotFound) {
			return nil, ResolvedPrincipal{}, fmt.Errorf("lookup user-token oauth client %s: %w", subject, err)
		}
	}

	// 3. User path (interactive sessions).
	//
	// Read the rows AS THEY ARE, then judge. Resolving through the ACTIVE-only
	// query instead would answer an empty set for a blocked user, and the caller
	// below cannot tell that apart from an identity with no mirror yet — so the
	// reduced claim set meant for first login was minted for a blocked user.
	users, err := s.users.FindByExternalID(ctx, domain.ExternalSubject(subject))
	if err != nil {
		return nil, ResolvedPrincipal{}, fmt.Errorf("find users by external_id: %w", err)
	}
	for _, u := range users {
		if u.InviteStatus.MayAuthenticate() {
			// A membership set may mix states across accounts; the first row that
			// may authenticate is the default active account.
			return s.userClaims(u, subject, hookCtx),
				ResolvedPrincipal{Kind: PrincipalUser, UserID: string(u.ID)}, nil
		}
	}
	if len(users) > 0 {
		// The subject is present and refused, not missing.
		return nil, ResolvedPrincipal{}, fmt.Errorf("subject %s: %w", subject, ErrSubjectNotActive)
	}

	return nil, ResolvedPrincipal{}, iamerr.Wrapf(iamerr.ErrNotFound, "subject %s not found (neither user nor service-account oauth client)", subject)
}

// expired reports whether a credential with this stated expiry may no longer
// mint tokens.
//
// Two decisions are load-bearing here. Прежде они сверялись с проверяющим
// ключевой материал докерной полосы — чтобы ключ не был жив на одной и мёртв на
// другой в один и тот же миг; тот проверяющий снят вместе с приёмом ключевого
// материала в поле пароля (задача #1143), и полосу ключа теперь несёт только
// путь провайдера. Решения остаются, и вот почему:
//
//   - nil means NON-EXPIRING, not invalid. The bootstrap-admin mapping (#58) is
//     inserted with no expiry, as is every row predating the SA-key TTL knobs;
//     reading nil as invalid would take the cluster-admin credential and all
//     legacy keys offline at once. Bounding those lifetimes is the issuer's job
//     (KANAME_SAKEY_DEFAULT_TTL), not a retroactive reinterpretation here.
//   - the boundary instant is EXPIRED (`!After(now)`, not `Before(now)`): at
//     exactly expires_at the credential is spent.
//
// The comparison is on time.Time instants, so a timestamptz decoded into any
// location compares correctly; it uses the service clock (not the database's)
// so every path in this process agrees on "now".
func (s *TokenEnrichmentService) expired(expiresAt *time.Time) bool {
	return expiresAt != nil && !expiresAt.After(s.now())
}

// userClaims assembles the ext_claims map for a User subject.
func (s *TokenEnrichmentService) userClaims(primary domain.User, subject string, hookCtx TokenHookContext) map[string]any {
	claims := map[string]any{
		"kaname_external_id":       subject,
		"kaname_user_id":           string(primary.ID),
		"kaname_active_account":    string(primary.AccountID),
		"kaname_groups":            []string{},
		domain.ClaimPrincipalType:  "user",
		domain.ClaimPrincipalID:    string(primary.ID),
		"kaname_account_id":        string(primary.AccountID),
		"kaname_device_compliance": "unknown",
		"kaname_mfa_at":            int64(0),
		"kaname_jkt":               hookCtx.CnfJkt,
		"kaname_x5t_s256":          hookCtx.CnfX5tS256,
		"kaname_acr":               hookCtx.ACR,
		"kaname_audience":          s.cfg.Domain,
		"kaname_issuer":            s.cfg.HydraIssuer,
		"kaname_issued_at":         s.now().Unix(),
	}

	// Device compliance: a webauthn/passkey scope ⇒ attested device.
	for _, sc := range hookCtx.GrantedScopes {
		if sc == "webauthn" || sc == "passkey" {
			claims["kaname_device_compliance"] = "attested"
			break
		}
	}
	// MFA timestamp: session auth_time when positive.
	if hookCtx.AuthTime > 0 {
		claims["kaname_mfa_at"] = hookCtx.AuthTime
	}

	return claims
}

// saClaims assembles the ext_claims map for a ServiceAccount-issued token
// (Phase 3a client_credentials).
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
		"kaname_hydra_client_id":   subject,
		domain.ClaimPrincipalType:  "service_account",
		domain.ClaimPrincipalID:    string(soc.SvaID),
		"kaname_sa_key_id":         string(soc.ID),
		"kaname_device_compliance": "unknown",
		"kaname_jkt":               hookCtx.CnfJkt,
		"kaname_x5t_s256":          hookCtx.CnfX5tS256,
		"kaname_acr":               hookCtx.ACR,
		"kaname_audience":          s.cfg.Domain,
		"kaname_issuer":            s.cfg.HydraIssuer,
		"kaname_issued_at":         s.now().Unix(),
	}
	if sa.ID != "" {
		claims["kaname_account_id"] = string(sa.AccountID)
		claims["kaname_active_account"] = string(sa.AccountID)
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
		// kaname_external_id stays the external assertion sub for audit.
		"kaname_external_id":        externalSub,
		"kaname_hydra_client_id":    hookCtx.OAuthClientID,
		domain.ClaimPrincipalType:   "service_account",
		domain.ClaimPrincipalID:     string(soc.SvaID),
		"kaname_sa_key_id":          string(soc.ID),
		"kaname_federation_issuer":  hookCtx.ExternalIssuer,
		"kaname_federation_subject": externalSub,
		"kaname_federation_mode":    "jwt-bearer",
		"kaname_device_compliance":  "unknown",
		"kaname_jkt":                hookCtx.CnfJkt,
		"kaname_x5t_s256":           hookCtx.CnfX5tS256,
		"kaname_acr":                hookCtx.ACR,
		"kaname_audience":           s.cfg.Domain,
		"kaname_issuer":             s.cfg.HydraIssuer,
		"kaname_issued_at":          s.now().Unix(),
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
		"kaname_hydra_client_id":   subject,
		domain.ClaimPrincipalType:  "user",
		domain.ClaimPrincipalID:    string(uoc.UserID),
		"kaname_user_id":           string(uoc.UserID),
		"kaname_user_token_id":     string(uoc.ID),
		"kaname_device_compliance": "unknown",
		"kaname_jkt":               hookCtx.CnfJkt,
		"kaname_x5t_s256":          hookCtx.CnfX5tS256,
		"kaname_acr":               hookCtx.ACR,
		"kaname_audience":          s.cfg.Domain,
		"kaname_issuer":            s.cfg.HydraIssuer,
		"kaname_issued_at":         s.now().Unix(),
	}
	if u.ID != "" {
		claims["kaname_account_id"] = string(u.AccountID)
		claims["kaname_active_account"] = string(u.AccountID)
	}
	return claims
}

// MinimalClaims returns the reduced ext_claims set for a subject with NO User
// or SA mapping at all.
//
// Its ONE population is the interactive identity whose kacho mirror has not
// committed yet: provisioning is asynchronous (the provision hook returns once
// the Operation is accepted), so a freshly registered human can request their
// first token before the User row exists. The caller — the token hook — refuses
// an unresolved MACHINE credential outright instead of coming here, so this set
// is not what an unknown or revoked OAuth client receives.
//
// It is also not what a BLOCKED user receives, and that sentence used to be
// false. The user lookup filtered on ACTIVE, so a blocked row came back as an
// empty result and landed here — this docstring claimed the population was one
// thing while the query fed it another. The lookup now returns rows as they are
// and the state is judged (ErrSubjectNotActive), so absence again means only
// absence.
//
// The principal type says `user` because that is what this population is, and
// because the value is read as a decision, not as a label. Two platform
// controls treat `service_account` as "there is no person here":
// grpcsrv.EvaluateStepUp lifts the interactive-authentication floor for it, and
// the gateway demands a sender-constrained token from it. Stamping it on a
// human hands them an exemption built for machines and a requirement they
// cannot meet — their tokens are ordinary bearers.
//
// It carries no principal id by construction. Wherever the gateway resolves the
// subject from the token's OWN claims that is the end of it: nothing resolves,
// and the request is unauthenticated.
//
// One path is not that, and the difference is worth stating rather than
// implying. With DPoP enabled (off by default) the gateway substitutes the OIDC
// `sub` as the principal id when the claim set names none, and stamps THIS type
// on it. A `user`-typed subject then satisfies relations granted to `user:*` —
// today exactly the global reference catalogue of machine and disk types, which
// the platform grants to every authenticated subject by design and which this
// population is about to need. A `service_account`-typed one did not satisfy
// them, so the change is not neutral there; it admits an authenticated human to
// data meant for authenticated humans. Stating an untruth about what they are
// is not the way to withhold it — the substitution is what turns a set that
// names nobody into a subject, and that belongs to the gateway.
func (s *TokenEnrichmentService) MinimalClaims(subject string) map[string]any {
	return map[string]any{
		"kaname_external_id":       subject,
		domain.ClaimPrincipalType:  "user",
		"kaname_device_compliance": "unknown",
		"kaname_issuer":            s.cfg.HydraIssuer,
		"kaname_audience":          s.cfg.Domain,
		"kaname_issued_at":         s.now().Unix(),
	}
}
