// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package registry_token — the IAM Docker Registry v2 auth-server use-case:
// authenticate an SA-key (Basic client_id/private-PEM), then BROKER a token from
// Ory Hydra. kacho-iam does not mint the registry token itself — it signs a
// short-lived ES256 client_assertion from the presented SA-key and exchanges it
// with Hydra (`client_credentials` + `private_key_jwt`), relaying Hydra's
// access_token to the docker client. Hydra is the issuer; the data-plane verifies
// against Hydra's JWKS.
//
// The token carries IDENTITY only (Вариант B): kacho-registry re-checks
// authorization per request against IAM, so no registry scope is embedded.
//
// Clean-arch: this package defines the ports (CredentialValidator, AssertionSigner,
// TokenExchanger) and the use-case; the infra-touching halves (SA-key store lookup,
// Hydra HTTP) live behind the ports, wired in the composition root.
package registry_token

import (
	"context"
	"errors"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/registrytoken"
)

// Credential — the verified SA-key identity a client_assertion is built from.
type Credential struct {
	// ClientID — the Hydra OAuth2 client_id; lands in the assertion iss & sub
	// and is the identity the data-plane resolves to a ServiceAccount.
	ClientID string
	// KeyID — the registered JWK kid (the SA-OAuth-client id); the assertion
	// protected-header kid so Hydra selects the right verification key.
	KeyID string
	// Subject — the owning ServiceAccount id (informational / audit).
	Subject string
}

// ErrInvalidCredentials — a validator's rejection (bad/unknown/expired/
// unsupported credential). Never surfaced verbatim to the client (no oracle);
// the use-case maps it to ErrUnauthenticated.
var ErrInvalidCredentials = errors.New("registry token: invalid credentials")

// ErrUnauthenticated — the use-case's outward auth-failure. The HTTP handler maps
// it to 401 + WWW-Authenticate (fail-closed; no distinction between missing,
// malformed and rejected credentials, and no distinction between a Hydra
// client/grant rejection and a local reject).
var ErrUnauthenticated = errors.New("registry token: unauthenticated")

// ErrIssuerUnavailable — Hydra (the token issuer, a hard mint-path dependency)
// is unreachable / misbehaving. The handler maps it to 503 (fail-closed): peer
// unavailability must NOT yield a token and must NOT open-fail.
var ErrIssuerUnavailable = errors.New("registry token: issuer unavailable")

// CredentialValidator — verifies the presented Basic credential (client_id +
// SA-key private PEM) and resolves the assertion identity. An unsupported or
// invalid credential MUST return ErrInvalidCredentials (never a partial-detail
// error that leaks which half was wrong).
type CredentialValidator interface {
	Validate(ctx context.Context, clientID, privateKeyPEM string) (Credential, error)
}

// AssertionInput — the RFC 7523 client_assertion parameters.
type AssertionInput struct {
	KeyID         string // protected-header kid.
	ClientID      string // iss & sub.
	Audience      string // aud — the Hydra token endpoint URL.
	PrivateKeyPEM string // the presented EC private key (signs the assertion).
	IssuedAt      int64  // iat — unix seconds.
	ExpiresAt     int64  // exp — unix seconds (short, ≤ MaxAssertionTTL).
	JTI           string // jti — unique assertion id.
}

// AssertionSigner — signs an ES256 client_assertion (JWS) from the presented
// private key. Pure crypto; no infra.
type AssertionSigner interface {
	Sign(in AssertionInput) (string, error)
}

// ExchangeInput — the token exchange request relayed to Hydra.
type ExchangeInput struct {
	ClientAssertion string // the signed ES256 assertion.
	Audience        string // requested token aud (the registry service).
	Scope           string // requested scope (may be empty).
}

// ExchangeOutput — Hydra's access_token relayed to the docker client.
type ExchangeOutput struct {
	AccessToken string
	ExpiresIn   int
}

// TokenExchanger — brokers the `client_credentials` + `private_key_jwt` exchange
// with Hydra. Implementations return ErrIssuerUnavailable when the issuer is
// unreachable (→ 503); any other error is collapsed to ErrUnauthenticated (401).
type TokenExchanger interface {
	Exchange(ctx context.Context, in ExchangeInput) (ExchangeOutput, error)
}

// Config — brokering policy.
type Config struct {
	// AssertionAudience — the `aud` of the client_assertion: the Hydra token
	// endpoint URL Hydra recognises (its external issuer's token endpoint).
	AssertionAudience string
	// DefaultService — requested token `aud` fallback when ?service= is omitted.
	DefaultService string
	// AssertionTTL — client_assertion lifetime. <=0 or > MaxAssertionTTL is
	// clamped to MaxAssertionTTL.
	AssertionTTL time.Duration
	// Scope — optional scope requested from Hydra (empty → not requested).
	Scope string
	// Anonymous — the configured public-principal identity the shim authenticates
	// as for anonymous pull (RG-1 D-7 / B13). A zero ClientID/PrivateKeyPEM leaves
	// anonymous pull DISABLED (no-Basic-creds → 401 challenge, secure-by-default).
	Anonymous AnonymousIdentity
}

// AnonymousIdentity — the configured public-principal the shim authenticates as
// for anonymous pull. Its Hydra client_id is one the registry data-plane resolves
// to the FGA wildcard AnonymousSubject (`user:*`); the shim holds its signing key
// — NO user/SA credential is presented for the anonymous flow. Because `user:*`
// carries only the per-repo `v_get` wildcard grant emitted for PUBLIC repos, an
// anonymous token can pull a PUBLIC repo but can never write (B13/B14).
type AnonymousIdentity struct {
	// ClientID — the Hydra OAuth2 client_id the shim authenticates as; the
	// data-plane resolves its token to AnonymousSubject.
	ClientID string
	// KeyID — the anon client's registered JWK kid (assertion protected-header).
	KeyID string
	// PrivateKeyPEM — the EC private key the shim signs the anon client_assertion
	// with (IAM-held; never a presented credential).
	PrivateKeyPEM string
}

// MaxAssertionTTL — hard ceiling on the client_assertion lifetime (a short-lived
// bearer proving possession of the SA-key private half).
const MaxAssertionTTL = 60 * time.Second

const (
	// AnonymousSubject — the FGA principal an anonymous (no-credential) docker
	// pull resolves to on the registry data-plane. The anon Hydra client's token
	// is mapped to this wildcard subject; `user:*` holds ONLY the per-repo `v_get`
	// wildcard grant emitted for PUBLIC repositories, so it can pull a PUBLIC repo
	// but can never write (D-7). PRIVATE/absent repos deny uniformly (404).
	AnonymousSubject = "user:*"
	// AnonymousReadScope — the ONLY scope an anonymous token requests: a read
	// (pull) verb. The shim NEVER requests a write/push verb for `user:*` — the
	// read-only floor is enforced HERE (IAM half) AND by the data-plane FGA Check
	// on `user:*` (which carries no write relation). A push with an anon token is
	// therefore denied (403 DENIED) even in a pull-able PUBLIC repo (B14).
	AnonymousReadScope = "registry:pull"
)

// IssueInput — the parsed docker token request.
type IssueInput struct {
	Username string // Basic-auth user — the Hydra client_id.
	Password string // Basic-auth pass — the SA-key private-key PEM.
	Service  string // ?service= — the registry service name (→ requested aud).
}

// IssueOutput — the Docker-compatible token response payload.
type IssueOutput struct {
	Token     string // the Hydra-issued access_token.
	ExpiresIn int    // seconds until exp (from Hydra).
	IssuedAt  int64  // unix seconds (informational).
}

// IssueRegistryTokenUseCase — verify the SA-key, sign a client_assertion, and
// broker a Hydra token.
type IssueRegistryTokenUseCase struct {
	cfg       Config
	validator CredentialValidator
	signer    AssertionSigner
	exchanger TokenExchanger
	now       func() time.Time
	jti       func() (string, error)
}

// NewIssueRegistryTokenUseCase — builder. AssertionTTL is clamped to
// (0, MaxAssertionTTL].
func NewIssueRegistryTokenUseCase(cfg Config, v CredentialValidator, s AssertionSigner, ex TokenExchanger) *IssueRegistryTokenUseCase {
	if cfg.AssertionTTL <= 0 || cfg.AssertionTTL > MaxAssertionTTL {
		cfg.AssertionTTL = MaxAssertionTTL
	}
	return &IssueRegistryTokenUseCase{
		cfg:       cfg,
		validator: v,
		signer:    s,
		exchanger: ex,
		now:       time.Now,
		jti:       registrytoken.NewJTI,
	}
}

// WithClock overrides the clock (tests / deterministic exp).
func (u *IssueRegistryTokenUseCase) WithClock(now func() time.Time) *IssueRegistryTokenUseCase {
	u.now = now
	return u
}

// WithJTIFunc overrides the jti generator (tests).
func (u *IssueRegistryTokenUseCase) WithJTIFunc(f func() (string, error)) *IssueRegistryTokenUseCase {
	u.jti = f
	return u
}

// Execute verifies the credential, signs a client_assertion, and brokers a Hydra
// token. A missing/rejected credential yields ErrUnauthenticated (fail-closed);
// an unreachable issuer yields ErrIssuerUnavailable (503, no token).
func (u *IssueRegistryTokenUseCase) Execute(ctx context.Context, in IssueInput) (IssueOutput, error) {
	if in.Username == "" || in.Password == "" {
		return IssueOutput{}, ErrUnauthenticated
	}
	cred, err := u.validator.Validate(ctx, in.Username, in.Password)
	if err != nil || cred.ClientID == "" || cred.KeyID == "" {
		// Collapse every validator error to ErrUnauthenticated — the client must
		// not learn whether the subject exists or which half of the credential
		// was wrong (no auth oracle).
		return IssueOutput{}, ErrUnauthenticated
	}

	jti, err := u.jti()
	if err != nil {
		return IssueOutput{}, err
	}
	now := u.now()
	assertion, err := u.signer.Sign(AssertionInput{
		KeyID:         cred.KeyID,
		ClientID:      cred.ClientID,
		Audience:      u.cfg.AssertionAudience,
		PrivateKeyPEM: in.Password,
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(u.cfg.AssertionTTL).Unix(),
		JTI:           jti,
	})
	if err != nil {
		// The presented key could not sign — treat as an invalid credential
		// (fail-closed 401), never leaking the crypto failure detail.
		return IssueOutput{}, ErrUnauthenticated
	}

	service := in.Service
	if service == "" {
		service = u.cfg.DefaultService
	}
	out, err := u.exchanger.Exchange(ctx, ExchangeInput{
		ClientAssertion: assertion,
		Audience:        service,
		Scope:           u.cfg.Scope,
	})
	if err != nil {
		if errors.Is(err, ErrIssuerUnavailable) {
			return IssueOutput{}, ErrIssuerUnavailable
		}
		// Hydra rejected the exchange (bad/expired/revoked key) — fail-closed 401.
		return IssueOutput{}, ErrUnauthenticated
	}
	return IssueOutput{
		Token:     out.AccessToken,
		ExpiresIn: out.ExpiresIn,
		IssuedAt:  now.Unix(),
	}, nil
}

// AnonymousEnabled reports whether anonymous-pull issuance is configured. When
// false the shim MUST fall back to the 401 Bearer challenge (secure-by-default:
// anonymous pull is opt-in and requires a configured anon identity + its key).
func (u *IssueRegistryTokenUseCase) AnonymousEnabled() bool {
	return u.cfg.Anonymous.ClientID != "" && u.cfg.Anonymous.PrivateKeyPEM != ""
}

// ExecuteAnonymous brokers a short-lived, read-only Bearer for the public
// AnonymousSubject principal — the docker anonymous-pull flow (no Basic creds,
// RG-1 B13). It signs a client_assertion AS the configured anonymous identity
// (whose token the data-plane resolves to `user:*`) and exchanges it with Hydra
// requesting the registry data-plane audience and the read-only AnonymousReadScope
// — NEVER a write verb (B14). No user/SA credential is validated: an anonymous
// caller is the wildcard principal, not a specific subject. Bounded TTL is
// inherited from the assertion clamp + the anon Hydra client's configured token
// lifespan (RG-1 introduces no new expiry mechanism).
//
// A missing/rejected exchange yields ErrUnauthenticated (→ 401 challenge); an
// unreachable issuer yields ErrIssuerUnavailable (→ 503, no token). Anonymous
// pull being unconfigured also fails closed (ErrUnauthenticated → 401).
func (u *IssueRegistryTokenUseCase) ExecuteAnonymous(ctx context.Context, service string) (IssueOutput, error) {
	if !u.AnonymousEnabled() {
		// Anonymous pull not configured → fail-closed (handler issues 401).
		return IssueOutput{}, ErrUnauthenticated
	}

	jti, err := u.jti()
	if err != nil {
		return IssueOutput{}, err
	}
	now := u.now()
	assertion, err := u.signer.Sign(AssertionInput{
		KeyID:         u.cfg.Anonymous.KeyID,
		ClientID:      u.cfg.Anonymous.ClientID,
		Audience:      u.cfg.AssertionAudience,
		PrivateKeyPEM: u.cfg.Anonymous.PrivateKeyPEM,
		IssuedAt:      now.Unix(),
		ExpiresAt:     now.Add(u.cfg.AssertionTTL).Unix(),
		JTI:           jti,
	})
	if err != nil {
		// The anon key could not sign — fail-closed 401, never leaking the detail.
		return IssueOutput{}, ErrUnauthenticated
	}

	if service == "" {
		service = u.cfg.DefaultService
	}
	out, err := u.exchanger.Exchange(ctx, ExchangeInput{
		ClientAssertion: assertion,
		Audience:        service,
		// Read-only floor — the anon token NEVER requests a write/push verb (B14).
		Scope: AnonymousReadScope,
	})
	if err != nil {
		if errors.Is(err, ErrIssuerUnavailable) {
			return IssueOutput{}, ErrIssuerUnavailable
		}
		// Hydra rejected the anon exchange — fail-closed 401.
		return IssueOutput{}, ErrUnauthenticated
	}
	return IssueOutput{
		Token:     out.AccessToken,
		ExpiresIn: out.ExpiresIn,
		IssuedAt:  now.Unix(),
	}, nil
}
