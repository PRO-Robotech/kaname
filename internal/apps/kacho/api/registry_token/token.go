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

	"github.com/PRO-Robotech/kacho-iam/internal/registrytoken"
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
}

// MaxAssertionTTL — hard ceiling on the client_assertion lifetime (a short-lived
// bearer proving possession of the SA-key private half).
const MaxAssertionTTL = 60 * time.Second

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
