// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package registry_token — the IAM Docker Registry v2 auth-server use-case:
// authenticate an API token (Basic user/pass) through a pluggable
// APITokenValidator, then mint a short-lived RS256 identity-JWT.
//
// The token carries IDENTITY only (Вариант B): kacho-registry re-checks
// authorization per request against IAM, so no registry scope is embedded. The
// MVP validator is a ServiceAccount-key; a future user-PAT validator plugs in as
// a second APITokenValidator WITHOUT any kacho-registry change (registry knows
// only «identity-JWT + JWKS», never the credential form).
//
// Clean-arch: this package defines the ports (APITokenValidator, TokenSigner) and
// the use-case; the infra-touching halves (SA-key store lookup, RSA key material)
// live behind the narrower SAKeyLookup / RSAKeyProvider ports, wired in the
// composition root.
package registry_token

import (
	"context"
	"errors"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/registrytoken"
)

// Subject — the authenticated identity a validator resolves from credentials.
type Subject struct {
	// ID — the subject id that lands in the JWT `sub` claim (e.g. a
	// ServiceAccount id). kacho-registry treats it as an opaque identity.
	ID string
}

// ErrInvalidCredentials — a validator's rejection (bad/unknown/expired/
// unsupported credential). Never surfaced verbatim to the client (no oracle);
// the use-case maps it to ErrUnauthenticated.
var ErrInvalidCredentials = errors.New("registry token: invalid credentials")

// ErrUnauthenticated — the use-case's outward auth-failure. The HTTP handler maps
// it to 401 + WWW-Authenticate (fail-closed; no distinction between missing,
// malformed and rejected credentials).
var ErrUnauthenticated = errors.New("registry token: unauthenticated")

// APITokenValidator — pluggable credential validator (Basic user/pass → subject).
// MVP concrete impl = SAKeyValidator (ServiceAccount-key). An unsupported or
// invalid credential MUST return ErrInvalidCredentials (never a partial-detail
// error that leaks which half was wrong).
type APITokenValidator interface {
	Validate(ctx context.Context, username, password string) (Subject, error)
}

// TokenSigner — mints a signed identity-JWT from claims (RS256, JWKS-verifiable).
type TokenSigner interface {
	Sign(ctx context.Context, claims registrytoken.Claims) (string, error)
}

// Config — issuer + TTL policy for minted tokens.
type Config struct {
	// Issuer — the `iss` claim (IAM token-issuer URL, e.g.
	// https://api.kacho.local/iam/token).
	Issuer string
	// DefaultService — `aud` fallback when the request omits ?service=.
	DefaultService string
	// TTL — token lifetime. <=0 or > MaxTTL is clamped to MaxTTL (short-TTL is
	// the documented revocation-latency residual for SA-key rotation).
	TTL time.Duration
}

// MaxTTL — hard ceiling on the identity-JWT lifetime (revocation-latency bound).
const MaxTTL = 5 * time.Minute

// IssueInput — the parsed token request.
type IssueInput struct {
	Username string // Basic-auth user (subject id for the SA-key validator).
	Password string // Basic-auth pass (the API token / SA-key).
	Service  string // ?service= — the registry service name (→ aud). Empty → DefaultService.
}

// IssueOutput — the Docker-compatible token response payload.
type IssueOutput struct {
	Token     string // the RS256 identity-JWT.
	ExpiresIn int    // seconds until exp.
	IssuedAt  int64  // unix seconds (iat).
}

// IssueRegistryTokenUseCase — validate credentials, then mint an identity-JWT.
type IssueRegistryTokenUseCase struct {
	cfg       Config
	validator APITokenValidator
	signer    TokenSigner
	now       func() time.Time
	jti       func() (string, error)
}

// NewIssueRegistryTokenUseCase — builder. TTL is clamped to (0, MaxTTL].
func NewIssueRegistryTokenUseCase(cfg Config, v APITokenValidator, s TokenSigner) *IssueRegistryTokenUseCase {
	if cfg.TTL <= 0 || cfg.TTL > MaxTTL {
		cfg.TTL = MaxTTL
	}
	return &IssueRegistryTokenUseCase{
		cfg:       cfg,
		validator: v,
		signer:    s,
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

// TTL returns the effective token lifetime (post-clamp) — used by the handler to
// populate expires_in without re-deriving the policy.
func (u *IssueRegistryTokenUseCase) TTL() time.Duration { return u.cfg.TTL }

// Execute authenticates the credentials and returns a minted identity-JWT.
// A missing/rejected credential yields ErrUnauthenticated (fail-closed); a
// signing failure surfaces as a plain error (handler → 500, no token).
func (u *IssueRegistryTokenUseCase) Execute(ctx context.Context, in IssueInput) (IssueOutput, error) {
	if in.Username == "" || in.Password == "" {
		return IssueOutput{}, ErrUnauthenticated
	}
	subj, err := u.validator.Validate(ctx, in.Username, in.Password)
	if err != nil {
		// Collapse every validator error to ErrUnauthenticated — the client must
		// not learn whether the subject exists or which half of the credential
		// was wrong (no auth oracle).
		return IssueOutput{}, ErrUnauthenticated
	}
	if subj.ID == "" {
		return IssueOutput{}, ErrUnauthenticated
	}

	aud := in.Service
	if aud == "" {
		aud = u.cfg.DefaultService
	}
	jti, err := u.jti()
	if err != nil {
		return IssueOutput{}, err
	}

	now := u.now()
	exp := now.Add(u.cfg.TTL)
	tok, err := u.signer.Sign(ctx, registrytoken.Claims{
		Issuer:    u.cfg.Issuer,
		Subject:   subj.ID,
		Audience:  aud,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
		JTI:       jti,
	})
	if err != nil {
		return IssueOutput{}, err
	}
	return IssueOutput{
		Token:     tok,
		ExpiresIn: int(u.cfg.TTL.Seconds()),
		IssuedAt:  now.Unix(),
	}, nil
}
