// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package bootstrap_token

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/registrytoken"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// Bounded TTL defaults (server policy; the request ttl_seconds is CLAMPED to
// [1, MaxTTL], IBT-09). The client_assertion itself is always ≤ 60s (RFC 7523).
const (
	// DefaultTTL — applied when the request ttl_seconds is 0.
	DefaultTTL = 5 * time.Minute
	// MaxTTL — hard ceiling on the minted bootstrap token lifetime.
	MaxTTL = 15 * time.Minute
	// assertionTTL — the client_assertion lifetime (short, ≤ 60s).
	assertionTTL = 60 * time.Second
)

// Config — mint policy + the env-held bootstrap signing key.
type Config struct {
	// SigningKeyPEM — the bootstrap SA ES256 (P-256, PKCS#8) private key PEM,
	// supplied from a k8s Secret. Used ONLY in-memory to sign client_assertions;
	// never persisted. Empty → mint disabled (fail-closed, ErrSigningKeyNotConfigured).
	SigningKeyPEM string
	// AssertionAudience — the `aud` of the client_assertion: the Hydra token
	// endpoint URL Hydra recognises.
	AssertionAudience string
	// GatewayAudience — the requested token `aud` (https://{API_DOMAIN}) — the
	// audience the production gateway accepts.
	GatewayAudience string
	// DefaultTTL / MaxTTL override the package defaults when non-zero.
	DefaultTTL time.Duration
	MaxTTL     time.Duration
}

// Result — the minted bootstrap token (transport-agnostic).
type Result struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int64
	ExpiresAt   time.Time
	PrincipalID string
	IssuedAt    time.Time
}

// MintUseCase idempotently provisions the bootstrap OAuth client (if absent) and
// mints a short-lived RS256 token for the bootstrap SA via the Hydra exchange.
type MintUseCase struct {
	store     BootstrapStore
	txb       service.TxBeginner
	hydra     OAuthClientAdmin
	exchanger TokenExchanger
	cfg       Config
	now       func() time.Time
	jti       func() (string, error)
	logger    *slog.Logger
}

// NewMintUseCase constructs. DefaultTTL/MaxTTL fall back to the package defaults.
func NewMintUseCase(store BootstrapStore, txb service.TxBeginner, hydra OAuthClientAdmin, exchanger TokenExchanger, cfg Config) *MintUseCase {
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = DefaultTTL
	}
	if cfg.MaxTTL <= 0 {
		cfg.MaxTTL = MaxTTL
	}
	if cfg.DefaultTTL > cfg.MaxTTL {
		cfg.DefaultTTL = cfg.MaxTTL
	}
	return &MintUseCase{
		store:     store,
		txb:       txb,
		hydra:     hydra,
		exchanger: exchanger,
		cfg:       cfg,
		now:       time.Now,
		jti:       registrytoken.NewJTI,
	}
}

// WithClock overrides the clock (deterministic tests).
func (u *MintUseCase) WithClock(now func() time.Time) *MintUseCase { u.now = now; return u }

// WithJTIFunc overrides the jti generator (deterministic tests).
func (u *MintUseCase) WithJTIFunc(f func() (string, error)) *MintUseCase { u.jti = f; return u }

// WithLogger wires the failure logger (composition root). nil → no logging.
func (u *MintUseCase) WithLogger(l *slog.Logger) *MintUseCase { u.logger = l; return u }

// Execute provisions (idempotently) and mints. Fail-closed: no signing key →
// UNAVAILABLE; Hydra unreachable/rejected → UNAVAILABLE (no token, no leak).
func (u *MintUseCase) Execute(ctx context.Context, ttlSeconds int64) (*Result, error) {
	if u.cfg.SigningKeyPEM == "" {
		u.logErr(ctx, "mint disabled", ErrSigningKeyNotConfigured)
		return nil, status.Error(codes.Unavailable, "bootstrap token minting is not configured")
	}

	id, err := u.provision(ctx)
	if err != nil {
		return nil, err
	}

	now := u.now()
	jti, jerr := u.jti()
	if jerr != nil {
		u.logErr(ctx, "jti", jerr)
		return nil, status.Error(codes.Internal, "internal error")
	}

	assertion, aerr := registrytoken.SignClientAssertionES256(id.SocID, u.cfg.SigningKeyPEM, registrytoken.AssertionClaims{
		Issuer:    id.ClientID,
		Subject:   id.ClientID,
		Audience:  u.cfg.AssertionAudience,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(assertionTTL).Unix(),
		JTI:       jti,
	})
	if aerr != nil {
		u.logErr(ctx, "sign assertion", aerr)
		return nil, status.Error(codes.Internal, "internal error")
	}

	out, xerr := u.exchanger.Exchange(ctx, ExchangeInput{
		ClientAssertion: assertion,
		Audience:        u.cfg.GatewayAudience,
	})
	if xerr != nil || out.AccessToken == "" {
		// Fail-closed: peer unavailability / rejection must NOT yield a token and
		// must NOT open-fail. The raw Hydra body never rides in the error (no
		// auth-oracle); the cause is logged, not returned.
		u.logErr(ctx, "hydra exchange", xerr)
		return nil, status.Error(codes.Unavailable, "bootstrap token issuer unavailable")
	}

	expiresIn := u.effectiveExpiresIn(ttlSeconds, out.ExpiresIn)
	return &Result{
		AccessToken: out.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		ExpiresAt:   now.Add(time.Duration(expiresIn) * time.Second).Truncate(time.Second),
		PrincipalID: id.SvaID,
		IssuedAt:    now.Truncate(time.Second),
	}, nil
}

// provision ensures the bootstrap OAuth-client mapping exists, creating the
// external Hydra client exactly once under the transaction-scoped advisory lock
// (IBT-03). Returns the reconciled bootstrap identity.
func (u *MintUseCase) provision(ctx context.Context) (Identity, error) {
	id := DeriveIdentity()

	tx, err := u.txb.Begin(ctx)
	if err != nil {
		u.logErr(ctx, "begin tx", err)
		return Identity{}, status.Error(codes.Internal, "internal error")
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	c, found, gerr := u.store.LockAndGet(ctx, tx)
	if gerr != nil {
		return Identity{}, u.mapErr(ctx, "lock-and-get", gerr)
	}

	if !found {
		jwk, pubPEM, kerr := publicJWKFromPrivatePEM(u.cfg.SigningKeyPEM, id.SocID)
		if kerr != nil {
			u.logErr(ctx, "derive public jwk", kerr)
			return Identity{}, status.Error(codes.Internal, "internal error")
		}
		// #nosec G101 -- "client_credentials"/"private_key_jwt" are OAuth2 grant /
		// client-assertion identifiers (RFC 6749/7521), not credentials.
		_, herr := u.hydra.CreateOAuthClient(ctx, clients.CreateOAuthClientRequest{
			ClientID:                    id.ClientID,
			ClientName:                  bootstrapClientNm,
			Owner:                       id.SvaID,
			GrantTypes:                  []string{"client_credentials"},
			TokenEndpointAuthMethod:     "private_key_jwt",
			TokenEndpointAuthSigningAlg: "ES256",
			JWKS:                        &clients.JWKS{Keys: []clients.JWK{jwk}},
			// Whitelist the gateway audience so the exchange requesting it is
			// accepted by Hydra (else "audience has not been whitelisted", #320).
			Audience:            []string{u.cfg.GatewayAudience},
			AccessTokenLifespan: u.cfg.MaxTTL.String(),
		})
		if herr != nil && !isHydraConflict(herr) {
			u.logErr(ctx, "hydra create-client", herr)
			return Identity{}, status.Error(codes.Unavailable, "bootstrap token issuer unavailable")
		}
		c = domain.ServiceAccountOAuthClient{
			ID:              domain.SAOAuthClientID(id.SocID),
			SvaID:           domain.ServiceAccountID(id.SvaID),
			OAuthClientID:   domain.OAuthClientID(id.ClientID),
			Description:     domain.Description("bootstrap-admin token-mint OAuth client (#58)"),
			CreatedByUserID: domain.UserID(id.CreatedByUserID),
			PublicKeyPEM:    pubPEM,
			KeyAlgorithm:    "ES256",
			Labels:          domain.Labels{},
		}
		if ierr := u.store.InsertMapping(ctx, tx, c); ierr != nil {
			return Identity{}, u.mapErr(ctx, "insert mapping", ierr)
		}
	}

	if cerr := tx.Commit(ctx); cerr != nil {
		u.logErr(ctx, "commit", cerr)
		return Identity{}, status.Error(codes.Internal, "internal error")
	}
	committed = true

	// Reconcile from the committed mapping (loser-reuse path returns the
	// winner-provisioned values).
	id.SvaID = string(c.SvaID)
	id.SocID = string(c.ID)
	id.ClientID = string(c.OAuthClientID)
	return id, nil
}

// clampTTL clamps the requested ttl to [1s, MaxTTL], defaulting a 0 request to
// DefaultTTL. Returns seconds.
func (u *MintUseCase) clampTTL(req int64) int64 {
	d := u.cfg.DefaultTTL
	if req > 0 {
		d = time.Duration(req) * time.Second
	}
	if d <= 0 {
		d = u.cfg.DefaultTTL
	}
	if d > u.cfg.MaxTTL {
		d = u.cfg.MaxTTL
	}
	return int64(d / time.Second)
}

// effectiveExpiresIn = min(clamped-request, hydra-token-lifespan, MaxTTL) — the
// reported expiry never exceeds the server hard-max (IBT-09) and never overstates
// the real Hydra token lifetime.
func (u *MintUseCase) effectiveExpiresIn(reqTTL int64, hydraExpiresIn int) int64 {
	eff := u.clampTTL(reqTTL)
	if hydraExpiresIn > 0 && int64(hydraExpiresIn) < eff {
		eff = int64(hydraExpiresIn)
	}
	maxSec := int64(u.cfg.MaxTTL / time.Second)
	if eff > maxSec || eff <= 0 {
		eff = maxSec
	}
	return eff
}

// isHydraConflict reports whether a Hydra create-client error is a 409 (the
// client already exists — a concurrent/prior provision under retry). Idempotent:
// treated as success so provisioning re-converges.
func isHydraConflict(err error) bool {
	var apiErr *clients.HydraAPIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict
}

// mapErr maps a repo error to a gRPC status, never leaking pgx/driver text.
func (u *MintUseCase) mapErr(ctx context.Context, action string, err error) error {
	if err == nil {
		return nil
	}
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return err
	}
	switch {
	case errors.Is(err, iamerr.ErrNotFound):
		return status.Error(codes.NotFound, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrFailedPrecondition):
		return status.Error(codes.FailedPrecondition, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrInvalidArg):
		return status.Error(codes.InvalidArgument, iamerr.StripSentinel(err))
	case errors.Is(err, iamerr.ErrUnavailable):
		return status.Error(codes.Unavailable, iamerr.StripSentinel(err))
	}
	u.logErr(ctx, action, err)
	return status.Error(codes.Internal, "internal error")
}

func (u *MintUseCase) logErr(ctx context.Context, action string, err error) {
	if u.logger != nil {
		u.logger.ErrorContext(ctx, "bootstrap token mint failure",
			slog.String("action", action), slog.Any("err", err))
	}
}
