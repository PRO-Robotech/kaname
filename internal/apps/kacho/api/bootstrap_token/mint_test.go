// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package bootstrap_token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ── fakes ─────────────────────────────────────────────────────────────────────

type fakeTx struct{ committed, rolledback bool }

func (t *fakeTx) Commit(context.Context) error   { t.committed = true; return nil }
func (t *fakeTx) Rollback(context.Context) error { t.rolledback = true; return nil }

type fakeTxBeginner struct{ last *fakeTx }

func (b *fakeTxBeginner) Begin(context.Context) (service.Tx, error) {
	b.last = &fakeTx{}
	return b.last, nil
}

type fakeStore struct {
	existing  *domain.ServiceAccountOAuthClient
	inserted  *domain.ServiceAccountOAuthClient
	insertErr error
	lockCalls int
}

func (s *fakeStore) LockAndGet(context.Context, service.Tx) (domain.ServiceAccountOAuthClient, bool, error) {
	s.lockCalls++
	if s.existing != nil {
		return *s.existing, true, nil
	}
	return domain.ServiceAccountOAuthClient{}, false, nil
}

func (s *fakeStore) InsertMapping(_ context.Context, _ service.Tx, c domain.ServiceAccountOAuthClient) error {
	if s.insertErr != nil {
		return s.insertErr
	}
	cp := c
	s.inserted = &cp
	return nil
}

type fakeHydra struct {
	calls   int
	lastReq clients.CreateOAuthClientRequest
	err     error
}

func (h *fakeHydra) CreateOAuthClient(_ context.Context, req clients.CreateOAuthClientRequest) (clients.HydraOAuthClient, error) {
	h.calls++
	h.lastReq = req
	if h.err != nil {
		return clients.HydraOAuthClient{}, h.err
	}
	return clients.HydraOAuthClient{ClientID: req.ClientID}, nil
}

type fakeExchanger struct {
	out          ExchangeOutput
	err          error
	lastAudience string
	lastAssert   string
}

func (x *fakeExchanger) Exchange(_ context.Context, in ExchangeInput) (ExchangeOutput, error) {
	x.lastAudience = in.Audience
	x.lastAssert = in.ClientAssertion
	return x.out, x.err
}

// ── helpers ───────────────────────────────────────────────────────────────────

func genES256PEM(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func newUseCase(t *testing.T, store BootstrapStore, hydra OAuthClientAdmin, ex TokenExchanger, cfg Config) *MintUseCase {
	t.Helper()
	if cfg.SigningKeyPEM == "" {
		cfg.SigningKeyPEM = genES256PEM(t)
	}
	if cfg.AssertionAudience == "" {
		cfg.AssertionAudience = "https://hydra.kacho.cloud/oauth2/token"
	}
	if cfg.GatewayAudience == "" {
		cfg.GatewayAudience = "https://api.kacho.cloud"
	}
	uc := NewMintUseCase(store, &fakeTxBeginner{}, hydra, ex, cfg)
	fixed := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	uc.WithClock(func() time.Time { return fixed })
	uc.WithJTIFunc(func() (string, error) { return "test-jti", nil })
	return uc
}

// ── IBT-08: Hydra unavailable → fail-closed UNAVAILABLE, no leak ────────────────

func TestMintBootstrapToken_HydraUnavailable_FailClosed(t *testing.T) {
	rawLeak := "dial tcp 10.1.2.3:4444: connection refused"
	uc := newUseCase(t, &fakeStore{}, &fakeHydra{},
		&fakeExchanger{err: errors.New(rawLeak)}, Config{})

	res, err := uc.Execute(context.Background(), 0)
	require.Nil(t, res)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Unavailable, st.Code(), "Hydra down must fail closed as UNAVAILABLE")
	// No auth-oracle / no infra leak: the fixed opaque text, never the raw cause.
	require.Equal(t, "bootstrap token issuer unavailable", st.Message())
	require.NotContains(t, st.Message(), "10.1.2.3", "raw Hydra/driver text must not leak")
	require.NotContains(t, st.Message(), "connection refused")
}

func TestMintBootstrapToken_IssuerUnavailableSentinel_FailClosed(t *testing.T) {
	uc := newUseCase(t, &fakeStore{}, &fakeHydra{},
		&fakeExchanger{err: ErrIssuerUnavailable}, Config{})
	_, err := uc.Execute(context.Background(), 0)
	require.Equal(t, codes.Unavailable, status.Code(err))
}

// ── IBT-09: bounded TTL (clamp to hard-max) ─────────────────────────────────────

func TestMintBootstrapToken_TTLClampedToMax(t *testing.T) {
	// Hydra reports a long-lived token; the request asks for a huge TTL.
	uc := newUseCase(t, &fakeStore{}, &fakeHydra{},
		&fakeExchanger{out: ExchangeOutput{AccessToken: "tok", ExpiresIn: 86400}}, Config{})

	res, err := uc.Execute(context.Background(), 86400)
	require.NoError(t, err)
	maxSec := int64(MaxTTL / time.Second)
	require.LessOrEqual(t, res.ExpiresIn, maxSec, "requested TTL must be clamped to the hard-max")
	require.Positive(t, res.ExpiresIn)
	// expiresAt - issuedAt == expiresIn (within second truncation) and ≤ hard-max.
	require.Equal(t, res.ExpiresIn, int64(res.ExpiresAt.Sub(res.IssuedAt)/time.Second))
}

func TestMintBootstrapToken_TTLZero_ServerDefault(t *testing.T) {
	uc := newUseCase(t, &fakeStore{}, &fakeHydra{},
		&fakeExchanger{out: ExchangeOutput{AccessToken: "tok", ExpiresIn: 86400}}, Config{})
	res, err := uc.Execute(context.Background(), 0)
	require.NoError(t, err)
	require.Equal(t, int64(DefaultTTL/time.Second), res.ExpiresIn, "ttl=0 → server default")
	require.LessOrEqual(t, res.ExpiresIn, int64(MaxTTL/time.Second))
}

// ── IBT-11: only-bootstrap — no arbitrary principal ─────────────────────────────

func TestMintBootstrapToken_NoArbitraryPrincipal(t *testing.T) {
	ex := &fakeExchanger{out: ExchangeOutput{AccessToken: "tok", ExpiresIn: 300}}
	uc := newUseCase(t, &fakeStore{}, &fakeHydra{}, ex, Config{})

	res, err := uc.Execute(context.Background(), 0)
	require.NoError(t, err)
	// The minted principal is ALWAYS the deterministic bootstrap SA — there is no
	// request field to name any other subject (skeleton-key rejected by construction).
	require.Equal(t, DeriveIdentity().SvaID, res.PrincipalID)
	require.Equal(t, "Bearer", res.TokenType)
	// The requested token audience is the gateway audience (not registry.*).
	require.Equal(t, "https://api.kacho.cloud", ex.lastAudience)
}

// ── provisioning wiring (supports IBT-01/02/03 at the unit boundary) ────────────

func TestMintBootstrapToken_FirstCall_ProvisionsHydraClientOnce(t *testing.T) {
	store := &fakeStore{}
	hydra := &fakeHydra{}
	uc := newUseCase(t, store, hydra,
		&fakeExchanger{out: ExchangeOutput{AccessToken: "tok", ExpiresIn: 300}}, Config{})

	res, err := uc.Execute(context.Background(), 0)
	require.NoError(t, err)
	require.Equal(t, 1, hydra.calls, "first call provisions the Hydra client exactly once")
	require.NotNil(t, store.inserted, "mapping row inserted")
	require.Equal(t, DeriveIdentity().SvaID, string(store.inserted.SvaID))
	require.Equal(t, "ES256", store.inserted.KeyAlgorithm)
	require.NotEmpty(t, store.inserted.PublicKeyPEM)
	// Hydra client provisioned with the gateway audience whitelisted + short lifespan.
	require.Contains(t, hydra.lastReq.Audience, "https://api.kacho.cloud")
	require.Equal(t, "private_key_jwt", hydra.lastReq.TokenEndpointAuthMethod)
	require.Equal(t, res.PrincipalID, string(store.inserted.SvaID))
}

func TestMintBootstrapToken_Idempotent_ReusesExistingMapping(t *testing.T) {
	existing := domain.ServiceAccountOAuthClient{
		ID:            domain.SAOAuthClientID(DeriveIdentity().SocID),
		SvaID:         domain.ServiceAccountID(DeriveIdentity().SvaID),
		OAuthClientID: domain.OAuthClientID(DeriveIdentity().ClientID),
	}
	store := &fakeStore{existing: &existing}
	hydra := &fakeHydra{}
	uc := newUseCase(t, store, hydra,
		&fakeExchanger{out: ExchangeOutput{AccessToken: "tok2", ExpiresIn: 300}}, Config{})

	res, err := uc.Execute(context.Background(), 0)
	require.NoError(t, err)
	require.Equal(t, 0, hydra.calls, "provisioned mapping is reused — no new Hydra client")
	require.Nil(t, store.inserted, "no new mapping inserted")
	require.Equal(t, DeriveIdentity().SvaID, res.PrincipalID)
}

// ── signing-key-not-configured → fail-closed ────────────────────────────────────

func TestMintBootstrapToken_NoSigningKey_FailClosed(t *testing.T) {
	uc := NewMintUseCase(&fakeStore{}, &fakeTxBeginner{}, &fakeHydra{},
		&fakeExchanger{out: ExchangeOutput{AccessToken: "tok"}}, Config{
			GatewayAudience: "https://api.kacho.cloud",
			// SigningKeyPEM deliberately empty.
		})
	_, err := uc.Execute(context.Background(), 0)
	require.Equal(t, codes.Unavailable, status.Code(err))
	require.Equal(t, "bootstrap token minting is not configured", status.Convert(err).Message())
}

// ── ids are byte-identical to migration 0058 seed ───────────────────────────────

func TestDeriveIdentity_MatchesMigrationSeed(t *testing.T) {
	id := DeriveIdentity()
	require.Equal(t, "svab91854890de887e6d", id.SvaID)
	require.Equal(t, "soc_db27d17291ff453b6", id.SocID)
	require.Equal(t, "kacho-bootstrap-admin", id.ClientID)
	require.Equal(t, "usr1a18042d81fb438d6", id.CreatedByUserID)
	require.True(t, strings.HasPrefix(id.SvaID, "sva"))
}
