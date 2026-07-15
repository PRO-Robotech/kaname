// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ── fakes ────────────────────────────────────────────────────────────────────

type fakeJWKSRepo struct {
	mu           sync.Mutex
	bootstrapErr error
	rotateErr    error
	getErr       error
	keys         map[domain.JWKSAlg]domain.OIDCJwksKey
	allKeys      []domain.OIDCJwksKey
}

func newFakeJWKSRepo() *fakeJWKSRepo {
	return &fakeJWKSRepo{keys: map[domain.JWKSAlg]domain.OIDCJwksKey{}}
}

func (f *fakeJWKSRepo) GetCurrent(ctx context.Context, alg domain.JWKSAlg) (domain.OIDCJwksKey, error) {
	if f.getErr != nil {
		return domain.OIDCJwksKey{}, f.getErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[alg]
	if !ok {
		return domain.OIDCJwksKey{}, iamerr.Wrapf(iamerr.ErrNotFound, "no current key for alg %s", alg)
	}
	return k, nil
}

func (f *fakeJWKSRepo) InsertBootstrap(ctx context.Context, tx service.Tx, k domain.OIDCJwksKey) (domain.OIDCJwksKey, error) {
	if f.bootstrapErr != nil {
		return domain.OIDCJwksKey{}, f.bootstrapErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys[k.Alg] = k
	f.allKeys = append(f.allKeys, k)
	return k, nil
}

func (f *fakeJWKSRepo) Rotate(ctx context.Context, tx service.Tx, newKey domain.OIDCJwksKey) (domain.OIDCJwksKey, error) {
	if f.rotateErr != nil {
		return domain.OIDCJwksKey{}, f.rotateErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.keys[newKey.Alg]; !exists {
		return domain.OIDCJwksKey{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"no current key for alg %s; use InsertBootstrap instead", newKey.Alg)
	}
	old := f.keys[newKey.Alg]
	old.Current = false
	now := time.Now()
	old.RotatedAt = &now
	for i := range f.allKeys {
		if f.allKeys[i].KID == old.KID {
			f.allKeys[i] = old
		}
	}
	f.keys[newKey.Alg] = newKey
	f.allKeys = append(f.allKeys, newKey)
	return newKey, nil
}

type fakeTXBeginner struct {
	beginErr error
}

func (f *fakeTXBeginner) Begin(ctx context.Context) (service.Tx, error) {
	if f.beginErr != nil {
		return nil, f.beginErr
	}
	return noopTx{}, nil
}

// noopTx — minimal service.Tx satisfier; fakeJWKSRepo does not touch the
// transaction, so Commit/Rollback are no-ops.
type noopTx struct{}

func (noopTx) Commit(ctx context.Context) error   { return nil }
func (noopTx) Rollback(ctx context.Context) error { return nil }

type fakeHydra struct {
	mu        sync.Mutex
	published []string
	deleted   []string
	pubErr    error
}

func (f *fakeHydra) PublishKey(ctx context.Context, alg domain.JWKSAlg, kid string, publicKeyPEM string) error {
	if f.pubErr != nil {
		return f.pubErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.published = append(f.published, kid)
	return nil
}
func (f *fakeHydra) DeleteKey(ctx context.Context, kid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, kid)
	return nil
}

type fakeAuditSvc struct {
	mu     sync.Mutex
	events []string
}

func (f *fakeAuditSvc) Emit(ctx context.Context, eventType string, payload map[string]any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, eventType)
	return nil
}
func (f *fakeAuditSvc) Events() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.events))
	copy(out, f.events)
	return out
}

// ── Tests ────────────────────────────────────────────────────────────────────

const fakeEncKey32 = "0123456789abcdef0123456789abcdef" // 32 bytes raw

func newService(t *testing.T, repo *fakeJWKSRepo, hydra *fakeHydra, audit *fakeAuditSvc) *service.JWKSRotationService {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return service.NewJWKSRotationService(
		service.JWKSRotationConfig{
			EncryptionKey:  []byte(fakeEncKey32),
			RotationPeriod: 90 * 24 * time.Hour,
		},
		repo,
		&fakeTXBeginner{},
		hydra,
		audit,
		logger,
	)
}

func TestJWKSRotation_Bootstrap_AllAlgsOnEmptyDB(t *testing.T) {
	repo := newFakeJWKSRepo()
	hydra := &fakeHydra{}
	audit := &fakeAuditSvc{}
	svc := newService(t, repo, hydra, audit)

	boot, rot, err := svc.Tick(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 3, boot, "RS256 + ES256 + EdDSA bootstrapped")
	assert.Equal(t, 0, rot)
	assert.Len(t, repo.keys, 3)
	for _, alg := range []domain.JWKSAlg{domain.JWKSAlgRS256Domain, domain.JWKSAlgES256Domain, domain.JWKSAlgEdDSADomain} {
		assert.Contains(t, repo.keys, alg)
		assert.True(t, repo.keys[alg].Current, "alg %s key must be current", alg)
		assert.NotEmpty(t, repo.keys[alg].PublicKeyPEM)
		assert.NotEmpty(t, repo.keys[alg].PrivateKeyPEMEncrypted)
	}
	// Hydra publish для каждого alg.
	assert.Len(t, hydra.published, 3)
	// Audit emit per alg.
	assert.Equal(t, []string{"iam.jwks.bootstrapped", "iam.jwks.bootstrapped", "iam.jwks.bootstrapped"}, audit.Events())
}

func TestJWKSRotation_Tick_NoOp_WhenKeysFresh(t *testing.T) {
	repo := newFakeJWKSRepo()
	hydra := &fakeHydra{}
	audit := &fakeAuditSvc{}
	now := time.Now()
	for _, alg := range []domain.JWKSAlg{domain.JWKSAlgRS256Domain, domain.JWKSAlgES256Domain, domain.JWKSAlgEdDSADomain} {
		repo.keys[alg] = domain.OIDCJwksKey{
			KID: "kacho-" + string(alg) + "-old",
			Alg: alg, Current: true,
			CreatedAt:              now.Add(-1 * 24 * time.Hour), // 1d old < 90d
			ExpiresAt:              now.Add(89 * 24 * time.Hour),
			PublicKeyPEM:           "x",
			PrivateKeyPEMEncrypted: []byte("x"),
		}
	}
	svc := newService(t, repo, hydra, audit)

	boot, rot, err := svc.Tick(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, boot)
	assert.Equal(t, 0, rot)
	assert.Empty(t, hydra.published)
	assert.Empty(t, audit.Events())
}

func TestJWKSRotation_Tick_RotatesExpiredKey(t *testing.T) {
	repo := newFakeJWKSRepo()
	hydra := &fakeHydra{}
	audit := &fakeAuditSvc{}
	now := time.Now()
	// RS256 — старый (95d), ES256/EdDSA — свежие (1d).
	seed := func(alg domain.JWKSAlg, kid string, createdAgo time.Duration) {
		k := domain.OIDCJwksKey{
			KID: kid, Alg: alg, Current: true,
			CreatedAt:              now.Add(-createdAgo),
			ExpiresAt:              now.Add(-createdAgo + 90*24*time.Hour),
			PublicKeyPEM:           "x",
			PrivateKeyPEMEncrypted: []byte("x"),
		}
		repo.keys[alg] = k
		repo.allKeys = append(repo.allKeys, k)
	}
	seed(domain.JWKSAlgRS256Domain, "kacho-rs256-old", 95*24*time.Hour)
	seed(domain.JWKSAlgES256Domain, "kacho-es256-old", 1*24*time.Hour)
	seed(domain.JWKSAlgEdDSADomain, "kacho-eddsa-old", 1*24*time.Hour)

	svc := newService(t, repo, hydra, audit)

	boot, rot, err := svc.Tick(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, boot)
	assert.Equal(t, 1, rot, "only RS256 rotated")
	// New key has different KID.
	newKey := repo.keys[domain.JWKSAlgRS256Domain]
	assert.NotEqual(t, "kacho-rs256-old", newKey.KID)
	assert.True(t, newKey.Current)
	// allKeys теперь 4: 3 existing + 1 new rotated.
	assert.Len(t, repo.allKeys, 4)
	assert.Equal(t, []string{"iam.jwks.rotated"}, audit.Events())
}

func TestJWKSRotation_BootstrapError_Propagated(t *testing.T) {
	repo := newFakeJWKSRepo()
	repo.bootstrapErr = errors.New("boom")
	hydra := &fakeHydra{}
	audit := &fakeAuditSvc{}
	svc := newService(t, repo, hydra, audit)

	_, _, err := svc.Tick(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insert bootstrap")
}

func TestJWKSRotation_InvalidEncKey_Fails(t *testing.T) {
	repo := newFakeJWKSRepo()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.NewJWKSRotationService(
		service.JWKSRotationConfig{EncryptionKey: []byte("too-short")},
		repo, &fakeTXBeginner{}, nil, nil, logger,
	)
	_, _, err := svc.Tick(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encryption key")
}

// AES-GCM round-trip + tampered-ciphertext coverage moved to the in-package
// jwks_aesgcm_internal_test.go (the decrypt helper is unexported — no
// production read/recovery path decrypts the stored key).
