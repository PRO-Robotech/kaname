// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// jwks_rotation_service.go — JWKS rotation use-case.
//
// Domain logic:
//
//  1. Для каждого alg в {RS256, ES256, EdDSA}:
//     - если current=true row не существует → bootstrap (новый keypair + INSERT).
//     - если row exists и now - created_at >= 90d → rotate (CTE atomic swap).
//  2. Cleanup pass: для каждого alg удалить rows WHERE current=false AND
//     rotated_at < now() - cleanup-grace.
//  3. HydraPublisher (опц.) — POST новый public key в Hydra admin endpoint.
//  4. Advisory lock pg_advisory_xact_lock per (RS256/ES256/EdDSA) обеспечивает
//     HA-safe rotation; реализация — в OIDCJwksKeyRepo.Rotate.
//
// Зависит от port-интерфейсов; реализации — adapter (`internal/repo/kacho/pg`,
// `internal/clients`).
package service

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// ── Port-интерфейсы ─────────────────────────────────────────────────────────

// JWKSKeyPort — read+write для oidc_jwks_keys.
type JWKSKeyPort interface {
	GetCurrent(ctx context.Context, alg domain.JWKSAlg) (domain.OIDCJwksKey, error)
	InsertBootstrap(ctx context.Context, tx Tx, k domain.OIDCJwksKey) (domain.OIDCJwksKey, error)
	Rotate(ctx context.Context, tx Tx, newKey domain.OIDCJwksKey) (domain.OIDCJwksKey, error)
}

// TXBeginner opens a transaction. Returns the opaque service.Tx handle (tx.go);
// the concrete pgx.Tx is materialized only inside repo adapters.
type TXBeginner interface {
	Begin(ctx context.Context) (Tx, error)
}

// JWKSPublisher — публикует public key в Hydra admin API.
type JWKSPublisher interface {
	PublishKey(ctx context.Context, alg domain.JWKSAlg, kid string, publicKeyPEM string) error
	DeleteKey(ctx context.Context, kid string) error
}

// AuditEmitterPort — для emit audit events.
type AuditEmitterPort interface {
	Emit(ctx context.Context, eventType string, payload map[string]any) error
}

// ── Service ─────────────────────────────────────────────────────────────────

// JWKSRotationConfig — runtime config.
type JWKSRotationConfig struct {
	EncryptionKey  []byte        // AES-256 GCM
	RotationPeriod time.Duration // default 90d
	CleanupGrace   time.Duration // grace period before deleting rotated keys (default 30m)
	KidPrefix      string        // default "kacho-"
}

// JWKSRotationService — use-case.
type JWKSRotationService struct {
	cfg     JWKSRotationConfig
	repo    JWKSKeyPort
	tx      TXBeginner
	hydra   JWKSPublisher    // nullable
	audit   AuditEmitterPort // nullable
	logger  *slog.Logger
	now     func() time.Time
	algList []domain.JWKSAlg
}

// NewJWKSRotationService — constructor.
func NewJWKSRotationService(
	cfg JWKSRotationConfig,
	repo JWKSKeyPort,
	tx TXBeginner,
	hydra JWKSPublisher,
	audit AuditEmitterPort,
	logger *slog.Logger,
) *JWKSRotationService {
	if cfg.RotationPeriod <= 0 {
		cfg.RotationPeriod = 90 * 24 * time.Hour
	}
	if cfg.CleanupGrace <= 0 {
		cfg.CleanupGrace = 30 * time.Minute
	}
	if cfg.KidPrefix == "" {
		cfg.KidPrefix = "kacho-"
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &JWKSRotationService{
		cfg:     cfg,
		repo:    repo,
		tx:      tx,
		hydra:   hydra,
		audit:   audit,
		logger:  logger,
		now:     time.Now,
		algList: []domain.JWKSAlg{domain.JWKSAlgRS256Domain, domain.JWKSAlgES256Domain, domain.JWKSAlgEdDSADomain},
	}
}

// Tick — выполняет один rotation cycle: bootstrap missing alg-ы + rotate
// expired-ы. Idempotent — повторный вызов в течение rotation-period == no-op
// (просто проверки).
//
// Returns the number of bootstrapped + rotated keys; non-nil err при любой
// нерекуверной ошибке.
func (s *JWKSRotationService) Tick(ctx context.Context) (bootstrapped int, rotated int, err error) {
	if len(s.cfg.EncryptionKey) != 32 {
		return 0, 0, fmt.Errorf("jwks rotation: encryption key must be 32 bytes (got %d)", len(s.cfg.EncryptionKey))
	}

	for _, alg := range s.algList {
		cur, getErr := s.repo.GetCurrent(ctx, alg)
		if errors.Is(getErr, iamerr.ErrNotFound) {
			// Bootstrap path.
			if err := s.bootstrapAlg(ctx, alg); err != nil {
				s.logger.Error("jwks bootstrap failed", "alg", alg, "err", err)
				return bootstrapped, rotated, err
			}
			bootstrapped++
			continue
		}
		if getErr != nil {
			return bootstrapped, rotated, fmt.Errorf("jwks get current %s: %w", alg, getErr)
		}
		// Если ключ старше rotation-period → rotate.
		age := s.now().Sub(cur.CreatedAt)
		if age >= s.cfg.RotationPeriod {
			if err := s.rotateAlg(ctx, alg, cur); err != nil {
				s.logger.Error("jwks rotate failed", "alg", alg, "err", err)
				return bootstrapped, rotated, err
			}
			rotated++
		}
	}
	return bootstrapped, rotated, nil
}

// bootstrapAlg — первая INSERT row для alg.
func (s *JWKSRotationService) bootstrapAlg(ctx context.Context, alg domain.JWKSAlg) error {
	priv, pub, err := generateKeypair(alg)
	if err != nil {
		return fmt.Errorf("generate keypair %s: %w", alg, err)
	}
	encryptedPriv, err := encryptAESGCM(s.cfg.EncryptionKey, priv)
	if err != nil {
		return fmt.Errorf("encrypt private key: %w", err)
	}

	kid := s.generateKID(alg)
	now := s.now()
	key := domain.OIDCJwksKey{
		KID:                    kid,
		Alg:                    alg,
		Current:                true,
		ExpiresAt:              now.Add(s.cfg.RotationPeriod),
		PublicKeyPEM:           pub,
		PrivateKeyPEMEncrypted: encryptedPriv,
		CreatedAt:              now,
	}

	tx, err := s.tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := s.repo.InsertBootstrap(ctx, tx, key); err != nil {
		return fmt.Errorf("insert bootstrap %s: %w", alg, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit bootstrap %s: %w", alg, err)
	}

	if s.hydra != nil {
		if err := s.hydra.PublishKey(ctx, alg, kid, pub); err != nil {
			s.logger.Warn("hydra publish failed (continuing)", "kid", kid, "err", err)
		}
	}
	if s.audit != nil {
		// JWKS key lifecycle is security-relevant — emit failure logged at
		// Error (key already persisted; no rollback at this point).
		logEmitFailure(s.logger, true, "audit", "iam.jwks.bootstrapped",
			s.audit.Emit(ctx, "iam.jwks.bootstrapped", map[string]any{
				"alg": string(alg),
				"kid": kid,
			}))
	}
	s.logger.Info("jwks bootstrap", "alg", alg, "kid", kid)
	return nil
}

// rotateAlg — CTE-swap старого current на новый.
func (s *JWKSRotationService) rotateAlg(ctx context.Context, alg domain.JWKSAlg, cur domain.OIDCJwksKey) error {
	priv, pub, err := generateKeypair(alg)
	if err != nil {
		return fmt.Errorf("generate keypair %s: %w", alg, err)
	}
	encryptedPriv, err := encryptAESGCM(s.cfg.EncryptionKey, priv)
	if err != nil {
		return fmt.Errorf("encrypt private key: %w", err)
	}

	kid := s.generateKID(alg)
	now := s.now()
	key := domain.OIDCJwksKey{
		KID:                    kid,
		Alg:                    alg,
		Current:                true,
		ExpiresAt:              now.Add(s.cfg.RotationPeriod),
		PublicKeyPEM:           pub,
		PrivateKeyPEMEncrypted: encryptedPriv,
		CreatedAt:              now,
	}

	tx, err := s.tx.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := s.repo.Rotate(ctx, tx, key); err != nil {
		return fmt.Errorf("rotate %s: %w", alg, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit rotate %s: %w", alg, err)
	}

	if s.hydra != nil {
		if err := s.hydra.PublishKey(ctx, alg, kid, pub); err != nil {
			s.logger.Warn("hydra publish failed", "kid", kid, "err", err)
		}
	}
	if s.audit != nil {
		// JWKS key lifecycle is security-relevant — emit failure logged at
		// Error (key already rotated; no rollback at this point).
		logEmitFailure(s.logger, true, "audit", "iam.jwks.rotated",
			s.audit.Emit(ctx, "iam.jwks.rotated", map[string]any{
				"alg":     string(alg),
				"new_kid": kid,
				"old_kid": cur.KID,
			}))
	}
	s.logger.Info("jwks rotated", "alg", alg, "old_kid", cur.KID, "new_kid", kid)
	return nil
}

// generateKID — детерминированный suffix `<prefix><alg-lowercase>-<unix-nano>`.
func (s *JWKSRotationService) generateKID(alg domain.JWKSAlg) string {
	algLower := ""
	switch alg {
	case domain.JWKSAlgRS256Domain:
		algLower = "rs256"
	case domain.JWKSAlgES256Domain:
		algLower = "es256"
	case domain.JWKSAlgEdDSADomain:
		algLower = "eddsa"
	default:
		algLower = "unk"
	}
	return fmt.Sprintf("%s%s-%d", s.cfg.KidPrefix, algLower, s.now().UnixNano())
}

// ── Keypair generation ──────────────────────────────────────────────────────

// generateKeypair — генерирует пару (private_pem, public_pem) для alg.
func generateKeypair(alg domain.JWKSAlg) (privPEM []byte, pubPEM string, err error) {
	switch alg {
	case domain.JWKSAlgRS256Domain:
		priv, e := rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			return nil, "", e
		}
		privPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		})
		pubBytes, e := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if e != nil {
			return nil, "", e
		}
		pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))
		return privPEM, pubPEM, nil

	case domain.JWKSAlgES256Domain:
		priv, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, "", e
		}
		privBytes, e := x509.MarshalECPrivateKey(priv)
		if e != nil {
			return nil, "", e
		}
		privPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
		pubBytes, e := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if e != nil {
			return nil, "", e
		}
		pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))
		return privPEM, pubPEM, nil

	case domain.JWKSAlgEdDSADomain:
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return nil, "", e
		}
		privBytes, e := x509.MarshalPKCS8PrivateKey(priv)
		if e != nil {
			return nil, "", e
		}
		privPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
		pubBytes, e := x509.MarshalPKIXPublicKey(pub)
		if e != nil {
			return nil, "", e
		}
		pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))
		return privPEM, pubPEM, nil
	}
	return nil, "", fmt.Errorf("unsupported alg %s", alg)
}

// ── AES-GCM encryption ──────────────────────────────────────────────────────

// encryptAESGCM — symmetric encryption private_pem с 32-byte key. Nonce
// prepended к ciphertext (12-byte). Output format: nonce || ciphertext.
func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}
