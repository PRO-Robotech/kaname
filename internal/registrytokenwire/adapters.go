// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package registrytokenwire — composition-root adapters binding the registry
// `/token` use-case + JWKS handler to iam infrastructure:
//
//   - RSAKeyProviderAdapter — the CURRENT oidc_jwks RS256 signing key (decrypting
//     the at-rest AES-GCM private key), so minted tokens are signed by iam's own
//     rotated key (NOT Hydra's).
//   - JWKSProviderAdapter — the public JWK Set (current RS256 key) verifiers use.
//   - SAKeyLookupAdapter — a subject's registered SA-key public halves.
//
// These are thin adapters over already-tested primitives (registrytoken crypto +
// the pg repos); they carry no policy.
package registrytokenwire

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	registrytokenuc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/registrytoken"
)

// jwksCurrentReader — reads the current key for an alg (satisfied by the
// oidc_jwks pg repo).
type jwksCurrentReader interface {
	GetCurrent(ctx context.Context, alg domain.JWKSAlg) (domain.OIDCJwksKey, error)
}

// jwksListReader — lists the current key per alg (satisfied by the oidc_jwks pg repo).
type jwksListReader interface {
	ListCurrent(ctx context.Context) ([]domain.OIDCJwksKey, error)
}

// saKeyLister — pages a subject's SA-OAuth-client rows (satisfied by the SA repo).
type saKeyLister interface {
	List(ctx context.Context, svaID domain.ServiceAccountID, pageToken string, pageSize int32) ([]domain.ServiceAccountOAuthClient, string, error)
}

// ── RSA signing-key provider ────────────────────────────────────────────────

// RSAKeyProviderAdapter — supplies the current oidc_jwks RS256 private key.
type RSAKeyProviderAdapter struct {
	repo   jwksCurrentReader
	encKey []byte // AES-256-GCM key for the at-rest private PEM.
}

// NewRSAKeyProvider — builder. encKey is the JWKS-encryption key (32 bytes).
func NewRSAKeyProvider(repo jwksCurrentReader, encKey []byte) *RSAKeyProviderAdapter {
	return &RSAKeyProviderAdapter{repo: repo, encKey: encKey}
}

var _ registrytokenuc.RSAKeyProvider = (*RSAKeyProviderAdapter)(nil)

// CurrentRSA fetches, decrypts and parses the current RS256 signing key.
func (a *RSAKeyProviderAdapter) CurrentRSA(ctx context.Context) (string, *rsa.PrivateKey, error) {
	key, err := a.repo.GetCurrent(ctx, domain.JWKSAlgRS256Domain)
	if err != nil {
		return "", nil, fmt.Errorf("registrytokenwire: get current RS256 key: %w", err)
	}
	privPEM, err := decryptAESGCM(a.encKey, key.PrivateKeyPEMEncrypted)
	if err != nil {
		return "", nil, fmt.Errorf("registrytokenwire: decrypt signing key: %w", err)
	}
	priv, err := parseRSAPrivatePEM(string(privPEM))
	if err != nil {
		return "", nil, err
	}
	return key.KID, priv, nil
}

// ── JWKS provider ───────────────────────────────────────────────────────────

// JWKSProviderAdapter — projects the current RS256 public key(s) as a JWK Set.
type JWKSProviderAdapter struct {
	repo jwksListReader
}

// NewJWKSProvider — builder.
func NewJWKSProvider(repo jwksListReader) *JWKSProviderAdapter {
	return &JWKSProviderAdapter{repo: repo}
}

// PublicJWKS returns the current RS256 verification key(s) as a JWK Set.
func (a *JWKSProviderAdapter) PublicJWKS(ctx context.Context) (registrytoken.JWKS, error) {
	keys, err := a.repo.ListCurrent(ctx)
	if err != nil {
		return registrytoken.JWKS{}, fmt.Errorf("registrytokenwire: list current keys: %w", err)
	}
	out := registrytoken.JWKS{Keys: make([]registrytoken.JWK, 0, 1)}
	for _, k := range keys {
		if k.Alg != domain.JWKSAlgRS256Domain {
			continue // registry identity-JWTs are RS256; skip other algs.
		}
		pub, perr := parseRSAPublicPEM(k.PublicKeyPEM)
		if perr != nil {
			return registrytoken.JWKS{}, fmt.Errorf("registrytokenwire: parse public key %s: %w", k.KID, perr)
		}
		out.Keys = append(out.Keys, registrytoken.RSAPublicJWK(k.KID, pub))
	}
	return out, nil
}

// ── SA-key lookup ───────────────────────────────────────────────────────────

// SAKeyLookupAdapter — a subject's registered SA-key public halves (paged).
type SAKeyLookupAdapter struct {
	repo saKeyLister
}

// NewSAKeyLookup — builder.
func NewSAKeyLookup(repo saKeyLister) *SAKeyLookupAdapter {
	return &SAKeyLookupAdapter{repo: repo}
}

var _ registrytokenuc.SAKeyLookup = (*SAKeyLookupAdapter)(nil)

// PublicKeysForSubject pages the subject's SA-OAuth-client rows and returns the
// public-key halves (federated rows without key material are skipped).
func (a *SAKeyLookupAdapter) PublicKeysForSubject(ctx context.Context, subjectID string) ([]registrytokenuc.SAKeyRef, error) {
	var out []registrytokenuc.SAKeyRef
	pageToken := ""
	for {
		rows, next, err := a.repo.List(ctx, domain.ServiceAccountID(subjectID), pageToken, 200)
		if err != nil {
			return nil, fmt.Errorf("registrytokenwire: list SA keys: %w", err)
		}
		for _, row := range rows {
			if row.PublicKeyPEM == "" {
				continue // federated row — no key material to authenticate against.
			}
			out = append(out, registrytokenuc.SAKeyRef{
				PublicKeyPEM: row.PublicKeyPEM,
				ExpiresAt:    row.ExpiresAt,
			})
		}
		if next == "" {
			return out, nil
		}
		pageToken = next
	}
}

// ── AES-GCM decrypt (nonce||ciphertext, mirror of the JWKS encryptor) ────────

func decryptAESGCM(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, fmt.Errorf("registrytokenwire: ciphertext shorter than nonce")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], nil)
}

// parseRSAPrivatePEM parses a PKCS#8 RSA private-key PEM.
func parseRSAPrivatePEM(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("registrytokenwire: invalid private PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("registrytokenwire: current signing key is not RSA")
	}
	return rsaKey, nil
}

// parseRSAPublicPEM parses a PKIX RSA public-key PEM.
func parseRSAPublicPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("registrytokenwire: invalid public PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("registrytokenwire: public key is not RSA")
	}
	return rsaPub, nil
}
