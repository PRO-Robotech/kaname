// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// hydra_admin_client.go — client for the Ory Hydra Admin API.
//
// Endpoints:
//   - PUT    /admin/keys/<set>          — publish new key (JWK) (create-or-update keyset).
//   - DELETE /admin/keys/<set>/<kid>    — delete key.
//
// Used by JWKSRotationService to sync the Kachō JWKS table with Hydra
// (the issuer for tokens is Hydra, not kacho-iam directly).
//
// Authentication: if HYDRA_ADMIN_TOKEN env is set — Bearer; otherwise
// anonymous (default Hydra config in the kind dev-stand exposes an
// anonymous admin port).
package clients

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// HydraAdminClient — HTTP-клиент к Hydra admin API.
type HydraAdminClient struct {
	BaseURL     string
	BearerToken string
	HTTPClient  *http.Client
	KeySet      string // default "hydra.openid.id-token"
}

// NewHydraAdminClient — constructor. Default timeout 10s, KeySet "hydra.openid.id-token".
func NewHydraAdminClient(baseURL, bearerToken string) *HydraAdminClient {
	return &HydraAdminClient{
		BaseURL:     strings.TrimRight(baseURL, "/"),
		BearerToken: bearerToken,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		KeySet: "hydra.openid.id-token",
	}
}

// PublishKey реализует service.JWKSPublisher.
//
// Конвертирует PEM-formatted public key в JWK (per RFC 7517) и PUT'ит в Hydra
// admin /admin/keys/<set> (create-or-update keyset).
func (c *HydraAdminClient) PublishKey(ctx context.Context, alg domain.JWKSAlg, kid string, publicKeyPEM string) error {
	jwk, err := publicKeyPEMToJWK(alg, kid, publicKeyPEM)
	if err != nil {
		return fmt.Errorf("convert PEM to JWK: %w", err)
	}
	body := map[string]any{
		"keys": []any{jwk},
	}
	bodyBytes, _ := json.Marshal(body)
	url := fmt.Sprintf("%s/admin/keys/%s", c.BaseURL, c.KeySet)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("hydra publish key: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("hydra publish key: status %d", resp.StatusCode)
	}
	return nil
}

// DeleteKey реализует service.JWKSPublisher.
func (c *HydraAdminClient) DeleteKey(ctx context.Context, kid string) error {
	url := fmt.Sprintf("%s/admin/keys/%s/%s", c.BaseURL, c.KeySet, kid)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("hydra delete key: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil // idempotent: already deleted
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("hydra delete key: status %d", resp.StatusCode)
	}
	return nil
}

// publicKeyPEMToJWK — конверсия PEM в JWK-форму (RFC 7517, секции 4 и 6).
func publicKeyPEMToJWK(alg domain.JWKSAlg, kid string, pemStr string) (map[string]any, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}

	jwk := map[string]any{
		"kid": kid,
		"use": "sig",
	}
	switch alg {
	case domain.JWKSAlgRS256Domain:
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("public key is not RSA")
		}
		jwk["kty"] = "RSA"
		jwk["alg"] = "RS256"
		jwk["n"] = base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes())
		jwk["e"] = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes())
	case domain.JWKSAlgES256Domain:
		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("public key is not ECDSA")
		}
		if ecKey.Curve != elliptic.P256() {
			return nil, errors.New("ES256 requires P-256 curve")
		}
		jwk["kty"] = "EC"
		jwk["alg"] = "ES256"
		jwk["crv"] = "P-256"
		// Uncompressed point (0x04 || X(32) || Y(32)) для P-256; извлекаем
		// fixed-length координаты для JWK x/y. Заменяет deprecated ecKey.X/Y.
		ecRaw, err := ecKey.Bytes()
		if err != nil {
			return nil, fmt.Errorf("encode EC public key: %w", err)
		}
		jwk["x"] = base64.RawURLEncoding.EncodeToString(ecRaw[1:33])
		jwk["y"] = base64.RawURLEncoding.EncodeToString(ecRaw[33:65])
	case domain.JWKSAlgEdDSADomain:
		edKey, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("public key is not Ed25519")
		}
		jwk["kty"] = "OKP"
		jwk["alg"] = "EdDSA"
		jwk["crv"] = "Ed25519"
		jwk["x"] = base64.RawURLEncoding.EncodeToString(edKey)
	default:
		return nil, fmt.Errorf("unsupported alg %s", alg)
	}
	return jwk, nil
}
