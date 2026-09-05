// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// hydra_admin_client.go — client for the Ory Hydra Admin API.
//
// Carries the shared connection config (base URL, bearer, HTTP client) for the
// Hydra admin surfaces iam actually drives, each in its own file:
//   - hydra_oauth_clients.go — OAuth2 client lifecycle (/admin/clients).
//
// It no longer publishes or deletes JWKs. iam owns no signing keyset: it mints
// nothing, Hydra is the issuer and signer, and iam only serves a byte-identical
// read-only MIRROR of Hydra's public keyset on :9097. The PublishKey/DeleteKey
// pair existed solely for the nightly JWKSRotationService, which was retired
// (713f7e1) together with the key store it rotated (migration 0065) — the
// service.JWKSPublisher interface they implemented no longer exists.
//
// Authentication: if HYDRA_ADMIN_TOKEN env is set — Bearer; otherwise
// anonymous (default Hydra config in the kind dev-stand exposes an
// anonymous admin port).
package clients

import (
	"net/http"
	"strings"
	"time"
)

// HydraAdminClient — HTTP-клиент к Hydra admin API.
type HydraAdminClient struct {
	BaseURL     string
	BearerToken string
	HTTPClient  *http.Client
}

// NewHydraAdminClient — constructor without a pinned trust anchor. Default
// timeout 10s. Kept for call sites that address a plaintext in-cluster admin API
// (a developer stand); production addresses it over TLS and must therefore use
// NewHydraAdminClientWithCA.
func NewHydraAdminClient(baseURL, bearerToken string) *HydraAdminClient {
	return &HydraAdminClient{
		BaseURL:     strings.TrimRight(baseURL, "/"),
		BearerToken: bearerToken,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// NewHydraAdminClientWithCA builds the client and, when an anchor is configured,
// verifies the provider against THAT bundle and nothing else.
//
// caFile empty ⇒ the default transport, unchanged. That is not an oversight: an
// in-cluster admin API served over plaintext http needs no anchor, and inventing
// one would refuse a stand deliberately configured that way. The production boot
// guard is what forbids that combination in production (config.Validate).
//
// caFile set ⇒ the returned client trusts that bundle ALONE. Not "in addition to
// the system roots": an internal-CA hop has no business accepting a publicly
// issued certificate for the same name, and narrowing the anchor is the whole
// point of pinning it.
//
// An anchor that cannot be read, or that holds no certificate, is an ERROR rather
// than a fallback. Continuing on the system roots would produce the one state
// nobody can see — the operator has configured verification against the internal
// CA, the process is not doing it, and everything works until a certificate
// rotates.
func NewHydraAdminClientWithCA(baseURL, bearerToken, caFile string) (*HydraAdminClient, error) {
	c := NewHydraAdminClient(baseURL, bearerToken)
	httpClient, err := ProviderHopHTTPClient(c.HTTPClient.Timeout, caFile, adminHopCASetting)
	if err != nil {
		return nil, err
	}
	c.HTTPClient = httpClient
	return c, nil
}
