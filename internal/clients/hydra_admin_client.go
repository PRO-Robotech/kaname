// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// hydra_admin_client.go — client for the Ory Hydra Admin API.
//
// Carries the shared connection config (base URL, bearer, HTTP client) for the
// Hydra admin surfaces iam actually drives, each in its own file:
//   - hydra_oauth_clients.go — OAuth2 client lifecycle (/admin/clients).
//   - hydra_trust_grants.go  — JWT-bearer trust grants (/admin/trust/grants).
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

// NewHydraAdminClient — constructor. Default timeout 10s.
func NewHydraAdminClient(baseURL, bearerToken string) *HydraAdminClient {
	return &HydraAdminClient{
		BaseURL:     strings.TrimRight(baseURL, "/"),
		BearerToken: bearerToken,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}
