// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// jwks_proxy.go — config for the cluster-INTERNAL Hydra-JWKS proxy HTTP listener
// (`GET /.well-known/jwks.json`).
//
// The listener is a short-TTL caching reverse-proxy of Hydra's PUBLIC JWKS: the
// data-plane (kacho-registry) fetches its verification keys from iam instead of
// dialing Hydra directly, while Hydra stays the token issuer/signer (iam mints
// nothing). It is served ONLY on the cluster-internal `kacho-iam-internal` Service
// (never external, ban #6) over one-way server-TLS (internal-CA leaf) — the
// Service wiring lives in kacho-deploy. The upstream Hydra JWKS URL is resolved
// via AuthNConfig.ResolveHydraJWKSURL (env KACHO_IAM_HYDRA_JWKS_URL).
package config

// JWKSProxyConfig — api-server.jwks-proxy section.
//
//	Endpoint — HTTP listen address (`tcp://0.0.0.0:9097` or bare `9097`).
//	           Empty disables the listener.
type JWKSProxyConfig struct {
	Endpoint string `mapstructure:"endpoint"`
}

// ListenAddress — normalised listen-addr for the JWKS-proxy HTTP server (empty
// endpoint → empty, i.e. the listener is disabled). A SEPARATE cluster-internal
// port from the gRPC / hooks / metrics / registry-token listeners.
func (c JWKSProxyConfig) ListenAddress() string { return listenAddress(c.Endpoint) }
