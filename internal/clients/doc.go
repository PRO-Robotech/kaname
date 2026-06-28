// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package clients — peer-gRPC clients for kacho-iam.
//
// kacho-iam is the leaf-owner of Account/Project/User and does not initiate
// peer-domain calls itself. The clients here are dependencies on adjacent
// systems (OpenFGA REBAC, OIDC providers, api-gateway cache invalidation,
// HSM/PKCS#11, S3 report-store, etc.) — see individual files for each
// client's scope.
//
// Peer-client template — `internal/clients/builder.go`-style: TTL+LRU
// cache + retries/dialTimeout/keepalive + TLS + optional
// dns:///+round_robin.
package clients
