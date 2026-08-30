// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package clients — peer-gRPC clients for kacho-iam.
//
// kacho-iam is the leaf-owner of Account/Project/User and does not initiate
// peer-domain calls itself. The clients here are dependencies on adjacent
// systems (OIDC providers, HSM/PKCS#11, S3 report-store, etc.) — see
// individual files for each client's scope. A client that pushed cache
// invalidation to the edge used to be listed here; that edge was retired
// (the edge now reads the subject-change journal itself), so nothing dials
// it any more.
// A client to an external relations engine used to stand here too; the verdict
// is now computed in this service's own database, so there is nothing to dial.
//
// Peer-client template — `internal/clients/builder.go`-style: TTL+LRU
// cache + retries/dialTimeout/keepalive + TLS + optional
// dns:///+round_robin.
package clients
