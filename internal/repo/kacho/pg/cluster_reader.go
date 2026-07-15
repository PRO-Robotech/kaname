// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// cluster_reader.go — read-only adapter for the singleton Cluster
// row (`cluster_kacho_root`).
//
// Thin wrapper over the existing `ClusterRepo.GetSingleton` (iam_core_repos.go).
// Exposed as a dedicated `ClusterReader` type so use-cases / handler
// can depend on a clean port-interface named after the RPC
// (InternalClusterService.Get) rather than the broader ClusterRepo.
package pg

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ClusterReader — singleton cluster row reader. Used by
// InternalClusterService.Get.
type ClusterReader struct {
	inner *ClusterRepo
}

// NewClusterReader — composition root constructor.
func NewClusterReader(pool *pgxpool.Pool) *ClusterReader {
	return &ClusterReader{inner: NewClusterRepo(pool)}
}

// Get — returns the singleton `cluster_kacho_root` row. The DB CHECK
// `clusters_id_singleton_ck` guarantees there is at most one cluster row,
// and migration 0001 section 3 seeds it on schema init.
func (r *ClusterReader) Get(ctx context.Context) (domain.Cluster, error) {
	return r.inner.GetSingleton(ctx)
}
