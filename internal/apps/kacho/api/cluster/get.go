// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package cluster

// get.go — GetClusterUseCase (InternalClusterService.Get).
//
// Synchronous read-only RPC. Returns the singleton Cluster row.
// No Operation envelope (not a mutation).

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// GetClusterUseCase — reads the singleton cluster row.
type GetClusterUseCase struct {
	reader clusterReader
}

// NewGetClusterUseCase — constructor.
func NewGetClusterUseCase(r clusterReader) *GetClusterUseCase {
	return &GetClusterUseCase{reader: r}
}

// Execute — returns the singleton cluster (domain.ClusterSingletonID).
func (uc *GetClusterUseCase) Execute(ctx context.Context) (domain.Cluster, error) {
	return uc.reader.Get(ctx)
}
