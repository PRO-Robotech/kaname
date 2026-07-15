// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package cluster

// list_admins.go — ListAdminsUseCase (InternalClusterService.ListAdmins).
//
// Synchronous read-only RPC. Returns all currently-active cluster admin grants
// with denormalised user fields (email, display_name) resolved by the SQL JOIN
// in ClusterAdminGrantReader.ListActive.

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ListAdminsUseCase — reads all active cluster admin grants.
type ListAdminsUseCase struct {
	reader grantReader
}

// NewListAdminsUseCase — constructor.
func NewListAdminsUseCase(r grantReader) *ListAdminsUseCase {
	return &ListAdminsUseCase{reader: r}
}

// Execute — returns the slice of active ClusterAdminEntry rows.
func (uc *ListAdminsUseCase) Execute(ctx context.Context) ([]domain.ClusterAdminEntry, error) {
	return uc.reader.ListActive(ctx)
}
