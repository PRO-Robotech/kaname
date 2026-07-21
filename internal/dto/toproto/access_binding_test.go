// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package toproto

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// redesign-2026 F10: the lifecycle status + audit columns MUST be surfaced on
// every AccessBinding read. Regression lock for the dropped-projection bug where
// toPb omitted Status → every binding read back as STATUS_UNSPECIFIED and :revoke
// was invisible to clients.
func TestAccessBindingToPb_LifecycleProjected(t *testing.T) {
	granter := domain.UserID("usr00000000000000gra")

	active, err := abObj{}.toPb(domain.AccessBinding{
		ID:              domain.AccessBindingID("acb00000000000000act"),
		Status:          domain.AccessBindingStatusActive,
		GrantedByUserID: granter,
	})
	require.NoError(t, err)
	assert.Equal(t, iamv1.AccessBinding_ACTIVE, active.GetStatus(), "ACTIVE binding must project ACTIVE, not STATUS_UNSPECIFIED")
	assert.Equal(t, "usr00000000000000gra", active.GetGrantedByUserId())

	revoker := domain.UserID("usr00000000000000rev")
	rat := time.Date(2026, 7, 21, 3, 4, 5, 987654321, time.UTC)
	revoked, err := abObj{}.toPb(domain.AccessBinding{
		ID:              domain.AccessBindingID("acb00000000000000rvk"),
		Status:          domain.AccessBindingStatusRevoked,
		RevokedAt:       &rat,
		RevokedByUserID: &revoker,
	})
	require.NoError(t, err)
	assert.Equal(t, iamv1.AccessBinding_REVOKED, revoked.GetStatus())
	assert.Equal(t, "usr00000000000000rev", revoked.GetRevokedByUserId())
	require.NotNil(t, revoked.GetRevokedAt())
	// truncated to the API second granularity (parity with created_at)
	assert.Equal(t, rat.Truncate(time.Second).Unix(), revoked.GetRevokedAt().AsTime().Unix())
	assert.Equal(t, int32(0), revoked.GetRevokedAt().GetNanos())
}

// An unset status projects STATUS_UNSPECIFIED (never guessed), and nullable
// timestamps stay nil.
func TestAccessBindingToPb_UnsetStatusAndNullables(t *testing.T) {
	pb, err := abObj{}.toPb(domain.AccessBinding{ID: domain.AccessBindingID("acb00000000000000non")})
	require.NoError(t, err)
	assert.Equal(t, iamv1.AccessBinding_STATUS_UNSPECIFIED, pb.GetStatus())
	assert.Nil(t, pb.GetRevokedAt())
	assert.Nil(t, pb.GetExpiresAt())
	assert.Equal(t, "", pb.GetRevokedByUserId())
}
