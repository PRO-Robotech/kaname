// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package toproto

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
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

// TestAccessBindingToPb_RevocationReasonHasPresence — причина отзыва — поле с
// присутствием (kaname#963, URG-E2): у действующей выдачи и у выдачи, отозванной до
// заведения поля (R0, Д7), поле не задано вовсе; у выдачи, отозванной с причиной,
// задано словом словаря. Нулевое значение перечня вместо «не задано» вернуло бы ключ
// в тело края.
func TestAccessBindingToPb_RevocationReasonHasPresence(t *testing.T) {
	rat := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		status domain.AccessBindingStatus
		reason domain.RevocationReason
		want   *iamv1.AccessBinding_RevocationReason
	}{
		{"действующая", domain.AccessBindingStatusActive, domain.RevocationReasonNone, nil},
		{"отозвана до заведения поля", domain.AccessBindingStatusRevoked, domain.RevocationReasonNone, nil},
		{"глагол Revoke", domain.AccessBindingStatusRevoked, domain.RevocationReasonRevoke,
			iamv1.AccessBinding_REVOCATION_REASON_REVOKE.Enum()},
		{"истёк срок", domain.AccessBindingStatusRevoked, domain.RevocationReasonExpired,
			iamv1.AccessBinding_REVOCATION_REASON_EXPIRED.Enum()},
		{"снята регистрация", domain.AccessBindingStatusRevoked, domain.RevocationReasonResourceUnregistered,
			iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED.Enum()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := domain.AccessBinding{ID: "acb00000000000000rsn", Status: tc.status, RevocationReason: tc.reason}
			if tc.status == domain.AccessBindingStatusRevoked {
				b.RevokedAt = &rat
			}
			pb, err := abObj{}.toPb(b)
			require.NoError(t, err)
			if tc.want == nil {
				assert.Nil(t, pb.RevocationReason, "причина задана у выдачи без причины")
				return
			}
			require.NotNil(t, pb.RevocationReason, "причина не задана у отозванной с причиной")
			assert.Equal(t, *tc.want, pb.GetRevocationReason())
		})
	}
}
