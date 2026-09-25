// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package tokenrevocation_test

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

// TestRevoked_AuthorizationFamilyIsACutoffKey — отзыв семейства авторизации
// (LINE-A-1 Р8) задевает предъявителей ЭТОЙ авторизации и не задевает
// предъявителя другой авторизации того же человека.
func TestRevoked_AuthorizationFamilyIsACutoffKey(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	r := &stubReader{before: map[string]time.Time{"agr-revoked": now.Add(time.Minute)}}
	mine := claims(map[string]any{"sub": "usr-alice", "iat": float64(now.Unix()), domain.ClaimAuthorizationID: "agr-revoked"})
	other := claims(map[string]any{"sub": "usr-alice", "iat": float64(now.Unix()), domain.ClaimAuthorizationID: "agr-live"})

	if revoked, err := tokenrevocation.Revoked(context.Background(), r, other); err != nil || revoked {
		t.Fatalf("положительный близнец: предъявитель другой авторизации отозван (%v, %v)", revoked, err)
	}
	if revoked, err := tokenrevocation.Revoked(context.Background(), r, mine); err != nil || !revoked {
		t.Fatalf("предъявитель отозванного семейства принят (%v, %v)", revoked, err)
	}
	keys := tokenrevocation.Keys(mine)
	if len(keys) != 2 || keys[1] != "agr-revoked" {
		t.Fatalf("ключи отсечки %v: ключ семейства не читается правилом", keys)
	}
}
