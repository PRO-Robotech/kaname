// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Граница семейства — меньшее из срока сессии и потолка семейства фундамента от
// рождения семейства. Сессия без срока границы не сужает.
func TestCeremonyFamilyBound(t *testing.T) {
	born := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	ceiling := born.Add(tokenpolicy.MaxRefreshTokenFamilyTTL)
	for _, tc := range []struct {
		name    string
		session time.Time
		want    time.Time
	}{
		{"сессия кончается раньше потолка", born.Add(time.Hour), born.Add(time.Hour)},
		{"сессия кончается позже потолка", ceiling.Add(time.Hour), ceiling},
		{"сессия без срока", time.Time{}, ceiling},
	} {
		if got := domain.CeremonyFamilyBound(born, tc.session); !got.Equal(tc.want) {
			t.Errorf("%s: граница %s, ожидалась %s", tc.name, got, tc.want)
		}
	}
}
