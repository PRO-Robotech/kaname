// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Граница семейства — меньшее из срока сессии и рождения плюс срок семейства.
// Сессия без срока границы не сужает. Срок — параметр: граница следует за ним,
// а не за константой (kaname#318).
func TestCeremonyFamilyBound(t *testing.T) {
	born := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	for _, familyTTL := range []time.Duration{2 * time.Hour, 168 * time.Hour} {
		end := born.Add(familyTTL)
		for _, tc := range []struct {
			name    string
			session time.Time
			want    time.Time
		}{
			{"сессия кончается раньше срока семейства", born.Add(time.Hour), born.Add(time.Hour)},
			{"сессия кончается позже срока семейства", end.Add(time.Hour), end},
			{"сессия без срока", time.Time{}, end},
		} {
			if got := domain.CeremonyFamilyBound(born, tc.session, familyTTL); !got.Equal(tc.want) {
				t.Errorf("срок семейства %s, %s: граница %s, ожидалась %s", familyTTL, tc.name, got, tc.want)
			}
		}
	}
}
