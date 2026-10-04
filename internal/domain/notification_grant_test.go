// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestDecideSend_EveryOutcomeAndTheGuardBoundary — таблица исходов Р5 и граница
// полосы на полной точности (NTF1-F20, УК8: дробная отсечка).
func TestDecideSend_EveryOutcomeAndTheGuardBoundary(t *testing.T) {
	const guard = 2 * time.Second
	c := time.Date(2026, 10, 4, 12, 0, 0, 123456000, time.UTC)
	tc := c.Add(time.Minute)
	for _, tt := range []struct {
		name  string
		found bool
		st    NotificationGrantState
		at    time.Time
		want  SendDecision
	}{
		{"записи нет", false, NotificationGrantState{}, c, SendNotYetGranted},
		{"запись без отсечки — строка до выдачи проходит", true, NotificationGrantState{}, c.Add(-time.Hour), SendAllow},
		{"надгробие пространства", true, NotificationGrantState{Revoked: true}, c.Add(time.Hour), SendRevoked},
		{"надгробие шаблона", true, NotificationGrantState{TemplateRevoked: true}, c.Add(time.Hour), SendRevoked},
		{"c − 0,5s", true, NotificationGrantState{Cutoff: &c}, c.Add(-500 * time.Millisecond), SendRevoked},
		{"c + G − 1ns", true, NotificationGrantState{Cutoff: &c}, c.Add(guard - time.Nanosecond), SendRevoked},
		{"c + G", true, NotificationGrantState{Cutoff: &c}, c.Add(guard), SendAllow},
		{"за полосой пространства, в полосе шаблона", true,
			NotificationGrantState{Cutoff: &c, TemplateCutoff: &tc}, c.Add(guard), SendRevoked},
		{"за обеими полосами", true,
			NotificationGrantState{Cutoff: &c, TemplateCutoff: &tc}, tc.Add(guard), SendAllow},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, DecideSend(tt.found, tt.st, tt.at, guard))
		})
	}
}
