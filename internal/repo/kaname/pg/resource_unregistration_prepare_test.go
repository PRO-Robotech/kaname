// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"testing"
	"time"
)

func TestResourceUnregistrationVersionPreservesLegacyAndOrderedCases(t *testing.T) {
	old := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	newer := old.Add(time.Hour)
	for _, tc := range []struct {
		name              string
		stored, tombstone time.Time
		want              bool
	}{
		{"legacy removes legacy", time.Time{}, time.Time{}, true},
		{"ordered removes legacy", time.Time{}, old, true},
		{"legacy does not remove ordered mirror", old, time.Time{}, false},
		{"same version", old, old, true},
		{"older tombstone", newer, old, false},
		{"newer tombstone", old, newer, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := resourceVersionAtMost(tc.stored, tc.tombstone); got != tc.want {
				t.Fatalf("got=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestResourceStoredVersionRejectsUnprovedCoordinates(t *testing.T) {
	for _, raw := range []string{`null`, `"infinity"`, `""`, `0`, `"0001-01-01T00:00:00Z"`, `"not-a-time"`} {
		if _, err := resourceStoredVersion(json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	got, err := resourceStoredVersion(json.RawMessage(`"-infinity"`))
	if err != nil || !got.IsZero() {
		t.Fatalf("legacy=%v %v", got, err)
	}
	got, err = resourceStoredVersion(json.RawMessage(`"2026-11-14T10:00:00.123456+00:00"`))
	if err != nil || got.Nanosecond() != 123456000 {
		t.Fatalf("finite=%v %v", got, err)
	}
}
