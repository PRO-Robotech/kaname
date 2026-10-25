// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

import (
	"testing"
	"time"
)

// TestTTLFromSecondsNeverReturnsAWrappedDuration — граница области перевода
// (kaname#993): наибольший представимый срок переводится дословно, срок на
// секунду длиннее и срок, заворачивающийся РОВНО в ноль, вне области; ноль —
// в области и остаётся нулём («срок не назван» судит вызывающий).
func TestTTLFromSecondsNeverReturnsAWrappedDuration(t *testing.T) {
	cases := []struct {
		name   string
		in     int64
		want   time.Duration
		wantOK bool
	}{
		{"ноль — срок не назван", 0, 0, true},
		{"час", 3600, time.Hour, true},
		{"наибольший представимый", MaxTTLSeconds, time.Duration(MaxTTLSeconds) * time.Second, true},
		{"на секунду длиннее представимого", MaxTTLSeconds + 1, 0, false},
		{"заворот ровно в ноль", 1 << 55, 0, false},
		{"отрицательный", -1, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := TTLFromSeconds(tc.in)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("TTLFromSeconds(%d) = (%v, %v); ожидалось (%v, %v)", tc.in, got, ok, tc.want, tc.wantOK)
			}
			if ok && got < 0 {
				t.Fatalf("TTLFromSeconds(%d) вернул отрицательную длительность %v", tc.in, got)
			}
		})
	}
}
