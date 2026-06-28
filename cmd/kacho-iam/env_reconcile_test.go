// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"
	"time"
)

// TestEnvDurationMS_ReconcileDrain — интервал дрейна reconcile-очереди стал poll-fallback
// на пропущенный NOTIFY (дренаж теперь NOTIFY-driven), latency материализации несет NOTIFY.
// Интервал остается env-конфигурируемым; проверяем контракт envDurationMS на этом ключе:
// unset/garbage/non-positive → дефолт, валидное положительное → миллисекунды из env.
func TestEnvDurationMS_ReconcileDrain(t *testing.T) {
	const key = "KACHO_IAM_RECONCILE_DRAIN_INTERVAL_MS"
	const def = 1 * time.Second

	cases := []struct {
		name string
		set  string
		want time.Duration
	}{
		{"unset → default", "", def},
		{"override 200ms", "200", 200 * time.Millisecond},
		{"garbage → default", "abc", def},
		{"non-positive → default", "0", def},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(key, c.set)
			if got := envDurationMS(key, def); got != c.want {
				t.Fatalf("envDurationMS(%q=%q): got %v, want %v", key, c.set, got, c.want)
			}
		})
	}
}
