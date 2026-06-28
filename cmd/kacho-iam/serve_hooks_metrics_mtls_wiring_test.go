// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"strings"
	"testing"
)

// TestHooksMetricsMTLS_ServeWiresTLSListeners — P0 hardening wiring guard.
//
// serve.go must wrap the HTTP hooks (:9092) and /metrics (:9095) net.Listen with
// tls.NewListener using a *tls.Config built per-edge from config.LoadMTLS() →
// HooksServerTLSConfig()/MetricsServerTLSConfig(). Default-off: when the *tls.Config
// is nil (enable=false) the listener stays PLAINTEXT (byte-identical to today).
//
// RED-demonstration: remove the tls.NewListener wrap / the per-edge builders from
// serve.go → this test fails before merge.
func TestHooksMetricsMTLS_ServeWiresTLSListeners(t *testing.T) {
	src := readFileT(t, "serve.go")

	// Both per-edge HTTP-listener TLS builders must be invoked in the
	// composition root.
	for _, m := range []string{"HooksServerTLSConfig()", "MetricsServerTLSConfig()"} {
		if !strings.Contains(src, m) {
			t.Errorf("serve.go: нет вызова %s (per-edge HTTP listener mTLS builder)", m)
		}
	}

	// The hooks + metrics listeners must be conditionally wrapped with
	// tls.NewListener (only when the per-edge *tls.Config is non-nil).
	if got := strings.Count(src, "tls.NewListener("); got < 2 {
		t.Errorf("serve.go: tls.NewListener( appears %d times, want >=2 (hooks + metrics)", got)
	}

	// MTLSConfig.Validate() must be called so an enabled-but-no-cert edge fails
	// fast at boot (fail-closed).
	if !strings.Contains(src, "mtlsCfg.Validate()") {
		t.Errorf("serve.go: нет mtlsCfg.Validate() — enabled-but-no-cert edge не fail-close'ится на старте")
	}

	// Startup log must reflect the two new per-edge states (observability +
	// audit trail that the listener is/ isn't TLS).
	for _, want := range []string{"hooks_mtls", "metrics_mtls"} {
		if !strings.Contains(src, want) {
			t.Errorf("serve.go: startup log не содержит %q (per-edge HTTP mTLS state)", want)
		}
	}
}
