// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// TestMetricsListener_ConfiguredSeparatePort — the composition root must serve
// /metrics on a SEPARATE cluster-internal port (default :9095), never the
// public tenant gRPC surface (exposing the registry there would leak internal
// cardinality — security.md). Behavioural check against the loaded config.
func TestMetricsListener_ConfiguredSeparatePort(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	metricsAddr := cfg.APIServer.MetricsListenAddress()
	if metricsAddr == "" {
		t.Fatal("metrics listener disabled by default — observability gap")
	}
	if metricsAddr == cfg.APIServer.ListenAddress() {
		t.Errorf("metrics addr %q == public gRPC addr — must be a separate port", metricsAddr)
	}
	if metricsAddr == cfg.APIServer.InternalListenAddress() {
		t.Errorf("metrics addr %q == internal gRPC addr — must be a separate port", metricsAddr)
	}
}

// TestServeWiresMetricsInterceptorAndListener — composition-root guard. serve.go
// must (1) create the prometheus registry, (2) register the gRPC metrics
// interceptor on BOTH listeners, and (3) stand up the /metrics HTTP listener.
//
// RED-demonstration: drop metricsReg.UnaryServerInterceptor() / the metrics
// listener from serve.go → this test fails before merge.
func TestServeWiresMetricsInterceptorAndListener(t *testing.T) {
	src := readFileT(t, "serve.go")

	for _, want := range []string{
		"metrics.NewRegistry()",
		"metricsReg.UnaryServerInterceptor()",
		"cfg.APIServer.MetricsListenAddress()",
		`metricsMux.Handle("/metrics", metricsReg.Handler())`,
		"metricsHTTPServer.Serve(metricsListener)",
		"metricsHTTPServer.Shutdown(",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("serve.go: missing metrics wiring %q", want)
		}
	}

	// The metrics interceptor must appear on BOTH gRPC servers — once for the
	// public listener, once for the internal listener.
	if got := strings.Count(src, "metricsReg.UnaryServerInterceptor()"); got != 2 {
		t.Errorf("metricsReg.UnaryServerInterceptor() wired %d times, want 2 (public + internal)", got)
	}
}
