// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// TestMetricsListenAddress_Default — the metrics HTTP listener defaults to a
// separate internal port (:9095), never the public tenant surface
// (RED: no MetricsEndpoint / MetricsListenAddress yet).
func TestMetricsListenAddress_Default(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.APIServer.MetricsListenAddress(); got != "0.0.0.0:9095" {
		t.Fatalf("MetricsListenAddress() = %q, want %q", got, "0.0.0.0:9095")
	}
	// Must differ from public + internal gRPC ports (never expose internal
	// cardinality on the tenant-facing :9090).
	if cfg.APIServer.MetricsListenAddress() == cfg.APIServer.ListenAddress() {
		t.Fatal("metrics listener must not share the public gRPC port")
	}
}

// TestMetricsListenAddress_NormalisesEndpoint — bare port + tcp:// forms
// normalise like the other listeners.
func TestMetricsListenAddress_NormalisesEndpoint(t *testing.T) {
	t.Parallel()
	c := config.APIServerConfig{MetricsEndpoint: "tcp://0.0.0.0:7000"}
	if got := c.MetricsListenAddress(); got != "0.0.0.0:7000" {
		t.Fatalf("MetricsListenAddress() = %q, want 0.0.0.0:7000", got)
	}
	c2 := config.APIServerConfig{MetricsEndpoint: "9999"}
	if got := c2.MetricsListenAddress(); got != ":9999" {
		t.Fatalf("MetricsListenAddress() = %q, want :9999", got)
	}
	c3 := config.APIServerConfig{MetricsEndpoint: ""}
	if got := c3.MetricsListenAddress(); got != "" {
		t.Fatalf("empty endpoint MetricsListenAddress() = %q, want empty", got)
	}
}
