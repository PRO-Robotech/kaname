// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// TestLoggerConfig_SlogLevel — the configured logger.level string maps to the
// right slog.Level. This is the wiring that revives the previously-dead
// logger.level config (the corelib logger hardcoded LevelInfo).
func TestLoggerConfig_SlogLevel(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
	}{
		{"DEBUG", slog.LevelDebug},
		{"debug", slog.LevelDebug},
		{"INFO", slog.LevelInfo},
		{"info", slog.LevelInfo},
		{"", slog.LevelInfo}, // empty → default INFO
		{"WARN", slog.LevelWarn},
		{"ERROR", slog.LevelError},
		{"FATAL", slog.LevelError}, // slog has no FATAL — clamp to ERROR
		{"  DEBUG  ", slog.LevelDebug},
	}
	for _, tc := range cases {
		got, err := config.LoggerConfig{Level: tc.in}.SlogLevel()
		if err != nil {
			t.Fatalf("SlogLevel(%q) returned error %v, want nil", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("SlogLevel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestLoggerConfig_SlogLevel_Unknown — an unknown level string is rejected with
// an error naming the allowed values (no silent clamp — operator typos are a
// boot-time misconfiguration).
func TestLoggerConfig_SlogLevel_Unknown(t *testing.T) {
	_, err := config.LoggerConfig{Level: "VERBOSE"}.SlogLevel()
	if err == nil {
		t.Fatal("SlogLevel(\"VERBOSE\") = nil error, want an error for an unknown level")
	}
	if !strings.Contains(err.Error(), "logger.level") {
		t.Fatalf("SlogLevel error = %q, want it to name logger.level", err.Error())
	}
}

// TestValidate_RejectsUnknownLoggerLevel — Config.Validate must reject an
// unknown logger.level so a typo fails fast at boot rather than silently
// degrading observability.
func TestValidate_RejectsUnknownLoggerLevel(t *testing.T) {
	cfg := goodEndpoints(config.ModeDev, "disable")
	cfg.Logger.Level = "TRACE"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for an unknown logger.level")
	}
	if !strings.Contains(err.Error(), "logger.level") {
		t.Fatalf("Validate() error = %q, want it to name logger.level", err.Error())
	}
}

// TestValidate_AcceptsKnownLoggerLevel — a known logger.level (and empty, which
// defaults to INFO) passes Validate.
func TestValidate_AcceptsKnownLoggerLevel(t *testing.T) {
	for _, lvl := range []string{"", "DEBUG", "info", "WARN", "ERROR", "FATAL"} {
		cfg := goodEndpoints(config.ModeDev, "disable")
		cfg.Logger.Level = lvl
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() with logger.level=%q = %v, want nil", lvl, err)
		}
	}
}
