// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"fmt"
	"log/slog"
	"strings"
)

// SlogLevel maps the configured logger.level string (FATAL|ERROR|WARN|INFO|
// DEBUG, case-insensitive) to a slog.Level. The composition root passes the
// result to observability.NewSloggerLevel so the operator-set level is actually
// honoured (the corelib default logger hardcoded LevelInfo, leaving this config
// dead).
//
//   - Empty → INFO (the default).
//   - FATAL → slog.LevelError: slog has no FATAL level; the highest standard
//     level is ERROR, so FATAL clamps onto it (kept as an accepted alias so an
//     operator's FATAL does not fail boot).
//   - Unknown → error naming logger.level + the allowed set (a typo is a
//     boot-time misconfiguration, surfaced loudly rather than silently degrading
//     observability).
func (l LoggerConfig) SlogLevel() (slog.Level, error) {
	switch strings.ToUpper(strings.TrimSpace(l.Level)) {
	case "", "INFO":
		return slog.LevelInfo, nil
	case "DEBUG":
		return slog.LevelDebug, nil
	case "WARN", "WARNING":
		return slog.LevelWarn, nil
	case "ERROR", "FATAL":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf(
			"logger.level=%q invalid (allowed: FATAL, ERROR, WARN, INFO, DEBUG)", l.Level)
	}
}
