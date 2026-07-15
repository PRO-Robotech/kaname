// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package main — single-purpose binary `kacho-iam`.
// Этот binary обслуживает только `serve` (gRPC API + internal endpoint);
// миграции — отдельный binary `cmd/migrator` (cobra-based).
//
// Thin entry-point. Responsibilities кратко: загрузить config, выбрать
// subcommand (только `serve` поддерживается), передать управление в
// runServe (см. serve.go). Все реальное wiring живет в:
//   - serve.go — lifecycle (pools, listeners, parallel.ExecAbstract, shutdown)
//   - wiring.go — composition (services struct + builders)
//   - grpc_register.go — public/internal RPC registration
//   - hooks_mux.go — HTTP hooks mux (Hydra token/refresh)
//   - env.go — env-helpers (DSN mask, FGA timeouts)
//   - listeners.go / governance_wiring.go /
//     subject_change_wiring.go — phase-specific wiring
package main

import (
	"log/slog"
	"os"

	"github.com/PRO-Robotech/kacho/pkg/observability"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// configPathEnv — путь к YAML-конфигу. Пустое значение допустимо (defaults +
// ENV-override). Helm chart выставляет KACHO_IAM_CONFIG_PATH=/etc/kacho-iam/config.yaml.
const configPathEnv = "KACHO_IAM_CONFIG_PATH"

func main() {
	// kacho-iam — single-purpose binary.
	// Миграции вынесены в отдельный `cmd/migrator` (cobra-based).

	// Bootstrap logger for the pre-config phase: config.Load/Validate run before
	// the operator-set logger.level is known, so this minimal stderr JSON logger
	// (LevelInfo) carries only fatal startup errors. The level-aware logger (per
	// cfg.Logger.Level) is built in runServe once config is validated.
	bootLog := observability.NewSlogger(os.Stderr)

	cfg, err := config.Load(os.Getenv(configPathEnv))
	if err != nil {
		bootLog.Error("config load failed", slog.Any("err", err))
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		bootLog.Error("config validation failed", slog.Any("err", err))
		os.Exit(1)
	}

	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "serve":
			// no-op: продолжаем в runServe
		case "migrate":
			bootLog.Error("`kacho-iam migrate ...` is not supported — use the separate binary `kacho-migrator {up|down|status|create}`")
			os.Exit(1)
		default:
			bootLog.Error("unknown command (this binary only serves the API; migrations live in `kacho-migrator`)",
				slog.String("command", os.Args[1]))
			os.Exit(1)
		}
	}

	if err := runServe(cfg); err != nil {
		bootLog.Error("kacho-iam exited with error", slog.Any("err", err))
		os.Exit(1)
	}
}
