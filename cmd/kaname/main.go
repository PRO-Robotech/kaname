// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package main — binary `kaname`.
// Подкоманд две: `serve` (gRPC API + internal endpoint; она же — умолчание) и
// `signing-key` — жизненный цикл ключа подписи, достижимый оператором
// (signing_key_command.go, #314). Миграции — отдельный binary `cmd/migrator`.
//
// Thin entry-point. Responsibilities кратко: загрузить config, выбрать
// subcommand, передать управление в runServe (см. serve.go) либо в
// runSigningKeyCommand. Все реальное wiring живет в:
//   - serve.go — lifecycle (pools, listeners, parallel.ExecAbstract, shutdown)
//   - wiring.go — composition (services struct + builders)
//   - grpc_register.go — public/internal RPC registration
//   - hooks_mux.go — HTTP hooks mux (Hydra token/refresh)
//   - env.go — env-helpers (DSN mask, FGA timeouts)
//   - listeners.go / governance_wiring.go /
//     wiring.go — phase-specific wiring
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/PRO-Robotech/corelib/observability"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
)

// configPathEnv — путь к YAML-конфигу. Пустое значение допустимо (defaults +
// ENV-override). Helm chart выставляет KANAME_CONFIG_PATH=/etc/kaname/config.yaml.
const configPathEnv = "KANAME_CONFIG_PATH"

func main() {
	// Миграции вынесены в отдельный `cmd/migrator` (cobra-based).

	// Bootstrap logger for the pre-config phase: config.Load/Validate run before
	// the operator-set logger.level is known, so this minimal stderr JSON logger
	// (LevelInfo) carries only fatal startup errors. The level-aware logger (per
	// cfg.Logger.Level) is built in runServe once config is validated.
	bootLog := observability.NewSlogger(os.Stderr)

	// Продукт объявляет, чем он называет себя в теле отказа, — ДО загрузки
	// настройки и до подъёма чего бы то ни было: производители отказа читают
	// объявление на первом же запросе, а отказ настройки — уже отказ, и он
	// уезжает с доменом. Задача продукта #2099, сценарий WIRE-3-03 приёмки
	// WIRE-1.
	if err := refusaldomain.Declare(refusaldomain.ProductSuffix); err != nil {
		bootLog.Error("refusal domain declaration failed", slog.Any("err", err))
		os.Exit(1)
	}

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
		case signingKeyCommandName:
			// Команда оператора идёт ПОСЛЕ той же загрузки и того же стража
			// настройки, что служба: ключ меняет процесс, настроенный как она.
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
			code := runSigningKeyCommand(ctx, cfg, os.Args[2:], os.Stdout, bootLog)
			stop()
			os.Exit(code)
		case "migrate":
			bootLog.Error("`kaname migrate ...` is not supported — use the separate binary `kaname-migrator {up|down|status}`")
			os.Exit(1)
		default:
			bootLog.Error("unknown command (commands: `serve`, `signing-key`; migrations live in `kaname-migrator`)",
				slog.String("command", os.Args[1]))
			os.Exit(1)
		}
	}

	if err := runServe(cfg); err != nil {
		bootLog.Error("kaname exited with error", slog.Any("err", err))
		os.Exit(1)
	}
}
