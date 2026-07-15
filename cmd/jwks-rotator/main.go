// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package main — `jwks-rotator` binary.
//
// CLI:
//
//	jwks-rotator once         — выполнить один rotation cycle (CronJob).
//	jwks-rotator daemon       — long-running daemon, tick каждые 1h (jittered).
//
// Configuration через те же ENV-переменные, что и kacho-iam serve:
//
//	KACHO_IAM_DB_URL / KACHO_IAM_DB_PASSWORD
//	KACHO_IAM_JWKS_ENC_KEY       — 32-byte hex AES-GCM key.
//	KACHO_IAM_HYDRA_ISSUER       — default https://hydra.<KACHO_IAM_DOMAIN>.
//	KACHO_IAM_HYDRA_ADMIN_TOKEN  — Bearer для Hydra admin (optional).
//	KACHO_IAM_DOMAIN             — публичный домен (default api.kacho.cloud).
//	KACHO_IAM_JWKS_ROTATION_DAYS — default 90.
//
// HA-safety: внутри Rotate уже advisory_xact_lock per-alg (см.
// internal/repo/kacho/pg/oidc_jwks_keys_repos.go::Rotate). Параллельные
// pod'ы безопасны.
package main

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/observability"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

const configPathEnv = "KACHO_IAM_CONFIG_PATH"

func main() {
	// Bootstrap logger for the pre-config phase (usage / config load+validate
	// run before the operator-set logger.level is known). Minimal stderr JSON
	// logger at LevelInfo; the level-aware operational logger is built after
	// cfg.Validate.
	bootLog := observability.NewSlogger(os.Stderr)

	if len(os.Args) < 2 {
		bootLog.Error("usage: jwks-rotator {once|daemon|dpop-cleanup}",
			slog.String("invocation", os.Args[0]))
		os.Exit(1)
	}
	cmd := os.Args[1]

	cfg, err := config.Load(os.Getenv(configPathEnv))
	if err != nil {
		bootLog.Error("config load failed", slog.Any("err", err))
		os.Exit(1)
	}
	if err := cfg.Validate(); err != nil {
		bootLog.Error("config validation failed", slog.Any("err", err))
		os.Exit(1)
	}

	// logger.level was validated above; SlogLevel cannot fail here. Defensive
	// fallback to INFO keeps the entry-point total.
	logLevel, _ := cfg.Logger.SlogLevel()
	logger := observability.NewSloggerLevel(os.Stdout, logLevel)
	slog.SetDefault(logger)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	pool, err := coredb.NewPool(ctx, cfg.DSN())
	if err != nil {
		logger.Error("pgxpool init failed", slog.Any("err", err))
		os.Exit(1)
	}
	defer pool.Close()

	switch cmd {
	case "once":
		if err := runOnce(ctx, cfg, pool, logger); err != nil {
			logger.Error("rotation once failed", slog.Any("err", err))
			os.Exit(1)
		}
	case "daemon":
		if err := runDaemon(ctx, cfg, pool, logger); err != nil {
			logger.Error("rotation daemon failed", slog.Any("err", err))
			os.Exit(1)
		}
	default:
		logger.Error("unknown command", slog.String("command", cmd))
		os.Exit(1)
	}
}

// pgxAdapter — thin adapter pgxpool→service.TXBeginner.
type pgxAdapter struct {
	pool *pgxpool.Pool
}

func (p *pgxAdapter) Begin(ctx context.Context) (service.Tx, error) {
	return p.pool.Begin(ctx)
}

func buildService(cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger) (*service.JWKSRotationService, error) {
	encKey, err := cfg.AuthN.ResolveJWKSEncryptionKey()
	if err != nil {
		return nil, err
	}
	repo := kachopg.NewOIDCJwksKeyRepo(pool)
	hydra := clients.NewHydraAdminClient(cfg.AuthN.ResolveHydraAdminURL(), os.Getenv("KACHO_IAM_HYDRA_ADMIN_TOKEN"))
	audit := &auditLoggerAdapter{logger: logger}
	svc := service.NewJWKSRotationService(
		service.JWKSRotationConfig{
			EncryptionKey:  encKey,
			RotationPeriod: cfg.AuthN.JWKSRotationDuration(),
			CleanupGrace:   30 * time.Minute,
			KidPrefix:      "kacho-",
		},
		repo,
		&pgxAdapter{pool: pool},
		hydra,
		audit,
		logger,
	)
	return svc, nil
}

func runOnce(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger) error {
	svc, err := buildService(cfg, pool, logger)
	if err != nil {
		return err
	}
	boot, rot, err := svc.Tick(ctx)
	if err != nil {
		return err
	}
	logger.Info("rotation tick complete", "bootstrapped", boot, "rotated", rot)
	return nil
}

func runDaemon(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger) error {
	svc, err := buildService(cfg, pool, logger)
	if err != nil {
		return err
	}
	// Первый tick — сразу при старте (для bootstrap).
	if boot, rot, err := svc.Tick(ctx); err != nil {
		logger.Error("initial tick failed", "err", err)
	} else {
		logger.Info("initial tick", "bootstrapped", boot, "rotated", rot)
	}

	// Daily ticks с ±10min jitter.
	baseInterval := 24 * time.Hour
	for {
		jitter := time.Duration(rand.Int64N(int64(20*time.Minute))) - 10*time.Minute // #nosec G404 -- non-crypto scheduler jitter, not security-sensitive.
		next := baseInterval + jitter
		logger.Info("next jwks rotation tick", "in", next.String())
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(next):
			boot, rot, err := svc.Tick(ctx)
			if err != nil {
				logger.Error("tick failed", "err", err)
				continue
			}
			logger.Info("tick complete", "bootstrapped", boot, "rotated", rot)
		}
	}
}

// auditLoggerAdapter — пишет audit events в structured log; in production
// можно подменить на адаптер, эмитящий в audit_outbox.
type auditLoggerAdapter struct {
	logger *slog.Logger
}

func (a *auditLoggerAdapter) Emit(ctx context.Context, eventType string, payload map[string]any) error {
	a.logger.Info("audit", "event_type", eventType, "payload", payload)
	return nil
}
