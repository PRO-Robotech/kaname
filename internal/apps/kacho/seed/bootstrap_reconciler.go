// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package seed

// bootstrap_reconciler.go — startup reconciler that drives RunBootstrapAdmin
// to convergence.
//
// Why a loop (not a one-shot call): RunBootstrapAdmin grants
// `system_admin@cluster_kacho_root` to the bootstrap user identified by
// KACHO_IAM_BOOTSTRAP_ROOT_EMAIL and enqueues the FGA tuple into the
// transactional fga_outbox. But the bootstrap user row only appears in
// kacho_iam.users on first login / fixture upsert (InternalUserService.
// UpsertFromIdentity), which happens AFTER kacho-iam boots. A single startup
// call therefore races the user row and skips ("user not registered"), so the
// cluster-admin tuple is never written → cluster-scope AccessBinding cases
// 403/404 (Bug B). The reconciler re-runs on an interval until the grant
// commits (Skipped=false) or a terminal skip ("email empty") short-circuits.
//
// Idempotent: once the grant exists, a subsequent run returns the 23505
// graceful-skip path — but the reconciler stops on the first committed grant,
// so that path is only hit on HA cold-start races.
//
// This is a thin orchestration seam (composition-root concern); the actual
// DB/outbox work stays in RunBootstrapAdmin. The runner is injected so the
// loop semantics are unit-testable without a database.

import (
	"context"
	"log/slog"
	"time"
)

// BootstrapRunFn — the unit of work the reconciler drives. In production this
// is a closure over RunBootstrapAdmin(pool, ...); tests inject a fake.
type BootstrapRunFn func(ctx context.Context) (BootstrapAdminResult, error)

// BootstrapReconcilerConfig — tunables.
type BootstrapReconcilerConfig struct {
	// Interval between retry attempts while the run keeps skipping. Defaults
	// to 10s when zero.
	Interval time.Duration
	// Logger — optional; slog.Default() when nil.
	Logger *slog.Logger
}

// BootstrapReconciler re-runs a BootstrapRunFn until it commits the grant.
type BootstrapReconciler struct {
	run      BootstrapRunFn
	interval time.Duration
	logger   *slog.Logger
}

// NewBootstrapReconciler constructs a reconciler around the supplied runner.
func NewBootstrapReconciler(run BootstrapRunFn, cfg BootstrapReconcilerConfig) *BootstrapReconciler {
	interval := cfg.Interval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &BootstrapReconciler{run: run, interval: interval, logger: logger}
}

// Run drives the runner to convergence. It returns nil on:
//   - committed grant (Skipped=false),
//   - terminal skip ("email empty" — no email configured, nothing to do),
//   - context cancellation (clean shutdown; never-converged is not an error).
//
// Transient errors and non-terminal skips ("user not registered") are retried
// on the configured interval. Run is non-fatal by contract — the bootstrap
// grant is a best-effort startup convenience, never a hard startup gate.
func (r *BootstrapReconciler) Run(ctx context.Context) error {
	// Immediate first attempt (don't wait a full interval on a fresh boot).
	for {
		res, err := r.run(ctx)
		switch {
		case err != nil:
			r.logger.WarnContext(ctx, "bootstrap admin reconcile attempt failed, will retry", slog.Any("err", err))
		case !res.Skipped:
			r.logger.InfoContext(ctx, "bootstrap admin reconciled — cluster-admin grant committed",
				slog.String("user_id", res.UserID),
				slog.String("grant_id", res.GrantID),
				slog.String("fga_outbox_id", res.FGAOutboxID))
			return nil
		case res.SkipReason == "email empty":
			// No bootstrap email configured — terminal, nothing to reconcile.
			r.logger.DebugContext(ctx, "bootstrap admin disabled (no email), reconciler exiting")
			return nil
		default:
			// Non-terminal skip (user not registered yet / concurrent race) — retry.
			r.logger.DebugContext(ctx, "bootstrap admin not yet reconciled, will retry",
				slog.String("reason", res.SkipReason))
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(r.interval):
		}
	}
}
