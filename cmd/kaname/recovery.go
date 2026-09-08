// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/operationresolver"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// startLROReconciler wires the orphan-reconciler backstop. Without it an operation
// left done=false by a crashed worker (kill-9, drain-timeout, or an exhausted
// terminal-write budget) would strand forever — the worker only recovers
// operations it dispatched in THIS process. The reconciler claims orphans
// (FOR UPDATE SKIP LOCKED, so replicas partition the set) and resolves each to its
// terminal outcome from the committed reality of the resource. It runs a boot
// sweep + a periodic background sweep; it is non-fatal by contract.
func startLROReconciler(ctx context.Context, pool *pgxpool.Pool, repo kanamerepo.Repository, catalogSource catalog.Source, rec operations.Recorder, logger *slog.Logger) {
	resolver := operationresolver.New(repo, catalogSource, operationresolver.WithLogger(logger))
	reconciler := operations.NewReconciler(pool, resolver, operations.ReconcilerConfig{
		Schema: "kaname",
	}, operations.WithReconcilerRecorder(rec), operations.WithReconcilerLogger(logger))
	go reconciler.Run(ctx)
	logger.Info("LRO orphan reconciler backstop started", "schema", "kaname")
}
