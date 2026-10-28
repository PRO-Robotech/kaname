// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"log/slog"

	reconcileapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// newRequestBindingReconciler — реконсайлер привязки ПУТИ ЗАПРОСА.
func newRequestBindingReconciler(tx reconcileapp.TxRunner, logger *slog.Logger, cat catalog.Source,
	reg *metrics.Registry) *reconcileapp.Reconciler {
	return reconcileapp.New(tx, logger, cat).
		WithSizeRecorder(reg.BindingMaterializationRecorder().RequestLane())
}

// newSweepBindingReconciler — реконсайлер привязки ФОНОВОГО ОБХОДА.
func newSweepBindingReconciler(tx reconcileapp.TxRunner, logger *slog.Logger, cat catalog.Source,
	reg *metrics.Registry) *reconcileapp.Reconciler {
	_ = reg
	return reconcileapp.New(tx, logger, cat)
}
