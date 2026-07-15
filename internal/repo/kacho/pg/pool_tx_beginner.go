// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// pool_tx_beginner.go — service.TxBeginner adapter over *pgxpool.Pool for
// use-cases in the cluster-admin grant flow (GrantAdmin / RevokeAdmin).
//
// The returned pgx.Tx satisfies service.Tx because service.Tx is defined as
// `interface{}` (opaque) and txAsPgx recovers the concrete type via type
// assertion. Composition root (cmd/kacho-iam/wiring.go) passes a
// *PoolTxBeginner to the cluster use-cases.

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// PoolTxBeginner — wraps *pgxpool.Pool to implement service.TxBeginner.
// The pgx.Tx it produces satisfies service.Tx (opaque interface implemented
// by any concrete pgx.Tx via txAsPgx).
type PoolTxBeginner struct {
	pool *pgxpool.Pool
}

// NewPoolTxBeginner — constructor.
func NewPoolTxBeginner(pool *pgxpool.Pool) *PoolTxBeginner {
	return &PoolTxBeginner{pool: pool}
}

// Begin — opens a read-write transaction from the pool.
func (b *PoolTxBeginner) Begin(ctx context.Context) (service.Tx, error) {
	return b.pool.Begin(ctx)
}

// Compile-time assertion.
var _ service.TxBeginner = (*PoolTxBeginner)(nil)
