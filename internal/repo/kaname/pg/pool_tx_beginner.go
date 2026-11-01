// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// pool_tx_beginner.go — service.TxBeginner adapter over *pgxpool.Pool for
// use-cases in the cluster-admin grant flow (GrantAdmin / RevokeAdmin).
//
// The returned pgx.Tx satisfies service.Tx because service.Tx is defined as
// `interface{}` (opaque) and txAsPgx recovers the concrete type via type
// assertion. Composition root (cmd/kaname/wiring.go) passes a
// *PoolTxBeginner to the cluster use-cases.

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/service"
)

// PoolTxBeginner — wraps *pgxpool.Pool to implement service.TxBeginner.
// The pgx.Tx it produces satisfies service.Tx (opaque interface implemented
// by any concrete pgx.Tx via txAsPgx).
type PoolTxBeginner struct {
	pool    *pgxpool.Pool
	options pgx.TxOptions
}

// NewPoolTxBeginner — constructor.
func NewPoolTxBeginner(pool *pgxpool.Pool) *PoolTxBeginner {
	return &PoolTxBeginner{pool: pool}
}

// NewRegistrationTxBeginner задаёт снимок каждого оператора: повторный обход
// потомков после замка должен видеть регистрации, завершённые после первого.
// Умолчание пула не меняется; каждый повтор открывает самостоятельную транзакцию.
func NewRegistrationTxBeginner(pool *pgxpool.Pool) *PoolTxBeginner {
	return &PoolTxBeginner{pool: pool, options: pgx.TxOptions{IsoLevel: pgx.ReadCommitted}}
}

// Begin — opens a read-write transaction from the pool.
func (b *PoolTxBeginner) Begin(ctx context.Context) (service.Tx, error) {
	return b.pool.BeginTx(ctx, b.options)
}

// Compile-time assertion.
var _ service.TxBeginner = (*PoolTxBeginner)(nil)
