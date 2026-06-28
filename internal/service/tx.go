// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// tx.go — opaque transaction handle for the service layer.
//
// Clean Architecture boundary: the service layer must depend ONLY on domain
// types and its own port-interfaces — never on the Postgres driver.
//
// `Tx` is an opaque transaction handle. The service layer drives its lifecycle
// (Begin via TxBeginner, Commit/Rollback here) but never inspects the concrete
// type. The concrete pgx transaction is materialized only inside repo/pg
// adapters via a type assertion (see repo/kacho/pg/service_tx.go::txAsPgx).
package service

import "context"

// Tx is an opaque transaction handle. The concrete pgx transaction type is
// materialized only inside repo/pg adapters via type assertion. The service
// layer uses it solely to drive transaction lifecycle.
//
// A concrete pgx transaction value satisfies this interface automatically (it
// already exposes Commit/Rollback with these signatures), so adapters can pass
// it where a service.Tx is expected and type-assert it back inside repo
// methods.
type Tx interface {
	// Commit commits the transaction.
	Commit(ctx context.Context) error
	// Rollback aborts the transaction. Safe to call after Commit (no-op).
	Rollback(ctx context.Context) error
}
