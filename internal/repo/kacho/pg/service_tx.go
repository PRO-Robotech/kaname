// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// service_tx.go — materializes the service layer's opaque transaction handle
// (service.Tx) back into a concrete *pgx.Tx inside repo adapters.
//
// Clean Architecture: the service layer (use-cases + port-interfaces) must not
// depend on the Postgres driver, so service ports accept service.Tx — an
// opaque interface. Repo adapters in this package are the only place the
// concrete pgx.Tx is recovered, via txAsPgx below.
package pg

import (
	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// txAsPgx recovers the concrete pgx.Tx from the service layer's opaque
// transaction handle. The handle is always produced by a *pgxTxBeginner
// (see beginner.go) which begins a real pgx.Tx, so the assertion never fails
// in production wiring. A failed assertion is a wiring bug — panic fast.
func txAsPgx(tx service.Tx) pgx.Tx {
	pt, ok := tx.(pgx.Tx)
	if !ok {
		panic("kacho-iam/repo/pg: service.Tx is not a pgx.Tx — composition root wired a non-pg transaction handle")
	}
	return pt
}
