// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

// register_resource_gamma_adapters.go — γ pg adapters consumed by the
// RegisterResource use-case in the SAME writer-tx as the β mirror co-commit:
//   - ReconcileEventEmitter — enqueue a resource_reconcile_outbox event.
//   - ProjectAccountResolver — resolve projects.account_id same-DB.
// Both recover the concrete pgx.Tx via txAsPgx (Clean Architecture boundary).

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/reconcile_outbox"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ReconcileEventEmitter — adapter for the γ reconcile-event emit-in-tx.
// Stateless — it recovers the concrete pgx.Tx from the caller tx at call time.
type ReconcileEventEmitter struct{}

// NewReconcileEventEmitter — composition-root constructor.
func NewReconcileEventEmitter() *ReconcileEventEmitter {
	return &ReconcileEventEmitter{}
}

// EmitTx enqueues a reconcile event on the caller tx (atomic with the mirror
// change). eventType is "mirror.upsert" | "mirror.delete".
func (e *ReconcileEventEmitter) EmitTx(ctx context.Context, tx service.Tx, eventType, objectType, objectID string) error {
	return reconcile_outbox.EmitTx(ctx, txAsPgx(tx), eventType, objectType, objectID)
}

// ProjectAccountResolver — adapter for the γ same-DB account backfill.
type ProjectAccountResolver struct{}

// NewProjectAccountResolver — composition-root constructor.
func NewProjectAccountResolver() *ProjectAccountResolver {
	return &ProjectAccountResolver{}
}

// AccountForProjectTx resolves a project's account_id SAME-DB (IAM owns Project)
// on the caller tx. ok=false when the project row is absent (not yet known /
// dangling) — the caller then keeps the owner-supplied value.
func (r *ProjectAccountResolver) AccountForProjectTx(ctx context.Context, tx service.Tx, projectID string) (string, bool, error) {
	var accID string
	err := txAsPgx(tx).QueryRow(ctx,
		`SELECT account_id FROM kacho_iam.projects WHERE id = $1`, projectID,
	).Scan(&accID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("resolve account for project %s: %w", projectID, err)
	}
	return accID, true, nil
}
