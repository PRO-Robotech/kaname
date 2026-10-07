// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// resource_mirror_emitter.go — pg adapter for service.ResourceMirrorEmitter.
//
// Sub-phase β. Recovers the concrete pgx.Tx from the opaque service.Tx and
// forwards the registration/withdrawal intent to the resource_mirror package,
// which puts it into the admission table on the caller-supplied tx (the one
// projection producer — trigger `resource_event` — applies it there) (atomic co-commit with the owner-tuple
// fga_outbox emit, ban #10 — D-β3). Stateless adapter; the statement never runs
// on a pool-managed connection — that would break atomicity.
package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// ResourceMirrorEmitter — adapter implementing service.ResourceMirrorEmitter on
// top of the resource_mirror package. Stateless.
type ResourceMirrorEmitter struct{}

// NewResourceMirrorEmitter — composition root constructor.
func NewResourceMirrorEmitter() *ResourceMirrorEmitter {
	return &ResourceMirrorEmitter{}
}

// UpsertTx — implements service.ResourceMirrorEmitter. Surfaces both verdicts the
// admission trigger decided: whether the generation was newer than the object's head and
// so applied, and whether the applied write left the selector-relevant projection
// byte-identical.
func (e *ResourceMirrorEmitter) UpsertTx(ctx context.Context, tx service.Tx, row service.ResourceMirrorRow) (bool, bool, error) {
	out, err := resource_mirror.UpsertTx(ctx, txAsPgx(tx), resource_mirror.Row{
		ObjectType:      row.ObjectType,
		ObjectID:        row.ObjectID,
		ParentProjectID: row.ParentProjectID,
		ParentAccountID: row.ParentAccountID,
		ParentChain:     row.ParentChain,
		Labels:          row.Labels,
		Generation:      row.Generation,
	})
	return out.Applied, out.ProjectionUnchanged, err
}

// DeleteTx — implements service.ResourceMirrorEmitter. `applied` is false when the
// withdrawal's generation was not newer than the object's head (REJECTED_STALE).
func (e *ResourceMirrorEmitter) DeleteTx(ctx context.Context, tx service.Tx, objectType, objectID string, generation int64) (bool, error) {
	out, err := resource_mirror.DeleteTx(ctx, txAsPgx(tx), objectType, objectID, generation)
	return out.Applied, err
}

// Compile-time assertion.
var _ service.ResourceMirrorEmitter = (*ResourceMirrorEmitter)(nil)
