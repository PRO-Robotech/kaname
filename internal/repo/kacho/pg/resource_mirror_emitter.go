// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// resource_mirror_emitter.go — pg adapter for service.ResourceMirrorEmitter.
//
// Sub-phase β. Recovers the concrete pgx.Tx from the opaque service.Tx and
// forwards UPSERT/DELETE to the resource_mirror helper package, which runs the
// statement on the caller-supplied tx (atomic co-commit with the owner-tuple
// fga_outbox emit, ban #10 — D-β3). Stateless adapter; the statement never runs
// on a pool-managed connection — that would break atomicity.
package pg

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/resource_mirror"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// ResourceMirrorEmitter — adapter implementing service.ResourceMirrorEmitter on
// top of the resource_mirror package. Stateless.
type ResourceMirrorEmitter struct{}

// NewResourceMirrorEmitter — composition root constructor.
func NewResourceMirrorEmitter() *ResourceMirrorEmitter {
	return &ResourceMirrorEmitter{}
}

// UpsertTx — implements service.ResourceMirrorEmitter. Surfaces both verdicts the
// statements already computed: whether a row was written, and whether the write left the
// selector-relevant projection byte-identical (a redelivery that still carried the newer
// version).
func (e *ResourceMirrorEmitter) UpsertTx(ctx context.Context, tx service.Tx, row service.ResourceMirrorRow) (bool, bool, error) {
	out, err := resource_mirror.UpsertTx(ctx, txAsPgx(tx), resource_mirror.Row{
		ObjectType:      row.ObjectType,
		ObjectID:        row.ObjectID,
		ParentProjectID: row.ParentProjectID,
		ParentAccountID: row.ParentAccountID,
		ParentChain:     row.ParentChain,
		Labels:          row.Labels,
		SourceVersion:   row.SourceVersion,
	})
	return out.Applied, out.ProjectionUnchanged, err
}

// DeleteTx — implements service.ResourceMirrorEmitter.
func (e *ResourceMirrorEmitter) DeleteTx(ctx context.Context, tx service.Tx, objectType, objectID string, tombstone time.Time) error {
	return resource_mirror.DeleteTx(ctx, txAsPgx(tx), objectType, objectID, tombstone)
}

// Compile-time assertion.
var _ service.ResourceMirrorEmitter = (*ResourceMirrorEmitter)(nil)
