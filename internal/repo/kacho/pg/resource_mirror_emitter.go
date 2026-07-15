// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/resource_mirror"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ResourceMirrorEmitter — adapter implementing service.ResourceMirrorEmitter on
// top of the resource_mirror package. Stateless.
type ResourceMirrorEmitter struct{}

// NewResourceMirrorEmitter — composition root constructor.
func NewResourceMirrorEmitter() *ResourceMirrorEmitter {
	return &ResourceMirrorEmitter{}
}

// UpsertTx — implements service.ResourceMirrorEmitter.
func (e *ResourceMirrorEmitter) UpsertTx(ctx context.Context, tx service.Tx, row service.ResourceMirrorRow) error {
	return resource_mirror.UpsertTx(ctx, txAsPgx(tx), resource_mirror.Row{
		ObjectType:      row.ObjectType,
		ObjectID:        row.ObjectID,
		ParentProjectID: row.ParentProjectID,
		ParentAccountID: row.ParentAccountID,
		Labels:          row.Labels,
		SourceVersion:   row.SourceVersion,
	})
}

// DeleteTx — implements service.ResourceMirrorEmitter.
func (e *ResourceMirrorEmitter) DeleteTx(ctx context.Context, tx service.Tx, objectType, objectID string, tombstone time.Time) error {
	return resource_mirror.DeleteTx(ctx, txAsPgx(tx), objectType, objectID, tombstone)
}

// Compile-time assertion.
var _ service.ResourceMirrorEmitter = (*ResourceMirrorEmitter)(nil)
