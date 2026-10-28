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
func (e *ResourceMirrorEmitter) DeleteTx(ctx context.Context, tx service.Tx, objectType, objectID string, tombstone time.Time) (bool, error) {
	return resource_mirror.DeleteTx(ctx, txAsPgx(tx), objectType, objectID, tombstone)
}

// Compile-time assertion.
// DescendantsTx — потомки объекта по цепи предков и отношения, стоящие на каждом,
// в снимке транзакции вызывающего (kaname#1002). Отношения читаются тем же телом,
// что у читателя остатка (`objectTuples`), но в транзакции: снятие потомков
// решается внутри неё, и потомок, заведённый между чтением и снятием, иначе ушёл
// бы без своих отношений.
func (e *ResourceMirrorEmitter) DescendantsTx(ctx context.Context, tx service.Tx, parentType, parentID string) ([]service.RegisteredDescendant, error) {
	ptx := txAsPgx(tx)
	found, err := resource_mirror.DescendantsTx(ctx, ptx, parentType, parentID)
	if err != nil {
		return nil, err
	}
	out := make([]service.RegisteredDescendant, 0, len(found))
	for _, d := range found {
		standing, err := objectTuples(ctx, ptx, d.ModelType+":"+d.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, service.RegisteredDescendant{ModelType: d.ModelType, ID: d.ID, Standing: standing})
	}
	return out, nil
}

// DropRegistrationTx — безусловное снятие регистрации потомка (kaname#1002).
func (e *ResourceMirrorEmitter) DropRegistrationTx(ctx context.Context, tx service.Tx, catalogType, modelType, objectID string) (bool, time.Time, error) {
	return resource_mirror.DropRegistrationTx(ctx, txAsPgx(tx), catalogType, modelType, objectID)
}

var _ service.ResourceMirrorEmitter = (*ResourceMirrorEmitter)(nil)
