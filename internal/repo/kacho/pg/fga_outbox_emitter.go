// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fga_outbox_emitter.go — pg adapter for service.RelationOutboxEmitter.
//
// Forwards emit-in-tx grant/revoke calls from governance code paths (JIT
// auto-grant, JitPending Approve, JIT/BG expirers, BG.ApproveB) to the
// internal helper package `fga_outbox` which performs the INSERT.
//
// Stateless adapter: the actual INSERT runs on the supplied tx, never on a
// pool-managed connection (otherwise the emit would no longer be atomic with
// the domain mutation).
package pg

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/fga_outbox"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// FGAOutboxEmitter — adapter implementing service.RelationOutboxEmitter on top of
// the fga_outbox package. Stateless.
type FGAOutboxEmitter struct{}

// NewFGAOutboxEmitter — composition root constructor.
func NewFGAOutboxEmitter() *FGAOutboxEmitter {
	return &FGAOutboxEmitter{}
}

// EmitWriteTx — implements service.RelationOutboxEmitter. Recovers the concrete
// pgx.Tx from the opaque handle and forwards to fga_outbox.EmitWriteTx.
func (e *FGAOutboxEmitter) EmitWriteTx(ctx context.Context, tx service.Tx, tuples []service.RelationTuple) error {
	return fga_outbox.EmitWriteTx(ctx, txAsPgx(tx), serviceTuplesToClients(tuples))
}

// EmitDeleteTx — symmetric revoke counterpart.
func (e *FGAOutboxEmitter) EmitDeleteTx(ctx context.Context, tx service.Tx, tuples []service.RelationTuple) error {
	return fga_outbox.EmitDeleteTx(ctx, txAsPgx(tx), serviceTuplesToClients(tuples))
}

// serviceTuplesToClients — service-layer RelationTuple → clients.RelationTuple (the
// shape the fga_outbox INSERT helper accepts). Both shapes are identical
// triples; the conversion exists only to keep the service layer free of
// the clients package import.
func serviceTuplesToClients(tuples []service.RelationTuple) []clients.RelationTuple {
	out := make([]clients.RelationTuple, len(tuples))
	for i, t := range tuples {
		out[i] = clients.RelationTuple{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	return out
}
