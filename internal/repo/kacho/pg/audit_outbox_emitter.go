// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// audit_outbox_emitter.go — pg adapter for service.AuditOutboxEmitter.
//
// Emits ONE durable kacho_iam.audit_outbox row inside a caller-owned writer-tx
// (recovered from the opaque service.Tx via txAsPgx). Atomic with the
// surrounding security-relevant mutation (запрет #10): the audit row commits iff
// the mutation commits.
//
// Stateless adapter: the pool argument is accepted for symmetry with other
// adapters; the actual INSERT runs on the supplied tx, never on a pool-managed
// connection (otherwise the emit would no longer be atomic with the mutation).
//
// id generation uses newAuditEventID() — `evt_<22-char crockford-base32>`,
// which satisfies audit_outbox_id_check (`^evt_…{20,30}$`). domain.NewKac127ID
// produces only a 17-char body, which is BELOW the CHECK's 20-char floor and was
// the latent bug #126 (hook-emit silently rejected at INSERT). This adapter is
// the single shared emit path for all cluster-admin / session audit events.
package pg

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// AuditOutboxEmitter — adapter implementing service.AuditOutboxEmitter on top of
// AuditOutboxRepo.InsertTx. Stateless.
type AuditOutboxEmitter struct {
	repo *AuditOutboxRepo
}

// NewAuditOutboxEmitter — composition root constructor (pool arg drives the
// underlying repo's read path; emit always runs on the caller-supplied tx).
func NewAuditOutboxEmitter(pool *pgxpool.Pool) *AuditOutboxEmitter {
	return &AuditOutboxEmitter{repo: NewAuditOutboxRepo(pool)}
}

// EmitTx — implements service.AuditOutboxEmitter. Recovers the concrete pgx.Tx
// from the opaque handle and INSERTs one audit_outbox row (status='pending',
// id=newAuditEventID()) atomically with the surrounding mutation.
func (e *AuditOutboxEmitter) EmitTx(ctx context.Context, tx service.Tx, ev service.AuditEvent) error {
	return insertAuditEventTx(ctx, txAsPgx(tx), ev)
}

// insertAuditEventTx — the single shared audit_outbox emit path: marshal the
// service.AuditEvent payload, build a domain.AuditOutboxEntry with a 22-char
// `evt_…` id (bug #126 regression-guard — NOT the 17-char NewKac127ID which
// fails audit_outbox_id_check) and status='pending', then INSERT it on the
// caller-owned pgx.Tx. Used by BOTH the service.AuditOutboxEmitter adapter
// (cluster/session/SAKey emit-in-tx) and writeTx.EmitAuditEvent (CRUD writer-tx)
// so the emit logic is defined exactly once (no duplication, запрет #11).
func insertAuditEventTx(ctx context.Context, tx pgx.Tx, ev service.AuditEvent) error {
	if ev.EventType == "" {
		return fmt.Errorf("emit audit_outbox: event_type required")
	}
	payload := ev.Payload
	if payload == nil {
		payload = map[string]any{}
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("emit audit_outbox: marshal payload: %w", err)
	}
	entry := domain.AuditOutboxEntry{
		ID:           domain.AuditEventID(newAuditEventID()),
		EventType:    domain.EventTypeName(ev.EventType),
		EventPayload: payloadJSON,
		Status:       domain.AuditOutboxStatusPending,
	}
	if ev.TenantAccountID != "" {
		aid := domain.AccountID(ev.TenantAccountID)
		entry.TenantAccountID = &aid
	}
	if _, err := (&AuditOutboxRepo{}).InsertTx(ctx, tx, entry); err != nil {
		return fmt.Errorf("emit audit_outbox %s: %w", ev.EventType, err)
	}
	return nil
}

var _ service.AuditOutboxEmitter = (*AuditOutboxEmitter)(nil)
