// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
)

// После final clock читается только уже удержанная owner-private строка.
// Команды — проверенные ветви исходного Go diff после общего TTL collector,
// audit ID/tenant/time — подготовленные сервером значения, а не новый lookup.
type resourceObjectBodyValues struct {
	Commands      []reconcile.BindingCommand `json:"commands"`
	TransactionAt time.Time                  `json:"transaction_at"`
	DecisionAt    time.Time                  `json:"decision_at"`
	Audits        []resourceObjectAuditValue `json:"audits"`
}
type resourceObjectAuditValue struct {
	Command int `json:"command"`
	Row     struct {
		ID              string          `json:"id"`
		EventType       string          `json:"event_type"`
		TenantAccountID *string         `json:"tenant_account_id"`
		Payload         json.RawMessage `json:"event_payload"`
		CreatedAt       time.Time       `json:"created_at"`
		NextAttemptAt   time.Time       `json:"next_attempt_at"`
	} `json:"row"`
}

func readResourceObjectBodyValues(ctx context.Context, tx *resourceDecisionTx) (resourceObjectBodyValues, error) {
	var result resourceObjectBodyValues
	var encoded []byte
	if err := tx.QueryRow(ctx, `SELECT kaname.authority_resource_object_body_values_v2()`).Scan(&encoded); err != nil {
		return result, err
	}
	if err := json.Unmarshal(encoded, &result); err != nil {
		return result, err
	}
	if result.TransactionAt.IsZero() || !result.DecisionAt.Equal(tx.lifetime.at) || result.Commands == nil || len(result.Commands) > 100000 {
		return result, kaname.ErrSourceUnconfirmed
	}
	return result, nil
}

// Переопределены только clock/ID/read-producing методы. Members и ledger
// исполняют прежний store SQL; now() соответствует проверенному RC tx timestamp.
type resourceObjectBodyStore struct {
	*reconcileStore
	transactionAt time.Time
	decisionAt    time.Time
	audit         *resourceObjectAuditValue
}

func (s *resourceObjectBodyStore) EmitTupleWrite(ctx context.Context, tuples []domain.MembershipTuple) error {
	return s.emit(ctx, fga_outbox.EventTypeWrite, tuples, s.transactionAt)
}
func (s *resourceObjectBodyStore) EmitTupleDelete(ctx context.Context, tuples []domain.MembershipTuple) error {
	return s.emit(ctx, fga_outbox.EventTypeDelete, tuples, s.decisionAt)
}
func (s *resourceObjectBodyStore) emit(ctx context.Context, kind string, tuples []domain.MembershipTuple, at time.Time) error {
	return fga_outbox.EmitDecisionTx(ctx, s.tx, kind, membershipTuplesToClients(tuples), at)
}
func (s *resourceObjectBodyStore) EmitContainmentAudit(ctx context.Context, binding domain.AccessBindingID, typ, id string, scope domain.ScopeAnchor) error {
	if s.audit == nil || s.audit.Row.ID == "" || s.audit.Row.EventType != "iam.access_binding.containment_rejected" || !s.audit.Row.CreatedAt.Equal(s.transactionAt) || !s.audit.Row.NextAttemptAt.Equal(s.transactionAt) {
		return kaname.ErrSourceUnconfirmed
	}
	var payload map[string]string
	if err := json.Unmarshal(s.audit.Row.Payload, &payload); err != nil {
		return err
	}
	if len(payload) != 6 || payload["binding_id"] != string(binding) || payload["object_type"] != typ || payload["object_id"] != id || payload["scope_type"] != scope.Type || payload["scope_id"] != scope.ID || payload["reason"] != "not contained in scope" {
		return kaname.ErrSourceUnconfirmed
	}
	_, err := s.tx.Exec(ctx, `INSERT INTO kaname.audit_outbox
(id,event_type,tenant_account_id,event_payload,status,attempts,created_at,next_attempt_at)
VALUES ($1,$2,$3,$4::jsonb,'pending',0,$5,$6)`, s.audit.Row.ID, s.audit.Row.EventType, s.audit.Row.TenantAccountID, s.audit.Row.Payload, s.audit.Row.CreatedAt, s.audit.Row.NextAttemptAt)
	return err
}

// Чтение private шага одновременно закрывает обязательства предыдущего.
func readResourceObjectStep(ctx context.Context, tx *resourceDecisionTx, ordinal int) (reconcile.BindingCommand, error) {
	var command reconcile.BindingCommand
	var encoded []byte
	if err := tx.QueryRow(ctx, `SELECT kaname.authority_resource_object_step_v2($1)`, ordinal).Scan(&encoded); err != nil {
		return command, err
	}
	if err := json.Unmarshal(encoded, &command); err != nil {
		return command, err
	}
	return command, nil
}
