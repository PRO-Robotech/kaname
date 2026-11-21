// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"time"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Команда выбирается только из private программы SQL. Исполнитель не принимает
// callback, произвольный SQL или подменяемый набор row images. Обычные адаптеры
// сохраняют прежние predicates; guards сопоставляют фактические OLD/NEW образы.
type resourceRegistrationCommand struct {
	Encoded             json.RawMessage `json:"-"`
	Journal             json.RawMessage `json:"journal"`
	Kind                string          `json:"kind"`
	Applied             *bool           `json:"applied"`
	ProjectionUnchanged *bool           `json:"projection_unchanged"`
	Row                 json.RawMessage `json:"row"`
	Receipt             json.RawMessage `json:"receipt"`
}
type resourceRegistrationBodyValues struct {
	Commands      []resourceRegistrationCommand `json:"commands"`
	Result        kaname.ResourceDecisionResult `json:"result"`
	TransactionAt time.Time                     `json:"transaction_at"`
	DecisionAt    time.Time                     `json:"decision_at"`
}

func (p *resourceRegistrationPreparation) applyPreparedDirect(ctx context.Context, tx *resourceDecisionTx) (kaname.ResourceDecisionResult, error) {
	var values resourceRegistrationBodyValues
	var encoded []byte
	if err := tx.QueryRow(ctx, `SELECT kaname.authority_resource_registration_body_values_v2()`).Scan(&encoded); err != nil {
		return values.Result, err
	}
	if err := json.Unmarshal(encoded, &values); err != nil {
		return values.Result, err
	}
	if values.Commands == nil || len(values.Commands) > 100000 || values.TransactionAt.IsZero() || !values.DecisionAt.Equal(tx.lifetime.at) || values.Result.CatalogType != p.row.ObjectType {
		return kaname.ResourceDecisionResult{}, kaname.ErrSourceUnconfirmed
	}
	for i := range values.Commands {
		if err := ctx.Err(); err != nil {
			return kaname.ResourceDecisionResult{}, err
		}
		if err := tx.QueryRow(ctx, `SELECT kaname.authority_resource_registration_step_v2($1)`, i+1).Scan(&encoded); err != nil {
			return kaname.ResourceDecisionResult{}, err
		}
		var command resourceRegistrationCommand
		if err := json.Unmarshal(encoded, &command); err != nil {
			return kaname.ResourceDecisionResult{}, err
		}
		command.Encoded = encoded
		if command.Kind != values.Commands[i].Kind {
			return kaname.ResourceDecisionResult{}, kaname.ErrSourceUnconfirmed
		}
		if err := p.applyDirectCommand(ctx, tx, command, values.TransactionAt); err != nil {
			return kaname.ResourceDecisionResult{}, err
		}
	}
	return values.Result, ctx.Err()
}

func (p *resourceRegistrationPreparation) applyDirectCommand(ctx context.Context, tx *resourceDecisionTx, c resourceRegistrationCommand, transactionAt time.Time) error {
	scopes := NewRegistrationScopeReader()
	switch c.Kind {
	case "mirror":
		if p.input.Action != kaname.ResourceDecisionRegister || c.Applied == nil || c.ProjectionUnchanged == nil {
			return kaname.ErrSourceUnconfirmed
		}
		applied, unchanged, err := NewResourceMirrorEmitter().UpsertTx(ctx, tx, p.row)
		if err != nil {
			return err
		}
		if applied != *c.Applied || unchanged != *c.ProjectionUnchanged {
			return kaname.ErrSourceUnconfirmed
		}
		return nil
	case "scope_clear":
		if p.input.Action != kaname.ResourceDecisionRegister {
			return kaname.ErrSourceUnconfirmed
		}
		_, err := tx.Exec(ctx, `DELETE FROM ONLY kaname.resource_registration_scope WHERE object_type=$1 AND object_id=$2`, p.catalog.identity.ObjectType, p.row.ObjectID)
		return err
	case "scope_insert":
		if p.input.Action != kaname.ResourceDecisionRegister {
			return kaname.ErrSourceUnconfirmed
		}
		var row struct {
			ObjectType string `json:"object_type"`
			ObjectID   string `json:"object_id"`
			ProjectID  string `json:"project_id"`
			AccountID  string `json:"account_id"`
		}
		if err := json.Unmarshal(c.Row, &row); err != nil {
			return err
		}
		if row.ObjectType != p.catalog.identity.ObjectType || row.ObjectID != p.row.ObjectID || row.AccountID == "" {
			return kaname.ErrSourceUnconfirmed
		}
		_, err := tx.Exec(ctx, `INSERT INTO kaname.resource_registration_scope(object_type,object_id,project_id,account_id) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, row.ObjectType, row.ObjectID, row.ProjectID, row.AccountID)
		return err
	case "receipt_invalidate":
		if p.input.Action == kaname.ResourceDecisionUnregister {
			return p.applyUnregistrationCommand(ctx, tx, c, transactionAt)
		}
		if p.input.Action != kaname.ResourceDecisionRegister {
			return kaname.ErrSourceUnconfirmed
		}
		return scopes.InvalidateRegistrationReceiptsTx(ctx, tx, p.input.Tuple.Object, p.row.SourceVersion, "projection_replaced")
	case "receipt_save":
		if p.input.Action != kaname.ResourceDecisionRegister && p.input.Action != kaname.ResourceDecisionPublish {
			return kaname.ErrSourceUnconfirmed
		}
		return executeResourceReceipt(ctx, tx, c.Receipt)
	case "pointer_save":
		if p.input.Action != kaname.ResourceDecisionRegister {
			return kaname.ErrSourceUnconfirmed
		}
		applied, err := scopes.SaveRegistrationPointerTx(ctx, tx, p.module.catalogModule, p.input.Tuple, p.row.SourceVersion)
		if err != nil {
			return err
		}
		if !applied {
			return kaname.ErrSourceUnconfirmed
		}
		return nil
	case "registration_journal":
		if p.input.Action != kaname.ResourceDecisionRegister {
			return kaname.ErrSourceUnconfirmed
		}
		return p.executeRegistrationJournal(ctx, tx, c.Journal, transactionAt)
	case "publication":
		if (p.input.Action != kaname.ResourceDecisionPublish && p.input.Action != kaname.ResourceDecisionUnpublish) || c.Applied == nil {
			return kaname.ErrSourceUnconfirmed
		}
		applied, err := NewPublicReadPublisher().ApplyTx(ctx, tx, p.catalog.identity.ObjectType, p.row.ObjectID, p.input.Action == kaname.ResourceDecisionPublish, p.row.SourceVersion)
		if err != nil {
			return err
		}
		if applied != *c.Applied {
			return kaname.ErrSourceUnconfirmed
		}
		return nil
	case "refusal_audit":
		return p.executePreparedRefusalAudit(ctx, tx, c.Row, transactionAt)
	case "registration_audit":
		if p.input.Action != kaname.ResourceDecisionRegister {
			return kaname.ErrSourceUnconfirmed
		}
		var audit resourceObjectAuditValue
		if err := json.Unmarshal(c.Row, &audit.Row); err != nil {
			return err
		}
		if audit.Row.ID == "" || audit.Row.EventType != "iam.resource_registration.registered" || !audit.Row.CreatedAt.Equal(transactionAt) || !audit.Row.NextAttemptAt.Equal(transactionAt) {
			return kaname.ErrSourceUnconfirmed
		}
		_, err := tx.Exec(ctx, `INSERT INTO kaname.audit_outbox
(id,event_type,tenant_account_id,event_payload,status,attempts,created_at,next_attempt_at)
VALUES ($1,$2,$3,$4::jsonb,'pending',0,$5,$6)`, audit.Row.ID, audit.Row.EventType, audit.Row.TenantAccountID, audit.Row.Payload, audit.Row.CreatedAt, audit.Row.NextAttemptAt)
		return err
	case "registration_reconcile":
		if p.input.Action != kaname.ResourceDecisionRegister {
			return kaname.ErrSourceUnconfirmed
		}
		var row struct {
			ID         int64     `json:"id"`
			EventType  string    `json:"event_type"`
			ObjectType string    `json:"object_type"`
			ObjectID   string    `json:"object_id"`
			CreatedAt  time.Time `json:"created_at"`
		}
		if err := json.Unmarshal(c.Row, &row); err != nil {
			return err
		}
		if row.ID <= 0 || row.EventType != "mirror.upsert" || row.ObjectType != p.row.ObjectType || row.ObjectID != p.row.ObjectID || !row.CreatedAt.Equal(transactionAt) {
			return kaname.ErrSourceUnconfirmed
		}
		_, err := tx.Exec(ctx, `INSERT INTO kaname.resource_reconcile_outbox
(id,event_type,object_type,object_id,created_at,attempt_count) OVERRIDING SYSTEM VALUE VALUES ($1,$2,$3,$4,$5,0)`, row.ID, row.EventType, row.ObjectType, row.ObjectID, row.CreatedAt)
		return err
	default:
		if p.input.Action == kaname.ResourceDecisionUnregister {
			return p.applyUnregistrationCommand(ctx, tx, c, transactionAt)
		}
		return kaname.ErrSourceUnconfirmed
	}
}

// Проверки catalog/scopes/publication уже выполнены private compiler под
// удержанными источниками. Тело сохраняет прежние UPDATE/UPSERT predicates,
// но получает version/scopes из подготовленной строки, без повторного SELECT.
func executeResourceReceipt(ctx context.Context, tx *resourceDecisionTx, encoded json.RawMessage) error {
	if len(encoded) == 0 || string(encoded) == "null" {
		return kaname.ErrSourceUnconfirmed
	}
	if _, err := tx.Exec(ctx, `UPDATE kaname.producer_source_receipt p
 SET active=false,invalidation='module_replaced',model_identity=NULL,catalog_identity=NULL,projector_version=NULL
 FROM jsonb_populate_record(NULL::kaname.producer_source_receipt,$1::jsonb) r
 WHERE p.kind=r.kind AND p.object_type=r.object_type AND p.object_id=r.object_id AND p.module<>r.module`, encoded); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO kaname.producer_source_receipt(kind,module,catalog_type,object_type,object_id,relation,subject_type,subject_id,condition_name,condition_parameters,scopes,source_version,versionless,active)
 SELECT r.kind,r.module,r.catalog_type,r.object_type,r.object_id,r.relation,r.subject_type,r.subject_id,r.condition_name,r.condition_parameters,r.scopes,r.source_version,r.versionless,true
 FROM jsonb_populate_record(NULL::kaname.producer_source_receipt,$1::jsonb) r
 ON CONFLICT(kind,module,object_type,object_id,relation,subject_type,subject_id) DO UPDATE SET catalog_type=EXCLUDED.catalog_type,scopes=EXCLUDED.scopes,source_version=greatest(producer_source_receipt.source_version,EXCLUDED.source_version),versionless=EXCLUDED.versionless,active=true,invalidation='',model_identity=NULL,catalog_identity=NULL,projector_version=NULL`, encoded)
	return err
}

// Тот же единичный owner-ordered journal и retirement DELETE. Relation lock,
// который общий emitter берёт внутри invalidateRetirementTx, уже получен
// current prewait; после часов здесь не выполняется новый LOCK TABLE.
func (p *resourceRegistrationPreparation) executeRegistrationJournal(ctx context.Context, tx *resourceDecisionTx, encoded json.RawMessage, transactionAt time.Time) error {
	var row struct {
		EventType string          `json:"event_type"`
		Payload   json.RawMessage `json:"payload"`
		CreatedAt time.Time       `json:"created_at"`
	}
	if err := json.Unmarshal(encoded, &row); err != nil {
		return err
	}
	if row.EventType != "fga.tuple.write" || !row.CreatedAt.Equal(transactionAt) {
		return kaname.ErrSourceUnconfirmed
	}
	if _, err := tx.Exec(ctx, `DELETE FROM ONLY kaname.resource_registration_retirement
 WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject=$4 AND $3::text IN ('project','parent','owner')`,
		p.catalog.identity.ObjectType, p.row.ObjectID, p.input.Tuple.Relation, p.input.Tuple.User); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO kaname.fga_outbox(event_type,payload,created_at) VALUES($1,$2::jsonb,$3)`, row.EventType, row.Payload, row.CreatedAt)
	return err
}
