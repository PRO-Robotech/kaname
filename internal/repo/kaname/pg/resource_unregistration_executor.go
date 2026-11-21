// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"time"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Только значения текущего private command. Ни исходный proposal, ни live
// repository adapter после final clock не выбирают строки или новые эффекты.
// Неизвестный kind остаётся отказом до закрытия полного compiler/executor.
func (p *resourceRegistrationPreparation) applyUnregistrationCommand(ctx context.Context, tx *resourceDecisionTx, c resourceRegistrationCommand, transactionAt time.Time) error {
	if p.input.Action != kaname.ResourceDecisionUnregister || len(c.Encoded) == 0 {
		return kaname.ErrSourceUnconfirmed
	}
	switch c.Kind {
	case "cleanup_publication":
		var v struct {
			ObjectType string  `json:"object_type"`
			ObjectID   string  `json:"object_id"`
			Version    *string `json:"version"`
			Applied    *bool   `json:"applied"`
		}
		if err := json.Unmarshal(c.Encoded, &v); err != nil {
			return err
		}
		if v.ObjectType != "registry_repository" || v.ObjectID == "" || v.Applied == nil {
			return kaname.ErrSourceUnconfirmed
		}
		var version time.Time
		if v.Version != nil && *v.Version != "-infinity" {
			parsed, err := time.Parse(time.RFC3339Nano, *v.Version)
			if err != nil {
				return err
			}
			version = parsed
		}
		applied, err := NewPublicReadPublisher().ApplyTx(ctx, tx, v.ObjectType, v.ObjectID, false, version)
		if err != nil {
			return err
		}
		if applied != *v.Applied {
			return kaname.ErrAuthorityClassificationChanged
		}
		return nil
	case "cleanup_audit":
		var audit resourceObjectAuditValue
		if err := json.Unmarshal(c.Row, &audit.Row); err != nil {
			return err
		}
		if audit.Row.ID == "" || audit.Row.EventType != "iam.resource_registration.unregistered" || !audit.Row.CreatedAt.Equal(transactionAt) || !audit.Row.NextAttemptAt.Equal(transactionAt) {
			return kaname.ErrSourceUnconfirmed
		}
		_, err := tx.Exec(ctx, `INSERT INTO kaname.audit_outbox
(id,event_type,tenant_account_id,event_payload,status,attempts,created_at,next_attempt_at)
VALUES ($1,$2,$3,$4::jsonb,'pending',0,$5,$6)`, audit.Row.ID, audit.Row.EventType, audit.Row.TenantAccountID, audit.Row.Payload, audit.Row.CreatedAt, audit.Row.NextAttemptAt)
		return err
	case "cleanup_reconcile":
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
		if row.ID <= 0 || row.EventType != "mirror.delete" || row.ObjectType == "" || row.ObjectID == "" || !row.CreatedAt.Equal(transactionAt) {
			return kaname.ErrSourceUnconfirmed
		}
		_, err := tx.Exec(ctx, `INSERT INTO kaname.resource_reconcile_outbox
(id,event_type,object_type,object_id,created_at,attempt_count) OVERRIDING SYSTEM VALUE VALUES ($1,$2,$3,$4,$5,0)`, row.ID, row.EventType, row.ObjectType, row.ObjectID, row.CreatedAt)
		return err
	case "cleanup_mirror_delete", "cleanup_edge_delete":
		var v struct {
			DottedType string `json:"dotted_type"`
			ObjectType string `json:"object_type"`
			ObjectID   string `json:"object_id"`
			DropAll    bool   `json:"drop_all"`
			Version    string `json:"version"`
			Deleted    *bool  `json:"deleted"`
		}
		if err := json.Unmarshal(c.Encoded, &v); err != nil {
			return err
		}
		if v.ObjectType == "" || v.ObjectID == "" || v.Version == "" {
			return kaname.ErrSourceUnconfirmed
		}
		if c.Kind == "cleanup_mirror_delete" {
			if v.DottedType == "" || v.Deleted == nil {
				return kaname.ErrSourceUnconfirmed
			}
			tag, err := tx.Exec(ctx, `DELETE FROM ONLY kaname.resource_mirror
WHERE object_type=$1 AND object_id=$2 AND ($3::boolean OR source_version<=$4::timestamptz)`, v.DottedType, v.ObjectID, v.DropAll, v.Version)
			if err != nil {
				return err
			}
			expected := int64(0)
			if *v.Deleted {
				expected = 1
			}
			if tag.RowsAffected() != expected {
				return kaname.ErrAuthorityClassificationChanged
			}
			return nil
		}
		_, err := tx.Exec(ctx, `DELETE FROM ONLY kaname.resource_parent_edge
WHERE object_type=$1 AND object_id=$2 AND ($3::boolean OR source_version<=$4::timestamptz)`, v.ObjectType, v.ObjectID, v.DropAll, v.Version)
		return err
	case "cleanup_pointer_retire":
		var v struct {
			Mode       string  `json:"mode"`
			Module     string  `json:"module"`
			ObjectType string  `json:"object_type"`
			ObjectID   string  `json:"object_id"`
			Version    *string `json:"version"`
		}
		if err := json.Unmarshal(c.Encoded, &v); err != nil {
			return err
		}
		if v.Module != p.module.catalogModule || v.ObjectType == "" || v.ObjectID == "" {
			return kaname.ErrSourceUnconfirmed
		}
		switch v.Mode {
		case "retire":
			_, err := tx.Exec(ctx, `UPDATE ONLY kaname.resource_registration_pointer
SET active=false,source_version=greatest(source_version,$4::timestamptz)
WHERE module=$1 AND object_type=$2 AND object_id=$3 AND ($4::timestamptz IS NULL OR source_version<$4 OR (source_version=$4 AND (NOT versionless OR NOT active)))`, v.Module, v.ObjectType, v.ObjectID, v.Version)
			return err
		case "retire_descendants":
			_, err := tx.Exec(ctx, `UPDATE ONLY kaname.resource_registration_pointer
SET active=false,source_version=greatest(source_version,$4::timestamptz)
WHERE module=$1 AND object_type=$2 AND object_id=$3 RETURNING subject,relation,object_type || ':' || object_id,versionless`, v.Module, v.ObjectType, v.ObjectID, v.Version)
			return err
		default:
			return kaname.ErrSourceUnconfirmed
		}
	case "receipt_invalidate":
		var v struct {
			ObjectType string `json:"object_type"`
			ObjectID   string `json:"object_id"`
			Version    string `json:"version"`
			Outcome    string `json:"outcome"`
		}
		if err := json.Unmarshal(c.Encoded, &v); err != nil {
			return err
		}
		if v.ObjectType == "" || v.ObjectID == "" || v.Version == "" || v.Outcome != "withdrawn" {
			return kaname.ErrSourceUnconfirmed
		}
		_, err := tx.Exec(ctx, `UPDATE ONLY kaname.producer_source_receipt
SET active=false,invalidation=$3,source_version=greatest(source_version,$4::timestamptz),model_identity=NULL,catalog_identity=NULL,projector_version=NULL
WHERE kind='registration_owner' AND object_type=$1 AND object_id=$2`, v.ObjectType, v.ObjectID, v.Outcome, v.Version)
		return err
	case "cleanup_retirement_save":
		_, err := tx.Exec(ctx, `INSERT INTO kaname.resource_registration_retirement(object_type,object_id,relation,subject,delete_through)
SELECT r.object_type,r.object_id,r.relation,r.subject,r.delete_through
FROM jsonb_populate_record(NULL::kaname.resource_registration_retirement,$1::jsonb) r
ON CONFLICT(object_type,object_id,relation,subject) DO UPDATE
SET delete_through=greatest(resource_registration_retirement.delete_through,EXCLUDED.delete_through)`, c.Row)
		return err
	case "cleanup_owner_receipts":
		_, err := tx.Exec(ctx, `UPDATE ONLY kaname.producer_source_receipt p
SET active=false,invalidation='owner_withdrawn',model_identity=NULL,catalog_identity=NULL,projector_version=NULL
FROM jsonb_array_elements($1::jsonb->'rows') x
WHERE p.kind='registration_owner' AND x->'tuple'->>'Relation'='owner' AND p.relation=x->'tuple'->>'Relation'
AND p.object_type=split_part(x->'tuple'->>'Object',':',1)
AND p.object_id=substr(x->'tuple'->>'Object',strpos(x->'tuple'->>'Object',':')+1)
AND p.subject_type=split_part(x->'tuple'->>'User',':',1)
AND p.subject_id=substr(x->'tuple'->>'User',strpos(x->'tuple'->>'User',':')+1)
AND p.source_version<=coalesce((x->>'source_version')::timestamptz,$2::timestamptz)`, c.Encoded, tx.lifetime.at)
		return err
	case "cleanup_journals", "withdrawal_journals":
		var v struct {
			Journals []struct {
				EventType string          `json:"event_type"`
				Payload   json.RawMessage `json:"payload"`
				CreatedAt time.Time       `json:"created_at"`
			} `json:"journals"`
		}
		if err := json.Unmarshal(c.Encoded, &v); err != nil {
			return err
		}
		if len(v.Journals) == 0 || len(v.Journals) > 100000 {
			return kaname.ErrSourceUnconfirmed
		}
		for _, row := range v.Journals {
			if row.EventType != "fga.tuple.delete" || !row.CreatedAt.Equal(tx.lifetime.at) || len(row.Payload) == 0 {
				return kaname.ErrSourceUnconfirmed
			}
		}
		_, err := tx.Exec(ctx, `INSERT INTO kaname.fga_outbox(event_type,payload,created_at)
SELECT r.event_type,r.payload,r.created_at FROM jsonb_array_elements($1::jsonb->'journals') WITH ORDINALITY x(v,n)
CROSS JOIN LATERAL jsonb_to_record(x.v) AS r(event_type text,payload jsonb,created_at timestamptz)
ORDER BY x.n`, c.Encoded)
		return err
	case "withdrawal_role", "withdrawal_projection_delete", "withdrawal_projection_insert":
		return applyResourceWithdrawalProjection(ctx, tx, c)
	case "withdrawal_binding":
		var v struct {
			Action int             `json:"action"`
			Before json.RawMessage `json:"before"`
			Row    json.RawMessage `json:"row"`
		}
		if err := json.Unmarshal(c.Encoded, &v); err != nil {
			return err
		}
		query := ""
		switch v.Action {
		case 1:
			query = `UPDATE ONLY kaname.access_bindings b SET status=n.status,revoked_at=n.revoked_at,revocation_reason=n.revocation_reason
FROM jsonb_populate_record(NULL::kaname.access_bindings,$1::jsonb) old,
jsonb_populate_record(NULL::kaname.access_bindings,$2::jsonb) n
WHERE b.id=old.id AND n.id=old.id AND b.revoked_at IS NULL AND b.status=old.status AND b.target=old.target`
		case 2:
			query = `UPDATE ONLY kaname.access_bindings b SET target=n.target,target_digest=n.target_digest,narrowed_at=n.narrowed_at
FROM jsonb_populate_record(NULL::kaname.access_bindings,$1::jsonb) old,
jsonb_populate_record(NULL::kaname.access_bindings,$2::jsonb) n
WHERE b.id=old.id AND n.id=old.id AND b.revoked_at IS NULL AND b.status=old.status AND b.target=old.target`
		default:
			return kaname.ErrSourceUnconfirmed
		}
		tag, err := tx.Exec(ctx, query, v.Before, v.Row)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return kaname.ErrAuthorityClassificationChanged
		}
		return nil
	case "withdrawal_subject_change":
		var v struct {
			ID        int64           `json:"id"`
			SubjectID string          `json:"subject_id"`
			Op        string          `json:"op"`
			EventType string          `json:"event_type"`
			Payload   json.RawMessage `json:"payload"`
			CreatedAt time.Time       `json:"created_at"`
		}
		if err := json.Unmarshal(c.Row, &v); err != nil {
			return err
		}
		if v.ID <= 0 || v.SubjectID == "" || v.Op != "binding_delete" || v.EventType != "binding_revoke" || !v.CreatedAt.Equal(transactionAt) {
			return kaname.ErrSourceUnconfirmed
		}
		_, err := tx.Exec(ctx, `INSERT INTO kaname.subject_change_outbox(id,subject_id,op,event_type,payload,created_at)
VALUES($1,$2,$3,$4,$5::jsonb,$6)`, v.ID, v.SubjectID, v.Op, v.EventType, v.Payload, v.CreatedAt)
		return err
	case "withdrawal_audit":
		var audit resourceObjectAuditValue
		if err := json.Unmarshal(c.Row, &audit.Row); err != nil {
			return err
		}
		if audit.Row.ID == "" || audit.Row.EventType == "" || !audit.Row.CreatedAt.Equal(transactionAt) || !audit.Row.NextAttemptAt.Equal(transactionAt) {
			return kaname.ErrSourceUnconfirmed
		}
		_, err := tx.Exec(ctx, `INSERT INTO kaname.audit_outbox
(id,event_type,tenant_account_id,event_payload,status,attempts,created_at,next_attempt_at)
VALUES($1,$2,$3,$4::jsonb,'pending',0,$5,$6)`, audit.Row.ID, audit.Row.EventType, audit.Row.TenantAccountID, audit.Row.Payload, audit.Row.CreatedAt, audit.Row.NextAttemptAt)
		return err
	default:
		return kaname.ErrSourceUnconfirmed
	}
}
