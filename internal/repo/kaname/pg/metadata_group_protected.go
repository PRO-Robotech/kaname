// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5"
)

// Отдельная обёртка объявляет Group-порт только при готовности SQL-контракта.
type groupAccessLabelMetadataWriters struct {
	*serviceAccountAccessLabelMetadataWriters
}

func groupAccessLabelRequest(value domain.Group, mask []string) metadataMutation {
	return metadataMutation{
		kind: "group", table: "groups", typ: "iam_group", id: string(value.ID),
		name: string(value.Name), description: string(value.Description),
		labels: value.Labels, accessLabels: value.AccessLabels,
		mode: metadataMutationAccessLabels, mask: slices.Clone(mask),
	}
}

func (p *groupAccessLabelMetadataWriters) GroupAccessLabelsWriter(ctx context.Context, value domain.Group, mask []string, actor domain.Subject) (kaname.SemanticAuthorityWriter, error) {
	return p.open(ctx, groupAccessLabelRequest(value, mask), actor)
}

type groupMetadataWrite struct {
	actor            string
	updated          domain.Group
	expectsReconcile bool
	reconcileUsed    bool
}

type protectedGroupMetadata struct {
	group.WriterIface
	tx *metadataWriteTx
}

func (w *metadataWriteTx) GroupsW() group.WriterIface {
	writer := w.semanticAuthorityWriteTx.GroupsW()
	if w.protected == nil || w.protected.root.Type != "iam.group" {
		return writer
	}
	return &protectedGroupMetadata{WriterIface: writer, tx: w}
}

func (w *protectedGroupMetadata) Update(ctx context.Context, value domain.Group, mask []string) (domain.Group, error) {
	_, err := w.tx.protected.ordinaryMask(groupAccessLabelRequest(value, mask))
	if err != nil {
		return domain.Group{}, err
	}
	effects := w.tx.groupWrite
	if effects == nil || effects.updated.ID != "" {
		return domain.Group{}, kaname.ErrSourceUnconfirmed
	}
	row := w.tx.tx.QueryRow(ctx, `SELECT `+groupCols+`
		FROM jsonb_populate_record(NULL::kaname.groups,kaname.authority_metadata_group_write_v1($1))`, value.ID)
	updated, err := scanGroup(row)
	if err != nil {
		return domain.Group{}, mapErr(err, "Group.Update", string(value.Name))
	}
	if updated.ID != value.ID || updated.AccountID != value.AccountID {
		return domain.Group{}, kaname.ErrSourceUnconfirmed
	}
	effects.updated = updated
	return updated, nil
}

// SQL уже записал аудит и пересчёт. Принимаем только ожидаемые вызовы тела
// операции, чтобы тот же эффект не записался повторно.
func (w *metadataWriteTx) confirmGroupAudit(ctx context.Context, ev service.AuditEvent) error {
	out := w.groupWrite
	fields, ok := ev.Payload["changed_fields"].([]string)
	if w.auditUsed || out.updated.ID == "" || len(w.changed) == 0 || ev.EventType != "iam.group.updated" ||
		ev.TenantAccountID != string(out.updated.AccountID) || len(ev.Payload) != 5 ||
		ev.Payload["actor"] != out.actor || ev.Payload["account_id"] != string(out.updated.AccountID) ||
		ev.Payload["resource_type"] != "group" || ev.Payload["resource_id"] != string(out.updated.ID) ||
		!ok || !slices.Equal(fields, w.changed) {
		return kaname.ErrSourceUnconfirmed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	w.auditUsed = true
	return nil
}

func (w *metadataWriteTx) EmitReconcileEvent(ctx context.Context, eventType, objectType, objectID string) error {
	out := w.groupWrite
	if out == nil {
		return w.semanticAuthorityWriteTx.EmitReconcileEvent(ctx, eventType, objectType, objectID)
	}
	if !out.expectsReconcile || out.reconcileUsed || out.updated.ID == "" || eventType != "mirror.upsert" ||
		objectType != "iam.group" || objectID != string(out.updated.ID) {
		return kaname.ErrSourceUnconfirmed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	out.reconcileUsed = true
	return nil
}

func (s *metadataStage) prepareGroupProtected(ctx context.Context, tx pgx.Tx, labels json.RawMessage, writes []string, work *int) error {
	budget, actor := s.plan.nativeBudget, s.plan.request.actor
	var cost protectedMetadataCost
	err := tx.QueryRow(ctx, `SELECT used_rows,used_reads,used_work
		FROM kaname.authority_metadata_group_prepare_v1($1,$2,$3,$4::jsonb,$5::jsonb,$6,$7,$8::jsonb,$9::text[],$10,$11,$12)`,
		s.request.id, s.xmin, s.ctid, s.old, labels, string(actor.Type), string(actor.ID),
		s.plan.epochs, writes, budget.RemainingRows(), budget.RemainingReads(), *work).
		Scan(&cost.Rows, &cost.Reads, &cost.Work)
	if err != nil {
		return mapProtectedMetadataErr(err)
	}
	return s.chargeProtected(cost, work)
}

func (s *metadataStage) groupRetentionInputs(ctx context.Context, tx pgx.Tx, actor domain.Subject, patch json.RawMessage, work *int) (json.RawMessage, error) {
	budget := s.plan.nativeBudget
	var envelope json.RawMessage
	err := tx.QueryRow(ctx, `SELECT kaname.authority_metadata_group_retention_inputs_v1($1::jsonb,$2,$3,$4,$5,$6,$7)`,
		patch, s.rename, string(actor.Type), string(actor.ID), budget.RemainingRows(), budget.RemainingReads(), *work).
		Scan(&envelope)
	return envelope, err
}

func (s *metadataStage) reserveGroupProtected(ctx context.Context, tx pgx.Tx, actor domain.Subject, desired json.RawMessage, work *int) error {
	budget := s.plan.nativeBudget
	var cost protectedMetadataCost
	err := tx.QueryRow(ctx, `SELECT kaname.authority_metadata_group_reserve_v1($1::jsonb,$2,$3,$4,$5,$6,$7)`,
		desired, string(s.auditID), string(actor.Type), string(actor.ID), budget.RemainingRows(), budget.RemainingReads(), *work).
		Scan(&cost)
	if err != nil {
		return mapProtectedMetadataErr(err)
	}
	return s.chargeProtected(cost, work)
}

func (s *metadataStage) acceptGroupProtected(ctx context.Context, tx pgx.Tx, actor domain.Subject, work *int) error {
	budget := s.plan.nativeBudget
	var cost protectedMetadataCost
	err := tx.QueryRow(ctx, `SELECT kaname.authority_metadata_group_accept_v1($1,$2,$3,$4,$5)`,
		string(actor.Type), string(actor.ID), budget.RemainingRows(), budget.RemainingReads(), *work).
		Scan(&cost)
	if err != nil {
		return mapProtectedMetadataErr(err)
	}
	return s.chargeProtected(cost, work)
}

func (s *metadataStage) reserveGroupOrdinary(ctx context.Context, tx pgx.Tx, actor domain.Subject, patch json.RawMessage, work *int) error {
	budget := s.plan.nativeBudget
	var audit *string
	mode := "noop"
	if len(s.changed) != 0 {
		id := string(s.auditID)
		audit = &id
		mode = "ordinary"
	}
	var receipt struct {
		protectedMetadataCost
		Mode    string   `json:"mode"`
		Changed []string `json:"changed_fields"`
	}
	err := tx.QueryRow(ctx, `SELECT kaname.authority_metadata_group_ordinary_reserve_v1(
		$1,$2,$3,$4::jsonb,$5::jsonb,$6,$7,$8,$9,$10,$11)`,
		s.request.id, s.xmin, s.ctid, s.old, patch, string(actor.Type), string(actor.ID), audit,
		budget.RemainingRows(), budget.RemainingReads(), *work).Scan(&receipt)
	if err != nil {
		return mapProtectedMetadataErr(err)
	}
	if receipt.Mode != mode || receipt.Changed == nil || !slices.Equal(receipt.Changed, s.changed) {
		return kaname.ErrSourceUnconfirmed
	}
	return s.chargeProtected(receipt.protectedMetadataCost, work)
}

var _ kaname.GroupAccessLabelsWriterFactory = (*groupAccessLabelMetadataWriters)(nil)
