// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// Один snapshot: все прежние abCols, реальные физические поколения, версия
// и полный bounded subjects set. abCols и старый scanner не меняются.
var accessLabelBindingSnapshotSQL = `WITH source_header AS MATERIALIZED (
 SELECT b.*,b.xmin::text AS source_xmin,b.ctid::text AS source_ctid
 FROM kaname.access_bindings b WHERE b.id=$1
 AND octet_length(to_jsonb(b)::text)<=8388608
), source_subjects AS MATERIALIZED (
 SELECT s.subject_type,s.subject_id,s.resource_type,s.resource_id,s.ordinal
 FROM kaname.access_binding_subjects s
 WHERE s.binding_id=$1 AND EXISTS(SELECT 1 FROM source_header)
 ORDER BY s.ordinal,s.subject_type COLLATE "C",s.subject_id COLLATE "C" LIMIT $2
)
SELECT ` + abCols + `,source_xmin,source_ctid,grant_capability_version,
 (SELECT coalesce(jsonb_agg(jsonb_build_object('Type',s.subject_type,'ID',s.subject_id,
 'ScopeType',s.resource_type,'ScopeID',s.resource_id)
 ORDER BY s.ordinal,s.subject_type COLLATE "C",s.subject_id COLLATE "C"),'[]'::jsonb)
 FROM source_subjects s)
FROM source_header`

// Дополнительные поля идут ПОСЛЕ единственного стандартного abCols scanner.
type accessLabelBindingSnapshotScanner struct {
	row    pgx.Row
	suffix []any
}

func (s accessLabelBindingSnapshotScanner) Scan(dest ...any) error {
	return s.row.Scan(append(append([]any(nil), dest...), s.suffix...)...)
}

// Полный persisted header + canonical subjects. Исключаются только поля,
// которые domain прямо объявляет non-persisted; meta/security labels остаются.
func accessLabelBindingImage(b domain.AccessBinding) ([32]byte, error) {
	if err := b.Validate(); err != nil {
		return [32]byte{}, err
	}
	subjects, err := domain.NormalizeSubjects(slices.Clone(b.Subjects), "", "")
	if err != nil {
		return [32]byte{}, err
	}
	slices.SortFunc(subjects, func(a, b domain.Subject) int {
		if a.Type < b.Type {
			return -1
		}
		if a.Type > b.Type {
			return 1
		}
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	b.Subjects = subjects
	b.MaterializedAt = time.Time{}
	b.HeldTargets = nil
	b.CreatedAt = b.CreatedAt.UTC()
	if b.ExpiresAt != nil {
		at := b.ExpiresAt.UTC()
		b.ExpiresAt = &at
	}
	if b.RevokedAt != nil {
		at := b.RevokedAt.UTC()
		b.RevokedAt = &at
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return [32]byte{}, err
	}
	if len(raw) > granteffect.MaxInputBytes {
		return [32]byte{}, kaname.ErrSourceReadLimit
	}
	return sha256.Sum256(raw), nil
}

type capturedAccessLabelBindingSource struct {
	owner    *preparedRoleWriteTx
	plan     *policyPlan
	native   *protectedNativeRead
	budget   *relverdict.AdministrativeReadBudget
	conn     *pgx.Conn
	bundle   *granteffect.Bundle
	actor    domain.Subject
	at       time.Time
	image    [32]byte
	snapshot kaname.AccessLabelBindingSourceSnapshot
}

func (p *capturedAccessLabelBindingSource) Snapshot() kaname.AccessLabelBindingSourceSnapshot {
	if p == nil {
		return kaname.AccessLabelBindingSourceSnapshot{}
	}
	return p.snapshot
}
func (p *capturedAccessLabelBindingSource) Validate(writer kaname.SemanticAuthorityWriter, actor domain.Subject, at time.Time, binding domain.AccessBinding, version int) error {
	w, ok := writer.(*preparedRoleWriteTx)
	if !ok || p == nil || p.owner != w || !w.canReadAccessLabelSource() {
		return kaname.ErrSourceUnconfirmed
	}
	if w.stage.plan != p.plan || w.nativeRead != p.native || w.producerBudget != p.budget ||
		w.tx.Conn() != p.conn || w.bundle != p.bundle || actor != p.actor ||
		!at.Equal(p.at) || !at.Equal(w.fence.decisionAt) {
		return kaname.ErrSourceUnconfirmed
	}
	if binding.ID != p.snapshot.BindingID || binding.RoleID != p.snapshot.RoleID ||
		version != p.snapshot.CapabilityVersion {
		return kaname.ErrSourceUnconfirmed
	}
	image, err := accessLabelBindingImage(binding)
	if err != nil {
		return err
	}
	if image != p.image {
		return kaname.ErrSourceUnconfirmed
	}
	return nil
}

// Источник actor с apply сам по себе не включает дополнительные чтения.
// Это только activation чтения: положительного authority-решения здесь нет.
func (w *preparedRoleWriteTx) AccessLabelBindingSourcesEnabled() bool {
	return w != nil && w.stage != nil && slices.ContainsFunc(w.stage.projection.Capabilities, func(cap domain.GrantCapabilityRule) bool {
		return cap.Kind == domain.GrantCapabilityApplyAccessLabel
	})
}

// Эти признаки живут в той же попытке writer. После первой DML роли её
// обновлённый образ не может стать источником полномочий этой же операции.
func (w *preparedRoleWriteTx) canReadAccessLabelSource() bool {
	if w == nil || w.semanticAuthorityWriteTx == nil || w.authorityWriteTx == nil ||
		w.writeTx == nil || w.tx == nil || w.closed || w.roleWriteStarted || w.applied ||
		w.stage == nil || w.stage.plan == nil || w.nativeRead == nil || w.nativeRead.boundary == nil || w.bundle == nil {
		return false
	}
	plan := w.stage.plan
	return plan.request.kind == kaname.AuthorityRole && plan.nativeBudget != nil &&
		w.producerBudget == plan.nativeBudget && w.nativeRead.budget == plan.nativeBudget &&
		w.nativeRead.boundary == plan.native
}

func (w *preparedRoleWriteTx) CaptureAccessLabelBindingSource(ctx context.Context, actor domain.Subject, at time.Time, wanted domain.AccessBinding, version int) (kaname.CapturedAccessLabelBindingSource, kaname.SourceReadCost, error) {
	zero := kaname.SourceReadCost{}
	if err := ctx.Err(); err != nil {
		return nil, zero, err
	}
	if !w.canReadAccessLabelSource() || !w.AccessLabelBindingSourcesEnabled() {
		return nil, zero, kaname.ErrSourceUnconfirmed
	}
	plan := w.stage.plan
	budget := plan.nativeBudget
	if actor != plan.request.actor || actor.Validate() != nil || actor.ID == "*" ||
		(actor.Type != domain.SubjectTypeUser && actor.Type != domain.SubjectTypeServiceAccount) ||
		!w.policyGuards[subjectPolicyKey(actor)] || at.IsZero() || !at.Equal(w.fence.decisionAt) {
		return nil, zero, kaname.ErrSourceUnconfirmed
	}
	if !nativeQuestionToken(string(wanted.ID)) || !nativeQuestionToken(string(wanted.RoleID)) ||
		!w.policyGuards["role:"+string(wanted.RoleID)] || version != 1 ||
		wanted.Status != domain.AccessBindingStatusActive || wanted.RevokedAt != nil ||
		(wanted.ExpiresAt != nil && !wanted.ExpiresAt.After(at)) || len(wanted.Target.Resources) != 0 {
		return nil, zero, kaname.ErrSourceUnconfirmed
	}
	expectedImage, err := accessLabelBindingImage(wanted)
	if err != nil {
		return nil, zero, err
	}
	rowsLeft := budget.RemainingRows()
	if rowsLeft < 2 || budget.RemainingReads() < 1 {
		return nil, zero, kaname.ErrSourceReadLimit
	}
	subjectLimit := min(domain.MaxSubjectsPerBinding, rowsLeft-1) + 1
	cost := kaname.SourceReadCost{Rows: 1 + subjectLimit, Reads: 1}
	var snapshot kaname.AccessLabelBindingSourceSnapshot
	var subjectsRaw []byte
	row := w.tx.QueryRow(ctx, accessLabelBindingSnapshotSQL, string(wanted.ID), subjectLimit)
	current, err := scanAB(accessLabelBindingSnapshotScanner{row: row, suffix: []any{&snapshot.RowXmin, &snapshot.RowCTID, &snapshot.CapabilityVersion, &subjectsRaw}})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			cost.Rows = 1
			err = kaname.ErrSourceUnconfirmed
		}
		return nil, cost, err
	}
	if len(subjectsRaw) > granteffect.MaxInputBytes {
		return nil, cost, kaname.ErrSourceReadLimit
	}
	var subjects []struct {
		Type               domain.SubjectType
		ID                 domain.SubjectID
		ScopeType, ScopeID string
	}
	decoder := json.NewDecoder(bytes.NewReader(subjectsRaw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&subjects); err != nil {
		return nil, cost, err
	}
	cost.Rows = 1 + len(subjects)
	if cost.Rows > rowsLeft || len(subjects) > domain.MaxSubjectsPerBinding {
		return nil, cost, kaname.ErrSourceReadLimit
	}
	if len(subjects) == 0 {
		return nil, cost, kaname.ErrSourceUnconfirmed
	}
	for _, subject := range subjects {
		if subject.ScopeType != string(current.ResourceType) || subject.ScopeID != current.ResourceID {
			return nil, cost, kaname.ErrSourceUnconfirmed
		}
		current.Subjects = append(current.Subjects, domain.Subject{Type: subject.Type, ID: subject.ID})
	}
	// Обе стороны прошли тот же scanner/нормализацию. Изменение любой persisted
	// части не подменяет старый source новым: вся попытка завершается mismatch.
	currentImage, err := accessLabelBindingImage(current)
	if err != nil {
		return nil, cost, err
	}
	if currentImage != expectedImage || snapshot.CapabilityVersion != version || snapshot.RowXmin == "" || snapshot.RowCTID == "" {
		return nil, cost, kaname.ErrSourceUnconfirmed
	}
	if err = ctx.Err(); err != nil {
		return nil, cost, err
	}
	snapshot.BindingID, snapshot.RoleID = current.ID, current.RoleID
	receipt := &capturedAccessLabelBindingSource{owner: w, plan: plan, native: w.nativeRead, budget: budget, conn: w.tx.Conn(), bundle: w.bundle, actor: actor, at: at, image: currentImage, snapshot: snapshot}
	return receipt, cost, nil
}

var _ kaname.AccessLabelBindingSourceReader = (*preparedRoleWriteTx)(nil)
