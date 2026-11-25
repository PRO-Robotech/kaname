// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

// Свидетельство хранит также версии предикатов регистрации. Владелец
// получает его целиком и сверяет с удержанным RC состоянием.
func (s *metadataStage) discoverOrdinaryMirror(ctx context.Context, rr pgx.Tx) (json.RawMessage, error) {
	if err := s.checkMirrorGrantIdentity(); err != nil {
		return nil, err
	}
	budget := s.plan.nativeBudget
	var snapshot json.RawMessage
	var rows, reads int
	err := rr.QueryRow(ctx, `WITH captured AS MATERIALIZED (
 SELECT kaname.authority_metadata_mirror_ordinary_discover_v1($1,$2,$3,$4) AS obj)
 SELECT obj,(obj->>'rows')::int,(obj->>'reads')::int FROM captured
 WHERE obj#>>'{identity,dotted}'=$1 AND obj#>>'{identity,id}'=$2
 AND obj#>>'{identity,mirror,0}'=$5 AND obj#>>'{identity,catalog,2,object_type}'=$6
 AND obj#>>'{identity,account,2,id}'=$7 AND (obj#>>'{identity,has_receipt}')::boolean=$8
 AND coalesce(obj#>>'{identity,project,2,id}','')=coalesce($9::jsonb->>'parent_project_id','')
 AND jsonb_typeof(obj->'registration')='object'`, s.request.kind, s.request.id, budget.RemainingRows(), budget.RemainingReads(), s.xmin, s.request.typ, s.mirrorAccount, s.grant.mirrorPolicyGlobal, s.old).Scan(&snapshot, &rows, &reads)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err != nil {
		return nil, mapProtectedMetadataErr(err)
	}
	if rows < 1 || reads < 1 || len(snapshot) == 0 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err = chargeNativePolicyBudget(budget, rows, reads); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// Вызывается в pending RC до первой policy-защиты, завершающей consumer.
// Маска передаётся целиком, включая явно указанную неизменную access_labels.
func (s *metadataStage) reserveOrdinaryMirror(ctx context.Context, tx pgx.Tx, rr, patch json.RawMessage, work *int) error {
	if work == nil {
		return kaname.ErrInvalidAuthorityFencePlan
	}
	var audit *string
	expected := "noop"
	switch {
	case len(s.changed) == 0:
	case len(s.changed) == 1 && s.changed[0] == "labels":
		expected = "ordinary"
		id := string(s.auditID)
		audit = &id
	default:
		return kaname.ErrSourceUnconfirmed
	}
	actor := s.plan.request.actor
	budget := s.plan.nativeBudget
	var mode string
	var cost protectedMetadataCost
	err := tx.QueryRow(ctx, `WITH reserved AS MATERIALIZED (
 SELECT kaname.authority_metadata_mirror_ordinary_preflight_v1($1,$2,$3::jsonb,$4::jsonb,$5,$6,$7,$8,$9,$10) AS obj)
 SELECT obj->>'mode',(obj->>'rows')::int,(obj->>'reads')::int,(obj->>'work')::int FROM reserved`,
		s.request.kind, s.request.id, rr, patch, string(actor.Type), string(actor.ID), audit, budget.RemainingRows(), budget.RemainingReads(), *work).Scan(&mode, &cost.Rows, &cost.Reads, &cost.Work)
	if err != nil {
		return mapProtectedMetadataErr(err)
	}
	if err = s.chargeProtected(cost, work); err != nil {
		return err
	}
	if mode != expected {
		return kaname.ErrSourceUnconfirmed
	}
	return nil
}

// Решение Go уже принято на финальных часах. Резервируем вызов accept и
// чтение результата точного final writer; стоимость удержания учтена в preflight.
func (s *metadataStage) acceptOrdinaryMirror(ctx context.Context, w *semanticAuthorityWriteTx) error {
	if !s.grant.source.lifetime.valid(w.authorityWriteTx, w.bundle) {
		return kaname.ErrSourceUnconfirmed
	}
	if err := chargeNativePolicyBudget(s.plan.nativeBudget, 1, 2); err != nil {
		return err
	}
	actor := s.plan.request.actor
	_, err := w.tx.Exec(ctx, `SELECT kaname.authority_metadata_mirror_ordinary_accept_v1($1,$2)`, string(actor.Type), string(actor.ID))
	return mapProtectedMetadataErr(err)
}
