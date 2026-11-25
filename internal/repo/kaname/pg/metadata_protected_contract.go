// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

const metadataProtectedWorkLimit = 400000

type protectedMetadataCost struct {
	Rows  int `json:"rows"`
	Reads int `json:"reads"`
	Work  int `json:"work"`
}

func (s *metadataStage) chargeProtected(cost protectedMetadataCost, work *int) error {
	if cost.Rows < 1 || cost.Reads < 1 || cost.Work < 1 || cost.Work > *work {
		return kaname.ErrSourceUnconfirmed
	}
	if err := chargeNativePolicyBudget(s.plan.nativeBudget, cost.Rows, cost.Reads); err != nil {
		return err
	}
	*work -= cost.Work
	return nil
}

// Выводит полный порядок блокировок до первого protectPolicyPlan.
func (s *metadataStage) prepareProtected(ctx context.Context, tx pgx.Tx, accessLabels json.RawMessage, work *int) error {
	writes := []string{}
	if !s.plan.global {
		for key := range s.plan.exclusive {
			writes = append(writes, key)
		}
		slices.Sort(writes)
	}
	budget := s.plan.nativeBudget
	if s.request.kind == "group" {
		return s.prepareGroupProtected(ctx, tx, accessLabels, writes, work)
	}
	var cost protectedMetadataCost
	err := tx.QueryRow(ctx, `SELECT used_rows,used_reads,used_work
 FROM kaname.authority_metadata_access_label_prepare_v1($1,$2,$3,$4::jsonb,$5::jsonb,$6::jsonb,$7::text[],$8,$9,$10)`,
		s.request.kind, s.request.id, s.xmin, s.old, accessLabels, s.plan.epochs, writes,
		budget.RemainingRows(), budget.RemainingReads(), *work).
		Scan(&cost.Rows, &cost.Reads, &cost.Work)
	if err != nil {
		return mapProtectedMetadataErr(err)
	}
	return s.chargeProtected(cost, work)
}

// SQL уже подтвердил точный OLD при удержании источников. Go рассчитывает
// предложения для NEW и передаёт их обратно владельцу для проверки и резерва.
func (s *metadataStage) freezeProtected(ctx context.Context, tx pgx.Tx, bundle *granteffect.Bundle, actor domain.Subject, patch json.RawMessage, work *int) error {
	budget := s.plan.nativeBudget
	var envelope json.RawMessage
	var err error
	if s.request.kind == "group" {
		envelope, err = s.groupRetentionInputs(ctx, tx, actor, patch, work)
	} else {
		err = tx.QueryRow(ctx, `SELECT kaname.authority_metadata_access_label_retention_inputs_v1($1::jsonb,$2,$3,$4,$5)`,
			patch, s.rename, budget.RemainingRows(), budget.RemainingReads(), *work).Scan(&envelope)
	}
	if err != nil {
		return mapProtectedMetadataErr(err)
	}
	desired, err := s.compileProtectedDesired(ctx, bundle, envelope, work)
	if err != nil {
		return err
	}
	if s.request.kind == "group" {
		return s.reserveGroupProtected(ctx, tx, actor, desired, work)
	}
	var cost protectedMetadataCost
	err = tx.QueryRow(ctx, `SELECT used_rows,used_reads,used_work
 FROM kaname.authority_metadata_access_label_preflight_v2($1::jsonb,$2,$3,$4,$5,$6,$7)`,
		desired, string(s.auditID), string(actor.Type), string(actor.ID),
		budget.RemainingRows(), budget.RemainingReads(), *work).
		Scan(&cost.Rows, &cost.Reads, &cost.Work)
	if err != nil {
		return mapProtectedMetadataErr(err)
	}
	return s.chargeProtected(cost, work)
}

func (s *metadataStage) compileProtectedDesired(ctx context.Context, bundle *granteffect.Bundle, envelope json.RawMessage, work *int) (json.RawMessage, error) {
	var halves catalog.Halves
	if err := json.Unmarshal(bundle.CanonicalCatalog(), &halves); err != nil {
		return nil, err
	}
	facts, err := catalog.NewFacts(halves)
	if err != nil {
		return nil, err
	}
	var cost protectedMetadataCost
	if err = json.Unmarshal(envelope, &cost); err != nil {
		return nil, err
	}
	if err = s.chargeProtected(cost, work); err != nil {
		return nil, err
	}
	return compileMetadataAccessLabelDesired(ctx, facts, envelope, s.plan.nativeBudget)
}
