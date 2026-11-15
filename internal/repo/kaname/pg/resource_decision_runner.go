// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"

	"github.com/PRO-Robotech/corelib/platformmodules"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Один immutable runner разделяет существующий runtime repo, bundle и roster
// gate. Per-attempt checker связывается отдельной копией gate; исходный pool
// checker и Registrar не меняются при конкурентных вызовах.
type ResourceDecisionRunner struct {
	repo   *Repository
	bundle *granteffect.Bundle
	gate   *authzguard.RelationWriteGate
	facts  *catalog.Facts
}

func NewResourceDecisionRunner(ctx context.Context, repo *Repository, bundle *granteffect.Bundle, gate *authzguard.RelationWriteGate) (*ResourceDecisionRunner, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if repo == nil || repo.master == nil || gate == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	if err := validateResourceRegistrationModel(bundle); err != nil {
		return nil, err
	}
	if err := repo.ValidateAuthorityRuntime(ctx); err != nil {
		return nil, err
	}
	if err := validatePolicyEpochStorage(ctx, repo); err != nil {
		return nil, err
	}
	mapping, err := json.Marshal(struct {
		ABI      int               `json:"abi"`
		Aliases  map[string]string `json:"aliases"`
		Fallback string            `json:"fallback"`
	}{ABI: 1, Aliases: platformmodules.AliasesByService(), Fallback: "identity"})
	if err != nil {
		return nil, err
	}
	var protected bool
	// Нет fallback при старом SQL ABI, неполном graph или недоступной проверке.
	// Владелец схемы поставляет этот contract вместе со всеми v2 consumers.
	if err := repo.master.QueryRow(ctx, `SELECT kaname.authority_resource_storage_v2($1::jsonb)`, mapping).Scan(&protected); err != nil {
		return nil, err
	}
	if !protected {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	var halves catalog.Halves
	if err := json.Unmarshal(bundle.CanonicalCatalog(), &halves); err != nil {
		return nil, err
	}
	facts, err := catalog.NewFacts(halves)
	if err != nil {
		return nil, err
	}
	return &ResourceDecisionRunner{repo: repo, bundle: bundle, gate: gate, facts: facts}, nil
}
