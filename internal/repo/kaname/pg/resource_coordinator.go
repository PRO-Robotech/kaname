// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

// Один вход одной whole-attempt. Здесь нет собственного цикла retry или
// rediscovery, иначе три попытки body незаметно превратились бы в девять entry.
// Переданная TX только что открыта на lease после завершения RR; SQL повторно
// проверяет freshness, владельцев и отсутствие ранних business locks.
func (r *ResourceDecisionRunner) enterResource(ctx context.Context, tx pgx.Tx, lifetime *resourceAttemptLifetime, footprint resourceFenceFootprint) (*authorityWriteTx, error) {
	if r == nil || r.repo == nil || r.bundle == nil || tx == nil || lifetime == nil || lifetime.ended || lifetime.prepared != nil || lifetime.bundle != r.bundle || lifetime.conn != tx.Conn() {
		return nil, kaname.ErrSourceUnconfirmed
	}
	intent := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityResource, Plan: footprint.plan, Owners: footprint.owners, Bundle: r.bundle}
	if err := validateAuthorityIntent(intent); err != nil {
		return nil, err
	}
	accounts, err := canonicalAuthorityAccounts(footprint.plan)
	if err != nil {
		return nil, err
	}
	owners, err := json.Marshal(append([]kaname.AuthorityOwnerRef{}, footprint.owners...))
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(accounts))
	for i, id := range accounts {
		ids[i] = string(id)
	}
	mode := "accounts"
	if footprint.plan.Mode == kaname.AuthorityFenceGlobal {
		mode = "global"
	}
	if r.repo.fullContract != nil && !r.repo.fullContractMatches(r.bundle) {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	identity := r.bundle.Identity()
	var at time.Time
	query := `SELECT kaname.authority_resource_enter_v2($1,$2::text[],$3::jsonb,$4,$5,$6)`
	if footprint.sourceWrite {
		query = `SELECT kaname.authority_resource_source_enter_v2($1,$2::text[],$3::jsonb,$4,$5,$6)`
	}
	if r.repo.fullContract != nil {
		query = `SELECT kaname.authority_resource_enter_v3($1,$2::text[],$3::jsonb,$4,$5,$6)`
		if footprint.sourceWrite {
			query = `SELECT kaname.authority_resource_source_enter_v3($1,$2::text[],$3::jsonb,$4,$5,$6)`
		}
	}
	if err = tx.QueryRow(ctx, query, mode, ids, owners, identity.ModelID, identity.CatalogID, identity.ProjectorVersion).Scan(&at); err != nil {
		return nil, err
	}
	if at.IsZero() {
		return nil, kaname.ErrSourceUnconfirmed
	}
	writer := &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: tx}}, fence: authorityFence{mode: footprint.plan.Mode, accounts: slices.Clone(accounts), decisionAt: at.UTC()}}
	if err = lifetime.prepare(writer); err != nil {
		return nil, err
	}
	return writer, nil
}
