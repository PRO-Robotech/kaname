// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5"
)

// ClusterAdminParticipant открывает GLOBAL participant до любых старых locks.
// Простой Begin сохраняет participant контракт. Публичные UC дополнительно
// выбирают RunAdminDecision с final reauth после полного preflight.
type ClusterAdminParticipant struct {
	repo   *Repository
	bundle *granteffect.Bundle
}

func NewClusterAdminParticipant(ctx context.Context, repo *Repository, bundle *granteffect.Bundle) (*ClusterAdminParticipant, error) {
	if repo == nil || repo.master == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	if err := repo.ValidateAuthorityRuntime(ctx); err != nil {
		return nil, err
	}
	return &ClusterAdminParticipant{repo: repo, bundle: bundle}, nil
}

func (p *ClusterAdminParticipant) Begin(ctx context.Context) (service.Tx, error) {
	if p == nil || p.repo == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	w, err := p.repo.coordinatedAuthorityWriter(ctx, kaname.AuthorityWriteIntent{
		Kind: kaname.AuthorityCluster, Bundle: p.bundle,
		Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal},
	}, "participant")
	if err != nil {
		return nil, err
	}
	// service adapters восстанавливают pgx.Tx, но lifecycle остаётся у writer.
	return &clusterAdminParticipantTx{Tx: w.tx, owner: w}, nil
}

type clusterAdminParticipantTx struct {
	pgx.Tx
	owner         *authorityWriteTx
	finalDecision bool
}

func (t *clusterAdminParticipantTx) Commit(ctx context.Context) error { return t.owner.Commit(ctx) }
func (t *clusterAdminParticipantTx) Rollback(ctx context.Context) error {
	// UC откатывает с исходным ctx; отмена запроса не должна удерживать GLOBAL.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return t.owner.Rollback(cleanup)
}

var _ service.TxBeginner = (*ClusterAdminParticipant)(nil)
var _ pgx.Tx = (*clusterAdminParticipantTx)(nil)

// Часы доступны адаптеру записи только после полного preflight.
func (t *clusterAdminParticipantTx) ClusterAdminDecisionAt() time.Time {
	if t == nil || !t.finalDecision || t.owner == nil {
		return time.Time{}
	}
	return t.owner.fence.decisionAt
}
