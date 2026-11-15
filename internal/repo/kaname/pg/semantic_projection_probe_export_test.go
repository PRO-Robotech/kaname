// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
)

// Сохранённый compare-порт нужен только ACL-пробам identity; он берёт GLOBAL.
func OpenSemanticIdentityCompareProbe(ctx context.Context, r *Repository, bundle *granteffect.Bundle) (kaname.SemanticAuthorityWriter, error) {
	return r.compareAuthorityIdentity(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle)
}

// Порт существует только при сборке тестов. Он не предоставляет authority API,
// native checker или методы записи: raw RC изолирует oracle стоимости SQL.
type projectionSQLComponentProbe struct {
	reader *semanticAuthorityWriteTx
}

func (p *projectionSQLComponentProbe) RoleProjectionCheckpoint(ctx context.Context, id domain.RoleID) (granteffect.ProjectionCheckpoint, kaname.SourceReadCost, error) {
	return p.reader.RoleProjectionCheckpoint(ctx, id)
}
func (p *projectionSQLComponentProbe) Rollback(ctx context.Context) error {
	return p.reader.tx.Rollback(ctx)
}

// Снимки двух SELECT намеренно могут различаться; это не защищённое решение
// о выдаче доступа. Ни compare helper, ни GLOBAL entry здесь не вызываются.
func OpenUnprotectedProjectionComponentProbe(ctx context.Context, r *Repository, bundle *granteffect.Bundle) (*projectionSQLComponentProbe, error) {
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	tx, err := r.master.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	reader := &semanticAuthorityWriteTx{
		authorityWriteTx: &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: tx}}},
		bundle:           bundle,
	}
	return &projectionSQLComponentProbe{reader: reader}, nil
}
