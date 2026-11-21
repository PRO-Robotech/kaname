// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package authorityprotocol

import (
	"context"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FullContract is immutable and bound to one runtime pool and semantic identity.
// Context propagation selects code, never DB authority: every entry revalidates it.
type FullContract struct {
	pool                      *pgxpool.Pool
	model, catalog, projector string
}
type fullContractContextKey struct{}

func NewFullContract(ctx context.Context, pool *pgxpool.Pool, model, catalog, projector string) (*FullContract, error) {
	if pool == nil || model == "" || catalog == "" || projector == "" {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	var ready bool
	if err := pool.QueryRow(ctx, `SELECT kaname.authority_full_contract_validate_v3($1,$2,$3)`, model, catalog, projector).Scan(&ready); err != nil {
		return nil, err
	}
	if !ready {
		return nil, kaname.ErrSemanticIdentityUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &FullContract{pool: pool, model: model, catalog: catalog, projector: projector}, nil
}
func (c *FullContract) Matches(pool *pgxpool.Pool, model, catalog, projector string) bool {
	return c != nil && c.pool == pool && c.model == model && c.catalog == catalog && c.projector == projector
}
func (c *FullContract) UsesPool(pool *pgxpool.Pool) bool { return c != nil && c.pool == pool }
func (c *FullContract) Context(ctx context.Context) context.Context {
	return context.WithValue(ctx, fullContractContextKey{}, c)
}
func contractFromContext(ctx context.Context) (*FullContract, bool) {
	c, present := ctx.Value(fullContractContextKey{}).(*FullContract)
	return c, present
}
