// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// bootstrap_token_repo.go — BootstrapStore adapter for the
// InternalBootstrapTokenService use-case (#58). Provisions the singleton
// bootstrap SA's OAuth-client mapping (service_account_oauth_clients row),
// serialising concurrent first-callers with a transaction-scoped advisory lock so
// the external Hydra client is created at most once (IBT-03); UNIQUE(sva_id) on
// the mapping is the DB backstop. pgx stays confined to this package.
package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// bootstrapSvaID — the deterministic bootstrap ServiceAccount id, byte-identical
// to migration 0058's `'sva' || substr(md5('kacho-bootstrap-admin'),1,17)` and to
// bootstrap_token.DeriveIdentity().SvaID (cross-checked by an integration test).
const bootstrapSvaID = "svab91854890de887e6d"

// bootstrapProvisionLockName — the advisory-lock namespace string; hashtext()'d to
// the lock key. Distinct string ⇒ collision-free with any other advisory lock.
const bootstrapProvisionLockName = "kacho_iam_bootstrap_sa_provision"

// BootstrapStore is the pg adapter implementing
// bootstrap_token.BootstrapStore.
type BootstrapStore struct {
	pool *pgxpool.Pool
}

// NewBootstrapStore constructs the adapter.
func NewBootstrapStore(pool *pgxpool.Pool) *BootstrapStore { return &BootstrapStore{pool: pool} }

// LockAndGet takes the transaction-scoped bootstrap provisioning advisory lock
// (released on commit/rollback), then returns the existing bootstrap OAuth-client
// mapping (found=false when not yet provisioned).
func (s *BootstrapStore) LockAndGet(ctx context.Context, txh service.Tx) (domain.ServiceAccountOAuthClient, bool, error) {
	tx := txAsPgx(txh)
	// Serialise concurrent first-callers so only the winner reaches the external
	// Hydra create; losers block here until the winner commits, then read the row.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, bootstrapProvisionLockName); err != nil {
		return domain.ServiceAccountOAuthClient{}, false, mapErr(err, "", "")
	}
	row := tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM service_account_oauth_clients WHERE sva_id = $1`, socCols),
		bootstrapSvaID)
	out, err := scanSAOAuthClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ServiceAccountOAuthClient{}, false, nil
	}
	if err != nil {
		return domain.ServiceAccountOAuthClient{}, false, mapErr(err, "", "")
	}
	return out, true, nil
}

// InsertMapping persists the bootstrap OAuth-client mapping row within tx, reusing
// the shared service_account_oauth_clients INSERT (public key only).
func (s *BootstrapStore) InsertMapping(ctx context.Context, txh service.Tx, c domain.ServiceAccountOAuthClient) error {
	r := &SAOAuthClientRepo{pool: s.pool}
	_, err := r.Insert(ctx, txh, c)
	return err
}
