// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/jackc/pgx/v5"
)

func lockMetadataAuthority(ctx context.Context, tx pgx.Tx) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := tx.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock_shared(1262569283,0)
		FROM pg_catalog.set_config('search_path','pg_catalog,pg_temp',true)`)
	return err
}
