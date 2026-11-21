// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Ошибка cleanup сохраняется вместе с отказом тела; отмена не удерживает lease.
func rollbackSeedAuthority(ctx context.Context, tx pgx.Tx) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err := tx.Rollback(cleanup)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}
