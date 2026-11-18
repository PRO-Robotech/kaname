// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// UserDeleteSchemaRefusalForTest изолирует рубеж схемы: обычный Writer уже
// прошёл неизменённый admission, а plain DELETE не повторяет программный WHERE
// guard. Настоящие trigger, savepoint rollback, mapErr и nameHold сохраняются.
// Native ошибка снимается до mapping; holder должен быть заранее committed,
// чтобы rollback оператора не уничтожил предмет последующего чтения остатка.
func UserDeleteSchemaRefusalForTest(ctx context.Context, repo *Repository, id domain.UserID) (native *pgconn.PgError, result error, cleanupErr error) {
	writer, err := repo.Writer(ctx)
	if err != nil {
		return nil, err, nil
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := writer.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			cleanupErr = err
		}
	}()
	tx := writer.(*writeTx).tx
	result = deleteUnderSavepoint(ctx, tx, "User.Delete", string(id), func(sp pgx.Tx) error {
		_, err := sp.Exec(ctx, `DELETE FROM kaname.users WHERE id=$1`, string(id))
		if err != nil {
			errors.As(err, &native)
		}
		return mapErr(err, "User.Delete", string(id))
	})
	return native, result, nil
}
