// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// kaname#1034: снимок старой транзакции не может сохранить разрешительный
// compatibility после strict. Это проверка backstop, не реализация drain.
func TestWriterProtocolOldSnapshotCannotBypassStrictBackstop(t *testing.T) {
	for _, isolation := range []pgx.TxIsoLevel{pgx.RepeatableRead, pgx.Serializable} {
		t.Run(string(isolation), func(t *testing.T) {
			r := writerProtocolRig(t)
			stale, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: isolation})
			require.NoError(t, err)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = stale.Rollback(ctx)
			})
			var phase string
			require.NoError(t, stale.QueryRow(r.ctx, `SELECT phase FROM kaname.authority_semantic_identity WHERE singleton`).Scan(&phase))
			require.Equal(t, "prepared", phase)

			// Отдельный owner commit меняет действующую policy. Старый snapshot
			// не держит row lock; целевая account row ещё им не читалась.
			r.strict(t)
			var mode string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT enforcement FROM kaname.authority_writer_protocol WHERE singleton`).Scan(&mode))
			require.Equal(t, "strict", mode)
			_, err = stale.Exec(r.ctx, `UPDATE kaname.accounts SET description='stale snapshot bypass' WHERE id=$1`, r.a)
			require.Error(t, err, "старый снимок не должен разрешить raw mutation после strict")
			var pgerr *pgconn.PgError
			require.ErrorAs(t, err, &pgerr)
			require.Equal(t, "40001", pgerr.Code, "изменённая policy должна отвергнуть устаревший snapshot")
			require.NoError(t, stale.Rollback(r.ctx))

			// Законная новая транзакция с настоящим attestation сохраняет
			// работоспособность той же мутации под ordinary runtime LOGIN.
			current, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			require.NoError(t, err)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = current.Rollback(ctx)
			})
			r.enter(t, current, r.intent(r.a), "decision")
			tag, err := current.Exec(r.ctx, `UPDATE kaname.accounts SET description='current guarded write' WHERE id=$1`, r.a)
			require.NoError(t, err)
			require.EqualValues(t, 1, tag.RowsAffected())
			require.NoError(t, current.Commit(r.ctx))
			var description string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT description FROM kaname.accounts WHERE id=$1`, r.a).Scan(&description))
			require.Equal(t, "current guarded write", description)
		})
	}
}
