// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type preparedAuditFaultRow struct { cause error }
func (r preparedAuditFaultRow) Scan(...any) error { return r.cause }

type preparedAuditFaultTx struct {
	pgx.Tx
	t *testing.T
	cause *pgconn.PgError
	queries, rollbacks *int
}
func (tx *preparedAuditFaultTx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	require.Contains(tx.t, sql, "INSERT INTO kaname.audit_outbox")
	(*tx.queries)++
	return preparedAuditFaultRow{cause: tx.cause}
}
func (tx *preparedAuditFaultTx) Commit(context.Context) error {
	tx.t.Fatal("ошибка audit body не допускает Commit")
	return nil
}
func (tx *preparedAuditFaultTx) Rollback(context.Context) error { (*tx.rollbacks)++; return nil }

// Проходим реальный EmitAuditEvent → InsertTx → mapErr и затем полный executor.
// Только ответ драйвера подменён: проверка не создаёт собственный ErrAborted.
func TestPreparedAuditBodyConflictPreservesCauseWithoutPublicSQL(t *testing.T) {
	for _, code := range []string{"40001", "40P01"} {
		t.Run(code, func(t *testing.T) {
			opened, queries, rollbacks := 0, 0, 0
			var last *pgconn.PgError
			err := executePreparedAttempts(context.Background(), func(context.Context) (*writeTx, error) {
				opened++
				last = &pgconn.PgError{Code: code, Message: "private SQL message", Detail: "private account row", Where: "private query context", Routine: "private server routine", InternalQuery: "SELECT private_secret FROM private_table"}
				mapped := mapErr(last, "", "")
				var exhausted interface { PreparedAttemptsExhausted() bool }
				require.False(t, errors.As(mapped, &exhausted), "одиночный legacy конфликт не означает исчерпание prepared budget")
				var cause *pgconn.PgError
				require.ErrorAs(t, mapped, &cause)
				require.Same(t, last, cause)
				require.Equal(t, iamerr.SerializationConflictSyncText, iamerr.StripSentinel(mapped))
				public := shared.MapRepoErr(mapped)
				require.Equal(t, codes.Aborted, status.Code(public))
				require.Equal(t, iamerr.SerializationConflictSyncText, status.Convert(public).Message())
				return &writeTx{readTx: readTx{tx: &preparedAuditFaultTx{t: t, cause: last, queries: &queries, rollbacks: &rollbacks}}}, nil
			}, func(ctx context.Context, w *writeTx) error {
				return w.EmitAuditEvent(ctx, service.AuditEvent{EventType: "prepared.body.conflict"})
			})
			require.Equal(t, authorityEntryAttempts, opened)
			require.Equal(t, opened, queries)
			require.Equal(t, opened, rollbacks)
			require.ErrorIs(t, err, iamerr.ErrAborted)
			var exhausted interface { PreparedAttemptsExhausted() bool }
			require.ErrorAs(t, err, &exhausted)
			require.True(t, exhausted.PreparedAttemptsExhausted(), "marker допустим только после всех трёх попыток")
			var cause *pgconn.PgError
			require.ErrorAs(t, err, &cause)
			require.Same(t, last, cause, "исчерпание сохраняет последнюю реальную причину body")
			require.Equal(t, iamerr.SerializationConflictSyncText, iamerr.StripSentinel(err))
			public := shared.MapRepoErrAt(context.Background(), err)
			require.Equal(t, codes.Aborted, status.Code(public))
			require.Equal(t, iamerr.SerializationConflictSyncText, status.Convert(public).Message())
			for _, secret := range []string{last.Message, last.Detail, last.Where, last.Routine, last.InternalQuery} {
				require.NotContains(t, err.Error(), secret)
				require.NotContains(t, public.Error(), secret)
			}
		})
	}
}
