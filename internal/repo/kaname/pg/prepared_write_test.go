// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"errors"
	"io"
	"testing"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

type preparedCommitControl struct { pgx.Tx; cause error }
func (t *preparedCommitControl) Commit(context.Context) error { return t.cause }

type preparedControlTx struct {
	commit func() error
	rollback func(context.Context) error
}
func (t *preparedControlTx) Commit(context.Context) error { return t.commit() }
func (t *preparedControlTx) Rollback(ctx context.Context) error { return t.rollback(ctx) }

func TestPreparedAttemptsRestageAfterKnownCommitAbort(t *testing.T) {
	opened, bodies, rolledBack, durable := 0, 0, 0, 0
	var previousBudget any
	err := executePreparedAttempts(context.Background(), func(ctx context.Context) (*preparedControlTx, error) {
		if opened != 0 { require.Equal(t, 1, rolledBack, "повтор начинается только после cleanup") }
		require.Equal(t, 1, authorityEntryLimit(ctx), "внутренний stage не получает второй budget")
		budget := preparedAdministrativeReadBudget(ctx)
		if previousBudget != nil { require.Same(t, previousBudget, budget, "read cap нельзя обнулить при restage") }
		previousBudget = budget
		opened++
		attempt := opened
		return &preparedControlTx{commit: func() error {
			if attempt == 1 {
				cause := &pgconn.PgError{Code: "40001", Message: "real private cause"}
				w := &writeTx{readTx: readTx{tx: &preparedCommitControl{cause: cause}}}
				err := w.Commit(ctx)
				require.Same(t, cause, err, "prepared Commit сохраняет первичную серверную причину")
				return err
			}
			durable++
			return nil
		}, rollback: func(context.Context) error { rolledBack++; return pgx.ErrTxClosed }}, nil
	}, func(context.Context, *preparedControlTx) error { bodies++; return nil })
	require.NoError(t, err)
	require.Equal(t, 2, opened)
	require.Equal(t, 2, bodies)
	require.Equal(t, 1, durable)
	require.Equal(t, 1, rolledBack, "успешный Commit не запускает cleanup/replay")
}

func TestPreparedAttemptsRejectUnknownCommitAndFailedCleanup(t *testing.T) {
	conflict := &pgconn.PgError{Code: "40001", Message: "private conflict"}
	cleanup := errors.New("rollback failed")
	for _, tc := range []struct { name string; body, commit, rollback error; uncertainDurable bool }{
		{"ambiguous_commit", nil, io.ErrUnexpectedEOF, pgx.ErrTxClosed, true},
		{"commit_cleanup_failure", nil, conflict, cleanup, false},
		{"body_cleanup_failure", conflict, nil, cleanup, false},
		{"joined_closed_is_not_cleanup_success", conflict, nil, errors.Join(pgx.ErrTxClosed, cleanup), false},
		{"permission_denied", iamerr.ErrPermissionDenied, nil, nil, false},
		{"denial_dominates_joined_conflict", errors.Join(iamerr.ErrPermissionDenied, conflict), nil, nil, false},
		{"unknown_postcommit_classification", nil, kaname.ErrAuthorityClassificationChanged, pgx.ErrTxClosed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opened, durable := 0, 0
			err := executePreparedAttempts(context.Background(), func(context.Context) (*preparedControlTx, error) {
				opened++
				return &preparedControlTx{commit: func() error { if tc.uncertainDurable { durable++ }; return tc.commit }, rollback: func(context.Context) error { return tc.rollback }}, nil
			}, func(context.Context, *preparedControlTx) error { return tc.body })
			require.Error(t, err)
			require.Equal(t, 1, opened)
			if tc.uncertainDurable { require.Equal(t, 1, durable, "повтор после потерянного ответа удвоил бы commit") }
			if tc.rollback != nil && tc.rollback != pgx.ErrTxClosed { require.ErrorIs(t, err, cleanup) }
		})
	}
}

func TestPreparedAttemptsEntryCleanupAndCancellationAreTerminal(t *testing.T) {
	conflict := &pgconn.PgError{Code: "40001"}
	cleanup := errors.New("entry cleanup failed")
	opened := 0
	err := executePreparedAttempts(context.Background(), func(context.Context) (*preparedControlTx, error) {
		opened++
		return nil, preparedEntryFailure(conflict, cleanup)
	}, func(context.Context, *preparedControlTx) error { t.Fatal("неудачный entry не выдаёт body"); return nil })
	require.ErrorIs(t, err, conflict)
	require.ErrorIs(t, err, cleanup)
	require.Equal(t, 1, opened)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opened, rollback, commits := 0, 0, 0
	err = executePreparedAttempts(ctx, func(context.Context) (*preparedControlTx, error) {
		opened++
		return &preparedControlTx{commit: func() error { commits++; return nil }, rollback: func(clean context.Context) error {
			require.NoError(t, clean.Err(), "cleanup не наследует отмену worker")
			_, bounded := clean.Deadline(); require.True(t, bounded)
			rollback++; return nil
		}}, nil
	}, func(context.Context, *preparedControlTx) error { cancel(); return conflict })
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, opened)
	require.Equal(t, 1, rollback)
	require.Zero(t, commits)
}

func TestPreparedAttemptsExhaustionPreservesLastCauseWithoutPublicLeak(t *testing.T) {
	opened := 0
	var last *pgconn.PgError
	err := executePreparedAttempts(context.Background(), func(context.Context) (*preparedControlTx, error) {
		opened++
		last = &pgconn.PgError{Code: "40001", Message: "secret database detail"}
		return nil, last
	}, func(context.Context, *preparedControlTx) error { t.Fatal("entry отказ не вызывает action"); return nil })
	require.Equal(t, authorityEntryAttempts, opened)
	require.ErrorIs(t, err, iamerr.ErrAborted)
	var primary *pgconn.PgError
	require.ErrorAs(t, err, &primary)
	require.Same(t, last, primary)
	require.Equal(t, iamerr.SerializationConflictSyncText, iamerr.StripSentinel(err))
	require.NotContains(t, err.Error(), last.Message)
}
