// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"testing"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestResourceAttemptsIncludeBodyAndCommitWithinOneBudget(t *testing.T) {
	for _, commit := range []bool{false, true} {
		calls := 0
		out, err := runResourceAttempts(context.Background(), func() (kaname.ResourceDecisionResult, error) {
			calls++
			if calls < 3 {
				return kaname.ResourceDecisionResult{Changed: true}, resourceFailedAttempt(&pgconn.PgError{Code: "40001"}, pgx.ErrTxClosed, commit)
			}
			return kaname.ResourceDecisionResult{CatalogType: "vpc.network", Changed: true}, nil
		})
		require.NoError(t, err)
		require.Equal(t, 3, calls)
		require.Equal(t, "vpc.network", out.CatalogType)
	}
}
func TestResourceAttemptsExhaustionNeverReturnsFailedBodyResult(t *testing.T) {
	calls := 0
	out, err := runResourceAttempts(context.Background(), func() (kaname.ResourceDecisionResult, error) {
		calls++
		return kaname.ResourceDecisionResult{Changed: true}, resourceFailedAttempt(kaname.ErrAuthorityClassificationChanged, nil, false)
	})
	require.ErrorIs(t, err, iamerr.ErrAborted)
	require.Equal(t, 3, calls)
	require.Equal(t, kaname.ResourceDecisionResult{}, out)
}
func TestResourceAttemptsNeverRepeatUnknownCommitOrUnconfirmedCleanup(t *testing.T) {
	backend := errors.New("commit connection lost")
	cleanup := errors.New("rollback connection lost")
	for _, err := range []error{
		resourceFailedAttempt(backend, pgx.ErrTxClosed, true),
		resourceFailedAttempt(&pgconn.PgError{Code: "40001"}, cleanup, true),
		resourceFailedAttempt(kaname.ErrAuthorityClassificationChanged, cleanup, false),
		resourceFailedAttempt(kaname.ErrAuthorityClassificationChanged, pgx.ErrTxClosed, true),
		&pgconn.PgError{Code: "40001"},
	} {
		calls := 0
		_, got := runResourceAttempts(context.Background(), func() (kaname.ResourceDecisionResult, error) { calls++; return kaname.ResourceDecisionResult{}, err })
		require.ErrorIs(t, got, err)
		require.Equal(t, 1, calls)
	}
}
func TestResourceAttemptsCancelRetainsCleanupFailureAndStopsRestage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cleanup := errors.New("rollback timed out")
	calls := 0
	_, err := runResourceAttempts(ctx, func() (kaname.ResourceDecisionResult, error) {
		calls++
		cancel()
		return kaname.ResourceDecisionResult{}, resourceFailedAttempt(&pgconn.PgError{Code: "40P01"}, cleanup, false)
	})
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, cleanup)
	require.Equal(t, 1, calls)
}

// COMMIT в уже отменённой TX является подтверждённым rollback PostgreSQL.
// Его можно повторить, в отличие от неопределённой ошибки доставки COMMIT.
func TestResourceAttemptsRepeatConfirmedCommitRollback(t *testing.T) {
	calls := 0
	result, err := runResourceAttempts(context.Background(), func() (kaname.ResourceDecisionResult, error) {
		calls++
		if calls == 1 {
			return kaname.ResourceDecisionResult{Changed: true}, resourceFailedAttempt(pgx.ErrTxCommitRollback, pgx.ErrTxClosed, true)
		}
		return kaname.ResourceDecisionResult{CatalogType: "vpc.network"}, nil
	})
	require.NoError(t, err)
	require.Equal(t, 2, calls)
	require.False(t, result.Changed)
}
