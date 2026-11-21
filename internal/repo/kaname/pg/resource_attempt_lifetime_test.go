// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

type resourceLifecycleTx struct {
	pgx.Tx
	conn               *pgx.Conn
	commits, rollbacks int
	commitErr          error
	cleanup            context.Context
}

func (t *resourceLifecycleTx) Conn() *pgx.Conn              { return t.conn }
func (t *resourceLifecycleTx) Commit(context.Context) error { t.commits++; return t.commitErr }
func (t *resourceLifecycleTx) Rollback(ctx context.Context) error {
	t.rollbacks++
	t.cleanup = ctx
	return ctx.Err()
}

func resourceLifetimeFixture(t *testing.T) (*resourceAttemptLifetime, *authorityWriteTx, *resourceLifecycleTx) {
	t.Helper()
	raw := &resourceLifecycleTx{conn: new(pgx.Conn)}
	l, err := newResourceAttemptLifetime(raw.conn, nativeBoundaryBundle(t))
	require.NoError(t, err)
	w := &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: raw}}, fence: authorityFence{decisionAt: time.Now().UTC()}}
	require.NoError(t, l.bind(w))
	return l, w, raw
}

func TestResourceAttemptLifetimeRejectsSameConnectionOtherAttempt(t *testing.T) {
	l, w, raw := resourceLifetimeFixture(t)
	c := &resourceInstallationCapture{lifetime: l, bundle: l.bundle, sources: map[domain.AccountID][]resourceInstallationWitness{"a": nil}, budget: &relverdict.AdministrativeReadBudget{}}
	require.True(t, l.valid(w, l.bundle))
	other := &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: raw}}, fence: w.fence}
	require.False(t, l.valid(other, l.bundle), "тот же backend и часы не означают ту же попытку")
	_, err := c.current(context.Background(), other, "a")
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.ErrorIs(t, l.bind(other), kaname.ErrSourceUnconfirmed)
	w.fence.decisionAt = w.fence.decisionAt.Add(time.Second)
	require.False(t, l.valid(w, l.bundle), "обновление часов не продлевает исходное решение")
}

func TestResourceAttemptLifetimeCommitFailureIsTerminal(t *testing.T) {
	l, w, raw := resourceLifetimeFixture(t)
	serialization := &pgconn.PgError{Code: "40001", Message: "deferred resource conflict"}
	raw.commitErr = serialization
	tx := &resourceDecisionTx{Tx: raw, owner: w, lifetime: l}
	require.ErrorIs(t, tx.Commit(context.Background()), iamerr.ErrAborted)
	require.True(t, l.ended)
	require.False(t, l.valid(w, l.bundle))
	require.Equal(t, 1, raw.commits)
	require.ErrorIs(t, tx.Commit(context.Background()), kaname.ErrSourceUnconfirmed)
	require.Equal(t, 1, raw.commits)
}

func TestResourceAttemptLifetimeEarlyCommitFailureClosesCapture(t *testing.T) {
	l, w, raw := resourceLifetimeFixture(t)
	tx := &resourceDecisionTx{Tx: raw, owner: nil, lifetime: l}
	require.ErrorIs(t, tx.Commit(context.Background()), kaname.ErrSourceUnconfirmed)
	require.True(t, l.ended)
	require.False(t, l.valid(w, l.bundle))
	require.Zero(t, raw.commits)
}

func TestResourceAttemptLifetimeCancelRollbackIsBounded(t *testing.T) {
	l, w, raw := resourceLifetimeFixture(t)
	tx := &resourceDecisionTx{Tx: raw, owner: w, lifetime: l}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	require.NoError(t, tx.Rollback(ctx))
	require.True(t, l.ended)
	require.Equal(t, 1, raw.rollbacks)
	deadline, ok := raw.cleanup.Deadline()
	require.True(t, ok)
	require.WithinDuration(t, started.Add(5*time.Second), deadline, time.Second)
	require.False(t, l.valid(w, l.bundle))
}

// Проверяем не только retry classifier, но и настоящий Commit wrapper:
// SQLSTATE должен пережить canonical mapErr и закрытие lifetime.
func TestResourceCommitWrapperPreservesConfirmedAbortForWholeAttempt(t *testing.T) {
	for _, code := range []string{"40001", "40P01", "55P03", "P1034"} {
		t.Run(code, func(t *testing.T) {
			attempts := 0
			var ended []*resourceAttemptLifetime
			result, err := runResourceAttempts(context.Background(), func() (kaname.ResourceDecisionResult, error) {
				for _, old := range ended {
					require.True(t, old.ended)
				}
				attempts++
				lifetime, owner, raw := resourceLifetimeFixture(t)
				ended = append(ended, lifetime)
				cause := &pgconn.PgError{Code: code, Message: "deferred resource abort"}
				if attempts == 1 {
					raw.commitErr = cause
				}
				decision := &resourceDecisionTx{Tx: raw, owner: owner, lifetime: lifetime}
				commitErr := decision.Commit(context.Background())
				require.True(t, owner.closed)
				require.True(t, lifetime.ended)
				require.Equal(t, 1, raw.commits)
				if commitErr != nil {
					var actual *pgconn.PgError
					require.ErrorAs(t, commitErr, &actual)
					require.Same(t, cause, actual)
					cleanup := rollbackResourceAttempt(context.Background(), raw)
					require.NoError(t, cleanup)
					require.Equal(t, 1, raw.rollbacks)
					return kaname.ResourceDecisionResult{Changed: true}, resourceFailedAttempt(commitErr, cleanup, true)
				}
				return kaname.ResourceDecisionResult{CatalogType: "vpc.box"}, nil
			})
			require.NoError(t, err)
			require.Equal(t, 2, attempts)
			require.Equal(t, kaname.ResourceDecisionResult{CatalogType: "vpc.box"}, result)
		})
	}
}

func TestResourceCommitWrapperDoesNotRetryUnknownDelivery(t *testing.T) {
	attempts := 0
	_, err := runResourceAttempts(context.Background(), func() (kaname.ResourceDecisionResult, error) {
		attempts++
		lifetime, owner, raw := resourceLifetimeFixture(t)
		raw.commitErr = io.EOF
		decision := &resourceDecisionTx{Tx: raw, owner: owner, lifetime: lifetime}
		commitErr := decision.Commit(context.Background())
		require.ErrorIs(t, commitErr, io.EOF)
		require.True(t, owner.closed)
		cleanup := rollbackResourceAttempt(context.Background(), raw)
		return kaname.ResourceDecisionResult{}, resourceFailedAttempt(commitErr, cleanup, true)
	})
	require.Equal(t, 1, attempts)
	require.True(t, errors.Is(err, io.EOF))
}
