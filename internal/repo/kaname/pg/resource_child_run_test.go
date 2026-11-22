// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestUserChildRunnerRequiresSameHumanAndFullBeforeAcquire(t *testing.T) {
	principal := operations.Principal{Type: "user", ID: "usr-child"}
	ctx := operations.WithPrincipal(t.Context(), principal)
	input := kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: "parent/candidate"}
	// Нулевой pool нельзя Acquire: отсутствие FULL должно остановить попытку раньше.
	runner := &ResourceDecisionRunner{repo: &Repository{master: &pgxpool.Pool{}}, bundle: nativeBoundaryBundle(t)}
	version, err := runner.RunUserChildRegistration(ctx, input, principal)
	require.True(t, version.IsZero())
	require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
	require.ErrorIs(t, err, iamerr.ErrUnavailable)

	other := operations.Principal{Type: "user", ID: "usr-other"}
	version, err = runner.RunUserChildRegistration(ctx, input, other)
	require.True(t, version.IsZero())
	require.ErrorIs(t, err, domain.ErrUserChildRegistrationRefused)
	version, err = runner.RunUserChildRegistration(t.Context(), input, principal)
	require.True(t, version.IsZero())
	require.ErrorIs(t, err, domain.ErrUserChildRegistrationRefused)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	version, err = runner.RunUserChildRegistration(canceled, input, principal)
	require.True(t, version.IsZero())
	require.ErrorIs(t, err, context.Canceled)
}

func TestUserChildErrorsKeepBackendFailureDistinctFromRefusal(t *testing.T) {
	for _, cause := range []error{kaname.ErrSourceUnconfirmed, kaname.ErrSourceReadLimit, kaname.ErrSemanticIdentityUnavailable,
		&pgconn.PgError{Code: "54000"}, &pgconn.PgError{Code: "08006"},
	} {
		err := resourceChildError(t.Context(), cause)
		require.ErrorIs(t, err, iamerr.ErrUnavailable)
		require.ErrorIs(t, err, cause)
		require.NotErrorIs(t, err, domain.ErrUserChildRegistrationRefused)
	}
	refused := domain.ErrUserChildRegistrationRefused
	require.ErrorIs(t, resourceChildError(t.Context(), refused), refused)
	protocol := &pgconn.PgError{Code: "42501", Message: "private manifest mismatch"}
	err := resourceChildError(t.Context(), protocol)
	require.ErrorIs(t, err, iamerr.ErrInternal)
	require.ErrorIs(t, err, protocol)
	require.NotErrorIs(t, err, refused)
	cleanup := errors.New("rollback failed")
	err = resourceChildError(t.Context(), resourceFailedAttempt(refused, cleanup, false))
	require.ErrorIs(t, err, iamerr.ErrUnavailable)
	require.ErrorIs(t, err, cleanup)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	err = resourceChildError(canceled, protocol)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, protocol)
}

func TestUserChildAttemptVersionOnlySurvivesSuccessfulRetry(t *testing.T) {
	confirmed := time.Unix(100, 0).UTC()
	calls := 0
	version, err := runResourceAttempts(t.Context(), func() (time.Time, error) {
		calls++
		if calls == 1 {
			return confirmed.Add(-time.Second), resourceFailedAttempt(&pgconn.PgError{Code: "P1034"}, nil, false)
		}
		return confirmed, nil
	})
	require.NoError(t, err)
	require.Equal(t, 2, calls)
	require.Equal(t, confirmed, version)
	unknownCommit := errors.New("commit connection lost")
	calls = 0
	version, err = runResourceAttempts(t.Context(), func() (time.Time, error) {
		calls++
		return confirmed, resourceFailedAttempt(unknownCommit, nil, true)
	})
	require.ErrorIs(t, err, unknownCommit)
	require.Equal(t, 1, calls)
	require.True(t, version.IsZero())
	calls = 0
	version, err = runResourceAttempts(t.Context(), func() (time.Time, error) {
		calls++
		return confirmed, resourceFailedAttempt(&pgconn.PgError{Code: "P1034"}, nil, false)
	})
	require.ErrorIs(t, resourceChildError(t.Context(), err), iamerr.ErrAborted)
	require.Equal(t, authorityEntryAttempts, calls)
	require.True(t, version.IsZero())
}
