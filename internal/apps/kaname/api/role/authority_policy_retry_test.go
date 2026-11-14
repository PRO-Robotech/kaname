// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Повтор включает ошибки, пришедшие уже из тела/Commit; mapped repo conflict
// теряет PgError, поэтому одного errors.As на драйвер было бы недостаточно.
func TestRoleMutationAttemptsRestartAfterReturnedWriterConflict(t *testing.T) {
	for _, failure := range []error{
		&pgconn.PgError{Code: "40P01"}, &pgconn.PgError{Code: "40001"},
		kaname.ErrAuthorityClassificationChanged, iamerr.Wrapf(iamerr.ErrAborted, "retry"),
	} {
		t.Run(failure.Error(), func(t *testing.T) {
			calls := 0
			got, err := roleMutationAttempts(context.Background(), func() (domain.Role, error) {
				calls++
				if calls == 1 {
					return domain.Role{}, fmt.Errorf("body or commit: %w", failure)
				}
				return domain.Role{ID: "rol-success"}, nil
			})
			require.NoError(t, err)
			require.Equal(t, 2, calls)
			require.Equal(t, domain.RoleID("rol-success"), got.ID)
		})
	}
}
func TestRoleMutationAttemptsBoundedAndPreservesTerminalFailure(t *testing.T) {
	for _, tc := range []struct {
		name    string
		failure error
		calls   int
	}{
		{"denied", iamerr.ErrPermissionDenied, 1},
		{"backend", iamerr.ErrUnavailable, 1},
		{"budget", kaname.ErrSourceReadLimit, 1},
		{"occ", iamerr.ErrFailedPrecondition, 1},
		{"cleanup", errors.Join(errRoleMutationCleanup, &pgconn.PgError{Code: "40P01"}), 1},
		{"exhausted", &pgconn.PgError{Code: "40001", Message: "private SQL diagnostic"}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			_, err := roleMutationAttempts(context.Background(), func() (domain.Role, error) { calls++; return domain.Role{}, tc.failure })
			require.Equal(t, tc.calls, calls)
			if tc.name == "exhausted" {
				require.ErrorIs(t, err, iamerr.ErrAborted)
				require.NotContains(t, err.Error(), "private SQL diagnostic")
			} else {
				require.ErrorIs(t, err, tc.failure)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	_, err := roleMutationAttempts(ctx, func() (domain.Role, error) { calls++; cancel(); return domain.Role{}, &pgconn.PgError{Code: "40001"} })
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, calls)
}
