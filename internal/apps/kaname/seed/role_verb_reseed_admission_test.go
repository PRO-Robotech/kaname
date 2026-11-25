// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
)

func TestRoleVerbReseedRetriesOnlyDeferredAdmission(t *testing.T) {
	timeout := &pgconn.PgError{Code: "57014"}
	observed := kanamerepo.InstallationOpenFailure{
		Stage: "open-enter-v2", Class: "sql-query-canceled",
		Cancel: kanamerepo.InstallationQueryCancel{Reason: "statement-timeout", Context: "active", Site: "consumer-admission"},
	}
	foreign := observed
	foreign.Cancel.Site = "global-coordinator"
	v3 := observed
	v3.Stage = "open-enter-v3"
	userRequest := observed
	userRequest.Cancel.Reason = "user-request"
	cases := []struct {
		name         string
		observation  kanamerepo.InstallationOpenFailure
		openErrors   map[int]error
		bodyError    error
		commitError  error
		wantReads    []domain.RoleID
		wantOpens    int
		wantReseeded int
	}{
		{name: "defer until first sweep ends", observation: observed, openErrors: map[int]error{1: timeout}, wantReads: []domain.RoleID{"second", "first"}, wantOpens: 3, wantReseeded: 2},
		{name: "repeat failure ends the role", observation: observed, openErrors: map[int]error{1: timeout, 3: timeout}, wantReads: []domain.RoleID{"second"}, wantOpens: 3, wantReseeded: 1},
		{name: "cleanup failed", observation: observed, openErrors: map[int]error{1: admissionCleanupError{timeout}}, wantReads: []domain.RoleID{"second"}, wantOpens: 2, wantReseeded: 1},
		{name: "different backend code", observation: observed, openErrors: map[int]error{1: &pgconn.PgError{Code: "55P03"}}, wantReads: []domain.RoleID{"second"}, wantOpens: 2, wantReseeded: 1},
		{name: "different lock", observation: foreign, openErrors: map[int]error{1: timeout}, wantReads: []domain.RoleID{"second"}, wantOpens: 2, wantReseeded: 1},
		{name: "v3 entry", observation: v3, openErrors: map[int]error{1: timeout}, wantReads: []domain.RoleID{"second"}, wantOpens: 2, wantReseeded: 1},
		{name: "user cancellation", observation: userRequest, openErrors: map[int]error{1: timeout}, wantReads: []domain.RoleID{"second"}, wantOpens: 2, wantReseeded: 1},
		{name: "body failure", observation: observed, bodyError: timeout, wantReads: []domain.RoleID{"first", "second"}, wantOpens: 2, wantReseeded: 1},
		{name: "ambiguous commit failure", observation: observed, commitError: timeout, wantReads: []domain.RoleID{"first", "second"}, wantOpens: 2, wantReseeded: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &admissionReseedRepository{
				observed: tc.observation, openErrors: tc.openErrors,
				bodyError: tc.bodyError, commitError: tc.commitError,
			}
			census, err := reseedListedRoleVerbs(t.Context(), repo, nil, nil, []systemRoleRules{{id: "first"}, {id: "second"}})
			if tc.wantReseeded == 2 {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.True(t, census.Completed)
			require.Equal(t, 2, census.Examined)
			require.Equal(t, tc.wantReseeded, census.Reseeded)
			require.Equal(t, 2-tc.wantReseeded, census.Failed)
			require.Equal(t, tc.wantOpens, repo.opens)
			require.Equal(t, tc.wantReads, repo.reads)
		})
	}

	t.Run("cancel before deferred role", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		repo := &admissionReseedRepository{observed: observed, openErrors: map[int]error{1: timeout}, onCommit: cancel}
		census, err := reseedListedRoleVerbs(ctx, repo, nil, nil, []systemRoleRules{{id: "first"}, {id: "second"}})
		require.True(t, errors.Is(err, context.Canceled))
		require.False(t, census.Completed)
		require.False(t, census.Structural())
		require.Equal(t, 2, census.Examined)
		require.Equal(t, 1, census.Reseeded)
		require.Zero(t, census.Failed)
		require.Equal(t, 2, repo.opens)
		require.Equal(t, []domain.RoleID{"second"}, repo.reads)
	})
}

type admissionCleanupError struct{ error }

func (e admissionCleanupError) Unwrap() error             { return e.error }
func (admissionCleanupError) PreparedCleanupFailed() bool { return true }

type admissionReseedRepository struct {
	kanamerepo.Repository
	observed    kanamerepo.InstallationOpenFailure
	openErrors  map[int]error
	bodyError   error
	commitError error
	onCommit    func()
	opens       int
	reads       []domain.RoleID
}

func (r *admissionReseedRepository) InstallationAuthorityWriter(ctx context.Context, _ kanamerepo.AuthorityOperation) (kanamerepo.Writer, error) {
	r.opens++
	if err := r.openErrors[r.opens]; err != nil {
		kanamerepo.ObserveInstallationOpenFailure(ctx, func() kanamerepo.InstallationOpenFailure { return r.observed })
		return nil, err
	}
	return &admissionReseedWriter{repo: r, attempt: r.opens}, nil
}

type admissionReseedWriter struct {
	kanamerepo.Writer
	role.WriterIface
	repo    *admissionReseedRepository
	attempt int
}

func (w *admissionReseedWriter) RolesW() role.WriterIface       { return w }
func (w *admissionReseedWriter) Rollback(context.Context) error { return nil }
func (w *admissionReseedWriter) Commit(context.Context) error {
	if w.repo.onCommit != nil {
		w.repo.onCommit()
	}
	if w.attempt == 1 {
		return w.repo.commitError
	}
	return nil
}

func (w *admissionReseedWriter) RulesForRegrain(_ context.Context, id domain.RoleID) (domain.Rules, domain.RulePolicy, bool, error) {
	w.repo.reads = append(w.repo.reads, id)
	// Снятая роль завершает транзакцию без необходимости фиктивного каталога.
	var policy domain.RulePolicy
	if w.attempt == 1 {
		return nil, policy, false, w.repo.bodyError
	}
	return nil, policy, false, nil
}
