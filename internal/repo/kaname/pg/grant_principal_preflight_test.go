// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Только проверка ветвления SQL ошибок; authority ответы не подменяются.
// Actual UC/native counterpart находится в integration test и D5 fixture.
type principalPreflightTx struct {
	pgx.Tx
	rowError  error
	rowErrors []error
	execError error
	query     string
	queries   int
}

func (p *principalPreflightTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, p.execError
}
func (p *principalPreflightTx) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	p.query = sql
	p.queries++
	if p.queries <= len(p.rowErrors) {
		return principalPreflightRow{p.rowErrors[p.queries-1]}
	}
	return principalPreflightRow{p.rowError}
}

type principalPreflightRow struct{ err error }

func (r principalPreflightRow) Scan(...any) error { return r.err }

func TestBindingRecipientPreflightClassifiesOnlyTypedAbsence(t *testing.T) {
	backend := errors.New("recipient query unavailable")
	conflict := &pgconn.PgError{Code: "40001", Message: "source changed"}
	for _, tc := range []struct {
		name          string
		failure, want error
	}{
		{"absent", pgx.ErrNoRows, iamerr.ErrPermissionDenied},
		{"backend", backend, backend},
		{"cancel", context.Canceled, context.Canceled},
		{"serialization", conflict, conflict},
		{"present", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &principalPreflightTx{rowError: tc.failure}
			b := domain.AccessBinding{Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: "sva-existing-other-type"}}}
			err := bindingDecisionPreflight(context.Background(), tx, b, true)
			require.Equal(t, tc.want, err)
			require.Equal(t, "SELECT 1 FROM kaname.users WHERE id=$1 FOR KEY SHARE", tx.query)
			require.Equal(t, 1, tx.queries)
		})
	}
	t.Run("preflight_failure_is_not_admission", func(t *testing.T) {
		tx := &principalPreflightTx{execError: backend, rowError: pgx.ErrNoRows}
		err := bindingDecisionPreflight(context.Background(), tx, domain.AccessBinding{}, true)
		require.Same(t, backend, err)
		require.Zero(t, tx.queries)
	})
	t.Run("gd_delegate_keeps_classification_retry", func(t *testing.T) {
		tx := &principalPreflightTx{rowError: pgx.ErrNoRows}
		require.ErrorIs(t, grantPrincipalPrelock(context.Background(), tx, "service_account", "absent"), kaname.ErrAuthorityClassificationChanged)
		require.Equal(t, "SELECT 1 FROM kaname.service_accounts WHERE id=$1 FOR KEY SHARE", tx.query)
	})
}

func TestBindingRecipientDiscoveryFullSetAndErrorIdentity(t *testing.T) {
	subjects := make([]domain.Subject, domain.MaxSubjectsPerBinding)
	for i := range subjects {
		subjects[i] = domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(fmt.Sprintf("usr-discovery-%d", i))}
	}
	t.Run("full_32", func(t *testing.T) {
		tx := &principalPreflightTx{}
		rows, reads, err := bindingRecipientDiscovery(context.Background(), tx, subjects)
		require.NoError(t, err)
		require.Equal(t, 32, rows)
		require.Equal(t, 32, reads)
		require.Equal(t, 32, tx.queries)
		require.Equal(t, "SELECT 1 FROM kaname.users WHERE id=$1", tx.query, "RR discovery не берёт row lock")
	})
	for _, tc := range []struct {
		name          string
		failure, want error
	}{
		{"last_absent", pgx.ErrNoRows, iamerr.ErrPermissionDenied},
		{"last_backend", errors.New("backend unavailable"), nil},
		{"last_cancel", context.Canceled, context.Canceled},
		{"last_serialization", &pgconn.PgError{Code: "40001", Message: "source changed"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &principalPreflightTx{rowErrors: make([]error, 32)}
			tx.rowErrors[31] = tc.failure
			rows, reads, err := bindingRecipientDiscovery(context.Background(), tx, subjects)
			want := tc.want
			if want == nil {
				want = tc.failure
			}
			require.Equal(t, want, err)
			require.Equal(t, 31, rows)
			require.Equal(t, 32, reads)
			require.Equal(t, 32, tx.queries)
		})
	}
	t.Run("33_rejected_without_query", func(t *testing.T) {
		tx := &principalPreflightTx{}
		_, _, err := bindingRecipientDiscovery(context.Background(), tx, append(subjects, domain.Subject{Type: domain.SubjectTypeUser, ID: "extra"}))
		require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
		require.Zero(t, tx.queries)
	})
	t.Run("class_needs_no_principal_row", func(t *testing.T) {
		tx := &principalPreflightTx{}
		rows, reads, err := bindingRecipientDiscovery(context.Background(), tx, []domain.Subject{{Type: domain.SubjectTypeSystemClass, ID: "authenticated"}})
		require.NoError(t, err)
		require.Zero(t, rows)
		require.Zero(t, reads)
		require.Zero(t, tx.queries)
	})
}

func TestPolicyDiscoveryChargesPriorRecipientReadsBeforeSQL(t *testing.T) {
	for _, tc := range []struct {
		reads int
		want  error
	}{
		{-1, errPolicyDiscoveryBudget}, {4097, errPolicyDiscoveryBudget}, {4096, kaname.ErrSourceReadLimit},
	} {
		t.Run(fmt.Sprint(tc.reads), func(t *testing.T) {
			tx := &principalPreflightTx{}
			writers := &GrantPolicyWriters{repo: &Repository{}}
			_, err := writers.discoverPolicyPlanWithRows(context.Background(), tx, policyWriteRequest{actor: domain.Subject{Type: domain.SubjectTypeUser, ID: "usr-budget"}, nativeQuestions: newNativePolicyQuestions(), consumedReads: tc.reads}, 32)
			require.ErrorIs(t, err, tc.want)
			require.Zero(t, tx.queries, "полный prior read budget проверяется до следующего SQL")
		})
	}
}
