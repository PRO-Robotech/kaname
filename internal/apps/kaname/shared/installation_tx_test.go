// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

import (
	"context"
	"errors"
	"testing"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type installationBoundaryRepo struct {
	kaname.Repository
	writer          kaname.Writer
	entryErr        error
	entries, legacy int
	kind            kaname.AuthorityOperation
}

func (r *installationBoundaryRepo) Writer(context.Context) (kaname.Writer, error) {
	r.legacy++
	return r.writer, nil
}
func (r *installationBoundaryRepo) InstallationAuthorityWriter(_ context.Context, kind kaname.AuthorityOperation) (kaname.Writer, error) {
	r.entries++
	r.kind = kind
	return r.writer, r.entryErr
}

type installationBoundaryWriter struct {
	kaname.Writer
	commits, rollbacks     int
	commitErr, rollbackErr error
}

func (w *installationBoundaryWriter) Commit(context.Context) error { w.commits++; return w.commitErr }
func (w *installationBoundaryWriter) Rollback(context.Context) error {
	w.rollbacks++
	return w.rollbackErr
}

// Пробы границы проверяют отказ до тела, сохранение ошибки и отсутствие повтора.
func TestInstallationBoundaryDoesNotFallbackOrRetry(t *testing.T) {
	fault := errors.New("installation boundary fault")
	for _, tc := range []struct {
		name                               string
		entry, body, commit, rollback      error
		wantBody, wantCommit, wantRollback int
	}{
		{name: "success", wantBody: 1, wantCommit: 1},
		{name: "entry", entry: fault},
		{name: "body", body: fault, wantBody: 1, wantRollback: 1},
		{name: "commit", commit: fault, wantBody: 1, wantCommit: 1, wantRollback: 1},
		{name: "cleanup", body: fault, rollback: errors.New("cleanup fault"), wantBody: 1, wantRollback: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &installationBoundaryWriter{commitErr: tc.commit, rollbackErr: tc.rollback}
			r := &installationBoundaryRepo{writer: w, entryErr: tc.entry}
			calls := 0
			err := DoWithInstallationWriteTxVoid(context.Background(), r, kaname.AuthorityRole, func(context.Context, kaname.Writer) error { calls++; return tc.body })
			if tc.name == "success" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			require.Equal(t, tc.wantBody, calls)
			require.Equal(t, tc.wantCommit, w.commits)
			require.Equal(t, tc.wantRollback, w.rollbacks)
			require.Equal(t, 1, r.entries)
			require.Zero(t, r.legacy)
			require.Equal(t, kaname.AuthorityRole, r.kind)
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &installationBoundaryRepo{}
	err := DoWithInstallationWriteTxVoid(ctx, r, kaname.AuthorityRole, func(context.Context, kaname.Writer) error { t.Fatal("тело после отмены"); return nil })
	require.Error(t, err)
	require.Zero(t, r.entries)
	require.Zero(t, r.legacy)
	err = DoWithInstallationWriteTxVoid(context.Background(), nil, kaname.AuthorityRole, func(context.Context, kaname.Writer) error { t.Fatal("тело без typed factory"); return nil })
	require.Error(t, err)
}

func TestInstallationObserverKeepsPrimaryFailure(t *testing.T) {
	deadlock := &pgconn.PgError{Code: "40P01"}
	serialization := &pgconn.PgError{Code: "40001"}
	for _, tc := range []struct {
		name                string
		entry, body, commit error
		want                error
	}{
		{name: "success"},
		{name: "entry", entry: deadlock, want: deadlock},
		{name: "body", body: deadlock, want: deadlock},
		{name: "commit", commit: serialization, want: serialization},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &installationBoundaryWriter{commitErr: tc.commit, rollbackErr: errors.New("cleanup fault")}
			r := &installationBoundaryRepo{writer: w, entryErr: tc.entry}
			var observed []error
			err := DoWithObservedInstallationWriteTxVoid(context.Background(), r, kaname.AuthorityRole,
				func(context.Context, kaname.Writer) error { return tc.body },
				func(err error) { observed = append(observed, err) })
			if tc.want == nil {
				require.NoError(t, err)
				require.Empty(t, observed)
				return
			}
			require.Equal(t, codes.Internal, status.Code(err))
			require.Len(t, observed, 1)
			require.Same(t, tc.want, observed[0])
		})
	}
}
