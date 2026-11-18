// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package shared

import (
	"context"
	"errors"
	"testing"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type preparedDispatchWriter struct {
	kaname.Writer
	commits, rollbacks int
}

func (w *preparedDispatchWriter) Commit(context.Context) error   { w.commits++; return nil }
func (w *preparedDispatchWriter) Rollback(context.Context) error { w.rollbacks++; return nil }

type preparedDispatchRepo struct {
	kaname.Repository
	writer *preparedDispatchWriter
	opens  int
}

func (r *preparedDispatchRepo) Writer(context.Context) (kaname.Writer, error) {
	r.opens++
	return r.writer, nil
}

type preparedDispatchCapability struct {
	*preparedDispatchRepo
	calls int
}

func (r *preparedDispatchCapability) RunPreparedWrite(ctx context.Context, fn func(context.Context, kaname.Writer) error) error {
	r.calls++
	if err := fn(ctx, r.writer); err != nil {
		return err
	}
	// Первый результат относится к незакоммиченной попытке. Второй отказ
	// не должен выпускать этот результат вызывающему.
	return fn(ctx, r.writer)
}
func TestPreparedWriteDispatchKeepsLegacySinglePassAndDiscardsFailedResult(t *testing.T) {
	legacy := &preparedDispatchRepo{writer: &preparedDispatchWriter{}}
	calls := 0
	out, err := DoWithWriteTx(context.Background(), legacy, func(context.Context, kaname.Writer) (int, error) { calls++; return 42, nil })
	require.NoError(t, err)
	require.Equal(t, 42, out)
	require.Equal(t, 1, calls)
	require.Equal(t, 1, legacy.opens)
	require.Equal(t, 1, legacy.writer.commits)
	prepared := &preparedDispatchCapability{preparedDispatchRepo: &preparedDispatchRepo{writer: &preparedDispatchWriter{}}}
	calls = 0
	out, err = DoWithWriteTx(context.Background(), prepared, func(context.Context, kaname.Writer) (int, error) {
		calls++
		if calls == 1 {
			return 42, nil
		}
		return 99, iamerr.ErrPermissionDenied
	})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Zero(t, out)
	require.Equal(t, 1, prepared.calls)
	require.Zero(t, prepared.opens)
	require.Zero(t, prepared.writer.commits, "Commit принадлежит capability, не внешнему shared helper")
}
func TestPreparedConfiguredCapabilityFailsClosedAndKeepsRawBodyCause(t *testing.T) {
	called := false
	err := ExecuteConfiguredPreparedWrite(context.Background(), struct{}{}, func(context.Context) (kaname.Writer, error) { called = true; return nil, nil }, func(context.Context, kaname.Writer) error { called = true; return nil })
	require.ErrorIs(t, err, iamerr.ErrUnavailable)
	require.False(t, called)
	cause := &pgconn.PgError{Code: "40001", Message: "private source"}
	ctx := context.WithValue(context.Background(), preparedBodyContextKey{}, true)
	require.Same(t, cause, mapPreparedBodyError(ctx, cause))
	require.False(t, errors.Is(mapPreparedBodyError(context.Background(), cause), cause), "legacy сохраняет прежнее публичное отображение")
}
