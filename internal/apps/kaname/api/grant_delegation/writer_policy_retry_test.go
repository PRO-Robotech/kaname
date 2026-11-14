// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grant_delegation

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type delegationRetryFactory struct {
	opens, commits, rollbacks int
	trace                     []string
}

func (f *delegationRetryFactory) GrantDelegationWriter(context.Context, kaname.GrantDelegationMutation, domain.GrantDelegation) (kaname.Writer, error) {
	f.opens++
	f.trace = append(f.trace, "open")
	return &delegationRetryWriter{factory: f}, nil
}

type delegationRetryWriter struct {
	kaname.Writer
	factory *delegationRetryFactory
}

func (w *delegationRetryWriter) Commit(context.Context) error {
	w.factory.commits++
	w.factory.trace = append(w.factory.trace, "commit")
	return nil
}
func (w *delegationRetryWriter) Rollback(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w.factory.rollbacks++
	w.factory.trace = append(w.factory.trace, "rollback")
	return nil
}

func TestDelegationPolicyRetryRestartsWholeAttemptAndClosesBeforeReopen(t *testing.T) {
	f := &delegationRetryFactory{}
	out, err := doDelegationWriteTx(context.Background(), delegationWriteRepo{configured: true, factory: f}, func(_ context.Context, _ Writer) (domain.GrantDelegation, error) {
		f.trace = append(f.trace, "body")
		if f.opens == 1 {
			return domain.GrantDelegation{}, iamerr.ErrAborted
		}
		return domain.GrantDelegation{ID: "committed"}, nil
	})
	require.NoError(t, err)
	require.Equal(t, domain.GrantDelegationID("committed"), out.ID)
	require.Equal(t, []string{"open", "body", "rollback", "open", "body", "commit"}, f.trace)
	require.Equal(t, 1, f.commits)
	require.Equal(t, 1, f.rollbacks)
}
func TestDelegationPolicyRetryBoundCancellationAndNonRetryable(t *testing.T) {
	for _, mode := range []string{"bound", "raw_deadlock", "raw_serialization", "cancel", "denied"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f := &delegationRetryFactory{}
			_, err := doDelegationWriteTx(ctx, delegationWriteRepo{configured: true, factory: f}, func(context.Context, Writer) (domain.GrantDelegation, error) {
				if mode == "cancel" {
					cancel()
				}
				if mode == "raw_deadlock" {
					return domain.GrantDelegation{}, &pgconn.PgError{Code: "40P01"}
				}
				if mode == "raw_serialization" {
					return domain.GrantDelegation{}, &pgconn.PgError{Code: "40001"}
				}
				if mode == "denied" {
					return domain.GrantDelegation{}, iamerr.ErrPermissionDenied
				}
				return domain.GrantDelegation{}, iamerr.ErrAborted
			})
			require.Error(t, err)
			require.Zero(t, f.commits)
			require.Equal(t, f.opens, f.rollbacks)
			if mode == "bound" || mode == "raw_deadlock" || mode == "raw_serialization" {
				require.Equal(t, 3, f.opens)
				require.Equal(t, codes.Aborted, status.Code(err))
			} else {
				require.Equal(t, 1, f.opens)
			}
		})
	}
}
