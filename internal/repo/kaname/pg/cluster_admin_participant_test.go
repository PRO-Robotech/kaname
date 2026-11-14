// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"
	"time"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

type clusterParticipantLifecycleTx struct {
	pgx.Tx
	commitErr          error
	commits, rollbacks int
	cleanup            context.Context
}

func (t *clusterParticipantLifecycleTx) Commit(context.Context) error {
	t.commits++
	return t.commitErr
}
func (t *clusterParticipantLifecycleTx) Rollback(ctx context.Context) error {
	t.rollbacks++
	t.cleanup = ctx
	return ctx.Err()
}

func TestClusterAdminParticipantPreservesOwnerAndCancelCleanup(t *testing.T) {
	sentinel := &pgconn.PgError{Code: "23503", ConstraintName: "accounts_owner_fk"}
	underlying := &clusterParticipantLifecycleTx{commitErr: sentinel}
	owner := &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: underlying}, ownerFKHint: "missing-user"}}
	wrapper := &clusterAdminParticipantTx{Tx: underlying, owner: owner}
	err := wrapper.Commit(context.Background())
	require.ErrorIs(t, err, iamerr.ErrFailedPrecondition)
	require.Contains(t, err.Error(), "missing-user")
	require.Equal(t, 1, underlying.commits)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	require.NoError(t, wrapper.Rollback(ctx))
	require.Equal(t, 1, underlying.rollbacks)
	deadline, ok := underlying.cleanup.Deadline()
	require.True(t, ok)
	require.WithinDuration(t, started.Add(5*time.Second), deadline, time.Second)
}

func TestClusterAdminParticipantMissingConfigurationFailsClosed(t *testing.T) {
	var p *ClusterAdminParticipant
	tx, err := p.Begin(context.Background())
	require.Nil(t, tx)
	require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
	p, err = NewClusterAdminParticipant(context.Background(), nil, nil)
	require.Nil(t, p)
	require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
}
