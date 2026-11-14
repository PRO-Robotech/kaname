// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestResourceObjectParticipantRejectsMissingAndForeignPoolBeforeSQL(t *testing.T) {
	ctx := context.Background()
	pool, foreign := &pgxpool.Pool{}, &pgxpool.Pool{}
	_, err := NewResourceObjectParticipant(ctx, nil, nil)
	require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
	_, err = NewResourceObjectParticipant(ctx, New(pool, nil), nil)
	require.Error(t, err)
	for _, p := range []*ResourceObjectParticipant{nil, {}, {repo: New(pool, nil)}} {
		_, err = p.RegistrationTxBeginner(foreign)
		require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
		_, err = p.NewObjectReconciler(nil)
		require.Error(t, err)
	}
	b := &resourceRegistrationBeginner{participant: &ResourceObjectParticipant{repo: New(pool, nil)}, pool: foreign}
	tx, err := b.Begin(ctx)
	require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
	require.Nil(t, tx)
	r := &resourceObjectTransactions{}
	require.Error(t, r.WithTx(ctx, nil))
	require.Error(t, r.WithObjectTx(ctx, "vpc.network", "x", nil))
}
