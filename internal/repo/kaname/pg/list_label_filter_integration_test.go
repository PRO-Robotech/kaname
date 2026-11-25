// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	repoaccount "github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

func TestAccountListLabelFilterBeforePagination(t *testing.T) {
	if testing.Short() {
		t.Skip("проверка требует PostgreSQL")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "l1043")
	otherOwner := mustSeedUser(t, ctx, pool, "l1043-other")
	missing := seedAccount(t, ctx, repo, "acc-l1043-missing", owner)
	wr, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = wr.Rollback(ctx) }()
	insert := func(owner domain.UserID, name, value string) domain.AccountID {
		account := newAccount(name, owner)
		account.Labels = domain.Labels{"team/platform@v2": domain.LabelVal(value), "env": "dev"}
		out, err := wr.AccountsW().Insert(ctx, account)
		require.NoError(t, err)
		return out.ID
	}
	first := insert(owner, "acc-l1043-first", "")
	second := insert(owner, "acc-l1043-second", "")
	nonempty := insert(otherOwner, "acc-l1043-nonempty", "dev")
	insert(otherOwner, "acc-l1043-outside", "")
	require.NoError(t, wr.Commit(ctx))

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	f := repoaccount.ListFilter{
		Filter:   `labels.team/platform@v2 = ""`,
		PageSize: 1,
		Candidates: &visibility.PageScope{
			ObjectIDs: []string{string(missing.ID), string(first), string(second), string(nonempty)},
		},
	}
	out, next, err := rd.Accounts().List(ctx, f)
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.NotEmpty(t, next)
	got := []domain.AccountID{out[0].ID}

	f.PageToken = next
	out, next, err = rd.Accounts().List(ctx, f)
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Empty(t, next)
	require.ElementsMatch(t, []domain.AccountID{first, second}, append(got, out[0].ID))
}
