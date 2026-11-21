// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	repogroup "github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestGroupListMemberCandidatesPagesAndTypedIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует PostgreSQL")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)
	uid := mustSeedUser(t, ctx, pool, "member-candidates")
	other := mustSeedUser(t, ctx, pool, "member-other")
	a := seedAccount(t, ctx, repo, "member-candidates-a", uid)
	b := seedAccount(t, ctx, repo, "member-candidates-b", uid)
	groups := []domain.Group{
		seedGroup(t, ctx, repo, a.ID, "member-a1"),
		seedGroup(t, ctx, repo, a.ID, "member-a2"),
		seedGroup(t, ctx, repo, b.ID, "member-b1"),
		seedGroup(t, ctx, repo, b.ID, "other-only"),
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	for i, g := range groups {
		memberID := uid
		if i == 3 {
			memberID = other
		}
		require.NoError(t, w.GroupsW().AddMember(ctx, domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(memberID)}))
	}
	require.NoError(t, w.Commit(ctx))
	// Одинаковое время заставляет курсор использовать и второй ключ, id.
	stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, g := range groups {
		_, err = pool.Exec(ctx, "UPDATE kaname.groups SET created_at=$1 WHERE id=$2", stamp, string(g.ID))
		require.NoError(t, err)
	}
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	member := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	collect := func(filter repogroup.ListFilter) []domain.GroupID {
		t.Helper()
		filter.PageSize = 1
		var ids []domain.GroupID
		seenTokens := map[string]bool{}
		for {
			page, next, listErr := rd.Groups().List(ctx, filter)
			require.NoError(t, listErr)
			require.LessOrEqual(t, len(page), 1)
			for _, g := range page {
				ids = append(ids, g.ID)
			}
			if next == "" {
				return ids
			}
			require.False(t, seenTokens[next], "курсор не должен повторяться")
			seenTokens[next] = true
			require.LessOrEqual(t, len(ids), len(groups), "перечисление должно завершаться")
			filter.PageToken = next
		}
	}
	require.ElementsMatch(t, []domain.GroupID{groups[0].ID, groups[1].ID, groups[2].ID}, collect(repogroup.ListFilter{Member: &member}))
	require.ElementsMatch(t, []domain.GroupID{groups[0].ID, groups[1].ID}, collect(repogroup.ListFilter{Member: &member, AccountID: a.ID}))
	wrongType := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: member.ID}
	require.Empty(t, collect(repogroup.ListFilter{Member: &wrongType}), "одинаковый id другого вида не даёт членства")
	require.ElementsMatch(t, []domain.GroupID{groups[0].ID, groups[1].ID}, collect(repogroup.ListFilter{AccountID: a.ID}), "nil сохраняет обычный List")
	for _, invalid := range []domain.Subject{{}, {Type: domain.SubjectTypeUser}, {Type: domain.SubjectTypeGroup, ID: "grp-any"}, {Type: domain.SubjectTypeSystemClass, ID: "authenticated"}} {
		_, _, err = rd.Groups().List(ctx, repogroup.ListFilter{Member: &invalid})
		require.ErrorIs(t, err, iamerr.ErrInvalidArg)
	}
}

func TestGroupListMemberCandidatesUseTheWriterTransaction(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует PostgreSQL")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)
	uid := mustSeedUser(t, ctx, pool, "member-writer")
	a := seedAccount(t, ctx, repo, "member-writer-a", uid)
	g := seedGroup(t, ctx, repo, a.ID, "member-writer-g")
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	member := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	filter := repogroup.ListFilter{Member: &member, AccountID: a.ID}
	rows, _, err := w.Groups().List(ctx, filter)
	require.NoError(t, err)
	require.Empty(t, rows)
	require.NoError(t, w.GroupsW().AddMember(ctx, domain.GroupMember{GroupID: g.ID, MemberType: member.Type, MemberID: member.ID}))
	rows, _, err = w.Groups().List(ctx, filter)
	require.NoError(t, err)
	require.Len(t, rows, 1, "same-writer чтение видит собственную незакоммиченную запись")
	require.Equal(t, g.ID, rows[0].ID)
	require.NoError(t, w.Rollback(ctx))
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	rows, _, err = rd.Groups().List(ctx, filter)
	require.NoError(t, err)
	require.Empty(t, rows, "откат не оставляет членство читателям")
}
