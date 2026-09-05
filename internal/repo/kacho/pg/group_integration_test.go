// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// group_integration_test.go — integration tests GroupRepo + GroupMember.
//
// Покрытие:
// - 21: CreateGroup + Get round-trip.
// - 22: AddMember happy (user + service_account) + idempotent повтор.
// - 23: AddMember с несущ. member_id → FailedPrecondition (триггер 23503).
// - 24: RemoveMember happy + идемпотент (повтор не ошибка).
// - 25: ListMembers.
// - 42a: DeleteGroup без bindings → OK (group_members CASCADE).
// - 42b: DeleteGroup с AccessBinding → FailedPrecondition.
// - DuplicateName per account → ErrAlreadyExists.

import (
	"context"
	stderrors "errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	repogroup "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/group"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

func seedGroup(t *testing.T, ctx context.Context, repo *kachopg.Repository, accID domain.AccountID, name string) domain.Group {
	t.Helper()
	g := domain.Group{
		ID:          domain.GroupID(ids.NewID(domain.PrefixGroup)),
		AccountID:   accID,
		Name:        domain.GroupName(name),
		Description: domain.Description("test grp " + name),
		Labels:      domain.Labels{},
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, err := w.GroupsW().Insert(ctx, g)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return out
}

func TestGroup_21_CreateGet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "g21")
	acc := seedAccount(t, ctx, repo, "acc-g21", uid)
	g := seedGroup(t, ctx, repo, acc.ID, "g-rt")
	assert.True(t, strings.HasPrefix(string(g.ID), "grp"))
	assert.Equal(t, acc.ID, g.AccountID)
	assert.WithinDuration(t, time.Now(), g.CreatedAt, 30*time.Second)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.Groups().Get(ctx, g.ID)
	require.NoError(t, err)
	assert.Equal(t, g.ID, got.ID)
}

func TestGroup_22_AddMember_Happy_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "g22")
	uid2 := mustSeedUser(t, ctx, pool, "g22b")
	acc := seedAccount(t, ctx, repo, "acc-g22", uid)
	g := seedGroup(t, ctx, repo, acc.ID, "g-mems")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.GroupsW().AddMember(ctx, domain.GroupMember{
		GroupID:    g.ID,
		MemberType: domain.SubjectTypeUser,
		MemberID:   domain.SubjectID(uid),
	}))
	require.NoError(t, w.GroupsW().AddMember(ctx, domain.GroupMember{
		GroupID:    g.ID,
		MemberType: domain.SubjectTypeUser,
		MemberID:   domain.SubjectID(uid2),
	}))
	// Идемпотентный повтор — не ошибка
	require.NoError(t, w.GroupsW().AddMember(ctx, domain.GroupMember{
		GroupID:    g.ID,
		MemberType: domain.SubjectTypeUser,
		MemberID:   domain.SubjectID(uid),
	}))
	require.NoError(t, w.Commit(ctx))

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	members, next, err := rd.Groups().ListMembers(ctx, g.ID, repogroup.MemberPage{PageSize: 50})
	require.NoError(t, err)
	assert.Equal(t, 2, len(members), "exactly 2 unique members (idempotent)")
	assert.Empty(t, next, "a page that fits carries no continuation token")
}

func TestGroup_23_AddMember_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "g23")
	acc := seedAccount(t, ctx, repo, "acc-g23", uid)
	g := seedGroup(t, ctx, repo, acc.ID, "g-23")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.GroupsW().AddMember(ctx, domain.GroupMember{
		GroupID:    g.ID,
		MemberType: domain.SubjectTypeUser,
		MemberID:   "usr0000000000000ghst", // не существует
	})
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition))
}

func TestGroup_24_RemoveMember_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "g24")
	acc := seedAccount(t, ctx, repo, "acc-g24", uid)
	g := seedGroup(t, ctx, repo, acc.ID, "g-24")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.GroupsW().AddMember(ctx, domain.GroupMember{
		GroupID:    g.ID,
		MemberType: domain.SubjectTypeUser,
		MemberID:   domain.SubjectID(uid),
	}))
	require.NoError(t, w.GroupsW().RemoveMember(ctx, g.ID, domain.SubjectTypeUser, domain.SubjectID(uid)))
	// Повтор не ошибка.
	require.NoError(t, w.GroupsW().RemoveMember(ctx, g.ID, domain.SubjectTypeUser, domain.SubjectID(uid)))
	require.NoError(t, w.Commit(ctx))
}

func TestGroup_42a_Delete_Happy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "g42a")
	acc := seedAccount(t, ctx, repo, "acc-g42a", uid)
	g := seedGroup(t, ctx, repo, acc.ID, "g-42a")

	// Add member — CASCADE на DELETE GROUP должна почистить.
	w0, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w0.GroupsW().AddMember(ctx, domain.GroupMember{
		GroupID:    g.ID,
		MemberType: domain.SubjectTypeUser,
		MemberID:   domain.SubjectID(uid),
	}))
	require.NoError(t, w0.Commit(ctx))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.GroupsW().Delete(ctx, g.ID))
	require.NoError(t, w.Commit(ctx))

	// Проверим что group_members тоже исчезли (CASCADE).
	var cnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM group_members WHERE group_id = $1`, string(g.ID)).Scan(&cnt))
	assert.Equal(t, 0, cnt, "group_members CASCADE")
}

func TestGroup_42b_Delete_WithAccessBinding(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "g42b")
	acc := seedAccount(t, ctx, repo, "acc-g42b", uid)
	g := seedGroup(t, ctx, repo, acc.ID, "g-42b")

	abID := ids.NewID(domain.PrefixAccessBinding)
	_, err = pool.Exec(ctx, `
		INSERT INTO access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id)
		VALUES ($1, 'group', $2, $3, 'account', 'acc0000000000000xxxx')`,
		abID, string(g.ID), seedSystemRoleIDIAMView,
	)
	require.NoError(t, err)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.GroupsW().Delete(ctx, g.ID)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition))
}

func TestGroup_DuplicateName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "gdup")
	acc := seedAccount(t, ctx, repo, "acc-gdup", uid)
	_ = seedGroup(t, ctx, repo, acc.ID, "dup-grp")

	g2 := domain.Group{
		ID:        domain.GroupID(ids.NewID(domain.PrefixGroup)),
		AccountID: acc.ID,
		Name:      "dup-grp",
		Labels:    domain.Labels{},
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.GroupsW().Insert(ctx, g2)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrAlreadyExists))
}

// TestGroup_ListMembers_PagesWithTheContinuationToken — the published pagination
// works end to end against real rows: a page smaller than the membership emits a
// token, the token resumes exactly after the last row returned, and the final page
// emits none. Without this the three published fields were a promise the service
// could not keep — a membership large enough to exceed the transport's message
// limit had no way out, because a caller cannot page past a listing that never
// emits a token.
func TestGroup_ListMembers_PagesWithTheContinuationToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "gpage")
	acc := seedAccount(t, ctx, repo, "acc-gpage", owner)
	g := seedGroup(t, ctx, repo, acc.ID, "g-page")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	want := make([]string, 0, 3)
	for _, suffix := range []string{"p1", "p2", "p3"} {
		uid := mustSeedUser(t, ctx, pool, "gpage-"+suffix)
		require.NoError(t, w.GroupsW().AddMember(ctx, domain.GroupMember{
			GroupID: g.ID, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(uid),
		}))
		want = append(want, string(uid))
	}
	require.NoError(t, w.Commit(ctx))

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	seen := make([]string, 0, 3)
	token := ""
	for page := 0; page < 4; page++ { // bounded: 3 members at 2 per page is 2 pages
		got, next, lerr := rd.Groups().ListMembers(ctx, g.ID, repogroup.MemberPage{PageSize: 2, PageToken: token})
		require.NoError(t, lerr)
		for _, m := range got {
			seen = append(seen, string(m.MemberID))
		}
		if next == "" {
			break
		}
		require.LessOrEqual(t, len(got), 2, "a page must never exceed the requested size")
		token = next
	}
	assert.ElementsMatch(t, want, seen, "paging must yield every member exactly once")

	// A garbage cursor is refused rather than silently restarting from the top —
	// restarting looks like a working listing that repeats its first page for ever.
	_, _, err = rd.Groups().ListMembers(ctx, g.ID, repogroup.MemberPage{PageSize: 2, PageToken: "!!not-base64!!"})
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrInvalidArg), "a malformed page_token must be an invalid argument, got %v", err)
}
