// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
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
	members, err := rd.Groups().ListMembers(ctx, g.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, len(members), "exactly 2 unique members (idempotent)")
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
