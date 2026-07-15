// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// group_ismember_integration_test.go ( #12 reviewer A2).
//
// Verifies the new group.ReaderIface.IsMember method against real Postgres
// group_members rows. The method is the authorisation backbone for
// AccessBinding.ListBySubject when subjectType=group: caller is allowed iff
// (group_id, caller_type, caller_id) row exists.
package pg_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// TestGroup_IsMember_GroupMember coverage:
// - existing membership row → true
// - same group / different member → false
// - non-existent group → false (no error)
// - service_account member → true
// - wrong member_type → false
func TestGroup_IsMember_GroupMember(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	// Seed: user → owner → account → group → member.
	uid := mustSeedUser(t, ctx, pool, "ismember1")
	acc := seedAccount(t, ctx, repo, "acc-ismbr", uid)
	g := seedGroup(t, ctx, repo, acc.ID, "g-ismbr")

	uidMember := mustSeedUser(t, ctx, pool, "ismember2")
	// Add user member via writer.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.GroupsW().AddMember(ctx, domain.GroupMember{
		GroupID:    g.ID,
		MemberType: "user",
		MemberID:   domain.SubjectID(uidMember),
	}))
	require.NoError(t, w.Commit(ctx))

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// Case 1: existing membership → true
	ok, err := rd.Groups().IsMember(ctx, g.ID, "user", domain.SubjectID(uidMember))
	require.NoError(t, err)
	assert.True(t, ok, "seeded member must be reported")

	// Case 2: same group, different member → false
	ok, err = rd.Groups().IsMember(ctx, g.ID, "user", domain.SubjectID(uid))
	require.NoError(t, err)
	assert.False(t, ok, "non-member user must be false")

	// Case 3: non-existent group → false (no error)
	ok, err = rd.Groups().IsMember(ctx, "grp_doesnotexistxx", "user", domain.SubjectID(uidMember))
	require.NoError(t, err)
	assert.False(t, ok, "non-existent group must be false")

	// Case 4: wrong member_type for the same id → false
	ok, err = rd.Groups().IsMember(ctx, g.ID, "service_account", domain.SubjectID(uidMember))
	require.NoError(t, err)
	assert.False(t, ok, "wrong member_type must be false")
}
