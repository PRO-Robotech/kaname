// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// delete_subject_ref_integration_test.go — SEC r8 (2026-07-06) HIGH/DATA.
//
// User / ServiceAccount / Group Delete guards historically probed only the
// legacy access_bindings.subject_id projection (= subjects[0]). A binding may,
// since the RBAC rules-model (migration 0028), grant to 1..N subjects, with
// subjects[1..N] living ONLY in the access_binding_subjects child table — each an
// INDEPENDENT grantee with its own emitted FGA tuple lineage. The delete-side
// guard was never extended to that child table, so a principal referenced ONLY as
// subjects[1..N] could be hard-deleted: the within-service reference is orphaned
// and a phantom FGA authz grant to the deleted principal survives (hard-rule #10,
// CWE-362 on the concurrent add-subject path).
//
// These testcontainers-Postgres tests prove the delete-side guard now rejects a
// User/SA/Group referenced at ANY subject ordinal (not just subjects[0]):
//   - -ReferencedAsSubjectN_Blocked: Delete of a principal present only in
//     access_binding_subjects → FailedPrecondition (not a hard delete);
//   - -ConcurrentAddSubjectN_NoDangling: the delete-vs-add-subject race
//     serializes on the referent row-lock (migration 0049 FOR KEY SHARE probe on
//     the insert side vs the delete's exclusive tuple lock), so no dangling
//     subject row for a deleted principal is ever produced.

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// seedMemberUser inserts a plain (non-owner) ACTIVE user in the given account —
// deletable by the guarded Delete once it carries no bindings / group memberships.
func seedMemberUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID, suffix string) string {
	t.Helper()
	uid := ids.NewID(domain.PrefixUser)
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'M', 'ACTIVE')`,
		uid, accID, "ext-"+suffix+"-"+uid, "m-"+suffix+"@example.com")
	require.NoError(t, err)
	return uid
}

// insertABSubjectRaw inserts an access_binding_subjects child row (subjects[N])
// directly, bypassing the domain layer so the raw DB guard is what is under test.
func insertABSubjectRaw(ctx context.Context, pool *pgxpool.Pool, bindingID, subjectType, subjectID string, ordinal int) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
		VALUES ($1, $2, $3, $4)`,
		bindingID, subjectType, subjectID, ordinal)
	return err
}

// TestUserDelete_ReferencedAsSubjectN_Blocked — a User present ONLY as subjects[1]
// (access_binding_subjects), never as the legacy subjects[0], must not be deletable.
func TestUserDelete_ReferencedAsSubjectN_Blocked(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx, pool := kac127Setup(t)
	owner, accID := kac127SeedUserAndAccount(t, ctx, pool, "dsru")
	prjID := kac127SeedProject(t, ctx, pool, accID, "dsru")
	roleID := seedProjectRole(t, ctx, pool, domain.ProjectID(prjID), "role_dsru")

	member := seedMemberUser(t, ctx, pool, accID, "dsru")

	// Binding whose legacy subjects[0] is the OWNER; `member` appears only as a
	// subjects[1] child row (the independent grantee the old guard missed).
	abID := padOrTrim20("acb00000dsru")
	require.NoError(t, insertBindingRaw(ctx, pool, abID, "user", owner, string(roleID), "project", prjID))
	require.NoError(t, insertABSubjectRaw(ctx, pool, abID, "user", member, 1))

	repo := kachopg.New(pool, nil)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.UsersW().Delete(ctx, domain.UserID(member))
	_ = w.Rollback(ctx)
	require.Error(t, err, "User referenced as subjects[1] must not be hard-deleted")
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
		"expected FailedPrecondition, got %v", err)
	assert.Contains(t, err.Error(), "access bindings")

	var cnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.users WHERE id=$1`, member).Scan(&cnt))
	assert.Equal(t, 1, cnt, "the referenced user must survive the rejected delete (no orphan subject row)")
}

// TestSADelete_ReferencedAsSubjectN_Blocked — ServiceAccount variant.
func TestSADelete_ReferencedAsSubjectN_Blocked(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx, pool := kac127Setup(t)
	owner, accID := kac127SeedUserAndAccount(t, ctx, pool, "dsrs")
	prjID := kac127SeedProject(t, ctx, pool, accID, "dsrs")
	roleID := seedProjectRole(t, ctx, pool, domain.ProjectID(prjID), "role_dsrs")

	member := seedSAID(t, ctx, pool, accID, "dsrs")

	abID := padOrTrim20("acb00000dsrs")
	require.NoError(t, insertBindingRaw(ctx, pool, abID, "user", owner, string(roleID), "project", prjID))
	require.NoError(t, insertABSubjectRaw(ctx, pool, abID, "service_account", member, 1))

	repo := kachopg.New(pool, nil)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.ServiceAccountsW().Delete(ctx, domain.ServiceAccountID(member))
	_ = w.Rollback(ctx)
	require.Error(t, err, "ServiceAccount referenced as subjects[1] must not be hard-deleted")
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
		"expected FailedPrecondition, got %v", err)
	assert.Contains(t, err.Error(), "access bindings")

	var cnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.service_accounts WHERE id=$1`, member).Scan(&cnt))
	assert.Equal(t, 1, cnt, "the referenced service account must survive the rejected delete")
}

// TestGroupDelete_ReferencedAsSubjectN_Blocked — Group variant.
func TestGroupDelete_ReferencedAsSubjectN_Blocked(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx, pool := kac127Setup(t)
	owner, accID := kac127SeedUserAndAccount(t, ctx, pool, "dsrg")
	prjID := kac127SeedProject(t, ctx, pool, accID, "dsrg")
	roleID := seedProjectRole(t, ctx, pool, domain.ProjectID(prjID), "role_dsrg")

	member := seedGroupID(t, ctx, pool, accID, "dsrg")

	abID := padOrTrim20("acb00000dsrg")
	require.NoError(t, insertBindingRaw(ctx, pool, abID, "user", owner, string(roleID), "project", prjID))
	require.NoError(t, insertABSubjectRaw(ctx, pool, abID, "group", member, 1))

	repo := kachopg.New(pool, nil)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.GroupsW().Delete(ctx, domain.GroupID(member))
	_ = w.Rollback(ctx)
	require.Error(t, err, "Group referenced as subjects[1] must not be hard-deleted")
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
		"expected FailedPrecondition, got %v", err)
	assert.Contains(t, err.Error(), "access bindings")

	var cnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.groups WHERE id=$1`, member).Scan(&cnt))
	assert.Equal(t, 1, cnt, "the referenced group must survive the rejected delete")
}

// TestUserDelete_ConcurrentAddSubjectN_NoDangling — the delete-vs-add-subject
// TOCTOU proof, written deterministically (no goroutine, no pg_stat_activity
// polling, no possible hang), mirroring TestABSubjectExists_ConcurrentDeleteVsCreate_NoDangling
// but exercising the access_binding_subjects (subjects[1..N]) child insert.
//
// One tx inserts an access_binding_subjects row for user U — its migration-0049
// subject_ref_exists trigger takes a FOR KEY SHARE lock on U's users row. A second
// connection then runs the real User.Delete guard under a short lock_timeout:
//
//   - The delete must exclusively lock U's row to remove it, so it CONFLICTS with
//     the insert's FOR KEY SHARE lock and blocks; the lock_timeout fires (55P03).
//     That the delete blocks at all PROVES the two paths serialize on U's row —
//     the write-skew window the subjects[0]-only guard could not close.
//   - After the insert commits (releasing the lock), the real repo User.Delete
//     re-qualifies against the now-committed subjects[1] row and rejects the
//     delete with FailedPrecondition — U and the subject row both survive.
//
// Net: no dangling subjects[1..N] row for a deleted principal is ever produced.
func TestUserDelete_ConcurrentAddSubjectN_NoDangling(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	// Mirrors the userWriter.Delete guard (incl. the access_binding_subjects
	// subjects[1..N] clause) — used only for the deterministic lock-timeout
	// serialization proof; the behavioural assertion below uses the real repo.
	const guardedUserDelete = `
		DELETE FROM kacho_iam.users u
		 WHERE u.id = $1
		   AND NOT EXISTS (SELECT 1 FROM kacho_iam.access_bindings         WHERE subject_type='user' AND subject_id=$1)
		   AND NOT EXISTS (SELECT 1 FROM kacho_iam.access_binding_subjects WHERE subject_type='user' AND subject_id=$1)
		   AND NOT EXISTS (SELECT 1 FROM kacho_iam.group_members           WHERE member_type='user'  AND member_id=$1)`

	ctx, pool := kac127Setup(t)
	owner, accID := kac127SeedUserAndAccount(t, ctx, pool, "dsrc")
	prjID := kac127SeedProject(t, ctx, pool, accID, "dsrc")
	roleID := seedProjectRole(t, ctx, pool, domain.ProjectID(prjID), "role_dsrc")

	member := seedMemberUser(t, ctx, pool, accID, "dsrc")

	// A committed binding whose legacy subjects[0] is the owner; `member` will be
	// added concurrently as a subjects[1] child row.
	abID := padOrTrim20("acb00000dsrc")
	require.NoError(t, insertBindingRaw(ctx, pool, abID, "user", owner, string(roleID), "project", prjID))

	// txInsert: add `member` as subjects[1]; its 0049 trigger takes FOR KEY SHARE
	// on the users row. Do NOT commit yet. Deferred rollback guarantees the lock is
	// released and the connection returned even if an assertion fails early.
	txInsert, err := pool.Begin(ctx)
	require.NoError(t, err)
	insertDone := false
	defer func() {
		if !insertDone {
			_ = txInsert.Rollback(ctx)
		}
	}()
	_, err = txInsert.Exec(ctx, `
		INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
		VALUES ($1, 'user', $2, 1)`, abID, member)
	require.NoError(t, err)

	// txDelete: the guarded delete under a short lock_timeout on a SEPARATE
	// connection must block on the insert's FOR KEY SHARE lock and time out — a
	// deterministic, self-releasing proof of serialization (no polling, no hang).
	func() {
		txDelete, derr := pool.Begin(ctx)
		require.NoError(t, derr)
		defer func() { _ = txDelete.Rollback(ctx) }()
		_, derr = txDelete.Exec(ctx, `SET LOCAL lock_timeout = '2s'`)
		require.NoError(t, derr)
		_, derr = txDelete.Exec(ctx, guardedUserDelete, member)
		require.Error(t, derr, "guarded delete must block on the insert's key-share lock (race window would otherwise be open)")
		assertSQLState(t, derr, "55P03") // lock_not_available — the delete was blocked
	}()

	// Commit the insert → releases the lock; `member` is now subjects[1].
	require.NoError(t, txInsert.Commit(ctx))
	insertDone = true

	// The real repo User.Delete now sees the committed subjects[1] row and rejects.
	repo := kachopg.New(pool, nil)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.UsersW().Delete(ctx, domain.UserID(member))
	_ = w.Rollback(ctx)
	require.Error(t, err, "post-commit delete of a subjects[1]-referenced user must be rejected, not a hard delete")
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
		"expected FailedPrecondition, got %v", err)

	// Invariant: the user survived AND the subject row still references a LIVE user.
	var userCnt, subCnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.users WHERE id=$1`, member).Scan(&userCnt))
	assert.Equal(t, 1, userCnt, "the referenced user must survive (no orphan subjects[1] row)")
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_subjects WHERE subject_type='user' AND subject_id=$1`, member).Scan(&subCnt))
	assert.Equal(t, 1, subCnt, "the committed subjects[1] row must reference the live user")
}

// TestDelete_SubjectRefTrigger_GuardBypassRejected — the migration-0050 BEFORE
// DELETE triggers are the AUTHORITATIVE within-service invariant: even a raw DELETE
// that bypasses the repo's software NOT EXISTS guard (the stale-snapshot path that
// a concurrent add-subject could slip through) is rejected with 23503 for a
// principal still referenced as a subjects[1..N] grantee. Exercises all three
// referent tables (users / service_accounts / groups) against one container.
func TestDelete_SubjectRefTrigger_GuardBypassRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx, pool := kac127Setup(t)
	owner, accID := kac127SeedUserAndAccount(t, ctx, pool, "dstg")
	prjID := kac127SeedProject(t, ctx, pool, accID, "dstg")
	roleID := seedProjectRole(t, ctx, pool, domain.ProjectID(prjID), "role_dstg")

	memberUser := seedMemberUser(t, ctx, pool, accID, "dstg")
	memberSA := seedSAID(t, ctx, pool, accID, "dstg")
	memberGroup := seedGroupID(t, ctx, pool, accID, "dstg")

	// One binding (subjects[0] = owner) carrying all three principals as subjects[1..3].
	abID := padOrTrim20("acb00000dstg")
	require.NoError(t, insertBindingRaw(ctx, pool, abID, "user", owner, string(roleID), "project", prjID))
	require.NoError(t, insertABSubjectRaw(ctx, pool, abID, "user", memberUser, 1))
	require.NoError(t, insertABSubjectRaw(ctx, pool, abID, "service_account", memberSA, 2))
	require.NoError(t, insertABSubjectRaw(ctx, pool, abID, "group", memberGroup, 3))

	cases := []struct {
		name, table, id string
	}{
		{"user", "kacho_iam.users", memberUser},
		{"service_account", "kacho_iam.service_accounts", memberSA},
		{"group", "kacho_iam.groups", memberGroup},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Raw DELETE — no NOT EXISTS guard, so only the DB trigger can stop it.
			_, err := pool.Exec(ctx, "DELETE FROM "+c.table+" WHERE id = $1", c.id)
			require.Error(t, err, "guard-bypassing DELETE of a referenced principal must be rejected by the trigger")
			assertSQLState(t, err, "23503")

			var cnt int
			require.NoError(t, pool.QueryRow(ctx,
				"SELECT count(*) FROM "+c.table+" WHERE id = $1", c.id).Scan(&cnt))
			assert.Equal(t, 1, cnt, "the referenced principal must survive the rejected raw delete")
		})
	}
}
