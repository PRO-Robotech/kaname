// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// access_binding_subject_exists_integration_test.go — testcontainers Postgres
// tests for the migration 0049 DB-level enforcement of the WITHIN-SERVICE
// subject reference carried by access_bindings.subject_id (and the
// access_binding_subjects child rows).
//
// Before 0049 the (subject_type, subject_id) pair was a bare TEXT column with a
// CHECK on the TYPE enum only and NO existence enforcement of the referenced
// user / service_account / group — unlike group_members, whose member existence
// is held by the group_members_member_exists() BEFORE-INSERT trigger. A grant
// could therefore be written for a non-existent principal (phantom grant), and a
// concurrent User.Delete-vs-AccessBinding.Create pair could leave a dangling
// binding for a just-deleted user (hard-rule #10 violation).
//
// These tests prove the reference is now enforced at the DB level:
//   - inserting a binding whose subject_id points at a non-existent user /
//     service_account / group is rejected with 23503 (→ FailedPrecondition);
//   - inserting an access_binding_subjects child row for a phantom subject is
//     likewise rejected;
//   - a live subject (user / SA / group) is accepted;
//   - the concurrent delete-vs-create race serializes on the FOR KEY SHARE probe
//     so exactly one outcome results and no dangling binding survives.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// seedSAID inserts a live service_accounts row in the given account and returns
// its id (there is no FK from access_bindings to it — the migration-0049 trigger
// is the enforcement point being exercised).
func seedSAID(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID, suffix string) string {
	t.Helper()
	said := ids.NewID(domain.PrefixServiceAccount)
	_, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.service_accounts (id, account_id, name)
		 VALUES ($1, $2, $3)`,
		said, accID, "sa-"+suffix)
	require.NoError(t, err)
	return said
}

// seedGroupID inserts a live groups row in the given account and returns its id.
func seedGroupID(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID, suffix string) string {
	t.Helper()
	gid := ids.NewID(domain.PrefixGroup)
	_, err := pool.Exec(ctx,
		`INSERT INTO kacho_iam.groups (id, account_id, name)
		 VALUES ($1, $2, $3)`,
		gid, accID, "grp-"+suffix)
	require.NoError(t, err)
	return gid
}

// insertBindingSubject inserts an access_bindings row directly via SQL with an
// arbitrary (subject_type, subject_id), bypassing the domain layer so the raw DB
// trigger is what is under test. Returns the pg error (nil on success).
func insertBindingRaw(ctx context.Context, pool *pgxpool.Pool, id, subjectType, subjectID, roleID, resType, resID string) error {
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_bindings
			(id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')`,
		id, subjectType, subjectID, roleID, resType, resID)
	return err
}

// TestABSubjectExists_InsertPhantomUser_Rejected — a binding whose subject_id
// references no users row is rejected with 23503 (the phantom-grant defect).
func TestABSubjectExists_InsertPhantomUser_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx, pool := kac127Setup(t)
	// Seed a real user+account+project+role so the binding is well-formed EXCEPT
	// for the subject reference.
	_, _, _, roleID := kac127SeedABRow(t, ctx, pool, "abse1", domain.AccessBindingStatusActive)
	var prjID string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT resource_id FROM kacho_iam.access_bindings WHERE role_id=$1 LIMIT 1`, roleID).Scan(&prjID))

	phantom := ids.NewID(domain.PrefixUser)
	err := insertBindingRaw(ctx, pool, padOrTrim20("acb00000abse1x"),
		"user", phantom, roleID, "project", prjID)
	require.Error(t, err, "binding referencing a non-existent user must be rejected")
	assertSQLState(t, err, "23503")
}

// TestABSubjectExists_InsertPhantomServiceAccount_Rejected — SA subject variant.
func TestABSubjectExists_InsertPhantomServiceAccount_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx, pool := kac127Setup(t)
	_, _, _, roleID := kac127SeedABRow(t, ctx, pool, "abse2", domain.AccessBindingStatusActive)
	var prjID string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT resource_id FROM kacho_iam.access_bindings WHERE role_id=$1 LIMIT 1`, roleID).Scan(&prjID))

	phantom := ids.NewID(domain.PrefixServiceAccount)
	err := insertBindingRaw(ctx, pool, padOrTrim20("acb00000abse2x"),
		"service_account", phantom, roleID, "project", prjID)
	require.Error(t, err, "binding referencing a non-existent service account must be rejected")
	assertSQLState(t, err, "23503")
}

// TestABSubjectExists_InsertPhantomGroup_Rejected — group subject variant.
func TestABSubjectExists_InsertPhantomGroup_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx, pool := kac127Setup(t)
	_, _, _, roleID := kac127SeedABRow(t, ctx, pool, "abse3", domain.AccessBindingStatusActive)
	var prjID string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT resource_id FROM kacho_iam.access_bindings WHERE role_id=$1 LIMIT 1`, roleID).Scan(&prjID))

	phantom := ids.NewID(domain.PrefixGroup)
	err := insertBindingRaw(ctx, pool, padOrTrim20("acb00000abse3x"),
		"group", phantom, roleID, "project", prjID)
	require.Error(t, err, "binding referencing a non-existent group must be rejected")
	assertSQLState(t, err, "23503")
}

// TestABSubjectExists_InsertLiveSubjects_Accepted — a binding for a LIVE user,
// SA and group each commits (no false positive from the trigger).
func TestABSubjectExists_InsertLiveSubjects_Accepted(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx, pool := kac127Setup(t)
	uid, accID := kac127SeedUserAndAccount(t, ctx, pool, "abse4")
	prjID := kac127SeedProject(t, ctx, pool, accID, "abse4")
	roleID := padOrTrim20("rol00000abse4")
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.roles (id, project_id, is_system, name, description, permissions)
		VALUES ($1, $2, false, 'role_abse4', '', '["x.y.*.z"]'::jsonb)`, roleID, prjID)
	require.NoError(t, err)

	said := seedSAID(t, ctx, pool, accID, "abse4")
	gid := seedGroupID(t, ctx, pool, accID, "abse4")

	require.NoError(t, insertBindingRaw(ctx, pool, padOrTrim20("acb00000abse4u"),
		"user", uid, roleID, "project", prjID), "live user subject must be accepted")
	require.NoError(t, insertBindingRaw(ctx, pool, padOrTrim20("acb00000abse4s"),
		"service_account", said, roleID, "project", prjID), "live SA subject must be accepted")
	require.NoError(t, insertBindingRaw(ctx, pool, padOrTrim20("acb00000abse4g"),
		"group", gid, roleID, "project", prjID), "live group subject must be accepted")
}

// TestABSubjectExists_ChildSubjectRowPhantom_Rejected — the same enforcement on
// the access_binding_subjects (0028) child table: a phantom subject row is
// rejected even when the parent binding itself is well-formed.
func TestABSubjectExists_ChildSubjectRowPhantom_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx, pool := kac127Setup(t)
	_, abID, _, _ := kac127SeedABRow(t, ctx, pool, "abse5", domain.AccessBindingStatusActive)

	phantom := ids.NewID(domain.PrefixGroup)
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
		VALUES ($1, 'group', $2, 1)`, abID, phantom)
	require.Error(t, err, "child subject row referencing a non-existent group must be rejected")
	assertSQLState(t, err, "23503")
}

// TestABSubjectExists_StatusTransitionOnExistingBinding_Unaffected — the trigger
// only re-validates when the subject columns CHANGE (FK semantics). An UPDATE
// that touches status/labels of an existing binding must NOT re-probe the
// subject, so a status transition still works even after the subject row is
// (out-of-band) removed. Proves the trigger does not regress revoke/label paths.
func TestABSubjectExists_StatusTransitionOnExistingBinding_Unaffected(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx, pool := kac127Setup(t)
	_, abID, _, _ := kac127SeedABRow(t, ctx, pool, "abse6", domain.AccessBindingStatusActive)

	// A label UPDATE keeps (subject_type, subject_id) unchanged, so the trigger
	// must short-circuit (FK semantics: an unchanged key is not re-checked) and
	// never re-probe the subject — the revoke/label/deletion-protection paths on
	// an existing binding are unaffected.
	_, err := pool.Exec(ctx,
		`UPDATE kacho_iam.access_bindings SET labels = '{"k":"v"}'::jsonb WHERE id=$1`, abID)
	require.NoError(t, err, "label update (subject unchanged) must not trip the subject-exists trigger")

	var lbl string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT labels::text FROM kacho_iam.access_bindings WHERE id=$1`, abID).Scan(&lbl))
	require.Contains(t, lbl, "\"k\": \"v\"")
}

// TestABSubjectExists_ConcurrentDeleteVsCreate_NoDangling — the TOCTOU proof,
// written deterministically (no goroutine, no pg_stat_activity polling, no
// possibility of a hang). One tx inserts a binding for user U — its migration-0049
// trigger takes a FOR KEY SHARE lock on U's users row. A second connection then
// runs the real User.Delete guarded CAS (DELETE … WHERE NOT EXISTS(access_bindings
// …)) under a short lock_timeout:
//
//   - Because the delete must lock U's row to remove it, it CONFLICTS with the
//     insert's FOR KEY SHARE lock and blocks; the lock_timeout fires (SQLSTATE
//     55P03). That the delete blocks at all PROVES the two paths serialize on U's
//     row — the write-skew window the old software-only guard could not close.
//   - After the insert commits (releasing the lock), a fresh guarded delete
//     re-qualifies against the now-committed binding (NOT EXISTS is false under
//     READ COMMITTED), deletes 0 rows, and leaves U + the binding intact.
//
// Net: no dangling binding for a deleted principal is ever produced.
func TestABSubjectExists_ConcurrentDeleteVsCreate_NoDangling(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	const guardedUserDelete = `
		DELETE FROM kacho_iam.users u
		 WHERE u.id = $1
		   AND NOT EXISTS (SELECT 1 FROM kacho_iam.access_bindings WHERE subject_type='user' AND subject_id=$1)
		   AND NOT EXISTS (SELECT 1 FROM kacho_iam.group_members  WHERE member_type='user'  AND member_id=$1)`

	ctx, pool := kac127Setup(t)
	// Seed an account (with its own owner) + project + role to bind on.
	_, accID := kac127SeedUserAndAccount(t, ctx, pool, "abse7o")
	prjID := kac127SeedProject(t, ctx, pool, accID, "abse7")
	roleID := padOrTrim20("rol00000abse7")
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.roles (id, project_id, is_system, name, description, permissions)
		VALUES ($1, $2, false, 'role_abse7', '', '["x.y.*.z"]'::jsonb)`, roleID, prjID)
	require.NoError(t, err)

	// A plain member user (account_id set, NOT an account owner → deletable by
	// the guarded delete once it carries no bindings).
	member := ids.NewID(domain.PrefixUser)
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'M', 'ACTIVE')`,
		member, accID, "ext-abse7m-"+member, "m-abse7@example.com")
	require.NoError(t, err)

	// txInsert: create a binding for `member`; its trigger takes FOR KEY SHARE on
	// the users row. Do NOT commit yet. Deferred rollback guarantees the lock is
	// released and the connection returned even if an assertion fails early (so
	// pool.Close in t.Cleanup can never hang on a leaked, still-acquired tx).
	txInsert, err := pool.Begin(ctx)
	require.NoError(t, err)
	insertDone := false
	defer func() {
		if !insertDone {
			_ = txInsert.Rollback(ctx)
		}
	}()
	_, err = txInsert.Exec(ctx, `
		INSERT INTO kacho_iam.access_bindings
			(id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		VALUES ($1, 'user', $2, $3, 'project', $4, 'ACTIVE')`,
		padOrTrim20("acb00000abse7"), member, roleID, prjID)
	require.NoError(t, err)

	// txDelete: the real guarded delete under a short lock_timeout on a SEPARATE
	// connection. It must block on the insert's FOR KEY SHARE lock and time out —
	// a deterministic, self-releasing proof of serialization (no polling, no hang).
	func() {
		txDelete, derr := pool.Begin(ctx)
		require.NoError(t, derr)
		defer func() { _ = txDelete.Rollback(ctx) }()
		_, derr = txDelete.Exec(ctx, `SET LOCAL lock_timeout = '2s'`)
		require.NoError(t, derr)
		_, derr = txDelete.Exec(ctx, guardedUserDelete, member)
		require.Error(t, derr, "guarded delete must block on the insert's key-share lock, not complete (race window would be open)")
		assertSQLState(t, derr, "55P03") // lock_not_available — the delete was blocked
	}()

	// Commit the insert → releases the lock. A fresh guarded delete now sees the
	// committed binding (NOT EXISTS false) and deletes 0 rows — clean no-op.
	require.NoError(t, txInsert.Commit(ctx))
	insertDone = true

	tag, err := pool.Exec(ctx, guardedUserDelete, member)
	require.NoError(t, err, "post-commit guarded delete must be a clean no-op, not an error")
	require.EqualValues(t, 0, tag.RowsAffected(), "guarded delete must remove 0 rows (the user still carries a binding)")

	// Invariant: the user survived AND the binding references a LIVE user — no
	// dangling binding for a deleted principal.
	var userCnt, bindCnt int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kacho_iam.users WHERE id=$1`, member).Scan(&userCnt))
	require.Equal(t, 1, userCnt, "the bound user must survive the guarded delete (no orphan binding)")
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_bindings WHERE subject_id=$1`, member).Scan(&bindCnt))
	require.Equal(t, 1, bindCnt, "the committed binding must reference the live user")
}
