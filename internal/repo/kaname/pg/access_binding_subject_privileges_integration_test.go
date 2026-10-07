// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_subject_privileges_integration_test.go — integration tests for
// Reader.ListSubjectPrivileges (RPC
// AccessBindingService.ListSubjectPrivileges).
//
// The repo method is purely SQL — it returns the subject's DIRECT AccessBindings
// LEFT JOINed with `roles` so role_name is resolved in ONE query (no N+1),
// filters out REVOKED rows, and keyset-paginates by (created_at, id) ASC.
// Authorization (self / account-admin) lives in the use-case layer
// (list_subject_privileges_test.go).
//
// Coverage:
//   - enriched rows carry resolved role_name via the JOIN.
//   - keyset pagination (page_size=1 → token → remainder).
//   - existing subject with 0 bindings → empty list, no token.
//   - present role → role_name resolved (схема не допускает висячей роли у выдачи роли).
//   - relation-form grant (role_id NULL) for group / service_account → listed
//     with role_id="" and role_name="" (промах LEFT JOIN), перечень не падает.
//   - REVOKED excluded: a REVOKED binding is NOT returned by default.
//   - account isolation: only the requested subject's rows are returned.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// seedUserInAccount — INSERT an ACTIVE user row whose account_id is the given
// (already-seeded) account, so the subject's home account is controllable
// (mustSeedUser auto-creates its own account, which we don't want here).
func seedUserInAccount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID domain.AccountID, suffix string) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err := pool.Exec(ctx, withWayIn(`
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`),
		string(uid), string(accID),
		"ext-spu-"+suffix+"-"+string(uid),
		"u-spu-"+suffix+"@example.com",
		"SP User "+suffix,
	)
	require.NoError(t, err, "seed user in account")
	return uid
}

func TestAB_SP01_EnrichedRoleNameViaJoin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "sp01o")
	acc := seedAccount(t, ctx, repo, "acc-sp01", owner)
	member := seedUserInAccount(t, ctx, pool, acc.ID, "sp01m")
	roleEditor := seedCustomRole(t, ctx, repo, acc.ID, "editor")
	roleViewer := seedCustomRole(t, ctx, repo, acc.ID, "viewer")
	proj := seedProject(t, ctx, repo, acc.ID, "proj-sp01")

	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: roleEditor.ID, ResourceType: "project", ResourceID: string(proj.ID),
		GrantedByUserID: owner,
	})
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: roleViewer.ID, ResourceType: "account", ResourceID: string(acc.ID),
		GrantedByUserID: owner,
	})

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	out, next, err := rd.AccessBindings().ListSubjectPrivileges(ctx,
		domain.SubjectTypeUser, domain.SubjectID(member), repoab.PageFilter{})
	require.NoError(t, err)
	require.Len(t, out, 2, "both direct bindings returned")
	assert.Empty(t, next)

	byRole := map[domain.RoleID]domain.SubjectPrivilege{}
	for _, p := range out {
		byRole[p.RoleID] = p
	}
	assert.Equal(t, domain.RoleName("editor"), byRole[roleEditor.ID].RoleName, "role_name resolved via JOIN")
	assert.Equal(t, domain.RoleName("viewer"), byRole[roleViewer.ID].RoleName)
	assert.Equal(t, "project", string(byRole[roleEditor.ID].ResourceType))
	assert.Equal(t, string(proj.ID), byRole[roleEditor.ID].ResourceID)
	assert.Equal(t, domain.ScopeProject, byRole[roleEditor.ID].Scope)
	assert.Equal(t, domain.AccessBindingStatusActive, byRole[roleEditor.ID].Status)
	assert.Equal(t, owner, byRole[roleEditor.ID].GrantedByUserID)
	assert.NotEmpty(t, byRole[roleEditor.ID].BindingID)
	assert.False(t, byRole[roleEditor.ID].CreatedAt.IsZero())
}

func TestAB_SP02_KeysetPagination(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "sp02o")
	acc := seedAccount(t, ctx, repo, "acc-sp02", owner)
	member := seedUserInAccount(t, ctx, pool, acc.ID, "sp02m")
	roleA := seedCustomRole(t, ctx, repo, acc.ID, "role_a")
	roleB := seedCustomRole(t, ctx, repo, acc.ID, "role_b")

	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: roleA.ID, ResourceType: "account", ResourceID: string(acc.ID), GrantedByUserID: owner,
	})
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: roleB.ID, ResourceType: "account", ResourceID: string(acc.ID), GrantedByUserID: owner,
	})

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	page1, next, err := rd.AccessBindings().ListSubjectPrivileges(ctx,
		domain.SubjectTypeUser, domain.SubjectID(member), repoab.PageFilter{PageSize: 1})
	require.NoError(t, err)
	require.Len(t, page1, 1, "page 1 holds exactly 1 row")
	require.NotEmpty(t, next, "next_page_token non-empty when more rows remain")

	page2, next2, err := rd.AccessBindings().ListSubjectPrivileges(ctx,
		domain.SubjectTypeUser, domain.SubjectID(member), repoab.PageFilter{PageSize: 1, PageToken: next})
	require.NoError(t, err)
	require.Len(t, page2, 1, "page 2 holds the remaining row")
	assert.Empty(t, next2, "no more pages")
	assert.NotEqual(t, page1[0].BindingID, page2[0].BindingID, "pages are disjoint")
}

func TestAB_SP09_ZeroBindings_EmptyList(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "sp09o")
	acc := seedAccount(t, ctx, repo, "acc-sp09", owner)
	empty := seedUserInAccount(t, ctx, pool, acc.ID, "sp09e")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	out, next, err := rd.AccessBindings().ListSubjectPrivileges(ctx,
		domain.SubjectTypeUser, domain.SubjectID(empty), repoab.PageFilter{})
	require.NoError(t, err)
	assert.Empty(t, out)
	assert.Empty(t, next)
}

func TestAB_SP13_DanglingRole_EmptyRoleName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "sp13o")
	acc := seedAccount(t, ctx, repo, "acc-sp13", owner)
	member := seedUserInAccount(t, ctx, pool, acc.ID, "sp13m")
	role := seedCustomRole(t, ctx, repo, acc.ID, "soon_gone")

	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: role.ID, ResourceType: "account", ResourceID: string(acc.ID), GrantedByUserID: owner,
	})

	// Роль, на которую ссылается ЖИВАЯ выдача роли, снять нельзя:
	// access_bindings_role_fk — ON DELETE RESTRICT, и ссылку держит любая строка,
	// отозванная тоже. Висячей роли у выдачи роли схема не допускает, поэтому
	// здесь утверждается положительная половина: JOIN находит роль и возвращает её
	// имя без ошибки.
	//
	// Промах LEFT JOIN на уровне SQL исполняется не здесь, а выдачей ФОРМЫ
	// ОТНОШЕНИЯ: у неё role_id IS NULL, роли JOIN не находит, и role_name обязан
	// прийти пустым — TestAB_SP_RelationFormGrant_IsListed.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	out, _, err := rd.AccessBindings().ListSubjectPrivileges(ctx,
		domain.SubjectTypeUser, domain.SubjectID(member), repoab.PageFilter{})
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, domain.RoleName("soon_gone"), out[0].RoleName)
}

func TestAB_SP_RevokedExcluded_AndAccountIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "spro")
	acc := seedAccount(t, ctx, repo, "acc-spr", owner)
	member := seedUserInAccount(t, ctx, pool, acc.ID, "sprm")
	stranger := seedUserInAccount(t, ctx, pool, acc.ID, "sprs")
	roleActive := seedCustomRole(t, ctx, repo, acc.ID, "active_role")
	roleRevoked := seedCustomRole(t, ctx, repo, acc.ID, "revoked_role")

	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: roleActive.ID, ResourceType: "account", ResourceID: string(acc.ID), GrantedByUserID: owner,
	})
	// The scope said "project" and carried an ACCOUNT id — a resource id that names no
	// project at all. Nothing checked it before, so the row went in and the case
	// measured a binding anchored to nothing. It now names a real project of the same
	// account, which is what the case meant: a revoked grant inside the tenant.
	prj := seedProject(t, ctx, repo, acc.ID, "prj-spr")
	revoked := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: roleRevoked.ID, ResourceType: "project", ResourceID: string(prj.ID), GrantedByUserID: owner,
	})
	// Binding for a DIFFERENT subject (stranger) — must not appear.
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(stranger),
		RoleID: roleActive.ID, ResourceType: "account", ResourceID: string(acc.ID), GrantedByUserID: owner,
	})

	// Revoke the member's roleRevoked binding.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	rb := owner
	_, err = w.AccessBindingsW().TransitionStatus(ctx, revoked.ID,
		[]domain.AccessBindingStatus{domain.AccessBindingStatusActive, domain.AccessBindingStatusPending},
		domain.AccessBindingStatusRevoked, &rb)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	out, _, err := rd.AccessBindings().ListSubjectPrivileges(ctx,
		domain.SubjectTypeUser, domain.SubjectID(member), repoab.PageFilter{})
	require.NoError(t, err)
	require.Len(t, out, 1, "REVOKED row excluded; only the member's ACTIVE row returned")
	assert.Equal(t, roleActive.ID, out[0].RoleID)
}

// TestAB_SP_GroupSubject_DirectBindingsEnriched — the repo SQL
// path (generic ab.subject_type filter) returns a GROUP subject's DIRECT
// bindings with role_name resolved via the JOIN, and isolates the group from a
// same-account user subject (no cross-subject_type leak).
func TestAB_SP_GroupSubject_DirectBindingsEnriched(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "spgo")
	acc := seedAccount(t, ctx, repo, "acc-spg", owner)
	grp := seedGroup(t, ctx, repo, acc.ID, "spg-team")
	member := seedUserInAccount(t, ctx, pool, acc.ID, "spgm")
	roleEditor := seedCustomRole(t, ctx, repo, acc.ID, "editor")
	roleViewer := seedCustomRole(t, ctx, repo, acc.ID, "viewer")
	proj := seedProject(t, ctx, repo, acc.ID, "proj-spg")

	// Group's own direct binding.
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeGroup, SubjectID: domain.SubjectID(grp.ID),
		RoleID: roleEditor.ID, ResourceType: "project", ResourceID: string(proj.ID),
		GrantedByUserID: owner,
	})
	// Same-account USER binding with same role-id space — must NOT appear for the
	// group subject (subject_type isolation).
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(member),
		RoleID: roleViewer.ID, ResourceType: "account", ResourceID: string(acc.ID),
		GrantedByUserID: owner,
	})

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	out, next, err := rd.AccessBindings().ListSubjectPrivileges(ctx,
		domain.SubjectTypeGroup, domain.SubjectID(grp.ID), repoab.PageFilter{})
	require.NoError(t, err)
	require.Len(t, out, 1, "only the group's own direct binding returned (subject_type isolation)")
	assert.Empty(t, next)
	assert.Equal(t, roleEditor.ID, out[0].RoleID)
	assert.Equal(t, domain.RoleName("editor"), out[0].RoleName, "group role_name resolved via JOIN")
	assert.Equal(t, "project", string(out[0].ResourceType))
	assert.Equal(t, string(proj.ID), out[0].ResourceID)
}

// TestAB_SP_RelationFormGrant_IsListed — выдача ФОРМЫ ОТНОШЕНИЯ (роли нет:
// role_id IS NULL, указано granted_relation; так её допускает
// access_bindings_grant_form_ck) перечисляется наравне с выдачей роли и не
// роняет чтение целиком. Субъект — группа и сервисный аккаунт: оба вида
// получателя законно держат системную выдачу отношением.
//
// Законный близнец в том же перечне — выдача РОЛИ тому же субъекту: она обязана
// вернуться со своей ролью, а отношение — с пустой ролью и пустым именем роли.
// Против близнеца выдача-отношение отличается ровно одним фактом — формой выдачи.
func TestAB_SP_RelationFormGrant_IsListed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "sprf")
	acc := seedAccount(t, ctx, repo, "acc-sprf", owner)
	proj := seedProject(t, ctx, repo, acc.ID, "proj-sprf")
	role := seedCustomRole(t, ctx, repo, acc.ID, "sprf_role")
	grp := seedGroup(t, ctx, repo, acc.ID, "sprf-team")
	sa := seedSA(t, ctx, repo, acc.ID, "sprf-sa")

	for _, tc := range []struct {
		name        string
		subjectType domain.SubjectType
		subjectID   domain.SubjectID
	}{
		{"group", domain.SubjectTypeGroup, domain.SubjectID(grp.ID)},
		{"service_account", domain.SubjectTypeServiceAccount, domain.SubjectID(sa.ID)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roleGrant := insertAB(t, ctx, repo, domain.AccessBinding{
				SubjectType: tc.subjectType, SubjectID: tc.subjectID,
				RoleID: role.ID, ResourceType: "project", ResourceID: string(proj.ID),
				GrantedByUserID: owner,
			})
			relationGrant := insertAB(t, ctx, repo, domain.AccessBinding{
				SubjectType: tc.subjectType, SubjectID: tc.subjectID,
				GrantedRelation: "viewer", System: true,
				ResourceType: "project", ResourceID: string(proj.ID),
				GrantedByUserID: owner,
			})

			// Предпосылка: строка действительно в форме отношения — роли в БД нет.
			var roleIsNull bool
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT role_id IS NULL FROM kaname.access_bindings WHERE id = $1`,
				string(relationGrant.ID)).Scan(&roleIsNull))
			require.True(t, roleIsNull, "предпосылка: у выдачи-отношения role_id обязан быть NULL")

			rd, err := repo.Reader(ctx)
			require.NoError(t, err)
			defer func() { _ = rd.Rollback(ctx) }()

			out, next, err := rd.AccessBindings().ListSubjectPrivileges(ctx,
				tc.subjectType, tc.subjectID, repoab.PageFilter{})
			require.NoError(t, err, "выдача без роли обязана перечисляться, а не ронять перечень целиком")
			assert.Empty(t, next)
			require.Len(t, out, 2, "перечень обязан нести обе выдачи: роли и отношения")

			byID := map[domain.AccessBindingID]domain.SubjectPrivilege{}
			for _, p := range out {
				byID[p.BindingID] = p
			}
			rg, ok := byID[roleGrant.ID]
			require.True(t, ok, "выдача роли (законный близнец) обязана быть в перечне")
			assert.Equal(t, role.ID, rg.RoleID)
			assert.Equal(t, domain.RoleName("sprf_role"), rg.RoleName)

			relg, ok := byID[relationGrant.ID]
			require.True(t, ok, "выдача отношения обязана быть в перечне")
			assert.Equal(t, domain.RoleID(""), relg.RoleID, "у формы отношения роли нет")
			assert.Equal(t, domain.RoleName(""), relg.RoleName, "у формы отношения нет и имени роли")
			assert.Equal(t, "project", string(relg.ResourceType))
			assert.Equal(t, string(proj.ID), relg.ResourceID)
			assert.Equal(t, domain.AccessBindingStatusActive, relg.Status)
		})
	}
}
