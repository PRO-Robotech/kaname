// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// role_assignable_integration_test.go — интеграционные пробы (testcontainers PG16)
// читающей стороны назначаемых ролей:
//
//   - Регрессия roleCols: Get/List теперь проецируют также cluster_id + project_id,
//     чтобы domain.Role содержал поля области, нужные предикату
//     (был только account_id); существующие чтения продолжают работать.
//   - Reader.ListAssignable фильтрует роли предикатом матрицы областей
//     (системные везде; роль аккаунта — только свой аккаунт; роль проекта — только
//     свой проект; кластер ⇒ только системные), страницы по ключу (created_at,id) ASC.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	reporole "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
)

// seedProjectRole — прямая вставка INSERT пользовательской роли области проекта
// для проверки чтения репозитория без вызова публичного Create. У роли заданы
// is_system=false, cluster_id NULL, account_id NULL и значение project_id.
func seedProjectRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, prj domain.ProjectID, name string) domain.RoleID {
	t.Helper()
	rid := domain.RoleID(ids.NewID(domain.PrefixRole))
	_, err := pool.Exec(ctx, `
		INSERT INTO roles (id, project_id, name, description, permissions)
		VALUES ($1, $2, $3, $4, '["iam.users.*.read"]'::jsonb)`,
		string(rid), string(prj), name, "project role "+name)
	require.NoError(t, err, "seed project-scoped role")
	return rid
}

// roleIDs собирает id из среза ролей для проверок множеств.
func roleIDs(rs []domain.Role) map[domain.RoleID]domain.Role {
	m := map[domain.RoleID]domain.Role{}
	for _, r := range rs {
		m[r.ID] = r
	}
	return m
}

// TestRole_RoleColsRegression_ScopeFieldsPopulated — Get/List должны заполнять
// ClusterID (системные) и ProjectID (область проекта) наряду с AccountID.
// До 1.5 roleCols пропускал cluster_id/project_id → оба оставались пустыми.
func TestRole_RoleColsRegression_ScopeFieldsPopulated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "rcr")
	acc := seedAccount(t, ctx, repo, "acc-rcr", owner)
	proj := seedProject(t, ctx, repo, acc.ID, "proj-rcr")

	accRole := seedCustomRole(t, ctx, repo, acc.ID, "rcr_acc")
	prjRoleID := seedProjectRole(t, ctx, pool, proj.ID, "rcr_prj")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// Роль аккаунта по-прежнему читает свой account_id (регрессия), project_id пуст.
	gotAcc, err := rd.Roles().Get(ctx, accRole.ID)
	require.NoError(t, err)
	assert.Equal(t, acc.ID, gotAcc.AccountID, "account_id still populated (regression)")
	assert.Empty(t, gotAcc.ProjectID)
	assert.Empty(t, gotAcc.ClusterID)

	// Роль проекта: project_id теперь заполнен (НОВАЯ проекция).
	gotPrj, err := rd.Roles().Get(ctx, prjRoleID)
	require.NoError(t, err)
	assert.Equal(t, proj.ID, gotPrj.ProjectID, "project_id populated by expanded roleCols")
	assert.Empty(t, gotPrj.AccountID)

	// Системная роль (миграция посева) содержит cluster_id.
	gotSys, err := rd.Roles().Get(ctx, domain.RoleID(domain.SystemViewerRoleID))
	require.NoError(t, err)
	assert.True(t, gotSys.IsSystem)
	assert.Equal(t, domain.ClusterID(domain.ClusterSingletonID), gotSys.ClusterID,
		"system role cluster_id populated by expanded roleCols")
}

// TestRole_ListAssignable_AccountResource — 1.5-01: ресурс аккаунта возвращает
// СИСТЕМНЫЕ + собственные роли АККАУНТА, но НЕ пользовательскую роль чужого аккаунта.
func TestRole_ListAssignable_AccountResource(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	ownerA := mustSeedUser(t, ctx, pool, "laa")
	accA := seedAccount(t, ctx, repo, "acc-laa-a", ownerA)
	ownerB := mustSeedUser(t, ctx, pool, "lab")
	accB := seedAccount(t, ctx, repo, "acc-laa-b", ownerB)

	accustom := seedCustomRole(t, ctx, repo, accA.ID, "laa_custom")
	bcustom := seedCustomRole(t, ctx, repo, accB.ID, "lab_custom")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// page_size достаточен для одной страницы (все системные роли + accustom).
	out, _, err := rd.Roles().ListAssignable(ctx, "account", string(accA.ID),
		reporole.ListFilter{PageSize: 1000})
	require.NoError(t, err)

	byID := roleIDs(out)
	assert.Contains(t, byID, accustom.ID, "own account-role assignable")
	assert.NotContains(t, byID, bcustom.ID, "foreign account-role NOT assignable (1.5-01 isolation)")

	// Присутствует хотя бы одна системная роль с is_system=true и областью кластера.
	sawSystem := false
	for _, r := range out {
		if r.IsSystem {
			sawSystem = true
			assert.NotEmpty(t, r.ClusterID)
		}
	}
	assert.True(t, sawSystem, "system roles assignable on account")
}

// TestRole_ListAssignable_ProjectResource_StrictAccountExcluded — 1.5-02 / 1.5-02b:
// ресурс проекта возвращает СИСТЕМНЫЕ + собственную роль ПРОЕКТА; СТРОГО исключает
// роль области аккаунта, которому принадлежит проект.
func TestRole_ListAssignable_ProjectResource_StrictAccountExcluded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "lap")
	acc := seedAccount(t, ctx, repo, "acc-lap", owner)
	proj := seedProject(t, ctx, repo, acc.ID, "proj-lap")

	accustom := seedCustomRole(t, ctx, repo, acc.ID, "lap_acc")
	pcustomID := seedProjectRole(t, ctx, pool, proj.ID, "lap_prj")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	out, _, err := rd.Roles().ListAssignable(ctx, "project", string(proj.ID),
		reporole.ListFilter{PageSize: 1000})
	require.NoError(t, err)

	byID := roleIDs(out)
	assert.Contains(t, byID, pcustomID, "own project-role assignable (1.5-02)")
	assert.NotContains(t, byID, accustom.ID, "account-role NOT assignable on project (1.5-02b STRICT)")
}

// TestRole_ListAssignable_ClusterResource_SystemOnly — 1.5-03: ресурс кластера
// возвращает ТОЛЬКО системные роли.
func TestRole_ListAssignable_ClusterResource_SystemOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "lac")
	acc := seedAccount(t, ctx, repo, "acc-lac", owner)
	accustom := seedCustomRole(t, ctx, repo, acc.ID, "lac_acc")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	out, _, err := rd.Roles().ListAssignable(ctx, "cluster", domain.ClusterSingletonID,
		reporole.ListFilter{PageSize: 1000})
	require.NoError(t, err)

	byID := roleIDs(out)
	assert.NotContains(t, byID, accustom.ID, "custom role NOT assignable on cluster")
	for _, r := range out {
		assert.True(t, r.IsSystem, "cluster ⇒ only system roles (1.5-03), got non-system %s", r.ID)
	}
	assert.NotEmpty(t, out, "system roles seeded → cluster returns them")
}

// TestRole_ListAssignable_Pagination — 1.5-04: страницы по ключу в отфильтрованном
// наборе (page_size=1 даёт страницу + курсор, вторая страница — остаток).
func TestRole_ListAssignable_Pagination(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	owner := mustSeedUser(t, ctx, pool, "lpg")
	acc := seedAccount(t, ctx, repo, "acc-lpg", owner)
	seedCustomRole(t, ctx, repo, acc.ID, "lpg_acc")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// Сначала собираем полный набор, чтобы узнать число элементов.
	full, _, err := rd.Roles().ListAssignable(ctx, "account", string(acc.ID),
		reporole.ListFilter{PageSize: 1000})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(full), 2, "system roles + accustom ≥ 2")

	// Обходим набор по элементу на страницу; собираем id; проверяем отсутствие повторов и полноту.
	seen := map[domain.RoleID]bool{}
	token := ""
	pages := 0
	for {
		page, next, perr := rd.Roles().ListAssignable(ctx, "account", string(acc.ID),
			reporole.ListFilter{PageSize: 1, PageToken: token})
		require.NoError(t, perr)
		require.LessOrEqual(t, len(page), 1, "page_size=1 yields ≤1 element")
		for _, r := range page {
			require.False(t, seen[r.ID], "no duplicate across pages: %s", r.ID)
			seen[r.ID] = true
		}
		pages++
		if next == "" {
			break
		}
		token = next
		require.LessOrEqual(t, pages, len(full)+2, "must terminate")
	}
	assert.Equal(t, len(full), len(seen), "paged walk covers the full filtered set")
}
