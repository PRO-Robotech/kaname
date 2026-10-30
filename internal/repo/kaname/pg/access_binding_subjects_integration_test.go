// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_subjects_integration_test.go — поддержка нескольких субъектов
// в модели правил RBAC. Интеграционные пробы с testcontainers Postgres 16
// для дочерней таблицы нескольких субъектов (kaname.access_binding_subjects,
// миграция 0028) и читающего аудита ListByRole.
//
//   - -ROUNDTRIP: InsertSubjects фиксируется вместе с INSERT выдачи,
//     а ListSubjects читает в точности записанный упорядоченный набор.
//   - -CASCADE: удаление строки выдачи каскадно удаляет строки её субъектов
//     (FK ON DELETE CASCADE) — после отзыва нет осиротевших строк субъектов.
//   - -UNIQUE: повтор (binding,subject) идемпотентно оставляет состояние прежним
//     (ON CONFLICT DO NOTHING); набор никогда не разрастается.
//   - -PERSUBJECT: DeleteSubject удаляет строку ОДНОГО субъекта, сохраняя
//     остальных (независимый отзыв).
//   - -BATCH: ListSubjectsForBindings загружает субъектов многих выдач одним запросом.
//   - -LISTBYROLE: ListByRole возвращает выдачи роли постранично по ключу,
//     скрывая REVOKED, если не задан IncludeRevoked.
//   - -RACE (запрет #10): конкурентные InsertSubjects ОДНОЙ пары (binding,subject)
//     сходятся ровно к одной строке (идемпотентность блокировкой строки PK, а не проверкой в коде).

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func countABSubjects(t *testing.T, ctx context.Context, repo *kanamepg.Repository, bindingID domain.AccessBindingID) int {
	t.Helper()
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	subs, err := rd.AccessBindings().ListSubjects(ctx, bindingID)
	require.NoError(t, err)
	return len(subs)
}

func insertSubjects(t *testing.T, ctx context.Context, repo *kanamepg.Repository, id domain.AccessBindingID, subs []domain.Subject) {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	if err := w.AccessBindingsW().InsertSubjects(ctx, id, subs); err != nil {
		_ = w.Rollback(ctx)
		require.NoError(t, err)
	}
	require.NoError(t, w.Commit(ctx))
}

func TestABSubjects_E34_RoundTripOrdered(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "absubrt")
	acc := seedAccount(t, ctx, repo, "acc-absubrt", uid)
	// subject_id — внутрисервисная ссылка, обеспеченная миграцией 0049: сеем настоящие
	// строки группы/SA, чтобы набор субъектов ссылался на существующих участников.
	gid := seedGroupID(t, ctx, pool, string(acc.ID), "absubrt")
	said := seedSAID(t, ctx, pool, string(acc.ID), "absubrt")
	ab := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: domain.SystemViewerRoleID, ResourceType: "account", ResourceID: string(acc.ID),
	})

	subs := []domain.Subject{
		{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)},
		{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(gid)},
		{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(said)},
	}
	insertSubjects(t, ctx, repo, ab.ID, subs)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.AccessBindings().ListSubjects(ctx, ab.ID)
	require.NoError(t, err)
	require.Len(t, got, 3)
	// Ordinal сохраняет порядок вставки → subjects[0] — пользователь.
	assert.Equal(t, domain.SubjectTypeUser, got[0].Type)
	assert.Equal(t, domain.SubjectID(uid), got[0].ID)
	assert.Equal(t, domain.SubjectTypeGroup, got[1].Type)
	assert.Equal(t, domain.SubjectTypeServiceAccount, got[2].Type)
}

func TestABSubjects_E30_CascadeOnBindingDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "absubcas")
	acc := seedAccount(t, ctx, repo, "acc-absubcas", uid)
	gid := seedGroupID(t, ctx, pool, string(acc.ID), "absubcas")
	ab := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: domain.SystemViewerRoleID, ResourceType: "account", ResourceID: string(acc.ID),
	})
	insertSubjects(t, ctx, repo, ab.ID, []domain.Subject{
		{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)},
		{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(gid)},
	})
	require.Equal(t, 2, countABSubjects(t, ctx, repo, ab.ID))

	// ФИЗИЧЕСКИ удаляем строку выдачи → CASCADE удаляет строки субъектов.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().Delete(ctx, ab.ID))
	require.NoError(t, w.Commit(ctx))

	assert.Equal(t, 0, countABSubjects(t, ctx, repo, ab.ID), "subject rows must CASCADE-drop with the binding")
}

func TestABSubjects_PerSubjectDelete_Independent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "absubdel")
	acc := seedAccount(t, ctx, repo, "acc-absubdel", uid)
	gid := seedGroupID(t, ctx, pool, string(acc.ID), "absubdel")
	ab := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: domain.SystemViewerRoleID, ResourceType: "account", ResourceID: string(acc.ID),
	})
	insertSubjects(t, ctx, repo, ab.ID, []domain.Subject{
		{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)},
		{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(gid)},
	})

	// Удаляем ТОЛЬКО субъекта-группу; субъект-пользователь сохраняется.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	deleted, err := w.AccessBindingsW().DeleteSubject(ctx, ab.ID, domain.Subject{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(gid)})
	require.NoError(t, err)
	require.True(t, deleted)
	require.NoError(t, w.Commit(ctx))

	got := func() []domain.Subject {
		rd, err := repo.Reader(ctx)
		require.NoError(t, err)
		defer func() { _ = rd.Rollback(ctx) }()
		s, err := rd.AccessBindings().ListSubjects(ctx, ab.ID)
		require.NoError(t, err)
		return s
	}()
	require.Len(t, got, 1)
	assert.Equal(t, domain.SubjectTypeUser, got[0].Type)

	// Идемпотентность: удаление отсутствующего субъекта возвращает false.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	d2, err := w2.AccessBindingsW().DeleteSubject(ctx, ab.ID, domain.Subject{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(gid)})
	require.NoError(t, err)
	assert.False(t, d2)
	require.NoError(t, w2.Commit(ctx))
}

func TestABSubjects_Batch_ListForBindings(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "absubbat")
	acc := seedAccount(t, ctx, repo, "acc-absubbat", uid)
	gid := seedGroupID(t, ctx, pool, string(acc.ID), "absubbat")
	said := seedSAID(t, ctx, pool, string(acc.ID), "absubbat")
	ab1 := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: domain.SystemViewerRoleID, ResourceType: "account", ResourceID: string(acc.ID),
	})
	// Пара второй выдачи — её единственный субъект: набор пишется вместе с
	// выдачей и начинается с пары, как у каждого пути записи продукта (kaname#902).
	ab2 := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeServiceAccount, SubjectID: domain.SubjectID(said),
		RoleID: domain.SystemAdminRoleID, ResourceType: "account", ResourceID: string(acc.ID),
	})
	insertSubjects(t, ctx, repo, ab1.ID, []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}, {Type: domain.SubjectTypeGroup, ID: domain.SubjectID(gid)}})
	insertSubjects(t, ctx, repo, ab2.ID, []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(said)}})

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	m, err := rd.AccessBindings().ListSubjectsForBindings(ctx, []domain.AccessBindingID{ab1.ID, ab2.ID})
	require.NoError(t, err)
	require.Len(t, m[ab1.ID], 2)
	require.Len(t, m[ab2.ID], 1)
	assert.Equal(t, domain.SubjectID(said), m[ab2.ID][0].ID)
}

func TestABSubjects_E33_ListByRole(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ablbr")
	acc := seedAccount(t, ctx, repo, "acc-ablbr", uid)
	gid := seedGroupID(t, ctx, pool, string(acc.ID), "ablbr")
	// Две выдачи ACTIVE с одной ролью; одна — с другой ролью.
	insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: domain.SystemViewerRoleID, ResourceType: "account", ResourceID: string(acc.ID),
	})
	insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeGroup, SubjectID: domain.SubjectID(gid),
		RoleID: domain.SystemViewerRoleID, ResourceType: "account", ResourceID: string(acc.ID),
	})
	insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: domain.SystemAdminRoleID, ResourceType: "account", ResourceID: string(acc.ID),
	})

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, _, err := rd.AccessBindings().ListByRole(ctx, domain.SystemViewerRoleID, repoab.ListByRoleFilter{PageSize: 50})
	require.NoError(t, err)
	require.Len(t, got, 2, "ListByRole returns exactly the bindings carrying the role")
	for _, b := range got {
		assert.Equal(t, domain.RoleID(domain.SystemViewerRoleID), b.RoleID)
	}
}

func TestABSubjects_RACE_ConcurrentInsertSameSubject_OneRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "absubrace")
	acc := seedAccount(t, ctx, repo, "acc-absubrace", uid)
	gid := seedGroupID(t, ctx, pool, string(acc.ID), "absubrace")
	ab := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(uid),
		RoleID: domain.SystemViewerRoleID, ResourceType: "account", ResourceID: string(acc.ID),
	})
	sub := domain.Subject{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(gid)}

	const n = 8
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			w, werr := repo.Writer(ctx)
			if werr != nil {
				return
			}
			if ierr := w.AccessBindingsW().InsertSubjects(ctx, ab.ID, []domain.Subject{sub}); ierr != nil {
				_ = w.Rollback(ctx)
				return
			}
			_ = w.Commit(ctx)
		}()
	}
	wg.Wait()

	// Ровно одна строка для (binding, group) — PK + ON CONFLICT DO NOTHING (запрет #10).
	got := func() []domain.Subject {
		rd, err := repo.Reader(ctx)
		require.NoError(t, err)
		defer func() { _ = rd.Rollback(ctx) }()
		s, err := rd.AccessBindings().ListSubjects(ctx, ab.ID)
		require.NoError(t, err)
		return s
	}()
	count := 0
	for _, s := range got {
		if s == sub {
			count++
		}
	}
	assert.Equal(t, 1, count, "concurrent identical InsertSubjects must converge to exactly one row")
}
