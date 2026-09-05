// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_system_grant_integration_test.go — СИСТЕМНАЯ ВЫДАЧА ЧИТАЕТСЯ И
// ОТЗЫВАЕТСЯ, И ОТЗЫВ ЗАКРЫВАЕТ ДОСТУП.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Встроенный доступ платформы переехал на поверхность выдач второй формой —
// выдачей ИМЕНОВАННОГО ОТНОШЕНИЯ. Форма считается состоявшейся только если верны
// оба конца:
//
//   - ЧИТАЕТСЯ: выдача возвращается чтением со своим отношением и признаком
//     системности, а роли у неё нет. Колонка роли стала допускать NULL — путь
//     чтения обязан это пережить, иначе перечисление выдач падает целиком, и
//     «встроенный доступ виден» превращается в «не виден вообще ничего».
//   - ОТЗЫВАЕТСЯ: снятие выдачи снимает ФАКТ. Отзыв повторяет РЕЕСТР выданного,
//     а не пересчёт по роли; у выдачи без роли пересчитывать нечего, поэтому
//     пустой реестр означал бы отзыв, который не отзывает: строка выдачи исчезла,
//     доступ остался. Ровно этот класс задача и закрывает.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЭТА ПРОБА НЕ ПОКРЫВАЕТ — НАЗВАНО, А НЕ УМОЛЧАНО
//
// Она идёт по ПУТИ ЗАПИСИ (реестр → снятие → журнал → факт), а не через права
// вызывающего: кто именно вправе отозвать системную выдачу — предмет стражи
// полномочий, у неё свои пробы, и здесь он не переспрашивается. Проверяется
// механизм, который заведён этой задачей и которого раньше не было.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// factExists — есть ли действующее основание доступа в том виде, в каком его
// читает вердикт.
func factExists(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID, relation, subject string) bool {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.relation_fact
		 WHERE object_type = $1 AND object_id = $2 AND relation = $3 AND subject = $4`,
		objType, objID, relation, subject).Scan(&n))
	return n > 0
}

// catalogGrantID — идентификатор системной выдачи публичного чтения справочников.
func catalogGrantID(t *testing.T, ctx context.Context, pool *pgxpool.Pool) domain.AccessBindingID {
	t.Helper()
	var id string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT id FROM kacho_iam.access_bindings
		 WHERE is_system AND granted_relation = 'viewer'
		   AND subject_type = 'user' AND subject_id = '*'
		   AND resource_type = 'cluster'`).Scan(&id),
		"системной выдачи публичного чтения нет — обратное заполнение не доехало")
	return domain.AccessBindingID(id)
}

// TestABSystem_R893_RelationFormIsReadable — путь чтения переживает выдачу без
// роли и возвращает обе новые координаты.
func TestABSystem_R893_RelationFormIsReadable(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)

	id := catalogGrantID(t, ctx, pool)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	got, err := rd.AccessBindings().Get(ctx, id)
	require.NoError(t, err, "выдача без роли обязана читаться — иначе перечисление падает целиком")

	assert.Equal(t, "viewer", got.GrantedRelation, "форма отношения обязана доезжать до чтения")
	assert.True(t, got.System, "признак системности обязан доезжать до чтения")
	assert.Equal(t, domain.RoleID(""), got.RoleID, "у формы отношения роли нет")
	assert.Equal(t, domain.SubjectID("*"), got.SubjectID, "подстановочный субъект обязан читаться как есть")
	assert.True(t, got.DeletionProtection, "системная выдача защищена от случайного снятия")

	// Перепись: сколько системных выдач вообще прочитано. «Ноль находок» обязано
	// быть отличимо от «ноль прочитанного».
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_bindings WHERE is_system`).Scan(&n))
	t.Logf("осмотрено: системных выдач %d", n)
	require.NotZero(t, n)
}

// TestABSystem_R893_RevokeClosesTheAccess — отзыв системной выдачи снимает факт;
// соседнее основание при этом остаётся (положительный контроль).
func TestABSystem_R893_RevokeClosesTheAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.New(pool, nil)

	id := catalogGrantID(t, ctx, pool)

	require.True(t, factExists(t, ctx, pool, "cluster", domain.ClusterSingletonID, "viewer", "user:*"),
		"предпосылка: публичное чтение справочников действует до отзыва")

	// Соседнее основание — то, что отзыв ОДНОЙ выдачи трогать не вправе.
	var neighbourSubject string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT subject FROM kacho_iam.relation_fact
		 WHERE object_type = 'cluster' AND relation = 'system_viewer'
		 ORDER BY subject LIMIT 1`).Scan(&neighbourSubject),
		"положительному контролю не на чем стоять — соседних оснований нет")

	// ── Реестр выданного ────────────────────────────────────────────────────
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	stored, err := rd.AccessBindings().SelectEmittedTuples(ctx, id)
	require.NoError(t, err)
	_ = rd.Rollback(ctx)
	require.Len(t, stored, 1,
		"у системной выдачи обязан быть реестр выданного: отзыв повторяет ЕГО, "+
			"а не пересчёт по роли — роли у этой формы нет, и пустой реестр дал бы "+
			"отзыв, который ничего не отзывает")
	assert.Equal(t, "user:*", stored[0].User)
	assert.Equal(t, "viewer", stored[0].Relation)
	assert.Equal(t, "cluster:"+domain.ClusterSingletonID, stored[0].Object)

	// ── Защита от удаления держит первое снятие ─────────────────────────────
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.AccessBindingsW().DeleteGuarded(ctx, id)
	_ = w.Rollback(ctx)
	require.Error(t, err, "системная выдача снимается только после снятия защиты")
	assert.ErrorIs(t, err, iamerr.ErrFailedPrecondition)

	require.True(t, factExists(t, ctx, pool, "cluster", domain.ClusterSingletonID, "viewer", "user:*"),
		"отказ снятия обязан оставить доступ на месте")

	// ── Штатный отзыв: снять защиту, снять выдачу, снять факт ───────────────
	w, err = repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().SetDeletionProtection(ctx, id, false)
	if err != nil {
		_ = w.Rollback(ctx)
		require.NoError(t, err)
	}
	if err := w.Commit(ctx); err != nil {
		_ = w.Rollback(ctx)
		require.NoError(t, err)
	}

	w, err = repo.Writer(ctx)
	require.NoError(t, err)
	failed := func(err error) bool {
		if err == nil {
			return false
		}
		_ = w.Rollback(ctx)
		assert.NoError(t, err)
		return true
	}
	if failed(w.AccessBindingsW().DeleteGuarded(ctx, id)) {
		t.FailNow()
	}
	if failed(w.AccessBindingsW().EmitRelationDelete(ctx, stored)) {
		t.FailNow()
	}
	if failed(w.Commit(ctx)) {
		t.FailNow()
	}

	assert.False(t, factExists(t, ctx, pool, "cluster", domain.ClusterSingletonID, "viewer", "user:*"),
		"отзыв обязан ЗАКРЫВАТЬ доступ: иначе выдача исчезла, а право осталось — "+
			"состояние, которое не видно ни на одной поверхности")

	assert.True(t, factExists(t, ctx, pool, "cluster", domain.ClusterSingletonID, "system_viewer", neighbourSubject),
		"положительный контроль: отзыв ОДНОЙ выдачи не трогает соседнее основание")
}
