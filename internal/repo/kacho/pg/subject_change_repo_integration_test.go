// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// subject_change_repo_integration_test.go — integration tests for SubjectChangeRepo.
// Verifies PollSubjectChanges returns ascending rows, honours limit, and
// reports headID correctly. Uses testcontainers Postgres (same pattern as
// sibling integration tests). Skipped under testing.Short().
//
// .3.
package pg_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/internal/pgtest"

	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// TestSubjectChangeRepo_PollSubjectChanges verifies:
// 1. Returns rows with id > since_id, ascending order.
// 2. Honours limit (requests 2 of 3 → receives 2).
// 3. headID = MAX(id) regardless of cursor position.
// 4. Continuing cursor returns the remaining row.
func TestSubjectChangeRepo_PollSubjectChanges(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}

	ctx := context.Background()
	dsn := kachopg.NewTestPostgres(t)

	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	repo := kachopg.NewSubjectChangeRepo(pool)

	// Посев идёт ТЕМ ЖЕ путём, каким пишет прод (`EmitSubjectChangeEvent`), а не
	// собственным INSERT'ом: фикстура не вправе быть снисходительнее продукта.
	// Прод кладёт в строку `payload` — тело, которое единственное и получает
	// декодер дренажа (его godoc это оговаривает), — а прежний посев называл
	// только `(subject_id, op)`. Такую строку прод не производит ни при каком
	// входе, и разобрать её нельзя: проба стерегла форму, которой в очереди не
	// бывает. Миграция 0097 закрепила это схемой, и посев через писателя
	// продукта означает, что расходиться с ним больше нечему.
	abRepo := kachopg.New(pool, nil)
	seed := func(subjectID, op string) int64 {
		t.Helper()
		w, err := abRepo.Writer(ctx)
		require.NoError(t, err)
		require.NoError(t, w.AccessBindingsW().EmitSubjectChangeEvent(ctx,
			access_binding.SubjectChangeEvent{SubjectID: subjectID, Op: op}))
		require.NoError(t, w.Commit(ctx))

		var id int64
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT id FROM kacho_iam.subject_change_outbox WHERE subject_id = $1`,
			subjectID).Scan(&id))
		return id
	}

	// Seed 3 rows.
	id1 := seed("usr_a", "binding_upsert")
	id2 := seed("usr_b", "binding_delete")
	id3 := seed("usr_c", "binding_upsert")

	// ── Poll 1: since=0, limit=2 → first 2 rows; headID=id3 ─────────────────
	changes, headID, err := repo.PollSubjectChanges(ctx, 0, 2)
	require.NoError(t, err)
	require.Len(t, changes, 2, "expected 2 changes (limit=2)")
	require.Equal(t, id1, changes[0].ID)
	require.Equal(t, "usr_a", changes[0].SubjectID)
	require.Equal(t, "binding_upsert", changes[0].Op)
	require.Equal(t, id2, changes[1].ID)
	require.Equal(t, "usr_b", changes[1].SubjectID)
	require.Equal(t, "binding_delete", changes[1].Op)
	require.Equal(t, id3, headID, "headID should be MAX(id)=id3")

	// ── Poll 2: since=id2, limit=256 → only third row; headID=id3 ────────────
	changes2, headID2, err := repo.PollSubjectChanges(ctx, id2, 256)
	require.NoError(t, err)
	require.Len(t, changes2, 1, "expected 1 remaining change")
	require.Equal(t, id3, changes2[0].ID)
	require.Equal(t, "usr_c", changes2[0].SubjectID)
	require.Equal(t, "binding_upsert", changes2[0].Op)
	require.Equal(t, id3, headID2)
}

// TestSubjectChangeRepo_PollCarriesTheSubjectType — тип субъекта доезжает до
// вызывающего (kacho#1022).
//
// # Что здесь проверяется и почему настоящей базой
//
// Тип субъекта колонкой не лежит — он живёт внутри `payload`, потому что полосе
// сплошного сброса кэша он был не нужен. Вызывающий, которому надо назвать
// субъекта целиком (`user:usrXXXX`), получал половину имени, и собрать вторую
// было неоткуда. Достаётся тип выражением по jsonb, а выражение по jsonb —
// именно то, что нельзя проверить подделкой: она вернёт то, что в неё положили.
//
// Посев идёт писателем продукта: фикстура не вправе быть снисходительнее.
func TestSubjectChangeRepo_PollCarriesTheSubjectType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}

	ctx := context.Background()
	dsn := kachopg.NewTestPostgres(t)

	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	// Закрытие с пределом: отложенное ждало бы соединение, которое проба,
	// упавшая внутри открытой транзакции, не вернёт никогда, — и унесло бы с
	// собой вердикт всего пакета.
	pgtest.ClosePoolAtEnd(t, pool)

	repo := kachopg.NewSubjectChangeRepo(pool)
	abRepo := kachopg.New(pool, nil)

	seed := func(evt access_binding.SubjectChangeEvent) {
		t.Helper()
		w, err := abRepo.Writer(ctx)
		require.NoError(t, err)
		require.NoError(t, w.AccessBindingsW().EmitSubjectChangeEvent(ctx, evt))
		require.NoError(t, w.Commit(ctx))
	}

	seed(access_binding.SubjectChangeEvent{
		SubjectID: "usr_typed", SubjectType: "user", Op: "binding_revoke",
	})
	seed(access_binding.SubjectChangeEvent{
		SubjectID: "sva_typed", SubjectType: "service_account", Op: "binding_upsert",
	})
	// Строка БЕЗ типа: так писали до того, как производители стали его
	// проставлять. Она обязана приехать с ПУСТЫМ типом, а не с выдуманным:
	// вызывающий отличит «не назван» от «назван» только так.
	seed(access_binding.SubjectChangeEvent{
		SubjectID: "usr_untyped", Op: "binding_upsert",
	})

	changes, _, err := repo.PollSubjectChanges(ctx, 0, 256)
	require.NoError(t, err)
	require.Len(t, changes, 3)

	got := make(map[string]string, len(changes))
	for _, c := range changes {
		got[c.SubjectID] = c.SubjectType
	}
	require.Equal(t, "user", got["usr_typed"])
	require.Equal(t, "service_account", got["sva_typed"])
	require.Equal(t, "", got["usr_untyped"],
		"строка без типа обязана приехать неназванной — иначе вызывающий соберёт субъекта, которого нет")
}
