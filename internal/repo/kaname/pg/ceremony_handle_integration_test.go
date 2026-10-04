// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_handle_integration_test.go — Ф13-33 (I) против настоящего Postgres:
// рукоятка церемонии человека — своя таблица, 64 случайных байта на человека,
// уникальная, уходящая КАСКАДОМ вместе с человеком (приёмка
// `passwordless-login-with-access-key.md`, Р3 редакции 9).
//
// Каскад и есть механизм развязки, ради которого решение Р3 принято: снят
// человек — снято и значение, и ни одна наша строка больше не связывает его с
// тем, что лежит в чужом хранилище держателя.
package pg_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func chRandom(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

func chInsert(pool *pgxpool.Pool, user string, handle []byte) error {
	_, err := pool.Exec(context.Background(),
		`INSERT INTO user_ceremony_handles (user_id, handle) VALUES ($1, $2)`, user, handle)
	return err
}

func chCount(t *testing.T, pool *pgxpool.Pool, user string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_ceremony_handles WHERE user_id = $1`, user).Scan(&n))
	return n
}

// TestCeremonyHandleSchema_F13_33_OneRandomValuePerPersonGoneWithThePerson —
// форма значения держится схемой: ровно 64 байта, одно на человека, уникально;
// снятие человека уносит строку каскадом, соседа не трогая.
func TestCeremonyHandleSchema_F13_33_OneRandomValuePerPersonGoneWithThePerson(t *testing.T) {
	pool := akPool(t)
	people := lmPeople(t, pool, "ch33", 3)
	gone, kept := string(people[1]), string(people[2])

	handle := chRandom(t, 64)
	require.NoError(t, chInsert(pool, gone, handle), "законный близнец: 64 байта первому человеку")
	require.NoError(t, chInsert(pool, kept, chRandom(t, 64)), "законный близнец: свои 64 байта второму")

	requireViolation(t, chInsert(pool, gone, chRandom(t, 64)), "23505", "вторая рукоятка того же человека")
	requireViolation(t, chInsert(pool, string(people[0]), handle), "23505", "та же рукоятка у другого человека")
	requireViolation(t, chInsert(pool, string(people[0]), chRandom(t, 63)), "23514", "63 байта — не граница нормы")
	requireViolation(t, chInsert(pool, string(people[0]), chRandom(t, 65)), "23514", "65 байт — за границей нормы")
	requireViolation(t, chInsert(pool, "usr0000000000nobody", chRandom(t, 64)), "23503", "рукоятка без человека")

	var stored []byte
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT handle FROM user_ceremony_handles WHERE user_id = $1`, gone).Scan(&stored))
	require.True(t, bytes.Equal(handle, stored), "значение ложится как есть")

	_, err := pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, gone)
	require.NoError(t, err)
	require.Zero(t, chCount(t, pool, gone), "снятие человека уносит его рукоятку каскадом")
	require.Equal(t, 1, chCount(t, pool, kept), "рукоятка соседа на месте")
}

// requireViolation — отказ базы с названным SQLSTATE.
func requireViolation(t *testing.T, err error, sqlstate, what string) {
	t.Helper()
	require.Error(t, err, "%s: база обязана отказать", what)
	require.Contains(t, err.Error(), "SQLSTATE "+sqlstate, "%s: %v", what, err)
}

// TestAccessKeyRepo_F13_33_EnsureCeremonyHandleUnderConcurrency — одновременные
// заведения рукоятки одного человека сходятся к ОДНОМУ значению (исход держит
// ключ строки, а не сравнение прочитанного); повтор возвращает то же; у
// другого человека значение своё.
func TestAccessKeyRepo_F13_33_EnsureCeremonyHandleUnderConcurrency(t *testing.T) {
	pool := akPool(t)
	repo := pg.NewAccessKeyRepo(pool)
	people := lmPeople(t, pool, "ch34", 2)
	ctx := context.Background()

	ensure := func(user domain.UserID) ([]byte, error) {
		minted, err := domain.NewCeremonyHandle()
		if err != nil {
			return nil, err
		}
		w, err := repo.Writer(ctx)
		if err != nil {
			return nil, err
		}
		defer func() { _ = w.Rollback(ctx) }()
		got, err := w.EnsureCeremonyHandle(ctx, user, minted)
		if err != nil {
			return nil, err
		}
		return got.Bytes(), w.Commit(ctx)
	}

	const writers = 8
	var wg sync.WaitGroup
	results := make(chan []byte, writers)
	failures := make(chan error, writers)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got, err := ensure(people[0])
			if err != nil {
				failures <- err
				return
			}
			results <- got
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		require.NoError(t, err, "одновременное заведение не отказывает")
	}
	var first []byte
	n := 0
	for got := range results {
		n++
		require.Len(t, got, 64)
		if first == nil {
			first = got
			continue
		}
		require.True(t, bytes.Equal(first, got), "одновременные заведения разошлись")
	}
	require.Equal(t, writers, n)
	require.Equal(t, 1, chCount(t, pool, string(people[0])), "строка одна")

	again, err := ensure(people[0])
	require.NoError(t, err)
	require.True(t, bytes.Equal(first, again), "повтор возвращает заведённое, а не новое")
	other, err := ensure(people[1])
	require.NoError(t, err)
	require.False(t, bytes.Equal(first, other), "у другого человека рукоятка своя")
	require.False(t, bytes.Contains(first, []byte(people[0])), "рукоятка не несёт id человека")
}
