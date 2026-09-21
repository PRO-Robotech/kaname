// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_key_irreversible_facts_integration_test.go — два факта строки ключа,
// которые нельзя записать потом, против НАСТОЯЩЕГО Postgres.
//
// # Что утверждают пробы этого файла
//
//   - обнаружимость доезжает до строки всеми тремя состояниями и читается
//     обратно ПОСТРОЧНО; состояние вне словаря отвергает ограничение схемы, а
//     не проверка в коде;
//   - вставка, не назвавшая обнаружимость, отказывает: умолчания у колонки нет,
//     и «забыли заполнить» не превращается молча в одно из трёх состояний;
//   - рукоятка человека заводится ОДНИМ оператором: первый вызов чеканит,
//     последующие возвращают то же значение, и под конкуренцией все вызывающие
//     получают ОДНО значение — исход производит ключ строки, а не сравнение
//     прочитанного (ban #10);
//   - рукоятка уникальна по службе — ключом уникальности, а не надеждой на
//     разрядность;
//   - снятие человека уносит рукоятку каскадом: это и есть механизм развязки,
//     ради которого рукоятка перестала быть платформенным `id`.
package pg_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// akEnsureHandle — рукоятка человека своей транзакцией, как её берут глаголы.
func akEnsureHandle(t *testing.T, repo *pg.AccessKeyRepo, user domain.UserID) domain.CeremonyHandle {
	t.Helper()
	ctx := context.Background()
	minted, err := domain.NewCeremonyHandle()
	require.NoError(t, err)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	got, err := w.EnsureCeremonyHandle(ctx, user, minted)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return got
}

// TestAccessKeyRepo_DiscoverabilityRoundTripsPerRow — три состояния доезжают до
// строки и читаются обратно; четвёртое отвергает схема.
func TestAccessKeyRepo_DiscoverabilityRoundTripsPerRow(t *testing.T) {
	pool := akPool(t)
	akCeiling(t, pool, 10)
	repo := pg.NewAccessKeyRepo(pool)
	people := lmPeople(t, pool, "akdisc", 1)
	ctx := context.Background()

	stored := map[domain.AccessKeyID]domain.AccessKeyDiscoverability{}
	for i, d := range domain.AccessKeyDiscoverabilities() {
		k := akKey(people[0], "disc-"+string(d))
		k.Discoverability = d
		got := akInsert(t, repo, k)
		require.Equal(t, d, got.Discoverability, "состояние %q не доехало до строки", d)
		stored[got.ID] = d
		require.Len(t, stored, i+1)
	}
	require.Len(t, domain.AccessKeyDiscoverabilities(), 3, "словарь закрыт тремя состояниями")

	// Перечитывание: признак читается ПОСТРОЧНО, а не одним значением на всех.
	keys, _, err := repo.KeysOf(ctx, people[0], "", 100)
	require.NoError(t, err)
	require.Len(t, keys, 3)
	seen := map[domain.AccessKeyDiscoverability]int{}
	for _, k := range keys {
		require.Equal(t, stored[k.ID], k.Discoverability, "строка %s вернула чужое состояние", k.ID)
		seen[k.Discoverability]++
	}
	require.Len(t, seen, 3, "три строки — три разных состояния: %v", seen)

	// Состояние вне словаря отвергает ОГРАНИЧЕНИЕ схемы: домен до базы такое не
	// пропустил бы, поэтому спрашиваем базу напрямую.
	_, err = pool.Exec(ctx, `
		INSERT INTO user_access_keys (id, user_id, credential_id, public_key, algorithm, sign_count, discoverability, name, description, created_at)
		VALUES ('ak-00000000000000bad', $1, $2, '\xa50102'::bytea, -7, 0, 'maybe', 'ak-00000000000000bad', '', now())`,
		string(people[0]), []byte("outside-the-vocabulary-32-bytes!"))
	require.Error(t, err, "состояние вне словаря принято базой")
	require.Contains(t, err.Error(), "user_access_keys_discoverability_check")

	// Вставка БЕЗ колонки — отказ: умолчание снято вместе с обратным
	// заполнением, и «забыли» не становится молча одним из трёх состояний.
	_, err = pool.Exec(ctx, `
		INSERT INTO user_access_keys (id, user_id, credential_id, public_key, algorithm, sign_count, name, description, created_at)
		VALUES ('ak-0000000000000nodc', $1, $2, '\xa50102'::bytea, -7, 0, 'ak-0000000000000nodc', '', now())`,
		string(people[0]), []byte("no-discoverability-named-32-byte"))
	require.Error(t, err, "строка без названного состояния принята базой")
	require.Contains(t, err.Error(), "discoverability")
}

// TestAccessKeyRepo_CeremonyHandleIsMintedOnceAndNeverChanges — рукоятка
// человека: первый вызов чеканит, следующие возвращают ТО ЖЕ; конкуренция даёт
// одно значение; у разных людей значения разные.
func TestAccessKeyRepo_CeremonyHandleIsMintedOnceAndNeverChanges(t *testing.T) {
	pool := akPool(t)
	repo := pg.NewAccessKeyRepo(pool)
	people := lmPeople(t, pool, "akhndl", 2)

	first := akEnsureHandle(t, repo, people[0])
	require.NoError(t, first.Validate())
	require.NotEqual(t, []byte(people[0]), []byte(first), "рукоятка — не платформенный id")

	second := akEnsureHandle(t, repo, people[0])
	require.Equal(t, []byte(first), []byte(second), "повторный вызов сменил рукоятку — ключи разошлись бы с аутентификатором")

	other := akEnsureHandle(t, repo, people[1])
	require.NotEqual(t, []byte(first), []byte(other), "у разных людей рукоятки разные")

	// Конкуренция: исход производит ключ строки, а не сравнение прочитанного.
	third := lmPeople(t, pool, "akhrace", 1)[0]
	const writers = 6
	var wg sync.WaitGroup
	got := make(chan string, writers)
	start := make(chan struct{})
	ctx := context.Background()
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			minted, err := domain.NewCeremonyHandle()
			if err != nil {
				return
			}
			w, err := repo.Writer(ctx)
			if err != nil {
				return
			}
			defer func() { _ = w.Rollback(ctx) }()
			h, err := w.EnsureCeremonyHandle(ctx, third, minted)
			if err != nil {
				return
			}
			if err := w.Commit(ctx); err != nil {
				return
			}
			got <- string(h)
		}()
	}
	close(start)
	wg.Wait()
	close(got)
	values := map[string]int{}
	for v := range got {
		values[v]++
	}
	require.Len(t, values, 1, "конкуренция дала %d разных рукояток — одна строка на человека не держится", len(values))
	var winners int
	for _, n := range values {
		winners = n
	}
	t.Logf("перепись: писателей %d · доложились %d · разных рукояток %d", writers, winners, len(values))
	require.NotZero(t, winners, "ни один писатель не доложился — конкуренция не исполнялась")
}

// TestAccessKeyRepo_RemovingThePersonUnlinksTheHandle — развязка: снятие
// человека уносит рукоятку каскадом, и значение, оставшееся в чужом
// аутентификаторе, больше не называет ничего нашего.
func TestAccessKeyRepo_RemovingThePersonUnlinksTheHandle(t *testing.T) {
	pool := akPool(t)
	repo := pg.NewAccessKeyRepo(pool)
	people := lmPeople(t, pool, "akunlnk", 2)
	ctx := context.Background()

	kept := akEnsureHandle(t, repo, people[0])
	gone := akEnsureHandle(t, repo, people[1])
	require.NotEqual(t, []byte(kept), []byte(gone))

	var before int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM user_ceremony_handles WHERE user_id = ANY($1)`,
		[]string{string(people[0]), string(people[1])}).Scan(&before))
	require.Equal(t, 2, before, "предпосылка пробы: обе рукоятки заведены")

	_, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, string(people[1]))
	require.NoError(t, err)

	var left int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM user_ceremony_handles WHERE user_id = $1`,
		string(people[1])).Scan(&left))
	require.Zero(t, left, "рукоятка пережила человека — развязки нет")

	// Положительный близнец: чужая рукоятка на месте — каскад снял ровно свою.
	var stillThere []byte
	require.NoError(t, pool.QueryRow(ctx, `SELECT handle FROM user_ceremony_handles WHERE user_id = $1`,
		string(people[0])).Scan(&stillThere))
	require.Equal(t, []byte(kept), stillThere)
}

// TestAccessKeyRepo_CeremonyHandleFormIsHeldByTheSchema — длину и уникальность
// рукоятки держит СХЕМА: негодная длина и повтор значения отвергаются
// ограничениями, а не проверкой перед записью.
func TestAccessKeyRepo_CeremonyHandleFormIsHeldByTheSchema(t *testing.T) {
	pool := akPool(t)
	people := lmPeople(t, pool, "akhform", 2)
	ctx := context.Background()

	good, err := domain.NewCeremonyHandle()
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO user_ceremony_handles (user_id, handle) VALUES ($1, $2)`,
		string(people[0]), []byte(good))
	require.NoError(t, err, "законный близнец: рукоятка длины нормы принимается")

	_, err = pool.Exec(ctx, `INSERT INTO user_ceremony_handles (user_id, handle) VALUES ($1, $2)`,
		string(people[1]), []byte("too-short"))
	require.Error(t, err, "рукоятка негодной длины принята базой")
	require.Contains(t, err.Error(), "user_ceremony_handles_handle_check")

	_, err = pool.Exec(ctx, `INSERT INTO user_ceremony_handles (user_id, handle) VALUES ($1, $2)`,
		string(people[1]), []byte(good))
	require.Error(t, err, "две рукоятки с одним значением приняты базой")
	require.Contains(t, err.Error(), "user_ceremony_handles_handle_key")
}
