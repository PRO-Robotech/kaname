// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// provider_mirror_integration_test.go — окно прежнего издателя считается по
// ТАБЛИЦЕ, и предикаты у таблиц разные.
//
// Утверждаются обе стороны каждого предиката: строка С зеркалом считается,
// строка БЕЗ зеркала — нет. Односторонняя проба («после посева зеркало
// насчитано») зеленела бы и на предикате `IS NOT NULL`, который у служебных
// учёток считает зеркалом каждый наш ключ.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iampg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestProviderMirrorRepo_CountsMirrorsPerTablePredicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	uid := mustSeedUser(t, ctx, pool, "mirrorwin")
	var accID string
	require.NoError(t, pool.QueryRow(ctx, `SELECT account_id FROM users WHERE id = $1`, string(uid)).Scan(&accID))
	svaID := ids.NewID(domain.PrefixServiceAccount)
	_, err = pool.Exec(ctx, `INSERT INTO service_accounts (id, account_id, name) VALUES ($1, $2, $3)`,
		svaID, accID, "mirror-window")
	require.NoError(t, err)

	repo := iampg.NewProviderMirrorRepo(pool)

	// Пустые таблицы — ноль, и это ноль по замеру, а не по умолчанию.
	got, err := repo.Count(ctx)
	require.NoError(t, err)
	require.Equal(t, iampg.ProviderMirrorRows{}, got, "на пустых таблицах окно закрыто")

	insertSA := func(id, mirror string) {
		t.Helper()
		_, e := pool.Exec(ctx, `
			INSERT INTO service_account_oauth_clients
			  (id, sva_id, hydra_client_id, description, created_by_user_id, public_key_pem, key_algorithm, credential_kind)
			VALUES ($1, $2, $3, '', $4, '', 'ES256', 'LEGACY')`, id, svaID, mirror, string(uid))
		require.NoError(t, e)
	}
	insertUser := func(id string, mirror *string) {
		t.Helper()
		_, e := pool.Exec(ctx, `
			INSERT INTO user_oauth_clients
			  (id, user_id, hydra_client_id, description, created_by_user_id, public_key_pem, key_algorithm, credential_kind)
			VALUES ($1, $2, $3, '', $4, '', 'ES256', 'LEGACY')`, id, string(uid), mirror, string(uid))
		require.NoError(t, e)
	}

	// Служебная учётка: строка ПЕРЕВЕДЁННОГО контура несёт своё имя (= id) — не зеркало.
	own := ids.NewID(domain.PrefixSAOAuthClient)
	insertSA(own, own)
	got, err = repo.Count(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(0), got.ServiceAccountKeys, "наше имя в колонке зеркалом не является")

	// Служебная учётка: строка ПРЕЖНЕГО выпуска — имя, назначенное прежним издателем.
	previous := ids.NewID(domain.PrefixSAOAuthClient)
	insertSA(previous, "prev-issuer-"+previous)
	got, err = repo.Count(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), got.ServiceAccountKeys, "имя, отличное от нашего, — зеркало")

	// Пользователь: переведённый контур зеркала не пишет (NULL) — не считается.
	insertUser(ids.NewID(domain.PrefixUserOAuthClient), nil)
	got, err = repo.Count(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(0), got.UserTokens, "пустое зеркало не считается")

	// Пользователь: строка прежнего выпуска — зеркало непусто.
	mirror := "prev-issuer-" + ids.NewID(domain.PrefixUserOAuthClient)
	insertUser(ids.NewID(domain.PrefixUserOAuthClient), &mirror)
	got, err = repo.Count(ctx)
	require.NoError(t, err)
	require.Equal(t, iampg.ProviderMirrorRows{ServiceAccountKeys: 1, UserTokens: 1}, got,
		"обе таблицы считаются своим предикатом и в одном снимке")
}
