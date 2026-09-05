// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// minted_token_revocation_integration_test.go — хранилище отзывов токенов,
// отчеканенных платформой (F1-25, сторона хранилища).
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

func TestMintedTokenRevocation_RevokeIsMonotonicAndAbsenceMeansNoRevocation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.NewMintedTokenRevocationRepo(pool)

	// Отсутствие записи — ЗАКОННЫЙ ответ «отзыва нет», а не отказ: вызывающий,
	// получивший ошибку там, где отзыва просто нет, закрылся бы на каждом
	// запросе.
	_, found, err := repo.RevokedBefore(ctx, "sva-none")
	require.NoError(t, err)
	require.False(t, found)

	later := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	earlier := later.Add(-time.Hour)

	require.NoError(t, repo.Revoke(ctx, "sva-a", later, "ключ утёк", "usr-admin"))
	got, found, err := repo.RevokedBefore(ctx, "sva-a")
	require.NoError(t, err)
	require.True(t, found)
	require.WithinDuration(t, later, got, time.Second)

	// Повторный отзыв БОЛЕЕ РАННИМ моментом границу не отодвигает: иначе
	// повтор запроса вернул бы к жизни уже отозванное.
	require.NoError(t, repo.Revoke(ctx, "sva-a", earlier, "повтор", "usr-admin"))
	got, _, err = repo.RevokedBefore(ctx, "sva-a")
	require.NoError(t, err)
	require.WithinDuration(t, later, got, time.Second, "граница отзыва откатилась назад")

	// …а более поздним — отодвигает: положительный контроль, без которого
	// монотонность неотличима от «запись игнорируется вовсе».
	newer := later.Add(time.Hour)
	require.NoError(t, repo.Revoke(ctx, "sva-a", newer, "ещё раз", "usr-admin"))
	got, _, err = repo.RevokedBefore(ctx, "sva-a")
	require.NoError(t, err)
	require.WithinDuration(t, newer, got, time.Second)

	// Действие такой цены не бывает анонимным и беспредметным.
	require.Error(t, repo.Revoke(ctx, "sva-a", newer, "", ""))
	require.Error(t, repo.Revoke(ctx, "", newer, "", "usr-admin"))
}
