// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_token_sweep_integration_test.go — уборка записей выпуска токена
// доступа (kaname#319).
//
// Записей столько, сколько выпусков, и темп задаёт арендатор: каждый обмен
// кода и каждая ротация выпускают токен. Строку позволено снять не раньше
// момента, после которого ни одна поверхность предъявления не изменила бы из-за
// неё своего исхода: истёкший токен каждая отвергает по сроку с допуском
// ClockSkew, запас на расхождение источников часов — RemovalSlack.
//
// Утверждается ПАРА: строка за порогом снята, строка внутри допуска — нет.
// Проба «снялось что-то» зеленела бы на уборщике, снимающем всё.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// accessTokenSweeper — уборщик записей выпуска.
type accessTokenSweeper interface {
	SweepExpiredAccessTokens(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// TestAccessTokenSweepRemovesOnlyWhatNoSurfaceCanStillAccept — порог — функция
// предиката читателя.
func TestAccessTokenSweepRemovesOnlyWhatNoSurfaceCanStillAccept(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	repo := kanamepg.NewOAuthCeremonyRepo(pool)
	rec := recorderOf(t, repo)
	sweeper, ok := any(repo).(accessTokenSweeper)
	require.True(t, ok, "у записей выпуска нет уборщика: таблица растёт с каждым выпуском без предела")

	scene := ceremonyScene(t, ctx, pool, "swpat")
	require.NoError(t, repo.IssueAuthorizationCode(ctx, kanamepg.NewAuthorizationCode{
		Context:             scene,
		CodeDigest:          ceremonyDigest(0x5000),
		RedirectURI:         "https://app.example.test/cb",
		CodeChallenge:       ceremonyChallenge,
		CodeChallengeMethod: domain.PKCEMethodS256,
		TTL:                 time.Minute,
	}), "семейство сцены")

	grace := tokenpolicy.ClockSkew + tokenpolicy.RemovalSlack
	now := time.Now().UTC()
	jti := func(tag string) string { return "tok" + ceremonyPad(tag) }
	rows := map[string]time.Time{
		// За порогом: срок вышел раньше, чем now − grace.
		jti("p1"): now.Add(-grace - time.Hour),
		jti("p2"): now.Add(-grace - 2*time.Hour),
		// Внутри допуска: срок вышел, но поверхность ещё вправе принять токен.
		jti("w1"): now.Add(-time.Second),
		// Живой.
		jti("v1"): now.Add(time.Hour),
	}
	for id, exp := range rows {
		require.NoError(t, rec.RecordAccessToken(ctx, id, scene.FamilyID, exp.Add(-time.Minute), exp),
			"посев выпуска %s", id)
	}

	// Партия в одну строку: проход обязан сказать, что упёрся в партию.
	removed, full, err := sweeper.SweepExpiredAccessTokens(ctx, grace, 1)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed, "партия в одну строку снимает одну")
	require.True(t, full, "полная партия обязана быть названа полной")

	removed, full, err = sweeper.SweepExpiredAccessTokens(ctx, grace, 100)
	require.NoError(t, err)
	require.EqualValues(t, 1, removed, "за порогом оставалась одна строка")
	require.False(t, full)

	var left []string
	r, err := pool.Query(ctx, `SELECT jti FROM kaname.access_tokens ORDER BY jti`)
	require.NoError(t, err)
	for r.Next() {
		var jti string
		require.NoError(t, r.Scan(&jti))
		left = append(left, jti)
	}
	r.Close()
	require.NoError(t, r.Err())
	require.Equal(t, []string{jti("v1"), jti("w1")}, left,
		"остаться обязаны строка внутри допуска и живая — и только они")
}
