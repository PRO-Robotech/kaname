// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// family_cutoff_integration_test.go — ОТЗЫВ СЕМЕЙСТВА ДОЕЗЖАЕТ ДО ПРЕДЪЯВЛЕНИЯ
// (задача PRO-Robotech/kaname#396, K1; половина слоя доступа).
//
// Токен доступа сверяют по ключам издателя, без записи семейства: место,
// принимающее токен, спрашивает только отсечку. Поэтому писатель отзыва
// семейства обязан положить отсечку по КЛЮЧУ СЕМЕЙСТВА туда, где её читает
// правило отзыва, — иначе отметка `token_families.revoked_at` снимает токен
// обновления, а токен доступа того же семейства живёт до своего `exp`.
//
// Писателей отзыва семейства в дереве два, и судятся оба: отзыв по
// идентификатору (`RevokeFamily` — повтор кода, повтор токена обновления,
// порт отзыва церемонии) и отзыв семейств снятой сессии. Отсечка читается
// НАСТОЯЩИМ читателем (`MintedTokenRevocationRepo`) и судится НАСТОЯЩИМ
// правилом (`tokenrevocation.Revoked`) — сквозь обе половины одним прогоном.

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

// seedFamily заводит код и его семейство в посеве сцены.
func seedFamily(t *testing.T, ctx context.Context, repo *kanamepg.OAuthCeremonyRepo, scene domain.CeremonyContext, n int) {
	t.Helper()
	require.NoError(t, repo.IssueAuthorizationCode(ctx, kanamepg.NewAuthorizationCode{
		Context:             scene,
		CodeDigest:          ceremonyDigest(n),
		RedirectURI:         "https://app.example.test/cb",
		CodeChallenge:       ceremonyChallenge,
		CodeChallengeMethod: domain.PKCEMethodS256,
		TTL:                 time.Minute,
	}), "посев кода и семейства")
}

// familyTokenRefused — отверг бы место предъявления токен этого семейства,
// выпущенный в миг iat.
func familyTokenRefused(t *testing.T, ctx context.Context, r tokenrevocation.Reader, scene domain.CeremonyContext, iat time.Time) bool {
	t.Helper()
	revoked, err := tokenrevocation.Revoked(ctx, r, jwt.MapClaims{
		"sub": scene.UserID, "iat": float64(iat.Unix()),
		tokenrevocation.FamilyKeyClaim: scene.FamilyID,
	})
	require.NoError(t, err)
	return revoked
}

func TestIntegration_FamilyRevocationWritesTheFamilyCutoff(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx, pool := catalogPool(t)
	repo := kanamepg.NewOAuthCeremonyRepo(pool)
	cutoffs := kanamepg.NewMintedTokenRevocationRepo(pool)

	// Метки сцен разной длины: посев сессии выводит её свёртку из длины метки.
	revoked := ceremonyScene(t, ctx, pool, "fcxrev")
	twin := ceremonyScene(t, ctx, pool, "fcxtwn2")
	seedFamily(t, ctx, repo, revoked, 7101)
	seedFamily(t, ctx, repo, twin, 7102)

	// Близнец до всякого отзыва: токены обоих семейств принимаются.
	require.False(t, familyTokenRefused(t, ctx, cutoffs, revoked, time.Now()),
		"НЕ ВЫПОЛНИЛОСЬ: токен семейства отвергнут до отзыва")

	rows, err := repo.RevokeFamily(ctx, revoked.FamilyID, domain.FamilyRevokedByCodeReplay)
	require.NoError(t, err)
	require.EqualValues(t, 1, rows, "отзыв живого семейства не затронул его строки")

	_, found, err := cutoffs.RevokedBefore(ctx, revoked.FamilyID)
	require.NoError(t, err)
	require.True(t, found, "отзыв семейства не положил отсечку по ключу семейства")

	for _, iat := range []time.Time{time.Now().Add(-time.Hour), time.Now(), time.Now().Add(time.Hour)} {
		require.Truef(t, familyTokenRefused(t, ctx, cutoffs, revoked, iat),
			"токен отозванного семейства с iat=%s принят при предъявлении", iat.Format(time.RFC3339))
	}
	require.False(t, familyTokenRefused(t, ctx, cutoffs, twin, time.Now()),
		"близнец: токен неотозванного семейства отвергнут")

	// Повтор — ноль строк, законный исход; причина первого отзыва остаётся.
	rows, err = repo.RevokeFamily(ctx, revoked.FamilyID, domain.FamilyRevokedByRefreshReplay)
	require.NoError(t, err)
	require.EqualValues(t, 0, rows)
	var reason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT revoked_reason FROM kaname.token_families WHERE id = $1`, revoked.FamilyID).Scan(&reason))
	require.Equal(t, string(domain.FamilyRevokedByCodeReplay), reason, "повтор отзыва переписал первую причину")
}

// Отсечка пишется БЕЗУСЛОВНО: семейство, отмеченное отозванным без отсечки
// (писателем мимо двери), получает её на следующем отзыве, хотя отметка уже
// стоит и строк он не трогает.
func TestIntegration_FamilyCutoffIsWrittenEvenWhenTheMarkAlreadyStands(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx, pool := catalogPool(t)
	repo := kanamepg.NewOAuthCeremonyRepo(pool)
	cutoffs := kanamepg.NewMintedTokenRevocationRepo(pool)

	scene := ceremonyScene(t, ctx, pool, "fcxbar")
	seedFamily(t, ctx, repo, scene, 7201)
	_, err := pool.Exec(ctx, `
		UPDATE kaname.token_families
		   SET revoked_at = now(), revoked_reason = 'code-replay', live = false
		 WHERE id = $1`, scene.FamilyID)
	require.NoError(t, err, "посев: отметка отзыва мимо двери")
	_, found, err := cutoffs.RevokedBefore(ctx, scene.FamilyID)
	require.NoError(t, err)
	require.False(t, found, "НЕ ВЫПОЛНИЛОСЬ: отсечка стоит до отзыва дверью")

	rows, err := repo.RevokeFamily(ctx, scene.FamilyID, domain.FamilyRevokedByCodeReplay)
	require.NoError(t, err)
	require.EqualValues(t, 0, rows, "НЕ ВЫПОЛНИЛОСЬ: отметка не стояла")
	require.True(t, familyTokenRefused(t, ctx, cutoffs, scene, time.Now()),
		"отзыв уже отмеченного семейства не положил отсечку — токен доступа живёт до exp")
}

// Снятие сессии отзывает её семейства — и кладёт отсечку по ключу КАЖДОГО из
// них той же транзакцией.
func TestIntegration_SessionEndWritesTheCutoffOfEveryFamilyItRevokes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx, pool := catalogPool(t)
	repo := kanamepg.NewOAuthCeremonyRepo(pool)
	cutoffs := kanamepg.NewMintedTokenRevocationRepo(pool)

	scene := ceremonyScene(t, ctx, pool, "fcxses")
	twin := ceremonyScene(t, ctx, pool, "fcxst2x")
	seedFamily(t, ctx, repo, scene, 7301)
	seedFamily(t, ctx, repo, twin, 7302)
	require.False(t, familyTokenRefused(t, ctx, cutoffs, scene, time.Now()),
		"НЕ ВЫПОЛНИЛОСЬ: токен семейства отвергнут до снятия сессии")

	sessions := kanamepg.NewHumanSessionRepo(pool)
	w, err := sessions.ForceLogoutWriter(ctx, domain.UserID(scene.UserID), time.Second)
	require.NoError(t, err)
	ended, err := w.EndOtherSessions(ctx, domain.UserID(scene.UserID), "", time.Now().UTC(), domain.RevokeReasonLogout)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	require.Equal(t, 1, ended, "НЕ ВЫПОЛНИЛОСЬ: снята не одна сессия посева")

	var reason *string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT revoked_reason FROM kaname.token_families WHERE id = $1`, scene.FamilyID).Scan(&reason))
	require.NotNil(t, reason, "НЕ ВЫПОЛНИЛОСЬ: снятие сессии не отозвало семейство")

	require.True(t, familyTokenRefused(t, ctx, cutoffs, scene, time.Now().Add(time.Minute)),
		"семейство снятой сессии отозвано, а токен доступа его принимается при предъявлении")
	require.False(t, familyTokenRefused(t, ctx, cutoffs, twin, time.Now()),
		"близнец: семейство чужой сессии отвергнуто")
}
