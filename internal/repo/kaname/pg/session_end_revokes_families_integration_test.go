// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// session_end_revokes_families_integration_test.go — СНЯТИЕ СЕССИИ ОТЗЫВАЕТ
// ВЫДАННОЕ В НЕЙ (задача kaname#313).
//
// Привязка семейства к сессии — внешний ключ с каскадом НА УДАЛЕНИИ строки, а
// снятие строку не удаляет: оно ставит отметку, а удаляет строку уборка спустя
// порог удержания. Без писателя причины «сессия окончена» обновляющий токен
// снятой сессии живёт и ротируется в свежие, а окно равно величине УДЕРЖАНИЯ —
// то есть настройке хранения, а не решению о безопасности.
//
// Проба судит НАБЛЮДАЕМОЕ состояние строк, а не вызов.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// TestIntegration_EndingSessionsRevokesTheirTokenFamilies — семейство снятой
// сессии отозвано с причиной «сессия окончена», а выданное по нему снято.
func TestIntegration_EndingSessionsRevokesTheirTokenFamilies(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	scene := ceremonyScene(t, ctx, pool, "sesend")
	ceremony := kanamepg.NewOAuthCeremonyRepo(pool)

	require.NoError(t, ceremony.IssueAuthorizationCode(ctx, kanamepg.NewAuthorizationCode{
		Context:             scene,
		CodeDigest:          ceremonyDigest(9001),
		RedirectURI:         "https://app.example.test/cb",
		CodeChallenge:       ceremonyChallenge,
		CodeChallengeMethod: domain.PKCEMethodS256,
		TTL:                 time.Minute,
	}), "посев кода и семейства")

	_, err = ceremony.ExchangeAuthorizationCode(ctx, kanamepg.CodeExchange{
		CodeDigest:         ceremonyDigest(9001),
		RefreshTokenDigest: ceremonyDigest(9002),
		RefreshTokenTTL:    time.Hour,
	})
	require.NoError(t, err, "обмен кода на обновляющий токен")

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: до снятия сессии семейство живо и токен активен.
	var revokedReason *string
	var refreshActive bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT revoked_reason FROM kaname.token_families WHERE id = $1`,
		scene.FamilyID).Scan(&revokedReason))
	require.Nil(t, revokedReason,
		"семейство отозвано ДО снятия сессии — отрицание ниже зеленело бы на пустом месте")
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT active FROM kaname.refresh_tokens WHERE token_digest = $1`,
		ceremonyDigest(9002)).Scan(&refreshActive))
	require.True(t, refreshActive, "обновляющий токен неактивен ДО снятия сессии")

	// ПРЕДМЕТ — снятие ВСЕХ записей личности той транзакцией, которой снимает
	// административный принудительный выход (kaname#340).
	sessions := kanamepg.NewHumanSessionRepo(pool)
	w, err := sessions.ForceLogoutWriter(ctx)
	require.NoError(t, err, "транзакция снятия")
	ended, err := w.EndOtherSessions(ctx, domain.UserID(scene.UserID), "",
		time.Now().UTC(), domain.RevokeReasonLogout)
	require.NoError(t, err, "снятие сессий")
	require.NoError(t, w.Commit(ctx), "фиксация снятия")
	require.Equal(t, 1, ended, "снята обязана быть ровно одна живая сессия посева")

	require.NoError(t, pool.QueryRow(ctx,
		`SELECT revoked_reason FROM kaname.token_families WHERE id = $1`,
		scene.FamilyID).Scan(&revokedReason))
	require.NotNil(t, revokedReason,
		"семейство снятой сессии НЕ отозвано: обновляющий токен живёт и ротируется "+
			"в свежие, а окно равно величине удержания строки, а не решению о доступе")
	require.Equal(t, string(domain.FamilyRevokedBySessionEnd), *revokedReason,
		"причина отзыва обязана называть СНЯТИЕ СЕССИИ: словарь закрыт, и запись "+
			"с чужой причиной неотличима в переписи от отзыва по другому поводу")

	require.NoError(t, pool.QueryRow(ctx,
		`SELECT active FROM kaname.refresh_tokens WHERE token_digest = $1`,
		ceremonyDigest(9002)).Scan(&refreshActive))
	require.False(t, refreshActive,
		"обновляющий токен снятой сессии остался активным — отзыв семейства не дошёл "+
			"до выданного по нему")
}
