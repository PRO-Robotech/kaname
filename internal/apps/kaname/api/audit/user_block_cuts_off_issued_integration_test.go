// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

// user_block_cuts_off_issued_integration_test.go — блокировка личности отсекает
// РАНЕЕ ВЫДАННОЕ, а не только новую выдачу (задача kaname#717).
//
// ПРЕДМЕТ. Блокировка — свойство личности целиком (`set_blocked.go`, шапка). До
// этой задачи она закрывала только двери ВЫДАЧИ: удостоверение, выданное до
// блокировки, предъявлением принималось до своего истечения. Край судит такое
// удостоверение по авторитету отзыва, а не по состоянию строки, поэтому
// наблюдаемый уровень здесь — тот же авторитет (`tokenrevocation.Revoked` над
// `MintedTokenRevocationRepo`), которым судит поверхность предъявления, и тот же
// читатель отсечки, которым судят полосы выдачи и сессия консоли
// (`UserTokenRevocationRepo.RevokedBefore`).
//
// БЛИЗНЕЦЫ, без которых отрицание ничего не значит:
//   - тот же токен ДО блокировки принимается — иначе «после отвергнут» зеленело
//     бы на правиле, отвергающем что угодно;
//   - токен ДРУГОГО человека того же аккаунта после блокировки принимается —
//     отсечка стоит на названной личности, а не на аккаунте;
//   - после снятия блокировки токен нового входа принимается — блокировка не
//     вечная отсечка принципала.

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

// blockProbeClaims — утверждения личного токена в той форме, в какой их видит
// поверхность предъявления: субъект — `users.id`, отметка выпуска — число,
// как после декодирования JSON настоящего токена.
func blockProbeClaims(uid domain.UserID, issued time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"sub": string(uid),
		"iat": float64(issued.Unix()),
	}
}

// confirmAddress — подтверждает текущий адрес названным личностям.
func confirmAddress(t *testing.T, ctx context.Context, env *testEnv, uids ...domain.UserID) {
	t.Helper()
	for _, uid := range uids {
		tag, err := env.pool.Exec(ctx,
			`UPDATE kaname.users SET email_verified_at = now() WHERE id = $1`, string(uid))
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected(), "личность фикстуры не найдена: %s", uid)
	}
}

// TestUserBlock_CutsOffCredentialsIssuedBeforeIt — выданное до блокировки
// после неё предъявлением не проходит; соседнее и выданное после снятия —
// проходит.
func TestUserBlock_CutsOffCredentialsIssuedBeforeIt(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	admin, accID := seedUserAccount(t, ctx, env.pool, "blkcut")
	target := seedExtraUser(t, ctx, env.pool, accID, "blkcuttarget")
	bystander := seedExtraUser(t, ctx, env.pool, accID, "blkcutother")
	// Адрес подтверждён: токен человека с неподтверждённым текущим адресом
	// поверхность отвергает и без всякой отсечки (`admission`), и такая фикстура
	// зеленила бы отрицание ниже на чужой причине.
	confirmAddress(t, ctx, env, target, bystander)

	authority := kanamepg.NewMintedTokenRevocationRepo(env.pool)
	cutoffs := kanamepg.NewUserTokenRevocationRepo(env.pool)

	issued := time.Now().UTC().Add(-time.Minute)
	targetTok := blockProbeClaims(target, issued)
	bystanderTok := blockProbeClaims(bystander, issued)

	// ── Близнец: до блокировки оба токена принимаются ───────────────────────
	revoked, err := tokenrevocation.Revoked(ctx, authority, targetTok)
	require.NoError(t, err)
	require.False(t, revoked, "токен отозван ДО блокировки — отрицание ниже ничего бы не доказало")
	revoked, err = tokenrevocation.Revoked(ctx, authority, bystanderTok)
	require.NoError(t, err)
	require.False(t, revoked, "токен соседа отозван ДО блокировки — фикстура негодна")

	// ── Блокировка ──────────────────────────────────────────────────────────
	block := userapp.NewBlockUserUseCase(env.repo, env.opsRepo)
	_, err = block.Execute(withPrincipal(admin), target)
	require.NoError(t, err)
	awaitWorkers(t)
	require.Equal(t, "BLOCKED", userInviteStatus(ctx, t, env, target))

	// ── Предмет: выданное до блокировки отсечено на предъявлении ────────────
	revoked, err = tokenrevocation.Revoked(ctx, authority, targetTok)
	require.NoError(t, err)
	require.True(t, revoked,
		"блокировка личности не отсекла ранее выданное: состояние записано, а "+
			"предъявление того же токена по-прежнему принимается")

	// И у читателя отсечки, которым судят выдача и сессия консоли.
	_, found, err := cutoffs.RevokedBefore(ctx, string(target))
	require.NoError(t, err)
	require.True(t, found, "отсечка личности не записана — сессия консоли блокировкой не задета")

	// ── Соседа отсечка не задевает ──────────────────────────────────────────
	revoked, err = tokenrevocation.Revoked(ctx, authority, bystanderTok)
	require.NoError(t, err)
	require.False(t, revoked, "блокировка одного человека отсекла токен другого")
	_, found, err = cutoffs.RevokedBefore(ctx, string(bystander))
	require.NoError(t, err)
	require.False(t, found, "отсечка легла на личность, которую никто не блокировал")

	// ── Снятие блокировки: новый вход даёт рабочий токен ────────────────────
	unblock := userapp.NewUnblockUserUseCase(env.repo, env.opsRepo)
	_, err = unblock.Execute(withPrincipal(admin), target)
	require.NoError(t, err)
	awaitWorkers(t)
	require.Equal(t, "ACTIVE", userInviteStatus(ctx, t, env, target))

	fresh := blockProbeClaims(target, time.Now().UTC().Add(time.Minute))
	revoked, err = tokenrevocation.Revoked(ctx, authority, fresh)
	require.NoError(t, err)
	require.False(t, revoked,
		"после снятия блокировки токен нового входа отвергнут — это вечная "+
			"отсечка принципала, а не снятие выданного")

	// Снятие блокировки выданное до неё не возвращает.
	revoked, err = tokenrevocation.Revoked(ctx, authority, targetTok)
	require.NoError(t, err)
	require.True(t, revoked, "снятие блокировки вернуло силу токену, выданному до неё")
}
