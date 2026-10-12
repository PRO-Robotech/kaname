// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

// user_block_cuts_off_issued_integration_test.go — блокировка личности отсекает
// РАНЕЕ ВЫДАННОЕ, и снятие блокировки выданного до неё не возвращает (задача
// kaname#717).
//
// ПРЕДМЕТ. Блокировка — свойство личности целиком (`set_blocked.go`, шапка).
// Записей отсечки у личности две, и судят по ним разные читатели:
//
//   - запись по субъекту выпуска (`minted_token_revocations`) — авторитет отзыва
//     на пути запроса, которым край судит токены нашей чеканки;
//   - запись личности (`user_token_revocations`) — полосы выдачи (обновление
//     сессии, личный токен) и отсечка сессии консоли (`SessionCutoffOf`).
//
// Пока личность заблокирована, сессию и выдачу закрывает и само состояние
// строки. Разница видна ПОСЛЕ снятия блокировки: полномочие, возникшее до неё,
// не должно ожить. Проба судит это ТЕМИ ЖЕ функциями решения, что и читатели
// (`tokenrevocation.Revoked`, `revocationpolicy.AtIssuance`,
// `revocationpolicy.Forbids`), а не своим пересказом правила.
//
// БЛИЗНЕЦЫ, без которых отрицание ничего не значит:
//   - то же полномочие ДО блокировки принимается — иначе «после отвергнуто»
//     зеленело бы на правиле, отвергающем что угодно;
//   - полномочие ДРУГОГО человека того же аккаунта после блокировки
//     принимается — отсечка стоит на названной личности, а не на аккаунте;
//   - после снятия блокировки новый вход даёт рабочее полномочие — блокировка
//     не вечная отсечка принципала.

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/service"
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

// blockProbe — три вопроса о полномочии, возникшем в момент at, по трём
// читателям отсечки.
type blockProbe struct {
	authority *kanamepg.MintedTokenRevocationRepo
	issuance  *kanamepg.SessionRevocationsAdapter
	console   *kanamepg.UserTokenRevocationRepo
}

// tokenRevoked — отвергает ли авторитет отзыва токен, выпущенный в at.
func (p blockProbe) tokenRevoked(t *testing.T, ctx context.Context, uid domain.UserID, at time.Time) bool {
	t.Helper()
	revoked, err := tokenrevocation.Revoked(ctx, p.authority, blockProbeClaims(uid, at))
	require.NoError(t, err)
	return revoked
}

// issuanceVerdict — вердикт выдачи для сессии, аутентифицированной в at.
func (p blockProbe) issuanceVerdict(t *testing.T, ctx context.Context, uid domain.UserID, at time.Time) revocationpolicy.Verdict {
	t.Helper()
	v, _, err := revocationpolicy.AtIssuance(ctx, p.issuance,
		service.ResolvedPrincipal{Kind: service.PrincipalUser, UserID: string(uid)}, at)
	require.NoError(t, err)
	return v
}

// consoleSessionCut — отсечена ли сессия консоли, аутентифицированная в at:
// край сравнивает ответ `SessionCutoffOf` (этот читатель) с моментом сессии.
func (p blockProbe) consoleSessionCut(t *testing.T, ctx context.Context, uid domain.UserID, at time.Time) bool {
	t.Helper()
	cutoff, found, err := p.console.RevokedBefore(ctx, string(uid))
	require.NoError(t, err)
	return found && revocationpolicy.Forbids(cutoff, at)
}

// TestUserBlock_CutsOffCredentialsIssuedBeforeIt — выданное до блокировки
// после неё не проходит ни у одного читателя отсечки и после снятия блокировки
// не оживает; соседнее и выданное после снятия — проходит.
func TestUserBlock_CutsOffCredentialsIssuedBeforeIt(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	admin, accID := seedUserAccount(t, ctx, env.pool, "blkcut")
	target := seedExtraUser(t, ctx, env.pool, accID, "blkcuttarget")
	bystander := seedExtraUser(t, ctx, env.pool, accID, "blkcutother")
	// Адрес подтверждён: полномочие человека с неподтверждённым текущим адресом
	// отвергается и без всякой отсечки (`admission`), и такая фикстура зеленила
	// бы отрицание ниже на чужой причине. Её поймал близнец.
	confirmAddress(t, ctx, env, target, bystander)

	p := blockProbe{
		authority: kanamepg.NewMintedTokenRevocationRepo(env.pool),
		issuance:  kanamepg.NewSessionRevocationsAdapter(env.pool),
		console:   kanamepg.NewUserTokenRevocationRepo(env.pool),
	}
	before := time.Now().UTC().Add(-time.Minute)

	// ── Близнец: до блокировки всё принимается ──────────────────────────────
	for _, uid := range []domain.UserID{target, bystander} {
		require.False(t, p.tokenRevoked(t, ctx, uid, before), "токен отозван ДО блокировки — фикстура негодна")
		require.Equal(t, revocationpolicy.Allowed, p.issuanceVerdict(t, ctx, uid, before),
			"выдача отказывает ДО блокировки — фикстура негодна")
		require.False(t, p.consoleSessionCut(t, ctx, uid, before), "сессия отсечена ДО блокировки — фикстура негодна")
	}

	// ── Блокировка ──────────────────────────────────────────────────────────
	block := userapp.NewBlockUserUseCase(env.repo, env.opsRepo)
	_, err := block.Execute(withPrincipal(admin), target)
	require.NoError(t, err)
	awaitWorkers(t)
	require.Equal(t, "BLOCKED", userInviteStatus(ctx, t, env, target))

	// ── Предмет: выданное до блокировки отсечено у каждого читателя ─────────
	require.True(t, p.tokenRevoked(t, ctx, target, before),
		"блокировка не отсекла ранее выданный токен: предъявление его принимается")
	require.Equal(t, revocationpolicy.Revoked, p.issuanceVerdict(t, ctx, target, before),
		"блокировка не отсекла сессию, аутентифицированную до неё, у полосы выдачи")
	require.True(t, p.consoleSessionCut(t, ctx, target, before),
		"блокировка не отсекла сессию консоли, аутентифицированную до неё")

	// ── Соседа отсечка не задевает ──────────────────────────────────────────
	require.False(t, p.tokenRevoked(t, ctx, bystander, before), "блокировка одного человека отсекла токен другого")
	require.Equal(t, revocationpolicy.Allowed, p.issuanceVerdict(t, ctx, bystander, before),
		"блокировка одного человека отсекла выдачу другому")
	require.False(t, p.consoleSessionCut(t, ctx, bystander, before),
		"блокировка одного человека отсекла сессию другого")

	// ── Снятие блокировки ───────────────────────────────────────────────────
	unblock := userapp.NewUnblockUserUseCase(env.repo, env.opsRepo)
	_, err = unblock.Execute(withPrincipal(admin), target)
	require.NoError(t, err)
	awaitWorkers(t)
	require.Equal(t, "ACTIVE", userInviteStatus(ctx, t, env, target))

	// Выданное до блокировки не оживает ни у одного читателя.
	require.True(t, p.tokenRevoked(t, ctx, target, before),
		"снятие блокировки вернуло силу токену, выданному до неё")
	require.Equal(t, revocationpolicy.Revoked, p.issuanceVerdict(t, ctx, target, before),
		"снятие блокировки вернуло выдачу сессии, аутентифицированной до неё")
	require.True(t, p.consoleSessionCut(t, ctx, target, before),
		"снятие блокировки вернуло силу сессии консоли, аутентифицированной до неё")

	// Новый вход после снятия даёт рабочее полномочие.
	after := time.Now().UTC().Add(time.Minute)
	require.False(t, p.tokenRevoked(t, ctx, target, after),
		"после снятия блокировки токен нового входа отвергнут — это вечная отсечка, а не снятие выданного")
	require.Equal(t, revocationpolicy.Allowed, p.issuanceVerdict(t, ctx, target, after),
		"после снятия блокировки выдача новому входу отвергнута")
	require.False(t, p.consoleSessionCut(t, ctx, target, after),
		"после снятия блокировки сессия нового входа отсечена")
}
