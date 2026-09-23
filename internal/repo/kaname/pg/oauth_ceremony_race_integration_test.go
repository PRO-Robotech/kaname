// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// oauth_ceremony_race_integration_test.go — ОБМЕН КОДА и РОТАЦИЯ обновляющего
// токена под КОНКУРИРУЮЩИМИ ТРАНЗАКЦИЯМИ (задача PRO-Robotech/kaname#313).
//
// # Почему проба обязана быть именно такой
//
// Движок чужого поставщика читает код ВНЕ транзакции и гасит ВНУТРИ: две
// одновременные копии запроса обе читают код живым и обе доходят до
// безусловного `UPDATE`. По одному коду уходит ДВОЙНАЯ выдача, и — вот что
// делает дефект незаметным — положительный путь при этом зелёный. Ни одна
// последовательная проба такой реализации от верной не отличает.
//
// Поэтому здесь N горутин обменивают ОДИН код одновременно, и утверждается
// ЧИСЛО: выдач ровно одна, остальные — отказ ПОВТОРА, семейство отозвано.
// Та же проба ставится на ротацию.
//
// # Два плеча и состояние семейства У ПРОИГРАВШЕГО (kaname#316)
//
// Каждая проба гоняется в двух плечах — умолчание сессий продукта и
// `serializable` (`ceremonyShoulders`). Число «выдач ровно одна» зелено в обоих
// при ЛЮБОМ уровне; различает уровни другое — исход проигравшего и состояние
// семейства, которое он застаёт на возврате. Поэтому каждый проигравший читает
// семейство СРАЗУ по возврату своего отказа: «отзыв сработал» и «отзыв молча не
// произошёл» иначе неотличимы.
//
// # Чего эта проба НЕ различает
//
// Чередование здесь выбирает планировщик, а не проба: проигравший, пришедший
// ПОСЛЕ фиксации победителя, видит погашенный код при любом уровне. Доказанное
// ожидание на строке победителя строит `TestOAuthCeremonyLoserWaitingOnTheWinnerIsAReplay`
// — эта проба перебирает чередования, которых та не строит.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// ceremonyDigest — свёртка объявленной формы из счётчика.
func ceremonyDigest(n int) string { return fmt.Sprintf("%064x", n) }

// ceremonyPad — 17 знаков crockford-base32: формы `ic-…`, `tfm-…`, `cg-…`
// закрыты ограничениями схемы.
func ceremonyPad(tag string) string {
	out := tag
	for len(out) < 17 {
		out = "0" + out
	}
	return out[len(out)-17:]
}

const ceremonyChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

// ceremonyScene заводит человека, его аккаунт, сессию и интерактивного клиента.
// Фикстура ПОЛНАЯ намеренно: гонка на коде без семейства и сессии зеленела бы,
// не имея чего отвергать.
func ceremonyScene(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tag string) domain.CeremonyContext {
	t.Helper()

	user := "usr" + ceremonyPad(tag+"u")
	account := "acc" + ceremonyPad(tag)
	session := "hs-" + ceremonyPad(tag)
	client := "client-" + tag

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'ceremony', 'ACTIVE')`,
		user, account, "ext-"+tag, tag+"@example.invalid")
	require.NoError(t, err, "посев человека")
	_, err = tx.Exec(ctx, `INSERT INTO accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		account, "acc-"+tag, user)
	require.NoError(t, err, "посев аккаунта")
	require.NoError(t, tx.Commit(ctx))

	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.human_sessions
		       (id, user_id, bearer_digest, authenticated_at, last_presented_at, expires_at,
		        assurance_level, presented_methods)
		VALUES ($1, $2, $3, now(), now(), now() + interval '1 hour', '1', ARRAY['password'])`,
		session, user, ceremonyDigest(len(tag)*104729+7))
	require.NoError(t, err, "посев сессии")

	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.interactive_clients (id, name, redirect_uris, client_id)
		VALUES ($1, $2, ARRAY['https://app.example.test/cb'], $3)`,
		"ic-"+ceremonyPad(tag), "ic-"+tag, client)
	require.NoError(t, err, "посев клиента")

	return domain.CeremonyContext{
		FamilyID:  "tfm-" + ceremonyPad(tag),
		ClientID:  client,
		UserID:    user,
		SessionID: session,
		Scope:     []string{"openid", "profile"},
	}
}

// TestOAuthCodeExchangeUnderConcurrentTransactions — N транзакций обменивают
// ОДИН код. Выдача ровно одна; остальные — ПОВТОР, и каждый проигравший застаёт
// семейство отозванным. В обоих плечах.
func TestOAuthCodeExchangeUnderConcurrentTransactions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, shoulders := ceremonyShoulders(t)
	for _, sh := range shoulders {
		t.Run(sh.name, func(t *testing.T) {
			pool := sh.pool
			repo := kanamepg.NewOAuthCeremonyRepo(pool)
			scene := ceremonyScene(t, ctx, sh.seed, "cerxchg")

			code := ceremonyDigest(0xc0de)
			require.NoError(t, repo.IssueAuthorizationCode(ctx, kanamepg.NewAuthorizationCode{
				Context:             scene,
				CodeDigest:          code,
				RedirectURI:         "https://app.example.test/cb",
				CodeChallenge:       ceremonyChallenge,
				CodeChallengeMethod: domain.PKCEMethodS256,
				TTL:                 5 * time.Minute,
			}), "выдача кода — положительный контроль")

			const racers = 16
			issued := make([]bool, racers)
			replays := make([]bool, racers)
			var others, liveAtLoser []string
			var mu sync.Mutex

			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := 0; i < racers; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					c, cancel := context.WithTimeout(ctx, 30*time.Second)
					defer cancel()
					_, err := repo.ExchangeAuthorizationCode(c, kanamepg.CodeExchange{
						CodeDigest:         code,
						RefreshTokenDigest: ceremonyDigest(0x1000 + i),
						RefreshTokenTTL:    30 * 24 * time.Hour,
					})
					// Состояние семейства — У ЭТОГО проигравшего, сразу по возврату.
					var st familyState
					var stErr error
					if domain.IsAuthorizationCodeReplay(err) {
						st, stErr = readFamily(ctx, sh.seed, scene.FamilyID)
					}
					mu.Lock()
					defer mu.Unlock()
					switch {
					case err == nil:
						issued[i] = true
					case domain.IsAuthorizationCodeReplay(err):
						replays[i] = true
						if stErr != nil || !st.revoked {
							liveAtLoser = append(liveAtLoser, fmt.Sprintf("гонщик %d: %+v %v", i, st, stErr))
						}
					default:
						others = append(others, err.Error())
					}
				}(i)
			}
			close(start)
			wg.Wait()

			var issuedN, replayN int
			for i := 0; i < racers; i++ {
				if issued[i] {
					issuedN++
				}
				if replays[i] {
					replayN++
				}
			}
			t.Logf("плечо %s, перепись: гонщиков %d, выдач %d, отказов-повторов %d, иных исходов %d, "+
				"проигравших при живом семействе %d", sh.name, racers, issuedN, replayN, len(others), len(liveAtLoser))
			require.Equal(t, 1, issuedN,
				"выдач по одному коду обязано быть РОВНО одна: %d означает, что обмен не "+
					"одноинструкционен и под гонкой даёт двойную выдачу", issuedN)
			assert.Equal(t, racers, issuedN+replayN,
				"исходов ровно два, и третьего нет; иные исходы: %v", others)
			assert.Empty(t, others, "иной исход означает отказ не о том: %v", others)
			assert.Empty(t, liveAtLoser,
				"проигравший, получивший ПОВТОР, обязан застать семейство отозванным: %v", liveAtLoser)

			// Семейство ОТОЗВАНО: повтор кода — признак похищения, и по нему снимается
			// всё выданное.
			var reason *string
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT revoked_reason FROM kaname.token_families WHERE id = $1`, scene.FamilyID).Scan(&reason))
			require.NotNil(t, reason, "семейство обязано быть отозвано после повтора кода")
			assert.Equal(t, string(domain.FamilyRevokedByCodeReplay), *reason)

			// Транзакция выдачи ОТКАЧЕНА у всех проигравших: обновляющий токен в
			// семействе ровно один, и он принадлежит победителю.
			var tokens int
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT count(*) FROM kaname.refresh_tokens WHERE family_id = $1`, scene.FamilyID).Scan(&tokens))
			assert.Equal(t, 1, tokens,
				"обновляющих токенов в семействе %d при одной выдаче: транзакция проигравшего "+
					"не откачена", tokens)

			// Погашенный код ЖИВЁТ: «неактивен» и «не найден» обязаны различаться.
			var active bool
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT active FROM kaname.authorization_codes WHERE code_digest = $1`, code).Scan(&active))
			assert.False(t, active, "погашенный код обязан остаться строкой и быть неактивен")
		})
	}
}

// TestOAuthRefreshRotationUnderConcurrentTransactions — N транзакций ротируют
// ОДИН обновляющий токен. Ротация ровно одна; остальные — ПОВТОР, и каждый
// проигравший застаёт семейство отозванным. В обоих плечах.
func TestOAuthRefreshRotationUnderConcurrentTransactions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, shoulders := ceremonyShoulders(t)
	for _, sh := range shoulders {
		t.Run(sh.name, func(t *testing.T) {
			pool := sh.pool
			repo := kanamepg.NewOAuthCeremonyRepo(pool)
			scene := ceremonyScene(t, ctx, sh.seed, "cerrttn")

			code := ceremonyDigest(0xc0df)
			require.NoError(t, repo.IssueAuthorizationCode(ctx, kanamepg.NewAuthorizationCode{
				Context:             scene,
				CodeDigest:          code,
				RedirectURI:         "https://app.example.test/cb",
				CodeChallenge:       ceremonyChallenge,
				CodeChallengeMethod: domain.PKCEMethodS256,
				TTL:                 5 * time.Minute,
			}))
			first := ceremonyDigest(0x2000)
			_, err := repo.ExchangeAuthorizationCode(ctx, kanamepg.CodeExchange{
				CodeDigest:         code,
				RefreshTokenDigest: first,
				RefreshTokenTTL:    30 * 24 * time.Hour,
			})
			require.NoError(t, err, "обмен кода — положительный контроль")

			const racers = 16
			rotated := make([]bool, racers)
			replays := make([]bool, racers)
			var others, liveAtLoser []string
			var mu sync.Mutex

			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := 0; i < racers; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					c, cancel := context.WithTimeout(ctx, 30*time.Second)
					defer cancel()
					_, err := repo.RotateRefreshToken(c, kanamepg.RefreshRotation{
						PresentedDigest: first,
						SuccessorDigest: ceremonyDigest(0x3000 + i),
						TTL:             30 * 24 * time.Hour,
					})
					var st familyState
					var stErr error
					if domain.IsRefreshTokenReplay(err) {
						st, stErr = readFamily(ctx, sh.seed, scene.FamilyID)
					}
					mu.Lock()
					defer mu.Unlock()
					switch {
					case err == nil:
						rotated[i] = true
					case domain.IsRefreshTokenReplay(err):
						replays[i] = true
						if stErr != nil || !st.revoked {
							liveAtLoser = append(liveAtLoser, fmt.Sprintf("гонщик %d: %+v %v", i, st, stErr))
						}
					default:
						others = append(others, err.Error())
					}
				}(i)
			}
			close(start)
			wg.Wait()

			var rotatedN, replayN int
			for i := 0; i < racers; i++ {
				if rotated[i] {
					rotatedN++
				}
				if replays[i] {
					replayN++
				}
			}
			t.Logf("плечо %s, перепись: гонщиков %d, ротаций %d, отказов-повторов %d, иных исходов %d, "+
				"проигравших при живом семействе %d", sh.name, racers, rotatedN, replayN, len(others), len(liveAtLoser))
			require.Equal(t, 1, rotatedN,
				"ротаций обязана быть РОВНО одна: %d означает разветвление семейства", rotatedN)
			assert.Equal(t, racers, rotatedN+replayN, "иные исходы: %v", others)
			assert.Empty(t, others, "иной исход означает отказ не о том: %v", others)
			assert.Empty(t, liveAtLoser,
				"проигравший, получивший ПОВТОР, обязан застать семейство отозванным: %v", liveAtLoser)

			var reason *string
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT revoked_reason FROM kaname.token_families WHERE id = $1`, scene.FamilyID).Scan(&reason))
			require.NotNil(t, reason, "семейство обязано быть отозвано после повтора токена")
			assert.Equal(t, string(domain.FamilyRevokedByRefreshReplay), *reason)

			// Поколений ровно два: исходное и преемник победителя. Разветвление дало бы
			// больше, и ключ `refresh_tokens_generation_uk` его отверг бы.
			var generations int
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT count(*) FROM kaname.refresh_tokens WHERE family_id = $1`, scene.FamilyID).Scan(&generations))
			assert.Equal(t, 2, generations, "поколений в семействе %d, ожидалось 2", generations)

			// Отротированный токен ЖИВЁТ неактивным.
			var active bool
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT active FROM kaname.refresh_tokens WHERE token_digest = $1`, first).Scan(&active))
			assert.False(t, active, "отротированный токен обязан остаться строкой и быть неактивен")
		})
	}
}

// TestOAuthCeremonyDistinguishesUnknownFromInactive — «не найден» и «неактивен»
// РАЗЛИЧАЮТСЯ. Без этого различения обнаружение повтора невыразимо.
func TestOAuthCeremonyDistinguishesUnknownFromInactive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	repo := kanamepg.NewOAuthCeremonyRepo(pool)
	scene := ceremonyScene(t, ctx, pool, "cerdstn")

	_, err := repo.ExchangeAuthorizationCode(ctx, kanamepg.CodeExchange{
		CodeDigest:         ceremonyDigest(0xdead),
		RefreshTokenDigest: ceremonyDigest(0xbeef),
		RefreshTokenTTL:    time.Hour,
	})
	require.ErrorIs(t, err, domain.ErrAuthorizationCodeUnknown,
		"кода, которого не выдавали, обязан быть ОТДЕЛЬНЫЙ исход")
	require.False(t, domain.IsAuthorizationCodeReplay(err),
		"неизвестный код повтором не является: слив этих исходов снял бы отзыв семейства "+
			"с единственного признака похищения")

	code := ceremonyDigest(0xc0e0)
	require.NoError(t, repo.IssueAuthorizationCode(ctx, kanamepg.NewAuthorizationCode{
		Context:             scene,
		CodeDigest:          code,
		RedirectURI:         "https://app.example.test/cb",
		CodeChallenge:       ceremonyChallenge,
		CodeChallengeMethod: domain.PKCEMethodS256,
		TTL:                 5 * time.Minute,
	}))
	redeemed, err := repo.ExchangeAuthorizationCode(ctx, kanamepg.CodeExchange{
		CodeDigest:         code,
		RefreshTokenDigest: ceremonyDigest(0x4000),
		RefreshTokenTTL:    time.Hour,
	})
	require.NoError(t, err, "положительный контроль обмена")
	assert.Equal(t, "https://app.example.test/cb", redeemed.RedirectURI)
	assert.Equal(t, ceremonyChallenge, redeemed.CodeChallenge)
	assert.Equal(t, scene.Scope, redeemed.Context.Scope)

	_, err = repo.ExchangeAuthorizationCode(ctx, kanamepg.CodeExchange{
		CodeDigest:         code,
		RefreshTokenDigest: ceremonyDigest(0x4001),
		RefreshTokenTTL:    time.Hour,
	})
	require.ErrorIs(t, err, domain.ErrAuthorizationCodeReplayed,
		"второе предъявление ТОГО ЖЕ кода обязано быть ПОВТОРОМ, а не «неизвестен»")
}

// TestOAuthConsentIsUniqueByItsTriple — согласие ложится на тройку, и
// уникальность держит база: N одновременных согласий дают одну строку и ни
// одного отказа. В обоих плечах.
func TestOAuthConsentIsUniqueByItsTriple(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, shoulders := ceremonyShoulders(t)
	for _, sh := range shoulders {
		t.Run(sh.name, func(t *testing.T) {
			pool := sh.pool
			repo := kanamepg.NewOAuthCeremonyRepo(pool)
			scene := ceremonyScene(t, ctx, sh.seed, "cercnst")

			const racers = 16
			var wg sync.WaitGroup
			start := make(chan struct{})
			failures := make([]string, racers)
			for i := 0; i < racers; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					c, cancel := context.WithTimeout(ctx, 30*time.Second)
					defer cancel()
					// Перечень несёт ПОВТОР области намеренно: повтор — одна область, а
					// не две, и свести его обязан вызываемый, а не отказ хранилища.
					if err := repo.GrantConsent(c, scene.UserID, scene.ClientID,
						[]string{"openid", "profile", "openid"}); err != nil {
						failures[i] = err.Error()
					}
				}(i)
			}
			close(start)
			wg.Wait()

			var failed []string
			for _, f := range failures {
				if f != "" {
					failed = append(failed, f)
				}
			}
			assert.Empty(t, failed,
				"согласие идемпотентно: повторное согласие на ту же тройку — не отказ, а та же "+
					"строка. Отказы: %v", failed)

			granted, err := repo.ConsentedScopes(ctx, scene.UserID, scene.ClientID)
			require.NoError(t, err)
			t.Logf("плечо %s, перепись: гонщиков %d, отказов %d, областей согласия %d",
				sh.name, racers, len(failed), len(granted))
			assert.Equal(t, []string{"openid", "profile"}, granted,
				"областей согласия обязано быть ровно две: строка на тройку, а не на попытку")

			require.NoError(t, repo.WithdrawConsent(ctx, scene.UserID, scene.ClientID, "profile"))
			granted, err = repo.ConsentedScopes(ctx, scene.UserID, scene.ClientID)
			require.NoError(t, err)
			assert.Equal(t, []string{"openid"}, granted, "отозванная область обязана уйти из согласия")

			// «Согласия не было» и «согласие отозвано» РАЗЛИЧАЮТСЯ: строка на месте.
			var rows int
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT count(*) FROM kaname.consent_grants WHERE user_id = $1 AND client_id = $2`,
				scene.UserID, scene.ClientID).Scan(&rows))
			assert.Equal(t, 2, rows, "отозванное согласие обязано остаться строкой с отметкой, строк %d", rows)
		})
	}
}
