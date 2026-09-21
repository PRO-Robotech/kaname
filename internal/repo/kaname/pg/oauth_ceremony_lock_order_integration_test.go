// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// oauth_ceremony_lock_order_integration_test.go — ОТЗЫВ СЕМЕЙСТВА ПРОТИВ ВЫДАЧИ
// по нему же: ПОРЯДОК ЗАМКОВ (задача PRO-Robotech/kaname#313).
//
// # Что ловит эта проба и чего не ловит соседняя
//
// `oauth_ceremony_race_integration_test.go` ставит N гонщиков на ОДИН предмет —
// один код, один токен — и утверждает, что выдача уходит ровно одна. Обе
// стороны там идут ОДНИМ путём, поэтому порядок взятия замков у них одинаковый,
// и цикла между ними не бывает ни при какой реализации. Та проба зелена и на
// форме, которую ловит эта.
//
// Здесь сталкиваются ДВА РАЗНЫХ пути, и различаются они именно порядком:
//
//   - выдача шла «ребёнок → родитель»: условный `UPDATE` предъявленной строки
//     брал замок на ребёнке, и лишь вставка преемника бралась за семейство;
//   - отзыв идёт «родитель → дети»: ключевое обновление семейства, за которым
//     `ON UPDATE CASCADE` идёт за замками всех его строк.
//
// Встречные порядки дают цикл, и движок снимает одного. Снимал он ОТЗЫВ: 6
// прогонов из 6 на postgres:16-alpine жертвой становилась транзакция отзыва —
// семейство оставалось ЖИВЫМ, а выданный по нему токен АКТИВНЫМ.
//
// # Почему это не «шумная проба», которую лечат повтором
//
// Проигрывает здесь не запрос арендатора, а КОНТРОЛЬ БЕЗОПАСНОСТИ, и повтора у
// него нет: признак повторяемости до клиента доезжает, но повторить обязан
// клиент, а похититель не повторяет. Поэтому утверждение пробы — не «отзыв
// когда-нибудь пройдёт», а «взаимной блокировки не возникает НИ РАЗУ», и
// исходом каждого прогона она судит КОНЕЧНОЕ СОСТОЯНИЕ: семейство отозвано,
// живого выданного не осталось.
//
// # Почему прогонов несколько
//
// Взаимная блокировка — свойство расписания, а не входа: один зелёный прогон
// равно совместим с её наличием. Прогоны идут с РАЗНЫМ порядком стартов, чтобы
// ни одна из трёх сцен — выдача первой, отзыв первым, одновременно — не
// осталась неосмотренной.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// lockOrderRuns — число прогонов на каждую сцену старта. Три сцены по четыре
// прогона: двенадцать столкновений, и каждое печатает свой исход.
const lockOrderRuns = 4

// lockOrderScene — СВОЯ фикстура, а не `ceremonyScene`, и это не дублирование
// без причины: соседний помощник выводит свёртку носителя сессии из ДЛИНЫ метки
// (`ceremonyDigest(len(tag)*104729+7)`), поэтому двенадцать сцен с метками
// одинаковой длины столкнулись бы на `human_sessions_bearer_digest_uniq` и
// проба покраснела бы на посеве, ничего не сказав о своём предмете.
//
// Здесь всё уникальное выводится из НОМЕРА сцены, и коллизии нет by
// construction. Метка — crockford-base32 (`k`, `n`, цифры): формы `ic-…` и
// `tfm-…` закрыты ограничениями схемы, а `l`, `o`, `u` в алфавит не входят.
func lockOrderScene(t *testing.T, ctx context.Context, pool *pgxpool.Pool, n int) domain.CeremonyContext {
	t.Helper()

	tag := fmt.Sprintf("kn%05d", n)
	user := "usr" + ceremonyPad(tag+"a")
	account := "acc" + ceremonyPad(tag)
	session := "hs-" + ceremonyPad(tag)
	client := "client-" + tag

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'lock-order', 'ACTIVE')`,
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
		session, user, ceremonyDigest(0x500000+n))
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

// TestOAuthFamilyRevocationDoesNotDeadlockWithIssuance — отзыв семейства и
// обмен кода того же семейства, идущие одновременно, НЕ дают взаимной
// блокировки, и контроль безопасности не становится её жертвой.
func TestOAuthFamilyRevocationDoesNotDeadlockWithIssuance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	repo := kanamepg.NewOAuthCeremonyRepo(pool)

	// Сцены различаются РОВНО ОДНИМ фактом — кто стартует раньше.
	scenes := []struct {
		name         string
		exchangeLate time.Duration
		revokeLate   time.Duration
	}{
		{"обмен первым", 0, 40 * time.Millisecond},
		{"отзыв первым", 40 * time.Millisecond, 0},
		{"одновременно", 0, 0},
	}

	var deadlocks int
	var seq int
	for si, scene := range scenes {
		for run := 1; run <= lockOrderRuns; run++ {
			seq++
			base := lockOrderScene(t, ctx, pool, seq)

			code := ceremonyDigest(0x100000 + si*100 + run)
			require.NoError(t, repo.IssueAuthorizationCode(ctx, kanamepg.NewAuthorizationCode{
				Context:             base,
				CodeDigest:          code,
				RedirectURI:         "https://app.example.test/cb",
				CodeChallenge:       ceremonyChallenge,
				CodeChallengeMethod: "S256",
				TTL:                 5 * time.Minute,
			}), "посев кода")

			var (
				wg                     sync.WaitGroup
				exchangeErr, revokeErr error
			)
			wg.Add(2)
			go func() {
				defer wg.Done()
				time.Sleep(scene.exchangeLate)
				_, exchangeErr = repo.ExchangeAuthorizationCode(ctx, kanamepg.CodeExchange{
					CodeDigest:         code,
					RefreshTokenDigest: ceremonyDigest(0x200000 + si*100 + run),
					RefreshTokenTTL:    time.Hour,
				})
			}()
			go func() {
				defer wg.Done()
				time.Sleep(scene.revokeLate)
				revokeErr = repo.RevokeFamily(ctx, base.FamilyID, domain.FamilyRevokedByLogout)
			}()
			wg.Wait()

			// `isDeadlock` — общий с `catalog_applier_lock_order_integration_test.go`:
			// он судит и 40P01, и обёртку `iamerr.ErrAborted`, в которую его кладёт
			// `wrapPgErr`. Второе написание разошлось бы с первым молча.
			if isDeadlock(exchangeErr) || isDeadlock(revokeErr) {
				deadlocks++
			}

			// КОНЕЧНОЕ СОСТОЯНИЕ — вот что судится. Кто из двоих отказал, зависит
			// от расписания и утверждению не подлежит; не подлежит сомнению
			// другое: семейство отозвано, живого выданного по нему нет.
			var live bool
			var liveTokens, liveCodes int
			require.NoError(t, pool.QueryRow(ctx, `
				SELECT f.live,
				       (SELECT count(*) FROM kaname.refresh_tokens t
				         WHERE t.family_id = f.id AND t.active),
				       (SELECT count(*) FROM kaname.authorization_codes c
				         WHERE c.family_id = f.id AND c.active)
				  FROM kaname.token_families f WHERE f.id = $1`,
				base.FamilyID).Scan(&live, &liveTokens, &liveCodes))

			t.Logf("сцена %q прогон %d: отзыв=%v · обмен=%v · семейство живо=%v · живых токенов=%d · живых кодов=%d",
				scene.name, run, revokeErr, exchangeErr, live, liveTokens, liveCodes)

			require.NoError(t, revokeErr,
				"сцена %q прогон %d: ОТЗЫВ обязан пройти — он контроль безопасности, "+
					"и повторить его некому: повторяет клиент, а похититель не повторяет",
				scene.name, run)
			require.False(t, live,
				"сцена %q прогон %d: семейство обязано быть отозвано", scene.name, run)
			require.Zero(t, liveTokens,
				"сцена %q прогон %d: живого обновляющего токена у отозванного семейства быть не может",
				scene.name, run)
			require.Zero(t, liveCodes,
				"сцена %q прогон %d: живого кода у отозванного семейства быть не может",
				scene.name, run)
		}
	}

	require.Zero(t, deadlocks,
		"взаимных блокировок обязано быть НОЛЬ на %d столкновений: цикл снимается порядком "+
			"замков (семейство берётся первым), а не повтором",
		len(scenes)*lockOrderRuns)
}

// TestOAuthExchangeTakesTheFamilyBeforeTheChild — ПОРЯДОК ЗАМКОВ УТВЕРЖДАЕТСЯ
// ПРЯМО, а не через вероятность столкновения.
//
// # Зачем она рядом с пробой выше
//
// Проба выше судит ИСХОД гонки, и этим хороша: она говорит о том, что видит
// арендатор. Но окно, в котором встречные порядки дают цикл, у неё узкое —
// на сломанной форме она краснеет не на каждом столкновении, а на части их.
// Гейт, который краснеет иногда, пропускает возврат сломанной формы.
//
// Эта проба закрывает ровно эту дыру: она ДЕТЕРМИНИРОВАНА и утверждает сам
// инвариант — «семейство берётся ПЕРВЫМ». Конструкция такая:
//
//   - посторонняя транзакция держит на семействе `FOR UPDATE`;
//   - обмен запускается и обязан встать НА СЕМЕЙСТВЕ, не тронув ребёнка;
//   - пока он стоит, у его backend'а НЕ ДОЛЖНО быть захвата
//     `RowExclusiveLock` на `authorization_codes`.
//
// На форме без упорядочивания обмен успевает изменить строку кода и встаёт
// только на вставке преемника — то есть захват на ребёнке БУДЕТ, и проба
// краснеет ВСЕГДА, а не иногда.
func TestOAuthExchangeTakesTheFamilyBeforeTheChild(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	repo := kanamepg.NewOAuthCeremonyRepo(pool)
	base := lockOrderScene(t, ctx, pool, 900)

	code := ceremonyDigest(0x900001)
	require.NoError(t, repo.IssueAuthorizationCode(ctx, kanamepg.NewAuthorizationCode{
		Context:             base,
		CodeDigest:          code,
		RedirectURI:         "https://app.example.test/cb",
		CodeChallenge:       ceremonyChallenge,
		CodeChallengeMethod: "S256",
		TTL:                 5 * time.Minute,
	}), "посев кода")

	// Посторонний держатель семейства. `FOR UPDATE` конфликтует с `FOR KEY
	// SHARE`, который берёт обмен, — значит обмен обязан встать здесь.
	holder, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = holder.Rollback(ctx) }()
	var held int
	require.NoError(t, holder.QueryRow(ctx,
		`SELECT 1 FROM kaname.token_families WHERE id = $1 FOR UPDATE`, base.FamilyID).Scan(&held))

	done := make(chan error, 1)
	go func() {
		_, exErr := repo.ExchangeAuthorizationCode(ctx, kanamepg.CodeExchange{
			CodeDigest:         code,
			RefreshTokenDigest: ceremonyDigest(0x900002),
			RefreshTokenTTL:    time.Hour,
		})
		done <- exErr
	}()

	// Ждём, пока обмен ВСТАНЕТ. Ожидание — по наблюдаемому состоянию движка, а
	// не по «достаточной» паузе: пауза на медленной машине даёт зелёное на
	// пустом месте.
	//
	// Ожидание строчного замка НЕ выглядит как незахваченный замок на
	// отношении: движок кладёт ждущего на `transactionid` держателя, и
	// `pg_locks.relation` у такой записи пуст. Поэтому ждущий опознаётся по
	// `pg_stat_activity.wait_event_type = 'Lock'`, а не по отношению.
	var waiterPID int
	for i := 0; i < 200; i++ {
		err := pool.QueryRow(ctx, `
			SELECT a.pid FROM pg_stat_activity a
			 WHERE a.datname = current_database()
			   AND a.wait_event_type = 'Lock'
			   AND a.state = 'active'
			 LIMIT 1`).Scan(&waiterPID)
		if err == nil && waiterPID != 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.NotZero(t, waiterPID,
		"обмен обязан ВСТАТЬ на семействе: если он не встал, он его не берёт — "+
			"а значит порядок замков не упорядочен и проба судит не тот предмет")

	// Встал он именно НА СЕМЕЙСТВЕ: ждущий висит на транзакции держателя, а
	// держатель — это наш `FOR UPDATE` на строке семейства.
	var waitsForHolder bool
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM pg_locks w
		   WHERE w.pid = $1 AND NOT w.granted
		     AND (w.relation = 'kaname.token_families'::regclass
		          OR w.locktype IN ('transactionid','tuple')))`, waiterPID).Scan(&waitsForHolder))
	require.True(t, waitsForHolder, "ждущий обязан стоять на держателе семейства")

	// ВОТ УТВЕРЖДЕНИЕ: стоя на семействе, обмен НЕ ДЕРЖИТ РЕБЁНКА.
	//
	// `RowExclusiveLock` на `authorization_codes` берётся первым же `UPDATE`
	// строки кода. Если он уже захвачен ТЕМ ЖЕ backend'ом, значит обмен успел
	// тронуть ребёнка раньше родителя — то есть идёт встречным порядком.
	var childHeld bool
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM pg_locks l
		   WHERE l.pid = $1 AND l.granted
		     AND l.relation = 'kaname.authorization_codes'::regclass
		     AND l.mode = 'RowExclusiveLock')`, waiterPID).Scan(&childHeld))
	require.False(t, childHeld,
		"обмен, стоящий на семействе, НЕ ДОЛЖЕН держать захвата на строке кода: "+
			"захват на ребёнке раньше родителя — это и есть встречный порядок, "+
			"дающий цикл с каскадом отзыва")

	// Отпускаем держателя — обмен обязан доехать, а не остаться висеть.
	require.NoError(t, holder.Rollback(ctx))
	select {
	case exErr := <-done:
		require.NoError(t, exErr, "обмен обязан завершиться после снятия постороннего замка")
	case <-time.After(30 * time.Second):
		t.Fatal("обмен не завершился после снятия постороннего замка")
	}
}
