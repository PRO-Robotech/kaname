// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// oauth_ceremony_isolation_integration_test.go — ИСХОД ПИСАТЕЛЕЙ ЦЕРЕМОНИИ НЕ
// ЗАВИСИТ ОТ УМОЛЧАНИЯ СЕССИИ (задача PRO-Robotech/kaname#316; приёмка LINE-A-1
// ред. 3, сценарии LINE-A-1-13 и LINE-A-1-17).
//
// # Два плеча, и отличие между ними — ОДИН факт
//
// Каждая сцена исполняется дважды, над двумя пулами одной формы
// (`coredb.NewPool`, как в службе). Плечо RC — пул с умолчанием продукта. Плечо
// S — тот же пул, у сессий которого умолчание `default_transaction_isolation`
// выставлено в `serializable`. Больше ничего не отличается: ни сцена, ни вход,
// ни утверждения. Поэтому плечо RC — законный близнец плеча S, и красное в S при
// зелёном RC называет ровно один предмет: исход писателя унаследован от
// умолчания, а не назван писателем.
//
// Умолчание сессии меняется не только в пробе: его ставят конфигурация сервера,
// `ALTER DATABASE … SET`, `ALTER ROLE … SET` и параметр подключения. Плечо S
// выставляет его последним способом — остальные дают то же умолчание и потому
// отдельными плечами не гоняются.
//
// # Ожидание ДОКАЗЫВАЕТСЯ, а не предполагается
//
// Различие уровней наблюдается в двух чередованиях, и оба начинаются с того,
// что писатель уже СТОИТ на строчном замке держателя:
//
//   - держатель фиксирует ИЗМЕНЕНИЕ строки, на которой писатель стоит (сцены
//     спора и `heldWriterCases`);
//   - держатель строку, на которой писатель стоит, только ДЕРЖИТ, а фиксирует
//     ДРУГУЮ строку, которую писатель прочтёт следующим оператором (обратная
//     сцена снятия сессии): новый снимок у следующего оператора есть лишь на
//     одном из уровней.
//
// Писатель, пришедший после фиксации, видит новое при любом уровне и различия
// не даёт. Поэтому каждая сцена строит чередование руками и УТВЕРЖДАЕТ его по
// состоянию движка: ждущий опознаётся по `pg_blocking_pids`, то есть по тому,
// КОГО он ждёт, а не по паузе. Не встал — сцена не построена, и это «не
// выполнилось», а не зелёное.
//
// # Чего проба НЕ различает
//
//   - одиночные ЧИТАТЕЛИ порта (`ClientSecretVerifier`, разбор нуля строк): у
//     одного оператора снимок один при любом уровне, и его исход
//     уровнем не решается; проба их не судит — перечень держит
//     `ceremonyPortClassification`;
//   - писателя, пишущего ЧИТАЮЩИМ оператором пула (`QueryRow`/`Query` с
//     `UPDATE … RETURNING`): перепись открытий
//     (`TestCeremonyWriterTransactionsOpenOnTheNamedLevel`) судит обращения
//     порта к пулу по имени метода, а не по тексту оператора, и такой писатель,
//     занесённый в перечень читателем, ушёл бы от сцен молча;
//   - умолчание `repeatable read` отдельным плечом не гоняется. Исход под ним
//     у разных пар РАЗНЫЙ: писатель, стоявший на строке, которую держатель
//     ИЗМЕНИЛ, получает 40001, как под `serializable`; снятие сессии, стоявшее
//     на выдаче, которая строку сессии только ДЕРЖАЛА, отказа не получает и
//     заведённого ею семейства не видит (снимок взят до фиксации выдачи). Плечо
//     S доказывает, что умолчание до транзакции писателя не доходит вовсе, а
//     перекрывает его одна и та же инструкция начала — какое бы оно ни было.
//
// Снятие сессии отзывает семейства оператором `revokeFamiliesOfSessionsTx`
// НЕ в транзакции этого порта, а в транзакции писателя сессии. Её двери
// (`sessionEnderDoors`) судятся обратной сценой
// (`TestSessionEndWaitingOnIssuanceRevokesTheIssuedFamily`), а их перечень
// сверяется с деревом переписью открытий.

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// ceremonyPortClassification — ПЕРЕЧЕНЬ методов порта церемонии по отношению к
// уровню изоляции. Писатель — метод, чей исход под конкуренцией решает движок
// перепроверкой условия на строке, которую держал другой; читатель — метод из
// одного читающего оператора.
//
// Перечень сверяется с МНОЖЕСТВОМ методов типа
// (`TestOAuthCeremonyPortMethodsAreClassified`), а покрытие писателей —
// с набором сцен (`TestOAuthCeremonyWritersKeepTheirOutcomeUnderEitherDefault`):
// новый метод, не попавший сюда, и писатель без сцены — находка, а не молчание.
var ceremonyPortClassification = map[string]string{
	"IssueAuthorizationCode":    "writer",
	"ExchangeAuthorizationCode": "writer",
	"RotateRefreshToken":        "writer",
	"RevokeFamily":              "writer",
	"SetClientSecretVerifier":   "writer",
	"ClearClientSecretVerifier": "writer",
	"ClientSecretVerifier":      "reader",
}

// TestOAuthCeremonyPortMethodsAreClassified — предпосылка перечня: он называет
// КАЖДЫЙ метод порта, и ни одного лишнего. Базы не требует.
func TestOAuthCeremonyPortMethodsAreClassified(t *testing.T) {
	typ := reflect.TypeOf(&kanamepg.OAuthCeremonyRepo{})
	var methods, unclassified []string
	for i := 0; i < typ.NumMethod(); i++ {
		name := typ.Method(i).Name
		methods = append(methods, name)
		if _, ok := ceremonyPortClassification[name]; !ok {
			unclassified = append(unclassified, name)
		}
	}
	var stale []string
	for name := range ceremonyPortClassification {
		if _, ok := typ.MethodByName(name); !ok {
			stale = append(stale, name)
		}
	}
	sort.Strings(stale)
	writers := 0
	for _, kind := range ceremonyPortClassification {
		if kind == "writer" {
			writers++
		}
	}
	t.Logf("перепись: методов порта %d · в перечне %d · писателей %d · читателей %d",
		len(methods), len(ceremonyPortClassification), writers, len(ceremonyPortClassification)-writers)
	require.NotEmpty(t, methods, "обход не нашёл ни одного метода порта — вердикта нет")
	assert.Empty(t, unclassified,
		"метод порта не классифицирован по отношению к уровню изоляции: %v", unclassified)
	assert.Empty(t, stale, "перечень называет метод, которого у порта нет: %v", stale)
}

// ceremonyShoulder — одно плечо: пул порта с его умолчанием и пул продукта для
// посева, держателей и наблюдения. База у плеча СВОЯ: посевы двух плеч не
// сталкиваются на уникальных ключах.
type ceremonyShoulder struct {
	name string
	// want — умолчание `default_transaction_isolation` сессий пула порта.
	want string
	// pool — пул, которым ходит порт.
	pool *pgxpool.Pool
	// seed — пул продукта той же базы: посев, держатели, наблюдатель.
	seed *pgxpool.Pool
}

func ceremonyShoulders(t *testing.T) (context.Context, []ceremonyShoulder) {
	t.Helper()
	ctx := context.Background()
	build := func(name, want, extra string) ceremonyShoulder {
		dsn := setupTestDB(t)
		seed, err := coredb.NewPool(ctx, dsn)
		require.NoError(t, err)
		pgtest.ClosePoolAtEnd(t, seed)
		portDSN := dsn
		if extra != "" {
			sep := "?"
			if strings.Contains(dsn, "?") {
				sep = "&"
			}
			portDSN = dsn + sep + extra
		}
		pool, err := coredb.NewPool(ctx, portDSN)
		require.NoError(t, err)
		pgtest.ClosePoolAtEnd(t, pool)

		// ПРЕДПОСЫЛКА ПЛЕЧА: умолчание сессий то, которое плечо объявляет.
		// Иначе оба плеча мерили бы одно и то же и зелёное S ничего бы не значило.
		var got, seedGot string
		require.NoError(t, pool.QueryRow(ctx, `SHOW default_transaction_isolation`).Scan(&got))
		require.NoError(t, seed.QueryRow(ctx, `SHOW default_transaction_isolation`).Scan(&seedGot))
		require.Equal(t, want, got, "плечо %s: умолчание пула порта не то, что объявлено", name)
		require.Equal(t, "read committed", seedGot, "плечо %s: пул посева обязан быть пулом продукта", name)
		return ceremonyShoulder{name: name, want: want, pool: pool, seed: seed}
	}
	return ctx, []ceremonyShoulder{
		build("RC", "read committed", ""),
		build("S", "serializable", "default_transaction_isolation=serializable"),
	}
}

// backendPID — номер обслуживающего процесса транзакции держателя.
func backendPID(t *testing.T, ctx context.Context, tx pgx.Tx) int {
	t.Helper()
	var pid int
	require.NoError(t, tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	return pid
}

// awaitBlockedBy — номер процесса, который СТОИТ на замке, удерживаемом
// `blocker`. Опознание — по `pg_blocking_pids`, то есть по тому, кого ждут, а не
// по паузе: пауза на медленной машине дала бы сцену, которой не было.
func awaitBlockedBy(t *testing.T, ctx context.Context, observer *pgxpool.Pool, blocker int, who string) int {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var pid int
		err := observer.QueryRow(ctx, `
			SELECT a.pid FROM pg_stat_activity a
			 WHERE a.datname = current_database()
			   AND a.wait_event_type = 'Lock'
			   AND $1 = ANY (pg_blocking_pids(a.pid))
			 ORDER BY a.pid LIMIT 1`, blocker).Scan(&pid)
		if err == nil {
			return pid
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			require.NoError(t, err, "наблюдатель замков")
		}
		if time.Now().After(deadline) {
			t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: %s не встал на замке процесса %d за 15 с — чередование "+
				"не построено, и вердикта о предмете у сцены нет", who, blocker)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// stillBlockedBy — стоит ли процесс `pid` на замке процесса `blocker` СЕЙЧАС.
func stillBlockedBy(t *testing.T, ctx context.Context, observer *pgxpool.Pool, pid, blocker int) bool {
	t.Helper()
	var blocked bool
	require.NoError(t, observer.QueryRow(ctx,
		`SELECT $2 = ANY (pg_blocking_pids($1))`, pid, blocker).Scan(&blocked))
	return blocked
}

// holdRefreshDigest — держатель, ОСТАНАВЛИВАЮЩИЙ победителя посреди его
// транзакции: незафиксированная строка обновляющего токена с той свёрткой,
// которую победитель вставит следом за своим условным `UPDATE`. Вставка
// победителя ждёт исхода держателя на уникальном ключе, а строку предмета
// победитель к этому моменту уже держит — ровно это и нужно проигравшему.
//
// Держатель ОТКАТЫВАЕТСЯ, а не фиксируется: откат снимает конфликт, и победитель
// доезжает до фиксации своим же путём.
func holdRefreshDigest(t *testing.T, ctx context.Context, seed *pgxpool.Pool,
	sc domain.CeremonyContext, digest string, generation int,
) (pgx.Tx, int) {
	t.Helper()
	tx, err := seed.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.refresh_tokens
		       (token_digest, family_id, client_id, user_id, session_id, scope, generation, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now() + interval '1 hour')`,
		digest, sc.FamilyID, sc.ClientID, sc.UserID, sc.SessionID, sc.Scope, generation)
	require.NoError(t, err, "держатель свёртки победителя")
	return tx, backendPID(t, ctx, tx)
}

// familyState — состояние семейства, прочитанное в момент наблюдения.
//
// Состояние — ОБЕ записи отзыва: отметка на семействе и отсечка по его ключу
// для места предъявления (`writeFamilyCutoffsTx`, kaname#396). Обе кладёт одна
// транзакция писателя; отметка без отсечки — отзыв, исполненный наполовину, и
// судится своим утверждением.
type familyState struct {
	revoked bool
	reason  string
	live    bool
	cutoff  bool
}

func readFamily(ctx context.Context, pool *pgxpool.Pool, familyID string) (familyState, error) {
	var st familyState
	err := pool.QueryRow(ctx, `
		SELECT f.revoked_at IS NOT NULL, coalesce(f.revoked_reason, ''), f.live,
		       EXISTS (SELECT 1 FROM kaname.minted_token_revocations r WHERE r.subject = f.id)
		  FROM kaname.token_families f WHERE f.id = $1`, familyID).
		Scan(&st.revoked, &st.reason, &st.live, &st.cutoff)
	return st, err
}

// contendedSubject — предмет, за который спорят победитель и проигравший:
// код авторизации (обмен) либо обновляющий токен (ротация).
type contendedSubject struct {
	name string
	// prepare заводит предмет в сцене и возвращает предъявляемую свёртку и
	// поколение, которое займёт преемник победителя.
	prepare func(t *testing.T, ctx context.Context, repo *kanamepg.OAuthCeremonyRepo,
		sc domain.CeremonyContext, n int) (presented string, successorGen int)
	// present — сам спорный вызов порта.
	present func(ctx context.Context, repo *kanamepg.OAuthCeremonyRepo,
		presented, successor string) error
	isReplay func(error) bool
	reason   domain.FamilyRevocationReason
	// tokensAfterReplay — обновляющих токенов в семействе победителя после
	// сцены повтора: выданное победителем и ничего от проигравшего.
	tokensAfterReplay int
}

func issueCeremonyCode(t *testing.T, ctx context.Context, repo *kanamepg.OAuthCeremonyRepo,
	sc domain.CeremonyContext, n int,
) string {
	t.Helper()
	code := ceremonyDigest(0x316000 + n)
	require.NoError(t, repo.IssueAuthorizationCode(ctx, kanamepg.NewAuthorizationCode{
		Context:             sc,
		CodeDigest:          code,
		RedirectURI:         "https://app.example.test/cb",
		CodeChallenge:       ceremonyChallenge,
		CodeChallengeMethod: domain.PKCEMethodS256,
		TTL:                 5 * time.Minute,
	}), "посев кода")
	return code
}

var contendedSubjects = []contendedSubject{
	{
		name: "ExchangeAuthorizationCode",
		prepare: func(t *testing.T, ctx context.Context, repo *kanamepg.OAuthCeremonyRepo,
			sc domain.CeremonyContext, n int) (string, int) {
			return issueCeremonyCode(t, ctx, repo, sc, n), 0
		},
		present: func(ctx context.Context, repo *kanamepg.OAuthCeremonyRepo, presented, successor string) error {
			_, err := repo.ExchangeAuthorizationCode(ctx, kanamepg.CodeExchange{
				CodeDigest:         presented,
				RefreshTokenDigest: successor,
				RefreshTokenTTL:    time.Hour,
			})
			return err
		},
		isReplay:          domain.IsAuthorizationCodeReplay,
		reason:            domain.FamilyRevokedByCodeReplay,
		tokensAfterReplay: 1,
	},
	{
		name: "RotateRefreshToken",
		prepare: func(t *testing.T, ctx context.Context, repo *kanamepg.OAuthCeremonyRepo,
			sc domain.CeremonyContext, n int) (string, int) {
			code := issueCeremonyCode(t, ctx, repo, sc, n)
			first := ceremonyDigest(0x317000 + n)
			_, err := repo.ExchangeAuthorizationCode(ctx, kanamepg.CodeExchange{
				CodeDigest: code, RefreshTokenDigest: first, RefreshTokenTTL: time.Hour,
			})
			require.NoError(t, err, "посев первого поколения")
			return first, 1
		},
		present: func(ctx context.Context, repo *kanamepg.OAuthCeremonyRepo, presented, successor string) error {
			_, err := repo.RotateRefreshToken(ctx, kanamepg.RefreshRotation{
				PresentedDigest: presented,
				SuccessorDigest: successor,
				TTL:             time.Hour,
			})
			return err
		},
		isReplay:          domain.IsRefreshTokenReplay,
		reason:            domain.FamilyRevokedByRefreshReplay,
		tokensAfterReplay: 2,
	},
}

// contendedOutcome — исходы сцены и состояние, снятое У ПРОИГРАВШЕГО.
type contendedOutcome struct {
	winnerErr, loserErr error
	// atLoser — состояние семейства, чей предмет предъявил проигравший,
	// прочитанное СРАЗУ по возврату его вызова.
	atLoser    familyState
	atLoserErr error
}

// runContended строит чередование «победитель держит строку предмета,
// проигравший стоит на ней» и возвращает исходы. `loserPresentsWinners` —
// ЕДИНСТВЕННЫЙ факт, которым сцена повтора отличается от близнеца: проигравший
// предъявляет предмет победителя либо свой, заведённый той же сценой.
func runContended(t *testing.T, ctx context.Context, sh ceremonyShoulder, subj contendedSubject,
	base int, loserPresentsWinners bool,
) (winnerScene, otherScene domain.CeremonyContext, winnerSuccessor, loserSuccessor string, out contendedOutcome) {
	t.Helper()
	repo := kanamepg.NewOAuthCeremonyRepo(sh.pool)
	winnerScene = lockOrderScene(t, ctx, sh.seed, base)
	otherScene = lockOrderScene(t, ctx, sh.seed, base+1)
	winnerPresented, gen := subj.prepare(t, ctx, repo, winnerScene, base)
	otherPresented, _ := subj.prepare(t, ctx, repo, otherScene, base+1)
	winnerSuccessor = ceremonyDigest(0x318000 + base)
	loserSuccessor = ceremonyDigest(0x319000 + base)

	holder, holderPID := holdRefreshDigest(t, ctx, sh.seed, winnerScene, winnerSuccessor, gen)

	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	winnerDone := make(chan error, 1)
	go func() { winnerDone <- subj.present(callCtx, repo, winnerPresented, winnerSuccessor) }()
	winnerPID := awaitBlockedBy(t, ctx, sh.seed, holderPID, "победитель "+subj.name)

	loserPresented, loserFamily := otherPresented, otherScene.FamilyID
	if loserPresentsWinners {
		loserPresented, loserFamily = winnerPresented, winnerScene.FamilyID
	}
	loserDone := make(chan contendedOutcome, 1)
	go func() {
		var o contendedOutcome
		o.loserErr = subj.present(callCtx, repo, loserPresented, loserSuccessor)
		o.atLoser, o.atLoserErr = readFamily(ctx, sh.seed, loserFamily)
		loserDone <- o
	}()

	var loser contendedOutcome
	if loserPresentsWinners {
		// Проигравший обязан ВСТАТЬ на строке, которую держит победитель.
		awaitBlockedBy(t, ctx, sh.seed, winnerPID, "проигравший "+subj.name)
		require.NoError(t, holder.Rollback(ctx), "держатель отпускает победителя")
		loser = <-loserDone
	} else {
		// Близнец: свой предмет не ждёт победителя — второй доезжает, пока
		// победитель ещё стоит посреди своей транзакции. Одновременность
		// утверждается, а не предполагается.
		//
		// Второй, вставший ЗА первым, — не «сцена не построена», а наблюдение о
		// продукте: реализация сводит разные предметы в одну очередь. Поэтому это
		// утверждение, а не отказ сцены, и исходы обоих судятся и после него.
		finished := false
		select {
		case loser = <-loserDone:
			finished = true
		case <-time.After(5 * time.Second):
		}
		assert.True(t, finished,
			"второй вызов по СВОЕМУ предмету обязан завершиться, пока первый стоит посреди "+
				"транзакции: он встал за первым")
		if finished {
			require.True(t, stillBlockedBy(t, ctx, sh.seed, winnerPID, holderPID),
				"НЕ ВЫПОЛНИЛОСЬ: первый обязан стоять посреди транзакции всё время вызова второго")
		}
		require.NoError(t, holder.Rollback(ctx), "держатель отпускает победителя")
		if !finished {
			select {
			case loser = <-loserDone:
			case <-time.After(30 * time.Second):
				t.Fatal("второй вызов не завершился и после снятия держателя")
			}
		}
	}
	select {
	case out.winnerErr = <-winnerDone:
	case <-time.After(30 * time.Second):
		t.Fatal("победитель не завершился после снятия держателя")
	}
	out.loserErr, out.atLoser, out.atLoserErr = loser.loserErr, loser.atLoser, loser.atLoserErr
	return winnerScene, otherScene, winnerSuccessor, loserSuccessor, out
}

// TestOAuthCeremonyLoserWaitingOnTheWinnerIsAReplay — LINE-A-1-17: проигравший,
// СТОЯВШИЙ на строке победителя, получает ПОВТОР, и к моменту его возврата
// семейство ОТОЗВАНО; выданное победителем не ротируется. В обоих плечах.
func TestOAuthCeremonyLoserWaitingOnTheWinnerIsAReplay(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	require.NotEmpty(t, contendedSubjects, "предметов спора нет — подпроб ноль, и вердикта нет")
	ctx, shoulders := ceremonyShoulders(t)
	for _, sh := range shoulders {
		for i, subj := range contendedSubjects {
			t.Run(sh.name+"/"+subj.name, func(t *testing.T) {
				winner, _, winnerSuccessor, _, out := runContended(t, ctx, sh, subj, 100+10*i, true)
				t.Logf("плечо %s: победитель=%v · проигравший=%v · семейство у проигравшего %+v",
					sh.name, out.winnerErr, out.loserErr, out.atLoser)

				require.NoError(t, out.winnerErr, "победитель обязан пройти")
				// Каждое утверждение ниже — СВОЁ: исход проигравшего и состояние
				// семейства краснеют независимо друг от друга.
				assert.True(t, subj.isReplay(out.loserErr),
					"проигравший, стоявший на строке победителя, обязан получить ПОВТОР, а получил: %v",
					out.loserErr)
				require.NoError(t, out.atLoserErr, "чтение семейства у проигравшего")
				assert.True(t, out.atLoser.revoked,
					"к возврату проигравшего семейство обязано быть ОТОЗВАНО: отказ без отзыва "+
						"исходом не является (LINE-A-1-13)")
				assert.Equal(t, string(subj.reason), out.atLoser.reason, "основание отзыва")
				assert.False(t, out.atLoser.live, "живость семейства у проигравшего")
				assert.True(t, out.atLoser.cutoff,
					"к возврату проигравшего отсечка семейства обязана лежать: отзыв, не дошедший "+
						"до места предъявления, исполнен наполовину")

				// Транзакция проигравшего ОТКАЧЕНА: считается ДО попытки ротации ниже,
				// иначе число мерило бы и её.
				var tokens int
				require.NoError(t, sh.seed.QueryRow(ctx,
					`SELECT count(*) FROM kaname.refresh_tokens WHERE family_id = $1`,
					winner.FamilyID).Scan(&tokens))
				assert.Equal(t, subj.tokensAfterReplay, tokens,
					"транзакция проигравшего обязана быть откачена целиком")

				// Выданное победителем СНЯТО: его токен неактивен и не ротируется.
				var active bool
				require.NoError(t, sh.seed.QueryRow(ctx,
					`SELECT active FROM kaname.refresh_tokens WHERE token_digest = $1`,
					winnerSuccessor).Scan(&active))
				assert.False(t, active, "токен победителя обязан быть снят отзывом семейства")
				repo := kanamepg.NewOAuthCeremonyRepo(sh.pool)
				_, rotErr := repo.RotateRefreshToken(ctx, kanamepg.RefreshRotation{
					PresentedDigest: winnerSuccessor,
					SuccessorDigest: ceremonyDigest(0x31a000 + i),
					TTL:             time.Hour,
				})
				assert.Error(t, rotErr, "токен победителя обязан НЕ ротироваться после повтора")

			})
		}
	}
}

// TestOAuthCeremonyConcurrentPresentationsOfDifferentSubjectsBothPass —
// близнец LINE-A-1-17: та же сцена, проигравший предъявляет СВОЙ предмет. Оба
// проходят, оба семейства живы, оба выданных ротируются. Отличает реализацию,
// отвергающую любой второй одновременный вызов, и ложный повтор.
func TestOAuthCeremonyConcurrentPresentationsOfDifferentSubjectsBothPass(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	require.NotEmpty(t, contendedSubjects, "предметов спора нет — подпроб ноль, и вердикта нет")
	ctx, shoulders := ceremonyShoulders(t)
	for _, sh := range shoulders {
		for i, subj := range contendedSubjects {
			t.Run(sh.name+"/"+subj.name, func(t *testing.T) {
				winner, other, winnerSuccessor, loserSuccessor, out := runContended(t, ctx, sh, subj, 200+10*i, false)
				t.Logf("плечо %s: первый=%v · второй=%v · семейство второго %+v",
					sh.name, out.winnerErr, out.loserErr, out.atLoser)

				assert.NoError(t, out.winnerErr, "первый обязан пройти")
				assert.NoError(t, out.loserErr, "второй, предъявивший СВОЙ предмет, обязан пройти")
				require.NoError(t, out.atLoserErr)
				assert.False(t, out.atLoser.revoked, "семейство второго обязано остаться живым")
				assert.False(t, out.atLoser.cutoff, "у живого семейства второго отсечки быть не может")

				repo := kanamepg.NewOAuthCeremonyRepo(sh.pool)
				for j, fam := range []struct {
					id, token string
				}{{winner.FamilyID, winnerSuccessor}, {other.FamilyID, loserSuccessor}} {
					st, err := readFamily(ctx, sh.seed, fam.id)
					require.NoError(t, err)
					assert.False(t, st.revoked, "семейство %s обязано остаться живым", fam.id)
					_, rotErr := repo.RotateRefreshToken(ctx, kanamepg.RefreshRotation{
						PresentedDigest: fam.token,
						SuccessorDigest: ceremonyDigest(0x31b000 + 10*i + j),
						TTL:             time.Hour,
					})
					assert.NoError(t, rotErr, "выданное в семействе %s обязано ротироваться", fam.id)
				}
			})
		}
	}
}

// heldWriterCase — писатель, встающий на строке, которую ИЗМЕНЯЕТ держатель.
type heldWriterCase struct {
	name string
	// hold ставит держателя и возвращает номер процесса, на котором писатель
	// обязан встать, и отпускание держателя.
	hold func(t *testing.T, ctx context.Context, sh ceremonyShoulder, repo *kanamepg.OAuthCeremonyRepo,
		sc domain.CeremonyContext, n int) (pid int, release func())
	act   func(ctx context.Context, repo *kanamepg.OAuthCeremonyRepo, sc domain.CeremonyContext) error
	check func(t *testing.T, ctx context.Context, sh ceremonyShoulder, repo *kanamepg.OAuthCeremonyRepo,
		sc domain.CeremonyContext, err error)
}

// holdingTx — держатель в транзакции пула посева; отпускание — фиксация.
func holdingTx(t *testing.T, ctx context.Context, seed *pgxpool.Pool, what, sql string, args ...any) (int, func()) {
	t.Helper()
	tx, err := seed.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	_, err = tx.Exec(ctx, sql, args...)
	require.NoError(t, err, "держатель: %s", what)
	return backendPID(t, ctx, tx), func() { require.NoError(t, tx.Commit(ctx), "фиксация держателя: %s", what) }
}

var heldWriterCases = []heldWriterCase{
	{
		// Сессия снята одновременно с выдачей: держатель ставит отметку снятия,
		// выдача стоит на строке сессии. Исход — «сессия не жива».
		name: "IssueAuthorizationCode",
		hold: func(t *testing.T, ctx context.Context, sh ceremonyShoulder, _ *kanamepg.OAuthCeremonyRepo,
			sc domain.CeremonyContext, _ int) (int, func()) {
			return holdingTx(t, ctx, sh.seed, "снятие сессии", `
				UPDATE kaname.human_sessions SET ended_at = now(), ended_reason = 'logout'
				 WHERE id = $1`, sc.SessionID)
		},
		act: func(ctx context.Context, repo *kanamepg.OAuthCeremonyRepo, sc domain.CeremonyContext) error {
			return repo.IssueAuthorizationCode(ctx, kanamepg.NewAuthorizationCode{
				Context: sc, CodeDigest: ceremonyDigest(0x31c001), RedirectURI: "https://app.example.test/cb",
				CodeChallenge: ceremonyChallenge, CodeChallengeMethod: domain.PKCEMethodS256, TTL: time.Minute,
			})
		},
		check: func(t *testing.T, ctx context.Context, sh ceremonyShoulder, _ *kanamepg.OAuthCeremonyRepo,
			sc domain.CeremonyContext, err error) {
			assert.ErrorIs(t, err, domain.ErrCeremonySessionNotLive,
				"выдача, стоявшая на снимаемой сессии, обязана получить «сессия не жива»")
			var families int
			require.NoError(t, sh.seed.QueryRow(ctx,
				`SELECT count(*) FROM kaname.token_families WHERE session_id = $1`, sc.SessionID).Scan(&families))
			assert.Zero(t, families, "семейство в снятой сессии заведено быть не может")
		},
	},
	{
		// Два обнаружения повтора отзывают ОДНО семейство: первый стоит на
		// каскаде (держатель держит строку ребёнка), второй — на строке первого.
		// Второй обязан быть пустым, а не отказом, и причину первого не трогает.
		name: "RevokeFamily",
		hold: func(t *testing.T, ctx context.Context, sh ceremonyShoulder, repo *kanamepg.OAuthCeremonyRepo,
			sc domain.CeremonyContext, n int) (int, func()) {
			code := issueCeremonyCode(t, ctx, repo, sc, n)
			childPID, releaseChild := holdingTx(t, ctx, sh.seed, "строка ребёнка",
				`SELECT 1 FROM kaname.authorization_codes WHERE code_digest = $1 FOR SHARE`, code)
			type revoked struct {
				rows int64
				err  error
			}
			firstDone := make(chan revoked, 1)
			go func() {
				rows, err := repo.RevokeFamily(ctx, sc.FamilyID, domain.FamilyRevokedByCodeReplay)
				firstDone <- revoked{rows, err}
			}()
			firstPID := awaitBlockedBy(t, ctx, sh.seed, childPID, "первый отзыв")
			return firstPID, func() {
				releaseChild()
				select {
				case first := <-firstDone:
					require.NoError(t, first.err, "первый отзыв обязан пройти")
					require.EqualValues(t, 1, first.rows, "первый отзыв обязан отметить семейство")
				case <-time.After(30 * time.Second):
					t.Fatal("первый отзыв не завершился после снятия держателя")
				}
			}
		},
		act: func(ctx context.Context, repo *kanamepg.OAuthCeremonyRepo, sc domain.CeremonyContext) error {
			rows, err := repo.RevokeFamily(ctx, sc.FamilyID, domain.FamilyRevokedByRefreshReplay)
			if err == nil && rows != 0 {
				// Отметка второго — не отказ, но и не пустой отзыв: исход судится
				// тем же утверждением, что отказ.
				return fmt.Errorf("второй отзыв отметил строк %d вместо нуля: отзыв не идемпотентен", rows)
			}
			return err
		},
		check: func(t *testing.T, ctx context.Context, sh ceremonyShoulder, _ *kanamepg.OAuthCeremonyRepo,
			sc domain.CeremonyContext, err error) {
			assert.NoError(t, err, "второй отзыв того же семейства обязан быть пустым, а не отказом")
			st, rErr := readFamily(ctx, sh.seed, sc.FamilyID)
			require.NoError(t, rErr)
			assert.True(t, st.revoked, "семейство отозвано")
			assert.Equal(t, string(domain.FamilyRevokedByCodeReplay), st.reason,
				"второй отзыв не вправе переписать причину первого")
			assert.True(t, st.cutoff, "отсечка семейства обязана лежать после обоих отзывов")
		},
	},
	{
		// Проверочное значение кладётся, пока строку клиента правит посторонний
		// писатель реестра. Исход — значение положено.
		name: "SetClientSecretVerifier",
		hold: func(t *testing.T, ctx context.Context, sh ceremonyShoulder, _ *kanamepg.OAuthCeremonyRepo,
			sc domain.CeremonyContext, _ int) (int, func()) {
			declareSecretClient(t, ctx, sh.seed, sc.ClientID)
			return holdingTx(t, ctx, sh.seed, "посторонний писатель реестра клиентов", `
				UPDATE kaname.interactive_clients SET redirect_uris = redirect_uris
				 WHERE client_id = $1`, sc.ClientID)
		},
		act: func(ctx context.Context, repo *kanamepg.OAuthCeremonyRepo, sc domain.CeremonyContext) error {
			return repo.SetClientSecretVerifier(ctx, sc.ClientID, verifierForCases)
		},
		check: func(t *testing.T, ctx context.Context, _ ceremonyShoulder, repo *kanamepg.OAuthCeremonyRepo,
			sc domain.CeremonyContext, err error) {
			assert.NoError(t, err, "значение обязано лечь")
			_, has, vErr := repo.ClientSecretVerifier(ctx, sc.ClientID)
			require.NoError(t, vErr)
			assert.True(t, has, "у клиента обязан появиться секрет")
		},
	},
	{
		name: "ClearClientSecretVerifier",
		hold: func(t *testing.T, ctx context.Context, sh ceremonyShoulder, repo *kanamepg.OAuthCeremonyRepo,
			sc domain.CeremonyContext, _ int) (int, func()) {
			declareSecretClient(t, ctx, sh.seed, sc.ClientID)
			require.NoError(t, repo.SetClientSecretVerifier(ctx, sc.ClientID, verifierForCases), "посев значения")
			return holdingTx(t, ctx, sh.seed, "посторонний писатель реестра клиентов", `
				UPDATE kaname.interactive_clients SET redirect_uris = redirect_uris
				 WHERE client_id = $1`, sc.ClientID)
		},
		act: func(ctx context.Context, repo *kanamepg.OAuthCeremonyRepo, sc domain.CeremonyContext) error {
			return repo.ClearClientSecretVerifier(ctx, sc.ClientID)
		},
		check: func(t *testing.T, ctx context.Context, _ ceremonyShoulder, repo *kanamepg.OAuthCeremonyRepo,
			sc domain.CeremonyContext, err error) {
			assert.NoError(t, err, "значение обязано сняться")
			_, has, vErr := repo.ClientSecretVerifier(ctx, sc.ClientID)
			require.NoError(t, vErr)
			assert.False(t, has, "у клиента не обязано остаться секрета")
		},
	},
}

// declareSecretClient — клиент сцены объявляется способом СЕКРЕТОМ до сцен
// проверочного значения. Сцена заводит клиента публичным (`none`), а материал
// лежит только у клиента, предъявляющего секрет
// (`interactive_clients_secret_verifier_method_ck`, kaname#317): без этого
// посева писатель получал бы отказ схемы, а не свой исход под конкуренцией.
func declareSecretClient(t *testing.T, ctx context.Context, seed *pgxpool.Pool, clientID string) {
	t.Helper()
	tag, err := seed.Exec(ctx, `
		UPDATE kaname.interactive_clients SET token_endpoint_auth_method = 'client_secret_basic'
		 WHERE client_id = $1`, clientID)
	require.NoError(t, err, "посев способа секретом")
	require.EqualValues(t, 1, tag.RowsAffected(), "посев способа секретом: клиента сцены нет")
}

// verifierForCases — проверочное значение объявленной формы.
var verifierForCases = func() domain.LoginVerifier {
	v, err := domain.NewLoginVerifier(
		"$argon2id$v=19$m=65536,t=3,p=4$" + strings.Repeat("A", 22) + "$" + strings.Repeat("B", 43))
	if err != nil {
		panic(err)
	}
	return v
}()

// TestOAuthCeremonyWritersKeepTheirOutcomeUnderEitherDefault — каждый писатель
// порта, СТОЯВШИЙ на строке, которую изменил другой, получает свой исход, а не
// отказ сериализации, — в обоих плечах. Покрытие сверяется с перечнем.
func TestOAuthCeremonyWritersKeepTheirOutcomeUnderEitherDefault(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	// ПРЕДПОСЫЛКА: у каждого писателя перечня есть сцена — здесь либо в
	// `contendedSubjects`. Писатель без сцены молчал бы, а не зеленел.
	covered := map[string]bool{}
	for _, c := range heldWriterCases {
		covered[c.name] = true
	}
	for _, s := range contendedSubjects {
		covered[s.name] = true
	}
	var missing []string
	writers := 0
	for name, kind := range ceremonyPortClassification {
		if kind != "writer" {
			continue
		}
		writers++
		if !covered[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	t.Logf("перепись: писателей в перечне %d · сцен держателя %d · сцен спора %d",
		writers, len(heldWriterCases), len(contendedSubjects))
	require.Empty(t, missing, "у писателя порта нет сцены под конкуренцией: %v", missing)

	ctx, shoulders := ceremonyShoulders(t)
	for _, sh := range shoulders {
		for i, c := range heldWriterCases {
			t.Run(sh.name+"/"+c.name, func(t *testing.T) {
				repo := kanamepg.NewOAuthCeremonyRepo(sh.pool)
				n := 300 + i
				sc := lockOrderScene(t, ctx, sh.seed, n)
				holderPID, release := c.hold(t, ctx, sh, repo, sc, n)

				callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- c.act(callCtx, repo, sc) }()
				awaitBlockedBy(t, ctx, sh.seed, holderPID, "писатель "+c.name)
				release()

				var err error
				select {
				case err = <-done:
				case <-time.After(30 * time.Second):
					t.Fatal("писатель не завершился после снятия держателя")
				}
				t.Logf("плечо %s: %s → %v", sh.name, c.name, err)
				c.check(t, ctx, sh, repo, sc, err)
			})
		}
	}
}

// ── Обратная сцена: снятие сессии стоит на выдаче ──────────────────────────

// holdCodeDigest — держатель, ОСТАНАВЛИВАЮЩИЙ выдачу ПОСЛЕ заведения её
// семейства: незафиксированная строка кода с той свёрткой, которую выдача
// вставит следом за семейством. К этому моменту выдача уже держит строку
// сессии (`FOR SHARE`) и завела в ней семейство — ровно это и нужно снятию.
//
// Строка держателя лежит в семействе ЧУЖОЙ сцены (`other`): ни строки сессии,
// ни человека, ни клиента сцены держатель не касается, и выдача ждёт его
// только на первичном ключе свёртки. Держатель ОТКАТЫВАЕТСЯ: откат снимает
// конфликт, и выдача доезжает до фиксации своим же путём.
func holdCodeDigest(t *testing.T, ctx context.Context, seed *pgxpool.Pool,
	other domain.CeremonyContext, digest string,
) (pgx.Tx, int) {
	t.Helper()
	tx, err := seed.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.token_families (id, client_id, user_id, session_id, scope)
		VALUES ($1, $2, $3, $4, $5)`,
		other.FamilyID, other.ClientID, other.UserID, other.SessionID, other.Scope)
	require.NoError(t, err, "держатель: семейство чужой сцены")
	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.authorization_codes
		       (code_digest, family_id, client_id, user_id, session_id, scope, redirect_uri,
		        code_challenge, code_challenge_method, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'https://app.example.test/cb', $7, 'S256',
		        now() + interval '5 minutes')`,
		digest, other.FamilyID, other.ClientID, other.UserID, other.SessionID, other.Scope,
		ceremonyChallenge)
	require.NoError(t, err, "держатель свёртки кода выдачи")
	return tx, backendPID(t, ctx, tx)
}

// sessionEnderDoor — дверь, выдающая транзакцию писателя сессии, и снятие
// записи сессии через неё. Снятие отзывает выданное в сессии оператором
// `revokeFamiliesOfSessionsTx` в ТОЙ ЖЕ транзакции, и исход пары «выдача
// против снятия» решает уровень, на котором эту транзакцию открыла дверь.
//
// Имя — «Тип.Метод» двери, как его называет перепись открытий
// (`TestCeremonyWriterTransactionsOpenOnTheNamedLevel`): дверь дерева без сцены
// здесь и сцена без двери в дереве — находки, а не молчание.
type sessionEnderDoor struct {
	name string
	// end открывает транзакцию двери на пуле порта, снимает запись сессии сцены,
	// фиксирует и отвечает числом снятых записей.
	end func(ctx context.Context, pool *pgxpool.Pool, sc domain.CeremonyContext) (int, error)
}

// endOneSession — снятие одной записи по идентификатору и фиксация.
func endOneSession(ctx context.Context, w interface {
	EndSession(ctx context.Context, id domain.HumanSessionID, at time.Time, reason string) (bool, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}, sc domain.CeremonyContext) (int, error) {
	defer func() { _ = w.Rollback(ctx) }()
	ended, err := w.EndSession(ctx, domain.HumanSessionID(sc.SessionID), time.Now(), domain.RevokeReasonLogout)
	if err != nil {
		return 0, err
	}
	if err = w.Commit(ctx); err != nil {
		return 0, err
	}
	if !ended {
		return 0, nil
	}
	return 1, nil
}

// endAllSessionsOf — снятие всех записей человека сцены и фиксация.
func endAllSessionsOf(ctx context.Context, w interface {
	EndOtherSessions(ctx context.Context, userID domain.UserID, keep domain.HumanSessionID, at time.Time, reason string) (int, error)
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}, sc domain.CeremonyContext, reason string) (int, error) {
	defer func() { _ = w.Rollback(ctx) }()
	n, err := w.EndOtherSessions(ctx, domain.UserID(sc.UserID), "", time.Now(), reason)
	if err != nil {
		return 0, err
	}
	if err = w.Commit(ctx); err != nil {
		return 0, err
	}
	return n, nil
}

var sessionEnderDoors = []sessionEnderDoor{
	{
		// Собственный выход человека.
		name: "HumanSessionRepo.Writer",
		end: func(ctx context.Context, pool *pgxpool.Pool, sc domain.CeremonyContext) (int, error) {
			w, err := kanamepg.NewHumanSessionRepo(pool).Writer(ctx)
			if err != nil {
				return 0, err
			}
			return endOneSession(ctx, w, sc)
		},
	},
	{
		// Смена пароля, снятие второго фактора, завершение восстановления.
		name: "HumanSessionRepo.SessionSetWriter",
		end: func(ctx context.Context, pool *pgxpool.Pool, sc domain.CeremonyContext) (int, error) {
			w, err := kanamepg.NewHumanSessionRepo(pool).SessionSetWriter(ctx, domain.UserID(sc.UserID))
			if err != nil {
				return 0, err
			}
			return endAllSessionsOf(ctx, w, sc, domain.RevokeReasonPasswordChange)
		},
	},
	{
		// Административный принудительный выход.
		name: "HumanSessionRepo.ForceLogoutWriter",
		end: func(ctx context.Context, pool *pgxpool.Pool, sc domain.CeremonyContext) (int, error) {
			w, err := kanamepg.NewHumanSessionRepo(pool).ForceLogoutWriter(ctx, domain.UserID(sc.UserID), 20*time.Second)
			if err != nil {
				return 0, err
			}
			return endAllSessionsOf(ctx, w, sc, domain.RevokeReasonAdminForceLogout)
		},
	},
	{
		// Регистрация несёт писателя сессии встроенным, и снятие ей
		// представимо той же транзакцией: живого вызывающего у него нет, но
		// судится дверь, а не вызывающий.
		name: "RegistrationStore.Writer",
		end: func(ctx context.Context, pool *pgxpool.Pool, sc domain.CeremonyContext) (int, error) {
			w, err := kanamepg.NewRegistrationStore(pool).Writer(ctx)
			if err != nil {
				return 0, err
			}
			return endOneSession(ctx, w, sc)
		},
	},
}

// TestSessionEndWaitingOnIssuanceRevokesTheIssuedFamily — ОБРАТНАЯ сцена пары
// «выдача против снятия сессии»: выдача держит строку сессии и уже завела в ней
// семейство, снятие сессии СТОИТ на ней. После фиксации выдачи снятие обязано
// отозвать заведённое ею семейство — в обоих плечах и через каждую дверь
// транзакции писателя сессии. Плечо RC — законный близнец плеча S.
//
// Прямая сцена той же пары (выдача стоит на снятии) — случай
// `IssueAuthorizationCode` в `heldWriterCases`.
func TestSessionEndWaitingOnIssuanceRevokesTheIssuedFamily(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	require.NotEmpty(t, sessionEnderDoors, "дверей писателя сессии нет — подпроб ноль, и вердикта нет")
	ctx, shoulders := ceremonyShoulders(t)
	for _, sh := range shoulders {
		for i, door := range sessionEnderDoors {
			t.Run(sh.name+"/"+door.name, func(t *testing.T) {
				repo := kanamepg.NewOAuthCeremonyRepo(sh.pool)
				n := 400 + 2*i
				sc := lockOrderScene(t, ctx, sh.seed, n)
				other := lockOrderScene(t, ctx, sh.seed, n+1)
				code := ceremonyDigest(0x31d000 + n)
				holder, holderPID := holdCodeDigest(t, ctx, sh.seed, other, code)

				callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				defer cancel()
				issued := make(chan error, 1)
				go func() {
					issued <- repo.IssueAuthorizationCode(callCtx, kanamepg.NewAuthorizationCode{
						Context: sc, CodeDigest: code, RedirectURI: "https://app.example.test/cb",
						CodeChallenge: ceremonyChallenge, CodeChallengeMethod: domain.PKCEMethodS256,
						TTL: time.Minute,
					})
				}()
				// Выдача стоит на свёртке кода, то есть ПОСЛЕ своего семейства:
				// ждать держателя ей больше не на чем.
				issuerPID := awaitBlockedBy(t, ctx, sh.seed, holderPID, "выдача")

				type endOutcome struct {
					ended int
					err   error
				}
				ended := make(chan endOutcome, 1)
				go func() {
					k, err := door.end(callCtx, sh.pool, sc)
					ended <- endOutcome{k, err}
				}()
				// Снятие обязано ВСТАТЬ на строке сессии, которую держит выдача.
				awaitBlockedBy(t, ctx, sh.seed, issuerPID, "снятие сессии "+door.name)
				require.NoError(t, holder.Rollback(ctx), "держатель отпускает выдачу")

				select {
				case err := <-issued:
					require.NoError(t, err, "выдача, взявшая строку сессии раньше снятия, обязана пройти")
				case <-time.After(30 * time.Second):
					t.Fatal("выдача не завершилась после снятия держателя")
				}
				var out endOutcome
				select {
				case out = <-ended:
				case <-time.After(30 * time.Second):
					t.Fatal("снятие сессии не завершилось после фиксации выдачи")
				}

				st, famErr := readFamily(ctx, sh.seed, sc.FamilyID)
				var sessionEnded bool
				require.NoError(t, sh.seed.QueryRow(ctx,
					`SELECT ended_at IS NOT NULL FROM kaname.human_sessions WHERE id = $1`,
					sc.SessionID).Scan(&sessionEnded))
				t.Logf("плечо %s: %s → снято %d, %v · сессия снята %v · семейство %+v",
					sh.name, door.name, out.ended, out.err, sessionEnded, st)

				// Каждое утверждение ниже — СВОЁ: исход снятия, отметка сессии и
				// состояние семейства краснеют независимо друг от друга.
				require.NoError(t, out.err, "снятие сессии, стоявшее на выдаче, обязано пройти")
				assert.Equal(t, 1, out.ended, "снята ровно запись сцены")
				assert.True(t, sessionEnded, "запись сессии обязана быть снята")
				require.NoError(t, famErr, "семейство, заведённое выдачей, обязано существовать")
				assert.True(t, st.revoked,
					"семейство, заведённое выдачей, на которой стояло снятие, обязано быть ОТОЗВАНО")
				assert.Equal(t, string(domain.FamilyRevokedBySessionEnd), st.reason, "основание отзыва")
				assert.False(t, st.live, "живость семейства после снятия сессии")
				assert.True(t, st.cutoff,
					"отсечка семейства, заведённого выдачей, обязана лечь той же транзакцией снятия")
			})
		}
	}
}
