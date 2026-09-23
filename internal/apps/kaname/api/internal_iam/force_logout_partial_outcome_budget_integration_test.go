// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// force_logout_partial_outcome_budget_integration_test.go — ЧАСТИЧНЫЙ ИСХОД
// ПРИНУДИТЕЛЬНОГО ВЫХОДА ЛОЖИТСЯ ПРИ ЛЮБОЙ ПРИЧИНЕ ОТКАЗА СНЯТИЯ, В ТОМ ЧИСЛЕ
// ТОГДА, КОГДА ПРИЧИНА — КОНЕЦ СРОКА ЗАПРОСА (задача kaname#340).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Под посадкой `own` снятие, отсечка и запись события — одна транзакция; при
// отказе снятия она откатывается, и отсечку с записью «снятие не состоялось»
// кладёт ВТОРАЯ. Отказ снятия бывает и оттого, что кончился срок самого запроса:
// снятие ждало блокировки строки сессии или просто шло дольше, чем вызывающий
// готов ждать. Если вторая транзакция открывается на том же истёкшем сроке, она
// не открывается вовсе — и не ложится НИЧЕГО: ни отсечки, ни записи события, а
// распорядитель получает `Internal`. Это хуже прежнего порядка, где отсечка
// фиксировалась до снятия и оставалась при любом его исходе.
//
// Утверждается наблюдаемое в базе и в ответе:
//
//   - снятие идёт дольше срока запроса → обе записи отсечки на месте, запись
//     события говорит «снятие не состоялось» и числа не несёт, ответ
//     `Unavailable`, операция отмечена ошибкой — опрос видит отказ, а не вечное
//     «не завершена»;
//   - снятие ждёт блокировки строки сессии, которую держит чужая транзакция,
//     дольше срока запроса → то же, и ОТВЕТ ПРИХОДИТ В СРОК ЗАПРОСА: ожидание
//     снятия ограничено своим пределом, а не сроком вызывающего;
//   - положительный близнец второй сцены: тот же срок, блокировки нет — выход
//     состоялся. Без него отказ второй сцены мог бы прийти от самого срока;
//   - срок запроса истекает, пока операция отмечается завершённой, → операция
//     всё равно завершена: отметка исхода не принадлежит тому, кто ушёл.
//
// ─────────────────────────────────────────────────────────────────────────────
// КАК ВЫЗВАНО ОЖИДАНИЕ — БАЗОЙ, НА НАСТОЯЩЕМ ПУТИ
//
// Долгое снятие — триггер, засыпающий на отметке окончания записи сессии;
// блокировка — `FOR SHARE` на строке сессии, тот самый замок, который держит
// выдача кода авторизации (`lockSessionOfCeremonySQL`). Обработчик собран так,
// как его собирает корень под `own`. База у каждой пробы своя (клон шаблона).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// callerBudget — срок, который вызывающий даёт принудительному выходу в сцене
// блокировки. Пять секунд — тот же срок одного вызова, что край ставит своим
// обращениям к службе (`callTimeout`, `backendCallTimeout`). Проба утверждает,
// что ответ приходит ВНУТРИ него: значит собственный предел ожидания снятия
// короче, и на запись частичного исхода остаётся время.
const callerBudget = 5 * time.Second

// freshBearerDigest — свёртка носителя в форме `human_sessions_bearer_digest_check`,
// своя на каждую запись: ключ уникален. Значение фикстуры, не секрет.
func freshBearerDigest(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return hex.EncodeToString(b)
}

// cutoffRecords — число записей обеих отсечек субъекта.
func cutoffRecords(t *testing.T, ctx context.Context, pool *pgxpool.Pool, uid domain.UserID) (user, minted int) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.user_token_revocations WHERE user_id = $1`,
		string(uid)).Scan(&user))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.minted_token_revocations WHERE subject = $1`,
		string(uid)).Scan(&minted))
	return user, minted
}

// forceLogoutOperationState — терминальность и код ошибки ЕДИНСТВЕННОЙ
// операции принудительного выхода в базе пробы. Код ошибки у незавершённой и у
// успешной операции не записан вовсе (NULL) и читается нулём — `OK`.
func forceLogoutOperationState(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (done bool, errorCode int) {
	t.Helper()
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT done, COALESCE(error_code, 0) FROM kaname.operations WHERE description LIKE 'Force logout%'`).
		Scan(&done, &errorCode), "операция принудительного выхода обязана существовать ровно одна")
	return done, errorCode
}

// installSleepOnSessionEnd — снятие записи сессии идёт `seconds` секунд.
func installSleepOnSessionEnd(t *testing.T, ctx context.Context, pool *pgxpool.Pool, seconds string) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		CREATE FUNCTION kaname.probe_slow_session_end() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_sleep(`+seconds+`);
			RETURN NEW;
		END $$`)
	require.NoError(t, err, "функция долгого снятия")
	_, err = pool.Exec(ctx, `
		CREATE TRIGGER probe_slow_session_end
		BEFORE UPDATE OF ended_at ON kaname.human_sessions
		FOR EACH ROW EXECUTE FUNCTION kaname.probe_slow_session_end()`)
	require.NoError(t, err, "триггер долгого снятия")
}

// awaitNoSleepingBackend — ждёт, пока в базе пробы не останется ни одного
// обслуживающего процесса, спящего в триггере: брошенная по сроку транзакция
// досыпает на сервере, и база пробы не снимается, пока она жива.
func awaitNoSleepingBackend(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var sleeping int
		require.NoError(t, pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND wait_event = 'PgSleep'`).Scan(&sleeping))
		if sleeping == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("в базе пробы осталось %d спящих процессов после 15 с", sleeping)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// requirePartialOutcomeLanded — частичный исход лёг целиком: обе записи
// отсечки, ровно одна запись события «снятие не состоялось» без числа, живая
// сессия цела, ответ `Unavailable`, операция отмечена этой ошибкой.
func requirePartialOutcomeLanded(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	sessions *kanamepg.HumanSessionRepo, uid domain.UserID, digest string, callErr error,
) {
	t.Helper()
	assert.Equal(t, humansession.SessionFound, resolveReason(t, ctx, sessions, digest),
		"фикстура не вызвала отказа снятия — утверждения о частичном исходе ниже судили бы полный")

	user, minted := cutoffRecords(t, ctx, pool, uid)
	assert.Equal(t, 1, user,
		"снятие отказало по сроку, и отсечка не легла: частичный исход не записан вовсе, "+
			"хотя до снятия отсечка стояла при любом его исходе")
	assert.Equal(t, 1, minted, "вторая запись отсечки обязана лечь вместе с первой")

	records := forceLogoutRecords(t, ctx, pool, uid)
	if assert.Len(t, records, 1,
		"снятие отказало по сроку, а записи события о принудительном выходе нет: "+
			"привилегированное действие не оставило следа") {
		assert.Equal(t, "failed", records[0]["session_teardown"],
			"запись частичного исхода обязана сказать, что снятие не состоялось: %v", records[0])
		_, carriesCount := records[0]["sessions_ended"]
		assert.False(t, carriesCount, "запись несостоявшегося снятия не несёт числа снятых: %v", records[0])
	}

	assert.Equal(t, codes.Unavailable, status.Code(callErr),
		"отказ снятия по сроку — состояние, которое проходит; ответ обязан звать повторить, "+
			"а не объявлять службу сломанной: %v", callErr)

	done, errorCode := forceLogoutOperationState(t, ctx, pool)
	assert.True(t, done,
		"операция осталась незавершённой: отметка ошибки шла на истёкшем сроке запроса, "+
			"и опрос будет отвечать «не завершена» вечно")
	assert.Equal(t, int(codes.Unavailable), errorCode,
		"опрос операции обязан увидеть тот же отказ, что получил вызывающий")
}

// TestIntegration_ForceLogoutWhoseTeardownOutlivesTheRequestStillRecordsThePartialOutcome
// — снятие идёт дольше срока запроса. Первая транзакция падает потому, что её
// срок истёк; частичный исход обязан лечь всё равно.
func TestIntegration_ForceLogoutWhoseTeardownOutlivesTheRequestStillRecordsThePartialOutcome(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	_, pool := newForceLogoutHandler(t)
	h := ownPostureForceLogoutHandler(t, pool)
	uid := seedForceLogoutUser(t, ctx, pool)
	digest := freshBearerDigest(t)
	seedOwnLoginSession(t, ctx, pool, uid, digest)
	sessions := kanamepg.NewHumanSessionRepo(pool)
	requireLiveBefore(t, ctx, sessions, digest)

	installSleepOnSessionEnd(t, ctx, pool, "1.5")
	t.Cleanup(func() { awaitNoSleepingBackend(t, ctx, pool) })

	reqCtx, cancel := context.WithTimeout(forceLogoutAdminCtx(), 400*time.Millisecond)
	defer cancel()
	_, err := h.ForceLogout(reqCtx, &iamv1.ForceLogoutRequest{
		UserId: string(uid),
		Reason: "admin-force-logout",
	})
	require.Error(t, err, "неснятая сессия не имеет права читаться как состоявшийся выход")
	require.Error(t, reqCtx.Err(),
		"срок запроса не истёк — проба судила бы не отказ по сроку, а что-то иное")

	requirePartialOutcomeLanded(t, ctx, pool, sessions, uid, digest, err)
}

// TestIntegration_ForceLogoutBlockedOnASessionRowLockAnswersWithinTheCallerBudget
// — строку сессии держит чужая транзакция `FOR SHARE` дольше срока запроса.
// Частичный исход ложится, и ответ приходит В СРОК вызывающего.
func TestIntegration_ForceLogoutBlockedOnASessionRowLockAnswersWithinTheCallerBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	_, pool := newForceLogoutHandler(t)
	h := ownPostureForceLogoutHandler(t, pool)
	uid := seedForceLogoutUser(t, ctx, pool)
	digest := freshBearerDigest(t)
	sid := seedOwnLoginSession(t, ctx, pool, uid, digest)
	sessions := kanamepg.NewHumanSessionRepo(pool)
	requireLiveBefore(t, ctx, sessions, digest)

	// Чужая транзакция держит строку сессии тем замком, которым её держит
	// выдача кода авторизации, и отпускает только после ответа выхода.
	blocker, err := pool.Begin(ctx)
	require.NoError(t, err, "транзакция, держащая строку сессии")
	defer func() { _ = blocker.Rollback(ctx) }()
	var held int
	require.NoError(t, blocker.QueryRow(ctx,
		`SELECT count(*) FROM (SELECT 1 FROM kaname.human_sessions WHERE id = $1 FOR SHARE) s`,
		string(sid)).Scan(&held))
	require.Equal(t, 1, held, "замок не взят — сцена блокировки не построена")

	reqCtx, cancel := context.WithTimeout(forceLogoutAdminCtx(), callerBudget)
	defer cancel()
	started := time.Now()
	_, err = h.ForceLogout(reqCtx, &iamv1.ForceLogoutRequest{
		UserId: string(uid),
		Reason: "admin-force-logout",
	})
	elapsed := time.Since(started)
	require.NoError(t, blocker.Rollback(ctx), "отпустить строку сессии")
	require.Error(t, err, "неснятая сессия не имеет права читаться как состоявшийся выход")

	assert.NoError(t, reqCtx.Err(),
		"ответ пришёл после срока вызывающего (%s): ожидание снятия ограничено его сроком, "+
			"а не своим пределом, — вызывающий ответа не дождётся", elapsed)

	requirePartialOutcomeLanded(t, ctx, pool, sessions, uid, digest, err)
}

// TestIntegration_ForceLogoutUnderTheCallerBudgetWithoutALockEndsTheSession —
// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ сцены блокировки: тот же срок, строку никто не держит —
// выход состоялся, запись говорит «снято» и называет одну запись.
func TestIntegration_ForceLogoutUnderTheCallerBudgetWithoutALockEndsTheSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	_, pool := newForceLogoutHandler(t)
	h := ownPostureForceLogoutHandler(t, pool)
	uid := seedForceLogoutUser(t, ctx, pool)
	digest := freshBearerDigest(t)
	seedOwnLoginSession(t, ctx, pool, uid, digest)
	sessions := kanamepg.NewHumanSessionRepo(pool)
	requireLiveBefore(t, ctx, sessions, digest)

	reqCtx, cancel := context.WithTimeout(forceLogoutAdminCtx(), callerBudget)
	defer cancel()
	_, err := h.ForceLogout(reqCtx, &iamv1.ForceLogoutRequest{
		UserId: string(uid),
		Reason: "admin-force-logout",
	})
	require.NoError(t, err, "без блокировки выход в срок вызывающего обязан состояться")

	assert.Equal(t, humansession.NoSessionEnded, resolveReason(t, ctx, sessions, digest))
	record := requireOneForceLogoutRecord(t, ctx, pool, uid)
	assert.Equal(t, "ended", record["session_teardown"], "%v", record)
	assert.Equal(t, json.Number("1"), record["sessions_ended"], "%v", record)
	done, errorCode := forceLogoutOperationState(t, ctx, pool)
	assert.True(t, done)
	assert.Zero(t, errorCode)
}

// TestIntegration_ForceLogoutWhoseRequestExpiresWhileTheOperationIsMarkedDoneStillCompletesIt
// — выход состоялся и зафиксирован, а срок запроса истёк, пока операция
// отмечалась завершённой. Операция обязана завершиться: иначе опрос вечно
// отвечает «не завершена» о выходе, который уже произошёл.
func TestIntegration_ForceLogoutWhoseRequestExpiresWhileTheOperationIsMarkedDoneStillCompletesIt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	_, pool := newForceLogoutHandler(t)
	h := ownPostureForceLogoutHandler(t, pool)
	uid := seedForceLogoutUser(t, ctx, pool)

	// Отметка операции идёт дольше срока запроса. Создание операции — вставка,
	// а не обновление, и триггер его не задевает.
	_, err := pool.Exec(ctx, `
		CREATE FUNCTION kaname.probe_slow_operation_mark() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_sleep(1.5);
			RETURN NEW;
		END $$`)
	require.NoError(t, err, "функция долгой отметки")
	_, err = pool.Exec(ctx, `
		CREATE TRIGGER probe_slow_operation_mark
		BEFORE UPDATE ON kaname.operations
		FOR EACH ROW EXECUTE FUNCTION kaname.probe_slow_operation_mark()`)
	require.NoError(t, err, "триггер долгой отметки")
	t.Cleanup(func() { awaitNoSleepingBackend(t, ctx, pool) })

	reqCtx, cancel := context.WithTimeout(forceLogoutAdminCtx(), 700*time.Millisecond)
	defer cancel()
	_, err = h.ForceLogout(reqCtx, &iamv1.ForceLogoutRequest{
		UserId: string(uid),
		Reason: "admin-force-logout",
	})
	require.NoError(t, err, "выход зафиксирован — ответ обязан это сказать")
	require.Error(t, reqCtx.Err(),
		"срок запроса не истёк — проба судила бы не отметку на истёкшем сроке")

	record := requireOneForceLogoutRecord(t, ctx, pool, uid)
	require.Equal(t, "ended", record["session_teardown"], "фикстура: выход обязан был состояться: %v", record)

	done, errorCode := forceLogoutOperationState(t, ctx, pool)
	assert.True(t, done,
		"выход состоялся, а операция не завершена: отметка шла на истёкшем сроке запроса, "+
			"и опрос будет отвечать «не завершена» о том, что уже произошло")
	assert.Zero(t, errorCode)
}
