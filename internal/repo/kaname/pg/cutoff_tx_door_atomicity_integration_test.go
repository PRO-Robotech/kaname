// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// cutoff_tx_door_atomicity_integration_test.go — ВТОРАЯ ВЕТВЬ ДВЕРИ ОТСЕЧКИ:
// вызов НА УЖЕ ОТКРЫТОЙ ТРАНЗАКЦИИ ВЫЗЫВАЮЩЕГО (kaname#313).
//
// # ПОЧЕМУ ЭТОТ ПРИБОР ЗАВЕДЁН ОТДЕЛЬНО
//
// Дверь `upsertSubjectCutoff` различает ДВУХ исполнителей: пул и транзакцию
// вызывающего. Пуловую ветвь судит соседняя проба отката на пуле — и она же
// была предъявлена доказательством починки. Прогнанная на коммите-РОДИТЕЛЕ,
// то есть ДО починки, она зеленеет: пуловая ветвь была транзакционной и там.
// Починка меняла ветвь ТРАНЗАКЦИОННУЮ, и ни одна проба её не судила.
//
// # ЧТО ИМЕННО УТВЕРЖДАЕТСЯ
//
// Когда дверь зовут на уже открытой транзакции вызывающего, она НЕ открывает
// своей; при отказе второй записи откатывается вся работа вызывающего, и ни
// одна из двух записей отсечки не остаётся.
//
// # ПОЧЕМУ ПОСЛЕДОВАТЕЛЬНАЯ, А НЕ КОНКУРИРУЮЩАЯ
//
// Предмет — АТОМАРНОСТЬ НА ОТКАЗЕ, а не видимость чужой незакоммиченной
// работы. Для атомарности достаточно отказа второй записи в одном потоке:
// различающее свойство целиком укладывается в исход коммита вызывающего и в
// состояние базы после него. Второй поток не добавил бы ни одного различения и
// добавил бы недетерминизм. Конкуренция понадобилась бы утверждению «сосед не
// видит половины» — это ДРУГОЕ утверждение, и здесь его нет.
//
// # ЧЕМ ВЫЗВАН ОТКАЗ — ВХОДОМ, А НЕ ПОДМЕНОЙ ИСПОЛНИТЕЛЯ
//
// Причина длиной свыше 121 знака проходит ограничение ПЕРВОЙ записи (предел
// причины там 256) и НЕ проходит ограничение ВТОРОЙ: имя механизма выводится
// из причины приставкой `kaname:`, а предел решившего во второй записи 128.
// Отказ приходит от схемы, на законном пути. Подставной исполнитель здесь был
// бы негоден в принципе: предмет — поведение настоящей транзакции, а подделка
// его не различает.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// txDoorRejectedReason — причина, которую ПЕРВАЯ запись принимает, а ВТОРАЯ
// отвергает. Длина выведена из обоих пределов, а не поставлена на глаз: 130
// знаков меньше предела причины первой записи (256) и вместе с приставкой
// механизма (`kaname:`, 7 знаков) больше предела решившего во второй (128).
func txDoorRejectedReason() string { return strings.Repeat("z", 130) }

// txDoorSessionEndedAt — отметка окончания записи сессии; nil означает, что
// сессия жива, то есть работа вызывающего до базы не доехала.
func txDoorSessionEndedAt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sessionID string) *time.Time {
	t.Helper()
	var endedAt *time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT ended_at FROM kaname.human_sessions WHERE id = $1`, sessionID).Scan(&endedAt))
	return endedAt
}

// txDoorRequireCutoffRows — число строк ОБЕИХ записей отсечки у субъекта.
// Обе названы поимённо: «ни одна не осталась» — утверждение о паре, и проверка
// одной из них его не делает.
func txDoorRequireCutoffRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID string, want int) {
	t.Helper()
	for _, q := range []struct{ name, sql string }{
		{"отсечка субъекта",
			`SELECT count(*) FROM kaname.user_token_revocations WHERE user_id = $1`},
		{"отсечка предъявления",
			`SELECT count(*) FROM kaname.minted_token_revocations WHERE subject = $1`},
	} {
		var n int
		require.NoError(t, pool.QueryRow(ctx, q.sql, userID).Scan(&n), q.name)
		require.Equal(t, want, n, "%s: строк %d, ожидалось %d", q.name, n, want)
	}
}

// txDoorTwinSubject — ВТОРОЙ человек сцены, со своей записью сессии.
//
// Заведён здесь, а не вторым вызовом общей сцены, по свойству самой сцены:
// свёртку носителя она выводит из ДЛИНЫ метки, и два её вызова с метками
// равной длины сталкиваются на единственности свёртки. Свойство это
// принадлежит помощнику, а не предмету пробы; здесь оно обойдено, а не
// починено — правка общей фикстуры тронула бы чужие пробы. Находка названа в
// возврате полосы.
//
// Второй субъект нужен отрицанию затем, чтобы «ни одной записи отсечки» было
// СЧЁТНЫМ: у субъекта положительного близнеца обе записи уже стоят.
func txDoorTwinSubject(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	scene domain.CeremonyContext, mark string,
) (userID, sessionID string) {
	t.Helper()
	userID = scene.UserID + "-" + mark
	sessionID = scene.SessionID + "-" + mark
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		SELECT $1, account_id, $2, $3, display_name, invite_status
		  FROM kaname.users WHERE id = $4`,
		userID, "ext-"+userID, userID+"@example.invalid", scene.UserID)
	require.NoError(t, err, "посев второго человека")
	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.human_sessions
		       (id, user_id, bearer_digest, authenticated_at, last_presented_at, expires_at,
		        assurance_level, presented_methods)
		VALUES ($1, $2, $3, now(), now(), now() + interval '1 hour', '1', ARRAY['password'])`,
		sessionID, userID, ceremonyDigest(313000+len(mark)))
	require.NoError(t, err, "посев записи сессии второго человека")
	return userID, sessionID
}

// TestIntegration_TxDoorRollsBackTheCallersWholeWorkWhenTheSecondRecordFails —
// ОТКАЗ ВТОРОЙ ЗАПИСИ НА ТРАНЗАКЦИИ ВЫЗЫВАЮЩЕГО НЕ ОСТАВЛЯЕТ НИЧЕГО: ни
// записей отсечки, ни работы, которую вызывающий сделал ДО двери.
//
// Вызывающий здесь настоящий, а не изображённый пробой: писатель сессий —
// тот самый путь выхода, смены пароля, восстановления и сброса второго
// фактора. Он снимает сессию, затем той же транзакцией кладёт отсечку.
//
// Половина, которую различает проба, ОПАСНА ИМЕННО В ЭТОМ ПОРЯДКЕ: сессия
// снята, отсечки нет — человек числится вышедшим, а прежний носитель
// продолжает аутентифицировать вызовы.
func TestIntegration_TxDoorRollsBackTheCallersWholeWorkWhenTheSecondRecordFails(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	sessions := kanamepg.NewHumanSessionRepo(pool)

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: тот же вызывающий, та же его транзакция, та же
	// дверь, ГОДНАЯ причина. Без него отрицание ниже зеленело бы и на двери,
	// которая на транзакции вызывающего не пишет вообще ничего.
	good := ceremonyScene(t, ctx, pool, "txwgd")
	wOK, err := sessions.Writer(ctx)
	require.NoError(t, err)
	endedOK, err := wOK.EndSession(ctx, domain.HumanSessionID(good.SessionID),
		time.Now().UTC(), domain.RevokeReasonLogout)
	require.NoError(t, err)
	require.True(t, endedOK, "посевная сессия обязана сниматься — иначе близнец беспредметен")
	require.NoError(t, wOK.UpsertCutoff(ctx, domain.UserTokenRevocation{
		UserID:       domain.UserID(good.UserID),
		RevokeBefore: time.Now().UTC(),
		Reason:       domain.RevokeReasonLogout,
	}, ""))
	require.NoError(t, wOK.Commit(ctx))
	txDoorRequireCutoffRows(t, ctx, pool, good.UserID, 1)
	require.NotNil(t, txDoorSessionEndedAt(t, ctx, pool, good.SessionID),
		"на годном входе работа вызывающего обязана встать — иначе проба ничего не различает")

	// ПРЕДМЕТ. Изменённый ФАКТ один — длина причины; субъект и запись сессии
	// свои, потому что отрицанию нужен субъект без стоящей отсечки, чтобы
	// «ни одной записи» было счётным.
	badUser, badSession := txDoorTwinSubject(t, ctx, pool, good, "bd")
	wBad, err := sessions.Writer(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = wBad.Rollback(ctx) })

	// РАБОТА ВЫЗЫВАЮЩЕГО — ДО двери. Не будь её, терять было бы нечего, и
	// утверждение об откате «всей работы» осталось бы без предмета.
	endedBad, err := wBad.EndSession(ctx, domain.HumanSessionID(badSession),
		time.Now().UTC(), domain.RevokeReasonLogout)
	require.NoError(t, err)
	require.True(t, endedBad, "снятие сессии обязано лечь в транзакцию ДО двери")

	require.Error(t, wBad.UpsertCutoff(ctx, domain.UserTokenRevocation{
		UserID:       domain.UserID(badUser),
		RevokeBefore: time.Now().UTC(),
		Reason:       txDoorRejectedReason(),
	}, ""), "вторая запись обязана быть отвергнута схемой — иначе утверждения ниже беспредметны")

	require.Error(t, wBad.Commit(ctx),
		"КОММИТ ВЫЗЫВАЮЩЕГО ПРОШЁЛ ПОСЛЕ ОТКАЗА ДВЕРИ: дверь открыла на чужой "+
			"транзакции СВОЮ — точку сохранения, — отказ второй записи откатился "+
			"к ней, и работа вызывающего доехала до базы БЕЗ отсечки: человек "+
			"числится вышедшим, а прежний носитель продолжает аутентифицировать вызовы")

	require.Nil(t, txDoorSessionEndedAt(t, ctx, pool, badSession),
		"снятие сессии осталось в базе, хотя ни одна запись отсечки не легла: "+
			"снятие доступа исполнено наполовину и выглядит исполненным целиком")
	txDoorRequireCutoffRows(t, ctx, pool, badUser, 0)
}

// TestIntegration_TxDoorRefusalPoisonsTheCallersTransaction — ПОВЕДЕНИЕ ПРИ
// ОТКАЗЕ НАЗВАНО ПРИБОРОМ: отказ второй записи ОТРАВЛЯЕТ транзакцию
// вызывающего, а не откатывается к точке сохранения двери.
//
// Различие это не стилистическое, и молчать о нём нельзя. Откат к точке
// сохранения оставляет транзакцию вызывающего ЖИВОЙ: следующий его оператор
// исполняется, коммит проходит, и вызывающий, не прочитавший отказ двери,
// сохраняет свою половину работы. Отравление не оставляет ему такого выбора —
// а именно этого требует пара записей, которые обязаны лечь вместе.
//
// Прибор судит наблюдаемое: строку состояния, которой Postgres отвечает на
// следующий оператор той же транзакции.
func TestIntegration_TxDoorRefusalPoisonsTheCallersTransaction(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	repo := kanamepg.NewUserTokenRevocationRepo(pool)

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: та же дверь на той же транзакции вызывающего,
	// ГОДНАЯ причина — следующий оператор вызывающего исполняется. Без него
	// отрицание ниже зеленело бы на транзакции, сломанной чем угодно другим.
	good := ceremonyScene(t, ctx, pool, "txpgd")
	txOK, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = txOK.Rollback(ctx) })
	require.NoError(t, repo.UpsertRevokeAllTx(ctx, txOK, domain.UserTokenRevocation{
		UserID:       domain.UserID(good.UserID),
		RevokeBefore: time.Now().UTC(),
		Reason:       domain.RevokeReasonLogout,
	}, ""))
	_, err = txOK.Exec(ctx, `SELECT 1`)
	require.NoError(t, err, "после УСПЕХА двери транзакция вызывающего обязана быть жива")
	require.NoError(t, txOK.Commit(ctx))

	// ПРЕДМЕТ: изменённый факт один — длина причины.
	badUser, _ := txDoorTwinSubject(t, ctx, pool, good, "bd")
	txBad, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = txBad.Rollback(ctx) })
	require.Error(t, repo.UpsertRevokeAllTx(ctx, txBad, domain.UserTokenRevocation{
		UserID:       domain.UserID(badUser),
		RevokeBefore: time.Now().UTC(),
		Reason:       txDoorRejectedReason(),
	}, ""), "вторая запись обязана быть отвергнута схемой — иначе утверждение ниже беспредметно")

	_, nextErr := txBad.Exec(ctx, `SELECT 1`)
	require.Error(t, nextErr,
		"СЛЕДУЮЩИЙ ОПЕРАТОР ВЫЗЫВАЮЩЕГО ИСПОЛНИЛСЯ: дверь откатилась к СВОЕЙ точке "+
			"сохранения, транзакция вызывающего отказа второй записи не заметила, и "+
			"вызывающий волен закоммитить свою половину работы")
	var pgErr *pgconn.PgError
	require.ErrorAs(t, nextErr, &pgErr,
		"отказ обязан прийти строкой состояния сервера, а не обрывом связи")
	require.Equal(t, "25P02", pgErr.Code,
		"транзакция вызывающего отвечает состоянием %q вместо 25P02 "+
			"(«транзакция прервана»): отравления нет", pgErr.Code)
}
