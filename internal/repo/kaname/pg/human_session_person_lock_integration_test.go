// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// human_session_person_lock_integration_test.go — СНЯТИЕ НЕСКОЛЬКИХ ЗАПИСЕЙ
// СЕССИИ ЧЕЛОВЕКА БЕРЁТ ЕГО СТРОКУ ЛИЧНОСТИ РАНЬШЕ ЛЮБОЙ ЕГО СТРОКИ СЕССИИ
// (задача kaname#340).
//
// Дверь `EndOtherSessions` — единственный оператор, СНИМАЮЩИЙ (отметкой
// окончания) несколько записей сессии одного человека (`endSessionsOfSQL`).
// Её вызывающие и прочие писатели нескольких строк сессии — перепись с
// предикатом у `lockPersonForSessionSetSQL`; двое из вызывающих после неё
// пишут в свою запись, то есть берут строки сессии «прочие → своя»;
// принудительный выход берёт все одним оператором в порядке просмотра. Общий
// полный порядок у них даёт только сериализация на строке личности, взятой ДО
// первой строки сессии, — и берёт её сама дверь, чтобы порядок не зависел от
// того, помнит ли о нём вызывающий.
//
// Утверждается наблюдаемое чужой транзакцией:
//
//   - после снятия строку личности держит замок, конфликтующий с другим
//     писателем нескольких сессий (`FOR NO KEY UPDATE … NOWAIT` отказывает
//     `55P03`), — и совместимый с проверкой внешнего ключа вставки сессии и
//     выдачи кода (`FOR KEY SHARE … NOWAIT` проходит): их эта сериализация не
//     останавливает. Выдачу входа она останавливает — её захват строки
//     личности `FOR SHARE` с этим замком конфликтует, и так решено kaname#385
//     (`human_session_login_capture_integration_test.go`);
//   - одна транзакция не сериализуется на ДВУХ личностях: порядок между
//     личностями не задан никем, и вторая дверь отказывает. Законный близнец —
//     повтор той же личности в той же транзакции.

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// personRowLockAttempt — чужая транзакция пробует взять строку личности
// замком `strength` без ожидания. nil — взяла; иначе отказ базы.
func personRowLockAttempt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID, strength string) error {
	t.Helper()
	_, err := pool.Exec(ctx, `SELECT 1 FROM kaname.users WHERE id = $1 FOR `+strength+` NOWAIT`, userID)
	return err
}

func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if stderrors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func TestIntegration_EndingSeveralSessionsHoldsThePersonRowFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	scene := ceremonyScene(t, ctx, pool, "psnk1")

	w, err := kanamepg.NewHumanSessionRepo(pool).Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()

	require.NoError(t, personRowLockAttempt(t, ctx, pool, scene.UserID, "NO KEY UPDATE"),
		"фикстура: до снятия строку личности не держит никто")

	n, err := w.EndOtherSessions(ctx, domain.UserID(scene.UserID), "", time.Now().UTC(), domain.RevokeReasonLogout)
	require.NoError(t, err)
	require.Equal(t, 1, n, "фикстура: снята ровно посеянная запись")

	refused := personRowLockAttempt(t, ctx, pool, scene.UserID, "NO KEY UPDATE")
	assert.Equal(t, "55P03", sqlState(refused),
		"после снятия строку личности не держит никто: второй писатель нескольких сессий того же "+
			"человека возьмёт его строки сессии в своём порядке — навстречу этому (%v)", refused)
	assert.NoError(t, personRowLockAttempt(t, ctx, pool, scene.UserID, "KEY SHARE"),
		"замок строки личности сильнее нужного: он останавливает проверку внешнего ключа — "+
			"вставку записи сессии и выдачу кода")
}

func TestIntegration_OneTransactionDoesNotSerializeOnTwoPersons(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	first := ceremonyScene(t, ctx, pool, "pstwa")
	second := ceremonyScene(t, ctx, pool, "pstwbb")
	repo := kanamepg.NewHumanSessionRepo(pool)

	t.Run("та же личность дважды", func(t *testing.T) {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()
		_, err = w.EndOtherSessions(ctx, domain.UserID(first.UserID), "", time.Now().UTC(), domain.RevokeReasonLogout)
		require.NoError(t, err)
		_, err = w.EndOtherSessions(ctx, domain.UserID(first.UserID), "", time.Now().UTC(), domain.RevokeReasonLogout)
		assert.NoError(t, err, "повтор той же личности — не вторая личность")
	})

	t.Run("вторая личность", func(t *testing.T) {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()
		_, err = w.EndOtherSessions(ctx, domain.UserID(first.UserID), "", time.Now().UTC(), domain.RevokeReasonLogout)
		require.NoError(t, err)
		_, err = w.EndOtherSessions(ctx, domain.UserID(second.UserID), "", time.Now().UTC(), domain.RevokeReasonLogout)
		assert.True(t, stderrors.Is(err, iamerr.ErrInternal),
			"транзакция сериализовалась на второй личности: две такие транзакции во встречном "+
				"порядке личностей блокируют друг друга (%v)", err)
	})
}
