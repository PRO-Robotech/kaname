// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// human_session_writer_login_method_integration_test.go — чтение строки способа
// входа ПИСАТЕЛЕМ сессии (`humansession.Writer.LoginMethod`; задача
// PRO-Robotech/kaname#305), против настоящего Postgres.
//
// Завершение восстановления доступа читает заведённые способы входа ПОСЛЕ
// применения кода, транзакцией записи: до точки решения чтение сделало бы
// полосы отказа «адрес есть» и «адреса нет» неравными по работе. Пробы этого
// файла утверждают три свойства чтения:
//
//   - ответ тот же, что у `LoginMethodRepo.Get` пулом: строка есть — та же
//     строка; строки этого вида нет — NOT_FOUND;
//   - чтение идёт соединением САМОЙ транзакции, второго из пула не берёт: в пуле
//     из одного соединения, занятого открытой транзакцией, чтение писателем
//     проходит в срок. Положительный контроль той же формы — `Get` пулом на том
//     же сроке упирается в срок: без него «прошло» было бы неотличимо от «пул и
//     не был занят»;
//   - транзакция видит свою запись: второй фактор, снятый ею, для её чтения уже
//     снят, а после отката — на месте.
package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestHumanSessionWriter_LoginMethodReadsOnTheTransactionsOwnConnection(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(pgtest.NewDB(t))
	require.NoError(t, err)
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	person := lmPeople(t, pool, "wlm", 1)[0]
	_, err = pool.Exec(ctx, `INSERT INTO user_login_methods (user_id, kind, verifier, state)
		VALUES ($1, 'password', 'material-password-wlm', 'active'), ($1, 'totp', 'material-totp-wlm', 'active')`,
		string(person))
	require.NoError(t, err, "Дано: пароль и заведённый второй фактор")
	methods := pg.NewLoginMethodRepo(pool)
	base, err := methods.Get(ctx, person, domain.LoginMethodTOTP)
	require.NoError(t, err, "Дано: строка второго фактора читается пулом")

	w, err := pg.NewHumanSessionRepo(pool).Writer(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Rollback(context.Background()) })

	// Срок, в который уложится обход базы и не уложится ожидание соединения.
	const within = 2 * time.Second
	bounded := func() (context.Context, context.CancelFunc) { return context.WithTimeout(ctx, within) }

	// Положительный контроль — ПЕРВЫМ: единственное соединение занято
	// транзакцией, и чтение пулом ждёт его до срока.
	cctx, cancel := bounded()
	_, err = methods.Get(cctx, person, domain.LoginMethodTOTP)
	cancel()
	require.Error(t, err, "контроль: пул из одного соединения занят открытой транзакцией — чтение пулом обязано "+
		"упереться в срок; иначе проба ниже ничего не различает")

	cctx, cancel = bounded()
	got, err := w.LoginMethod(cctx, person, domain.LoginMethodTOTP)
	cancel()
	require.NoError(t, err, "чтение писателем идёт соединением транзакции и второго соединения не ждёт")
	require.Equal(t, base.UserID, got.UserID)
	require.Equal(t, base.Kind, got.Kind)
	require.Equal(t, base.State, got.State)
	require.True(t, base.CreatedAt.Equal(got.CreatedAt), "та же строка, что у Get: %v против %v", got.CreatedAt, base.CreatedAt)
	require.False(t, got.Verifier.IsZero(), "материал в своём типе")

	_, err = w.LoginMethod(ctx, person, domain.LoginMethodLookupSecret)
	require.ErrorIs(t, err, iamerr.ErrNotFound, "строки вида нет — NOT_FOUND, как у Get")

	removed, err := w.RemoveSecondFactor(ctx, person)
	require.NoError(t, err)
	require.True(t, removed, "Дано: транзакция снимает второй фактор")
	_, err = w.LoginMethod(ctx, person, domain.LoginMethodTOTP)
	require.ErrorIs(t, err, iamerr.ErrNotFound, "транзакция видит свою запись: снятая ею строка для её чтения снята")

	require.NoError(t, w.Rollback(ctx))
	after, err := methods.Get(ctx, person, domain.LoginMethodTOTP)
	require.NoError(t, err, "после отката строка на месте")
	require.Equal(t, domain.LoginMethodStateActive, after.State)
}
