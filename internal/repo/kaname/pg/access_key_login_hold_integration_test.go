// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_key_login_hold_integration_test.go — строка ключа под замком
// транзакции выдачи входа ключом (`humanSessionWriter.HoldAccessKeyForLogin`,
// задача PRO-Robotech/kaname#669, Ф13 Р8, Р15), против настоящего Postgres.
//
//   - исходы оператора: свой ключ — взят; ключ другой личности и снятый —
//     одно «строки нет»; без захвата личности той же транзакции — отказ без
//     обхода базы (порядок «личность → ключ»);
//   - МЕХАНИЗМ: пока выдача держит строку, удаление этой строки (оператор
//     снятия) ждёт её фиксации — проверено ожиданием настоящего замка
//     (`lock_timeout`), а не чтением кода; сдвиг счётчика тем же ключом НЕ
//     ждёт (близнец силы замка).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestF13_21_HoldAccessKeyForLoginOutcomes(t *testing.T) {
	pool := akPool(t)
	akCeiling(t, pool, 10)
	repo := pg.NewAccessKeyRepo(pool)
	people := lmPeople(t, pool, "akhold", 2)
	own := akInsert(t, repo, akKey(people[0], "hold-own"))
	foreign := akInsert(t, repo, akKey(people[1], "hold-foreign"))
	ctx := context.Background()
	sessions := pg.NewHumanSessionRepo(pool)

	// Без захвата личности — отказ без обхода базы.
	w, err := sessions.Writer(ctx)
	require.NoError(t, err)
	err = w.HoldAccessKeyForLogin(ctx, people[0], own.ID)
	require.ErrorIs(t, err, iamerr.ErrInternal, "строка ключа берётся только после личности той же транзакции")
	require.NoError(t, w.Rollback(ctx))

	w, err = sessions.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	_, _, err = w.LockPersonForLogin(ctx, people[0])
	require.NoError(t, err)
	require.NoError(t, w.HoldAccessKeyForLogin(ctx, people[0], own.ID), "свой ключ — взят")
	require.ErrorIs(t, w.HoldAccessKeyForLogin(ctx, people[0], foreign.ID), iamerr.ErrNotFound,
		"ключ другой личности — «строки нет»")
	require.ErrorIs(t, w.HoldAccessKeyForLogin(ctx, people[0], domain.AccessKeyID("ak-0000000000000000z")), iamerr.ErrNotFound,
		"снятый (несуществующий) ключ — «строки нет»")
}

// lockWaitRefused — оператор отвергнут по `lock_timeout` (55P03): он ЖДАЛ
// замка, а не исполнился.
func lockWaitRefused(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "55P03"
}

func TestF13_21_HeldAccessKeyBlocksItsDeletionButNotTheCounter(t *testing.T) {
	pool := akPool(t)
	akCeiling(t, pool, 10)
	repo := pg.NewAccessKeyRepo(pool)
	people := lmPeople(t, pool, "akheld", 1)
	k := akInsert(t, repo, akKey(people[0], "held"))
	ctx := context.Background()

	w, err := pg.NewHumanSessionRepo(pool).Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	_, _, err = w.LockPersonForLogin(ctx, people[0])
	require.NoError(t, err)
	require.NoError(t, w.HoldAccessKeyForLogin(ctx, people[0], k.ID))

	// Встречные операторы — своим соединением с коротким ожиданием замка.
	try := func(sql string, args ...any) error {
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		_, err = tx.Exec(ctx, `SET LOCAL lock_timeout = '300ms'`)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, sql, args...)
		return err
	}
	// Близнец силы замка: сдвиг счётчика (неключевые колонки) не ждёт.
	require.NoError(t, try(`UPDATE kaname.user_access_keys SET last_used_at = $2 WHERE id = $1`, string(k.ID), time.Now().UTC()),
		"сдвиг счётчика тем же ключом совместим с замком выдачи")
	// Удаление строки (оператор снятия) ждёт фиксации выдачи.
	err = try(`DELETE FROM kaname.user_access_keys WHERE user_id = $1 AND id = $2`, string(people[0]), string(k.ID))
	require.Truef(t, lockWaitRefused(err), "удаление строки ключа обязано ждать выдачу, держащую строку; получено %v", err)
}
