// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// active_identity_producers_integration_test.go — производитель строки `ACTIVE`
// получает отказ, если способа входа он не заводит (задача
// PRO-Robotech/kaname#608, приёмка `active-identity-has-a-way-in.md` AWI-01,
// AWI-08). Предмет — ОТКАЗ ПРОИЗВОДИТЕЛЯ, а не схемы: оператор
// `userWriter.InsertActive` (внутреннее заведение личности) исполняется своим
// путём, транзакцией писателя репозитория, и фиксация отвергается отложенным
// ключом. Отказ переводится в внутреннюю ошибку без текста драйвера: строку
// без способа входа производит НАШ код, а не ввод вызывающего.
//
// Близнец — тот же производитель с паролем той же транзакцией: единственный
// отличающий факт — строка пароля.

import (
	"bytes"
	"context"
	stderrors "errors"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

func TestIntegration_ActiveProducerWithoutAWayInIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	produce := func(withPassword bool) (domain.UserID, error) {
		uid := domain.UserID(ids.NewID(domain.PrefixUser))
		acc := domain.AccountID(ids.NewID(domain.PrefixAccount))
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		w := &writeTx{readTx: readTx{tx: tx}}
		defer func() { _ = w.Rollback(ctx) }()
		_, err = w.UsersW().InsertActive(ctx, domain.User{
			ID: uid, AccountID: acc, ExternalID: domain.ExternalSubject("ext-awi-" + string(uid)),
			Email: domain.Email("awi-" + string(uid) + "@example.invalid"), DisplayName: "AWI",
			InviteStatus: domain.InviteStatusActive,
		})
		require.NoError(t, err, "вставка сама по себе проходит: проверка отложена")
		_, err = w.AccountsW().Insert(ctx, domain.Account{ID: acc, Name: domain.AccountName("awi-" + string(acc[len(acc)-6:])), OwnerUserID: uid, Labels: domain.Labels{}})
		require.NoError(t, err)
		if withPassword {
			v, verr := domain.NewLoginVerifier("$2a$12$awi.producer.twin")
			require.NoError(t, verr)
			_, err = insertLoginMethod(ctx, tx, domain.LoginMethod{
				UserID: uid, Kind: domain.LoginMethodPassword, Verifier: v, State: domain.LoginMethodStateActive,
			})
			require.NoError(t, err)
		}
		return uid, w.Commit(ctx)
	}

	uid, err := produce(false)
	require.Error(t, err, "AWI-01: InsertActive без способа входа зафиксирован — производитель тупика не получил отказа")
	require.True(t, stderrors.Is(err, iamerr.ErrInternal), "отказ — наш дефект, а не ввод вызывающего: %v", err)
	require.NotContains(t, err.Error(), "violates", "текст драйвера наружу не выходит")
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE id = $1`, string(uid)).Scan(&n))
	require.Zero(t, n, "после отказа строки личности нет")
	require.Contains(t, logBuf.String(), "users_active_has_a_way_in_fk", "журнал называет ограничение")

	twin, err := produce(true)
	require.NoError(t, err, "близнец: тот же производитель с паролем той же транзакцией фиксируется")
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE id = $1`, string(twin)).Scan(&n))
	require.Equal(t, 1, n)
}
