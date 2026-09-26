// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// oauth_ceremony_call_end_integration_test.go — отказ хранилища церемонии на
// КОНЧИВШЕМСЯ контексте вызова порта несёт конец контекста в цепочке (задача
// PRO-Robotech/kaname#423, столкновение с правилом kaname#383 в сборке 425).
//
// Пул службы доводит отмену до сервера (`coredb.NewPool`, CancelRequest), и
// оператор снимается там строкой состояния 57014 — без ошибки контекста в
// цепочке. Мост церемонии фундамента судит отказ порта по цепочке: без конца
// контекста в ней срок вызова, истёкший на ожидании хранилища, уезжает отказом
// сервера (500), а не временной недоступностью (503).
//
// Различает два случая ровно один факт — кончился ли контекст вызова. Близнец —
// тот же 57014 от собственного потолка оператора на ЖИВОМ контексте: он отказ
// хранилища, а не конец вызова, и повтором не лечится.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/pgtest"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// lockClientsTable — держатель: транзакция на ОТДЕЛЬНОЙ связи держит таблицу
// клиентов церемонии замком, несовместимым с чтением. Каждый оператор
// хранилищ, читающий её, стоит на сервере, пока держатель не отпустит.
func lockClientsTable(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err, "связь держателя")
	tx, err := conn.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `LOCK TABLE kaname.interactive_clients IN ACCESS EXCLUSIVE MODE`)
	require.NoError(t, err, "замок держателя")
	t.Cleanup(func() {
		_ = tx.Rollback(context.Background())
		_ = conn.Close(context.Background())
	})
}

func TestCeremonyVaults_StoreFailureOnAnEndedCallCarriesTheEndOfTheCall(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	v := kanamepg.NewCeremonyVaults(pool)

	calls := []struct {
		name string
		call func(context.Context) error
	}{
		{"LookupClient", func(c context.Context) error { _, e := v.LookupClient(c, "client-held"); return e }},
		{"FetchAuthorizationCode", func(c context.Context) error {
			_, e := v.FetchAuthorizationCode(c, ceremonyDigest(0x7e0001))
			return e
		}},
		{"FetchRefreshToken", func(c context.Context) error {
			_, e := v.FetchRefreshToken(c, ceremonyDigest(0x7e0002))
			return e
		}},
	}

	// Контроль без держателя: ответ хранилища — «записи нет», а не отказ.
	for _, c := range calls {
		err := c.call(ctx)
		require.Error(t, err, "%s: контроль", c.name)
		require.NotErrorIs(t, err, iamerr.ErrInternal, "%s: контроль без держателя — отказ хранилища", c.name)
	}

	lockClientsTable(t, ctx, dsn)

	for _, c := range calls {
		t.Run(c.name+"/срок истёк на ожидании хранилища", func(t *testing.T) {
			callCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
			defer cancel()
			err := c.call(callCtx)
			require.Error(t, err)
			require.ErrorIs(t, err, context.DeadlineExceeded,
				"%s: отказ хранилища на истёкшем сроке вызова не несёт конца срока: %v", c.name, err)
		})
	}
	t.Run("LookupClient/отмена на ожидании хранилища", func(t *testing.T) {
		callCtx, cancel := context.WithCancel(ctx)
		time.AfterFunc(300*time.Millisecond, cancel)
		err := calls[0].call(callCtx)
		require.Error(t, err)
		require.ErrorIs(t, err, context.Canceled,
			"отказ хранилища на отменённом вызове не несёт отмены: %v", err)
	})
}

// Близнец: 57014 от собственного потолка оператора на ЖИВОМ контексте — отказ
// хранилища, конец вызова ему не приписывается.
func TestCeremonyVaults_StatementCeilingOnALiveCallStaysAStoreFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	pool, err := coredb.NewPool(ctx, dsn+sep+"pool_max_conns=1")
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	// Потолок оператора единственной связи пула — короткий: пул связи не
	// сбрасывает, и следующий вызов исполнится на ней же.
	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, `SET statement_timeout = '300ms'`)
	conn.Release()
	require.NoError(t, err)

	v := kanamepg.NewCeremonyVaults(pool)
	lockClientsTable(t, ctx, dsn)

	_, err = v.LookupClient(ctx, "client-held")
	require.Error(t, err)
	require.ErrorIs(t, err, iamerr.ErrInternal, "потолок оператора — не отказ хранилища: %v", err)
	require.NotErrorIs(t, err, context.DeadlineExceeded, "живому вызову приписан конец срока")
	require.NotErrorIs(t, err, context.Canceled, "живому вызову приписана отмена")
}
