// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package journalwrite_test

// journalwrite_integration_test.go — открывающий пишущей транзакции службы
// выставляет инициатора журнала ЛОКАЛЬНО и в обоих исходах (NTF-3, Р2;
// сценарий NTF3-63).
//
// Соединения контейнера проб несут ролевую настройку инициатора посева
// (`journalfixture`), и это предпосылка, а не помеха: проба утверждает, что
// транзакция продукта её НЕ наследует. Положительный контроль предпосылки —
// первая подпроба: вне транзакции соединение настройку видит.

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/auth"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/journaltx"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/journalwrite"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/testsupport/journalfixture"
)

func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		Name:    "journalwrite",
		Migrate: journalfixture.Migrate(migrations.FS),
	}))
}

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), pgtest.NewDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// insertJournalRow — строка журнала, чей инициатор даёт только умолчание
// колонки; оператор колонку не называет.
const insertJournalRow = `INSERT INTO kaname.resource_journal
	  (resource_kind, resource_id, event_type, payload)
	VALUES ('iam_group', $1, 'CREATED', '{}'::jsonb)
	RETURNING initiator`

func settingIn(t *testing.T, tx pgx.Tx) string {
	t.Helper()
	var got *string
	require.NoError(t, tx.QueryRow(context.Background(),
		`SELECT current_setting($1, true)`, journaltx.SettingInitiator).Scan(&got))
	if got == nil {
		return ""
	}
	return *got
}

func TestWriteOpener_InitiatorIsStatedLocallyInBothOutcomes(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	pool := newPool(t)

	// ПРЕДПОСЫЛКА: соединение контейнера проб несёт ролевого инициатора
	// посева. Без неё «не наследует» ниже было бы утверждением о пустоте.
	var inherited string
	require.NoError(t, pool.QueryRow(ctx, `SELECT current_setting($1, true)`,
		journaltx.SettingInitiator).Scan(&inherited))
	require.Equal(t, journalfixture.FixtureInitiator, inherited,
		"фикстура: соединение не несёт ролевой настройки посева — проба наследования судила бы пустоту")

	usr := ids.NewID(ids.PrefixUser)
	asUser := operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: usr})

	t.Run("принципал с формой инициатора — строка журнала несёт его", func(t *testing.T) {
		tx, err := journalwrite.Begin(asUser, pool)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		require.Equal(t, "user:"+usr, settingIn(t, tx))
		var got string
		require.NoError(t, tx.QueryRow(ctx, insertJournalRow, "grp-jw-user").Scan(&got))
		require.Equal(t, "user:"+usr, got)
	})

	t.Run("принципала нет — отсутствие выставлено, ролевая настройка не унаследована, запись отвергнута 23502", func(t *testing.T) {
		tx, err := journalwrite.Begin(ctx, pool)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		require.Empty(t, settingIn(t, tx),
			"транзакция без принципала унаследовала инициатора соединения")
		var got string
		err = tx.QueryRow(ctx, insertJournalRow, "grp-jw-anon").Scan(&got)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr), "запись без инициатора ПРИНЯТА: %v (%q)", err, got)
		require.Equal(t, "23502", pgErr.Code)
		require.Equal(t, "initiator", pgErr.ColumnName)
	})

	t.Run("принципал без формы инициатора — как без принципала", func(t *testing.T) {
		sys := operations.WithPrincipal(ctx, operations.SystemPrincipal())
		_, ierr := auth.InitiatorOf(operations.SystemPrincipal())
		require.ErrorIs(t, ierr, auth.ErrNoInitiator, "фикстура: системный принципал обрёл форму инициатора")
		tx, err := journalwrite.Begin(sys, pool)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		require.Empty(t, settingIn(t, tx))
	})

	t.Run("уровень изоляции вызывающего доходит до транзакции помощника", func(t *testing.T) {
		tx, err := journalwrite.BeginTx(asUser, pool, pgx.TxOptions{IsoLevel: pgx.Serializable})
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		var level string
		require.NoError(t, tx.QueryRow(ctx, `SHOW transaction_isolation`).Scan(&level))
		require.Equal(t, "serializable", level)
		require.Equal(t, "user:"+usr, settingIn(t, tx))
	})

	t.Run("читающая транзакция открывающим не открывается", func(t *testing.T) {
		_, err := journalwrite.BeginTx(asUser, pool, pgx.TxOptions{AccessMode: pgx.ReadOnly})
		require.Error(t, err)
	})
}
