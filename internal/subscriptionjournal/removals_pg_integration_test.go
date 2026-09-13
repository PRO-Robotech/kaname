// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package subscriptionjournal_test

// removals_pg_integration_test.go — адаптер журнала читает НАСТОЯЩИЕ строки,
// написанные НАСТОЯЩИМИ триггерами.
//
// Пробы с подставной дверью (`narrow_test.go`) утверждают развилку клиента и
// ничего не говорят о том, совпадает ли форма захваченной области с той, что
// пишет схема. Разойдись они — обе пробы остались бы зелёными: это ровно тот
// разрыв, который не виден ни с одной стороны по отдельности.

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/subscriptionjournal"
)

func TestMain(m *testing.M) {
	os.Exit(pgtest.Run(m, pgtest.Config{
		Name:    "subscriptionjournal",
		Migrate: pgtest.Goose(migrations.FS),
	}))
}

// freshSchema — своя база с накатанной цепью миграций.
func freshSchema(t *testing.T) (*pgxpool.Pool, *sql.DB) {
	t.Helper()
	dsn := pgtest.NewEmptyDB(t)

	sqlDB, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	goose.SetLogger(goose.NopLogger())
	require.NoError(t, goose.Up(sqlDB, "."))

	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool, sqlDB
}

// TestIntegration_CapturedScopesReadWhatTheTriggersWrote — форма, которую пишет
// схема, и форма, которую читает адаптер, суть ОДНА форма.
func TestIntegration_CapturedScopesReadWhatTheTriggersWrote(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	pool, db := freshSchema(t)

	_, err := db.ExecContext(ctx, `
		INSERT INTO kaname.users (id, external_id, email, account_id)
		VALUES ('usr-own', 'usr-own', 'own@example.test', 'acc-x');
		INSERT INTO kaname.accounts (id, name, owner_user_id)
		VALUES ('acc-x', 'acc-x', 'usr-own');
		INSERT INTO kaname.groups (id, account_id, name)
		VALUES ('grp-live', 'acc-x', 'live'), ('grp-gone', 'acc-x', 'gone');`)
	require.NoError(t, err)

	_, err = db.ExecContext(ctx, `DELETE FROM kaname.groups WHERE id = 'grp-gone'`)
	require.NoError(t, err)

	got, err := subscriptionjournal.NewPoolRemovalScopes(pool).
		CapturedScopes(ctx, "iam_group", []string{"grp-live", "grp-gone"})
	require.NoError(t, err)

	assert.Equal(t,
		[]subscriptionjournal.Scope{{Type: "account", ID: "acc-x"}}, got["grp-gone"],
		"область снятого предмета обязана прочитаться ровно той, какой её "+
			"записал триггер: разойдись формы — обе стороны остались бы зелёными")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ в том же прогоне: живой предмет в ответе
	// ОТСУТСТВУЕТ, и это то, чем клиент отличает снятие от жизни.
	_, live := got["grp-live"]
	assert.False(t, live,
		"живой предмет в ответе быть не должен: присутствие ключа и есть "+
			"признак снятия, и по нему клиент решает, спрашивать ли область")
}

// TestIntegration_CapturedScopesAnswerTheFreshestRow — предметом вопроса
// является ПОСЛЕДНЯЯ строка, а не любая.
func TestIntegration_CapturedScopesAnswerTheFreshestRow(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	pool, db := freshSchema(t)

	_, err := db.ExecContext(ctx, `
		INSERT INTO kaname.users (id, external_id, email, account_id)
		VALUES ('usr-own', 'usr-own', 'own@example.test', 'acc-y');
		INSERT INTO kaname.accounts (id, name, owner_user_id)
		VALUES ('acc-y', 'acc-y', 'usr-own');
		INSERT INTO kaname.groups (id, account_id, name)
		VALUES ('grp-edit', 'acc-y', 'edit');
		UPDATE kaname.groups SET description = 'изменено' WHERE id = 'grp-edit';`)
	require.NoError(t, err)

	got, err := subscriptionjournal.NewPoolRemovalScopes(pool).
		CapturedScopes(ctx, "iam_group", []string{"grp-edit"})
	require.NoError(t, err)

	_, removed := got["grp-edit"]
	assert.False(t, removed,
		"у предмета есть строки создания и правки, но свежая — не снятие: "+
			"предикат «где-нибудь есть снятие» отвечал бы здесь неверно")
}
