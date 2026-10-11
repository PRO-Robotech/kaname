// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// person_and_account_keys_test.go — гейт ведомости ключей на `users` и
// `accounts` (KN664-60, KN664-61): судья на синтетике, в обе стороны, и
// держатель на НАКАТАННОЙ схеме с инъекцией настоящего ключа.
package migrations_test

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

func syntheticKey(name, table, refs, act string) migrations.ForeignKeyOnPersonOrAccount {
	return migrations.ForeignKeyOnPersonOrAccount{Name: name, Table: table, References: refs, OnDelete: act}
}

func ledgerRow(k migrations.ForeignKeyOnPersonOrAccount, reason string) migrations.KeyLedgerRow {
	return migrations.KeyLedgerRow{ForeignKeyOnPersonOrAccount: k, Reason: reason}
}

// TestPersonAndAccountKeysJudgeBothWays — судья на синтетике: законный близнец
// молчит, каждый дефект называет свою координату, пустой обход — не вердикт.
func TestPersonAndAccountKeysJudgeBothWays(t *testing.T) {
	home := syntheticKey("users_account_fk", "users", "accounts", "SET NULL")
	sessions := syntheticKey("human_sessions_user_fk", "human_sessions", "users", "CASCADE")
	ledger := []migrations.KeyLedgerRow{ledgerRow(home, "дом пустеет со снятием аккаунта"), ledgerRow(sessions, "сессии уходят с человеком")}

	t.Run("законный близнец молчит", func(t *testing.T) {
		got, err := migrations.JudgePersonAndAccountKeys([]migrations.ForeignKeyOnPersonOrAccount{home, sessions}, ledger)
		require.NoError(t, err)
		require.Empty(t, got)
	})
	t.Run("ключ без строки назван", func(t *testing.T) {
		injected := syntheticKey("kn664_injected_fk", "session_revocations", "users", "RESTRICT")
		got, err := migrations.JudgePersonAndAccountKeys([]migrations.ForeignKeyOnPersonOrAccount{home, sessions, injected}, ledger)
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.Contains(t, got[0], "kn664_injected_fk")
		require.Contains(t, got[0], "RESTRICT")
	})
	t.Run("сменённое действие названо", func(t *testing.T) {
		changed := syntheticKey("users_account_fk", "users", "accounts", "RESTRICT")
		got, err := migrations.JudgePersonAndAccountKeys([]migrations.ForeignKeyOnPersonOrAccount{changed, sessions}, ledger)
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.Contains(t, got[0], "users_account_fk")
	})
	t.Run("истёкшая строка названа", func(t *testing.T) {
		got, err := migrations.JudgePersonAndAccountKeys([]migrations.ForeignKeyOnPersonOrAccount{home}, ledger)
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.Contains(t, got[0], "human_sessions_user_fk")
		require.Contains(t, got[0], "истекла")
	})
	t.Run("строка без довода названа", func(t *testing.T) {
		got, err := migrations.JudgePersonAndAccountKeys([]migrations.ForeignKeyOnPersonOrAccount{home},
			[]migrations.KeyLedgerRow{ledgerRow(home, " ")})
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.Contains(t, got[0], "без довода")
	})
	t.Run("пустой обход — не вердикт", func(t *testing.T) {
		_, err := migrations.JudgePersonAndAccountKeys(nil, ledger)
		require.True(t, errors.Is(err, migrations.ErrNoKeysWalked))
	})
}

// TestPersonAndAccountKeysLedgerParses — ведомость читается, и поле с опечаткой
// отвергается, а не читается строкой без довода.
func TestPersonAndAccountKeysLedgerParses(t *testing.T) {
	rows, err := migrations.ParseKeyLedger(migrations.PersonAndAccountKeysLedger)
	require.NoError(t, err)
	require.NotEmpty(t, rows, "ведомость пуста — сверять нечего")
	_, err = migrations.ParseKeyLedger([]byte(`{"keys":[{"name":"x","table":"t","references":"users","on_delete":"CASCADE","reson":"typo"}]}`))
	require.Error(t, err)
}

// keysOnPersonAndAccount — ключи каталога на `users` и `accounts`.
func keysOnPersonAndAccount(t *testing.T, db *sql.DB) []migrations.ForeignKeyOnPersonOrAccount {
	t.Helper()
	rows, err := db.Query(`
		SELECT c.conname, src.relname, dst.relname, c.confdeltype::text
		  FROM pg_constraint c
		  JOIN pg_class src ON src.oid = c.conrelid
		  JOIN pg_class dst ON dst.oid = c.confrelid
		  JOIN pg_namespace n ON n.oid = dst.relnamespace
		 WHERE c.contype = 'f' AND n.nspname = 'kaname' AND dst.relname IN ('users', 'accounts')
		 ORDER BY c.conname`)
	require.NoError(t, err)
	defer rows.Close()
	var out []migrations.ForeignKeyOnPersonOrAccount
	for rows.Next() {
		var k migrations.ForeignKeyOnPersonOrAccount
		var code string
		require.NoError(t, rows.Scan(&k.Name, &k.Table, &k.References, &code))
		word, werr := migrations.OnDeleteWord(code)
		require.NoError(t, werr)
		k.OnDelete = word
		out = append(out, k)
	}
	require.NoError(t, rows.Err())
	return out
}

func fullyMigrated(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."))
	return db
}

// TestKN664_60_EveryKeyOnPersonAndAccountIsLedgered — KN664-60: на накатанной
// схеме каждый ключ записан, и обход печатает объём осмотренного.
func TestKN664_60_EveryKeyOnPersonAndAccountIsLedgered(t *testing.T) {
	db := fullyMigrated(t)
	ledger, err := migrations.ParseKeyLedger(migrations.PersonAndAccountKeysLedger)
	require.NoError(t, err)
	found := keysOnPersonAndAccount(t, db)
	t.Logf("KN664-60: осмотрено ключей на users и accounts: %d; строк ведомости: %d", len(found), len(ledger))
	findings, err := migrations.JudgePersonAndAccountKeys(found, ledger)
	require.NoError(t, err)
	require.Empty(t, findings, "ключи без ведомости или ведомость без ключей:\n  %s", strings.Join(findings, "\n  "))
}

// TestKN664_61_NewRestrictKeyWithoutALedgerRowIsFound — KN664-61, близнец
// KN664-60: тот же обход, плюс НАСТОЯЩИЙ ключ RESTRICT на users.
func TestKN664_61_NewRestrictKeyWithoutALedgerRowIsFound(t *testing.T) {
	db := fullyMigrated(t)
	_, err := db.Exec(`ALTER TABLE kaname.session_revocations
		ADD CONSTRAINT kn664_injected_fk FOREIGN KEY (user_id) REFERENCES kaname.users(id) ON DELETE RESTRICT`)
	require.NoError(t, err)
	ledger, err := migrations.ParseKeyLedger(migrations.PersonAndAccountKeysLedger)
	require.NoError(t, err)
	findings, err := migrations.JudgePersonAndAccountKeys(keysOnPersonAndAccount(t, db), ledger)
	require.NoError(t, err)
	require.Len(t, findings, 1, "инъекция одного ключа обязана дать ровно одну находку: %v", findings)
	require.Contains(t, findings[0], "kn664_injected_fk")
	require.Contains(t, findings[0], "RESTRICT")
}
