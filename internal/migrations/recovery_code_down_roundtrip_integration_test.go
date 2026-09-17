// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// recovery_code_down_roundtrip_integration_test.go — откат миграции
// `20260917015400_recovery_code_is_our_record` восстанавливает прежнее: словарь
// очереди писем из одного вида, обязательный внешний субъект журнала
// завершений, отсутствие таблицы кодов; повторный накат сходится (Ф5, kacho#1271).
//
// Откат идёт ДО СВОЕЙ миграции, а не «на один шаг» (см. пробу отката потолков:
// «на один шаг» утверждало бы, что предмет — последняя миграция дерева).

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

func TestRecoveryCodeMigration_DownRestoresTheSingleKindAndTheReapplyConverges(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."))

	insertKind := func(kind, id string) error {
		_, err := db.Exec(`INSERT INTO kaname.invite_mail_outbox (event_type, payload, resource_kind, resource_id)
			VALUES ($1, '{"to":"who@example.invalid","user_id":"usr-x","code":"AAAAA-AAAAA"}'::jsonb, 'RecoveryMail', $2)`, kind, id)
		return err
	}
	var recoveryRows int
	require.NoError(t, insertKind("mail.recovery.send", "usr-rt-1"), "на голове второй вид принимается")
	_, err = db.Exec(`INSERT INTO kaname.recovery_completions (recovery_jti, external_id, user_id) VALUES ('rcv-rt', NULL, 'usr-x')`)
	require.NoError(t, err, "на голове журнал принимает поток без внешнего субъекта")

	const recoveryVersion int64 = 20260917015400
	steps := 0
	for {
		v, verr := goose.GetDBVersion(db)
		require.NoError(t, verr)
		if v < recoveryVersion {
			break
		}
		require.NoError(t, goose.Down(db, "."), "откат обязан проходить")
		steps++
	}
	require.Positive(t, steps, "откат не сделал ни шага — утверждения ниже беспредметны")
	t.Logf("откат: миграций снято %d (до версии ниже %d)", steps, recoveryVersion)

	var exists bool
	require.NoError(t, db.QueryRow(`SELECT to_regclass('kaname.recovery_codes') IS NOT NULL`).Scan(&exists))
	require.False(t, exists, "таблица кодов снята откатом")
	require.Error(t, insertKind("mail.recovery.send", "usr-rt-2"), "после отката словарь очереди снова из одного вида")
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.invite_mail_outbox WHERE event_type = 'mail.recovery.send'`).Scan(&recoveryRows))
	require.Zero(t, recoveryRows, "строки второго вида сняты вместе с видом")
	_, err = db.Exec(`INSERT INTO kaname.recovery_completions (recovery_jti, external_id, user_id) VALUES ('rcv-rt-2', NULL, 'usr-x')`)
	require.Error(t, err, "после отката внешний субъект журнала снова обязателен")
	var ledgerRows int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.recovery_completions WHERE recovery_jti = 'rcv-rt'`).Scan(&ledgerRows))
	require.Zero(t, ledgerRows, "строка нашего потока снята вместе со своим источником")

	// Повторный накат сходится: словарь снова из двух видов, таблица есть.
	require.NoError(t, goose.Up(db, "."))
	require.NoError(t, db.QueryRow(`SELECT to_regclass('kaname.recovery_codes') IS NOT NULL`).Scan(&exists))
	require.True(t, exists)
	require.NoError(t, insertKind("mail.recovery.send", "usr-rt-3"))
	_, err = db.Exec(`INSERT INTO kaname.recovery_completions (recovery_jti, external_id, user_id) VALUES ('rcv-rt-3', NULL, 'usr-x')`)
	require.NoError(t, err)
}
