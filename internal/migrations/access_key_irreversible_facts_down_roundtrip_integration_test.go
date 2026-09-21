// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// access_key_irreversible_facts_down_roundtrip_integration_test.go — откат
// миграции `20260921183000_access_key_records_discoverability_and_its_own_handle`.
//
// # Что утверждается
//
// Откат ОТКАЗЫВАЕТСЯ уничтожать то, что не восстанавливается ниоткуда:
// рукоятку, уже лежащую в чужом аутентификаторе, и обнаружимость, сообщённую
// один раз. Отказ — это исход СТРАЖА, а не падение: он называет обе величины
// числом и следующий шаг. Положительный близнец отличается РОВНО ОДНИМ фактом —
// строк нет: тогда откат проходит, и повторный накат сходится.
//
// Откат идёт ДО СВОЕЙ миграции, а не «на один шаг»: «на один шаг» утверждало бы,
// что предмет — последняя миграция дерева.

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

const accessKeyFactsVersion int64 = 20260921183000

func TestAccessKeyFactsMigration_DownRefusesToDestroyWhatCannotBeRecorded(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."))

	// Один человек и его рукоятка — минимальный предмет, который откат снёс бы.
	// Аккаунт и его владелец ссылаются друг на друга, поэтому сев идёт одной
	// транзакцией с отложенными ограничениями — как у прочих проб дерева.
	seed, err := db.Begin()
	require.NoError(t, err)
	_, err = seed.Exec(`SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)
	_, err = seed.Exec(`INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ('usr00000000000akdn01', 'ext-akdn-01', 'akdn@example.invalid', 'person', 'acc00000000000akdn1', 'ACTIVE')`)
	require.NoError(t, err)
	_, err = seed.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id)
		VALUES ('acc00000000000akdn1', 'acc-akdn', 'usr00000000000akdn01')`)
	require.NoError(t, err)
	_, err = seed.Exec(`INSERT INTO kaname.user_ceremony_handles (user_id, handle)
		VALUES ('usr00000000000akdn01', decode(repeat('ab', 64), 'hex'))`)
	require.NoError(t, err)
	require.NoError(t, seed.Commit(), "предпосылка пробы: рукоятка заведена")

	downErr := goose.Down(db, ".")
	require.Error(t, downErr, "откат снёс рукоятку, лежащую в чужом аутентификаторе")
	require.Contains(t, downErr.Error(), "cannot be recorded again",
		"отказ обязан называть причину, а не только код")
	require.Contains(t, downErr.Error(), "WAY OUT", "отказ обязан называть следующий шаг")
	require.Contains(t, downErr.Error(), "1 ceremony handle row",
		"отказ обязан называть ЧИСЛО, а не «строки есть»")

	v, verr := goose.GetDBVersion(db)
	require.NoError(t, verr)
	require.Equal(t, accessKeyFactsVersion, v, "отказ отката не сдвинул версию")

	var still int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.user_ceremony_handles`).Scan(&still))
	require.Equal(t, 1, still, "страж отказал, а строка всё равно ушла")
}

func TestAccessKeyFactsMigration_DownPassesWhenThereIsNothingToDestroy(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."))

	var keys, handles int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.user_access_keys`).Scan(&keys))
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.user_ceremony_handles`).Scan(&handles))
	require.Zero(t, keys+handles, "предпосылка близнеца: уничтожать нечего")

	steps := 0
	for {
		v, verr := goose.GetDBVersion(db)
		require.NoError(t, verr)
		if v < accessKeyFactsVersion {
			break
		}
		require.NoError(t, goose.Down(db, "."), "откат на пустых таблицах обязан проходить")
		steps++
	}
	require.Positive(t, steps, "откат не сделал ни шага — утверждения ниже беспредметны")
	t.Logf("откат: миграций снято %d (до версии ниже %d)", steps, accessKeyFactsVersion)

	var exists bool
	require.NoError(t, db.QueryRow(`SELECT to_regclass('kaname.user_ceremony_handles') IS NOT NULL`).Scan(&exists))
	require.False(t, exists, "таблица рукояток снята откатом")
	var hasColumn bool
	require.NoError(t, db.QueryRow(`SELECT count(*) > 0 FROM information_schema.columns
		WHERE table_schema = 'kaname' AND table_name = 'user_access_keys' AND column_name = 'discoverability'`).Scan(&hasColumn))
	require.False(t, hasColumn, "колонка обнаружимости снята откатом")

	// Повторный накат сходится: обе величины на месте, словарь закрыт.
	require.NoError(t, goose.Up(db, "."))
	require.NoError(t, db.QueryRow(`SELECT to_regclass('kaname.user_ceremony_handles') IS NOT NULL`).Scan(&exists))
	require.True(t, exists)
	require.NoError(t, db.QueryRow(`SELECT count(*) > 0 FROM information_schema.columns
		WHERE table_schema = 'kaname' AND table_name = 'user_access_keys' AND column_name = 'discoverability'`).Scan(&hasColumn))
	require.True(t, hasColumn)
	var hasDefault bool
	require.NoError(t, db.QueryRow(`SELECT column_default IS NOT NULL FROM information_schema.columns
		WHERE table_schema = 'kaname' AND table_name = 'user_access_keys' AND column_name = 'discoverability'`).Scan(&hasDefault))
	require.False(t, hasDefault, "умолчание ушло вместе с обратным заполнением: вставка обязана называть состояние")
}
