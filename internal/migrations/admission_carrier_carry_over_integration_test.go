// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// admission_carrier_carry_over_integration_test.go — A197-06: существующие окна
// темпа заведения переносятся миграцией носителя без сброса (приёмка
// `docs/engineering/acceptance/admission-rate-carrier-is-fixed-at-registration.md`,
// Р3; задача PRO-Robotech/kaname#197; миграция [a197Migration]).
//
// «Дано» строится на схеме ДО миграции предмета: человек нашей полосы и его
// окно заводятся там, затем накатывается вся цепочка. Утверждается лежащая
// строка и исход следующего заведения, а не текст миграции.
package migrations_test

import (
	"database/sql"
	"io/fs"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// a197Migration — файл предмета.
const a197Migration = "20261006152443_admission_carrier_is_fixed_when_the_identity_is_minted.sql"

// a197Before — последняя миграция цепочки ПОД предметом: «Дано» живёт на ней.
// Предпосылка сверяется с цепочкой, когда файл предмета в ней есть.
const a197Before int64 = 20261005040457

// TestA197_06_ExistingWindowsAreCarriedOverWithoutReset — A197-06 и близнец
// (потолок 2 вместо 1).
func TestA197_06_ExistingWindowsAreCarriedOverWithoutReset(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	if _, err := fs.Stat(migrations.FS, a197Migration); err == nil {
		_, previous := versionsOf(t, a197Migration)
		require.Equal(t, a197Before, previous,
			"ПРЕДПОСЫЛКА: под миграцией предмета лежит не та версия, на которой строится «Дано»")
	} else {
		t.Logf("файла предмета %s в цепочке нет — накат ниже не заводит носителя", a197Migration)
	}

	for _, tc := range []struct {
		name    string
		ceiling int
		admit   bool
	}{
		{"потолок 1 — отказ рубежом темпа, счётчик не сброшен", 1, false},
		{"близнец: потолок 2 — заведение проходит, счётчик 2", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
			require.NoError(t, err)
			t.Cleanup(func() { _ = db.Close() })
			goose.SetBaseFS(migrations.FS)
			require.NoError(t, goose.SetDialect("postgres"))
			require.NoError(t, goose.UpTo(db, ".", a197Before), "цепочка обязана дойти до версии %d", a197Before)

			userID := ids.NewID(domain.PrefixUser)
			accountID := ids.NewID(domain.PrefixAccount)
			email := "Old-H-" + userID[4:10] + "@Example.Invalid"
			tx, err := db.Begin()
			require.NoError(t, err)
			_, err = tx.Exec(`INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
				VALUES ($1, $2, $3, $4, 'old-h', 'ACTIVE')`, userID, accountID, string(domain.NewOwnLaneSubject()), email)
			require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): человек нашей полосы до миграции")
			_, err = tx.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id, labels) VALUES ($1, $2, $3, '{}'::jsonb)`,
				accountID, "a197-06-"+strings.ToLower(userID[4:12]), userID)
			require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): первое заведение")
			_, err = tx.Exec(`INSERT INTO kaname.user_login_methods (user_id, kind, verifier) VALUES ($1, 'password', 'fixture-password-row-without-a-known-password')`, userID)
			require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): способ входа")
			require.NoError(t, tx.Commit())
			carrier := strings.ToLower(email)
			var before int
			require.NoError(t, db.QueryRow(`SELECT admitted FROM kaname.identity_admission_windows WHERE kind = 'iam.account' AND carrier_id = $1`, carrier).Scan(&before),
				"НЕ-ВЫПОЛНИЛОСЬ(фикстура): окно до миграции")
			require.Equal(t, 1, before)

			require.NoError(t, goose.Up(db, "."), "накат цепочки")

			var got string
			require.NoError(t, db.QueryRow(`SELECT admission_carrier FROM kaname.users WHERE id = $1`, userID).Scan(&got),
				"A197-06: носитель человека после миграции")
			require.Equal(t, carrier, got, "A197-06: носитель — нынешний адрес в нижнем регистре")

			_, err = db.Exec(`UPDATE kaname.account_admission_rate_limits SET max_events = $1, window_seconds = 3600
				WHERE kind = 'iam.account' AND withdrawn_at IS NULL`, tc.ceiling)
			require.NoError(t, err)
			_, err = db.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id, labels) VALUES ($1, $2, $3, '{}'::jsonb)`,
				ids.NewID(domain.PrefixAccount), "a197-06b-"+strings.ToLower(userID[4:12]), userID)
			var windows, admitted int
			require.NoError(t, db.QueryRow(`SELECT count(*), coalesce(max(admitted), 0) FROM kaname.identity_admission_windows
				WHERE kind = 'iam.account' AND carrier_id = $1`, carrier).Scan(&windows, &admitted))
			require.Equal(t, 1, windows, "A197-06: окно носителя одно")
			if tc.admit {
				require.NoError(t, err, "A197-06 близнец: заведение при потолке 2")
				require.Equal(t, 2, admitted, "A197-06 близнец: счётчик продолжился — 2")
				return
			}
			require.Error(t, err, "A197-06: перенос сбросил окно — второе заведение прошло")
			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr)
			require.Equal(t, "KQ004", pgErr.Code, "A197-06: отказ рубежом темпа")
			require.Equal(t, 1, admitted, "A197-06: счётчик не сброшен")
		})
	}
}
