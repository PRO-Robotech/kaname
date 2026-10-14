// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// person_machine_entry_fact_condition_integration_test.go — писатель факта
// прикладывает условие, которое модель объявляет на прямом списке отношения
// (kaname#133, исход (а); приёмка `assurance-level-is-declared-by-our-session.md`
// §3.4, звено З2; миграция 20261011120000).
//
// Наблюдается на строке факта, сложенной из строки журнала, — тем писателем,
// которым продукт кладёт факт. Каждое отрицание стоит рядом с положительным
// близнецом, отличающимся одним фактом: тип субъекта либо отношение.

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

const personMachineEntryConditionVersion int64 = 20261011120000

func journalWrite(t *testing.T, db *sql.DB, object, relation, user string) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		VALUES ('fga.tuple.write',
		        jsonb_build_object('object', $1::text, 'relation', $2::text, 'user', $3::text),
		        now())`, object, relation, user)
	require.NoErrorf(t, err, "строка журнала %s#%s@%s", object, relation, user)
}

// factCondition — условие на строке факта; found=false — строки нет.
func factCondition(t *testing.T, db *sql.DB, objectID, relation, subject string) (string, bool) {
	t.Helper()
	var cond string
	err := db.QueryRow(`SELECT condition_name FROM kaname.relation_fact
		 WHERE object_type = 'compute_instance' AND object_id = $1 AND relation = $2 AND subject = $3`,
		objectID, relation, subject).Scan(&cond)
	if err == sql.ErrNoRows {
		return "", false
	}
	require.NoError(t, err)
	return cond, true
}

func requireCondition(t *testing.T, db *sql.DB, objectID, relation, subject, want, msg string) {
	t.Helper()
	got, ok := factCondition(t, db, objectID, relation, subject)
	require.Truef(t, ok, "%s: строки факта нет — писатель не сложил строку журнала", msg)
	require.Equalf(t, want, got, "%s", msg)
}

func TestPersonMachineEntryFactCarriesTheModelsCondition(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."))

	// Голова: человек на `ssh` и `console` — с условием модели.
	journalWrite(t, db, "compute_instance:ins-head", "ssh", "user:usr-head")
	journalWrite(t, db, "compute_instance:ins-head", "console", "user:usr-head")
	requireCondition(t, db, "ins-head", "ssh", "user:usr-head", "mfa_fresh",
		"факт человека на ssh несёт условие модели `[user with mfa_fresh]`")
	requireCondition(t, db, "ins-head", "console", "user:usr-head", "mfa_fresh",
		"факт человека на console несёт условие модели")

	// Близнецы одного факта: служебная учётка на `ssh` (модель — без условия) и
	// человек на безусловном отношении того же объекта.
	journalWrite(t, db, "compute_instance:ins-head", "ssh", "service_account:sva-head")
	journalWrite(t, db, "compute_instance:ins-head", "admin", "user:usr-head")
	requireCondition(t, db, "ins-head", "ssh", "service_account:sva-head", "",
		"факт служебной учётки на ssh безусловен — модель объявляет её без условия")
	requireCondition(t, db, "ins-head", "admin", "user:usr-head", "",
		"факт человека на безусловном отношении безусловен")

	// Откат до прежнего писателя: условие, приложенное миграцией, снято, и
	// прежний писатель кладёт строку без условия.
	steps := 0
	for {
		v, verr := goose.GetDBVersion(db)
		require.NoError(t, verr)
		if v < personMachineEntryConditionVersion {
			break
		}
		require.NoError(t, goose.Down(db, "."), "откат обязан проходить")
		steps++
	}
	require.Positive(t, steps, "откат не сделал ни шага — утверждения ниже беспредметны")
	requireCondition(t, db, "ins-head", "ssh", "user:usr-head", "",
		"откат снимает условие, которого прежний писатель не производил")
	journalWrite(t, db, "compute_instance:ins-before", "ssh", "user:usr-before")
	requireCondition(t, db, "ins-before", "ssh", "user:usr-before", "",
		"ПРЕДПОСЫЛКА обратного заполнения: прежний писатель кладёт факт человека без условия")

	// Накат: обратное заполнение даёт условие строкам прежнего писателя, а
	// служебной учётке — нет.
	require.NoError(t, goose.Up(db, "."), "повторный накат обязан проходить")
	requireCondition(t, db, "ins-before", "ssh", "user:usr-before", "mfa_fresh",
		"обратное заполнение: факт человека без условия на ssh не переживает миграцию")
	requireCondition(t, db, "ins-head", "console", "user:usr-head", "mfa_fresh",
		"обратное заполнение: console")
	requireCondition(t, db, "ins-head", "ssh", "service_account:sva-head", "",
		"обратное заполнение не трогает служебную учётку")
	requireCondition(t, db, "ins-head", "admin", "user:usr-head", "",
		"обратное заполнение не трогает безусловное отношение")
}
