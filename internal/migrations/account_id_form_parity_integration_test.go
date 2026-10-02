// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// account_id_form_parity_integration_test.go — форма идентификатора аккаунта
// объявлена в схеме ОДНОЙ функцией и совпадает с формой генератора поштучно;
// создание, пришедшее во время наката реестра, в реестр попадает (задача
// kaname#549, разбор экспозиции классов: условия 2 и 7, заказы П3 и П4).
//
// # Почему паритет, а не прочтение
//
// Форма генератора в Go — `ids.IsValid(id, "acc")`. В схеме её зовут четыре
// места: проверка реестра, отбор триггера, отбор обратного заполнения и проверка
// имени. Два написания одного предиката расходятся молча: диапазон `a-z` вместо
// перечня 32 знаков принимает `i`, `l`, `o`, `u`, а регистронезависимое сравнение
// — заглавные. Проба сверяет вердикты ПОШТУЧНО на таблице AID-05, границах AID-06
// и посеянном идентификаторе. Её способность упасть доказана в ней же: на тех же
// значениях форма с диапазоном расходится с генератором.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// accountIDFormFunction — единственное объявление формы в схеме.
const accountIDFormFunction = "kaname.account_id_has_generator_form(text)"

// accountIDFormCorpus — значения, на которых судится паритет: таблица AID-05
// (каждое отличается от годного одним фактом), границы AID-06 и посеянный.
func accountIDFormCorpus() []string {
	return []string{
		"acc7m3k9q2x5v8b4n6t1",
		"acc00000000000000000",
		"acczzzzzzzzzzzzzzzzz",
		"acc1a18042d81fb438d6",
		ids.NewID(domain.PrefixAccount),
		"acc7M3K9Q2X5V8B4N6T1",
		"acc7m3k9q2x5v8b4n6tu",
		"acc7m3k9q2x5v8b4n6ti",
		"acc7m3k9q2x5v8b4n6tl",
		"acc7m3k9q2x5v8b4n6to",
		"acc7m3k9q2x5v8b4n6t",
		"acc7m3k9q2x5v8b4n6t12",
		"prj7m3k9q2x5v8b4n6t1",
		"acc-7m3k9q2x5v8b4n6t1",
		" acc7m3k9q2x5v8b4n6t1",
		"acc7m3k9q2x5v8b4n6t1 ",
		"acc7m3k9q2x5v8b4n6tа",
		"acc00000000000000lim",
		"acc",
		"",
	}
}

func migratedToRegistry(t *testing.T) *sql.DB {
	t.Helper()
	db := accountIDsBeforeRegistry(t)
	requireRegistryMigrationInChain(t)
	require.NoError(t, goose.UpTo(db, ".", accountIDRegistryVersion(t)))
	return db
}

// TestAccountIDFormInTheSchemaAgreesWithTheGenerator — заказ П3.
func TestAccountIDFormInTheSchemaAgreesWithTheGenerator(t *testing.T) {
	db := migratedToRegistry(t)

	var present bool
	require.NoError(t, db.QueryRow(`SELECT to_regprocedure($1) IS NOT NULL`, accountIDFormFunction).Scan(&present))
	require.True(t, present, "функции формы %s в схеме нет", accountIDFormFunction)

	var accepted, refused int
	for _, v := range accountIDFormCorpus() {
		var sqlVerdict bool
		require.NoError(t, db.QueryRow(`SELECT kaname.account_id_has_generator_form($1)`, v).Scan(&sqlVerdict))
		goVerdict := ids.IsValid(v, domain.PrefixAccount)
		require.Equal(t, goVerdict, sqlVerdict, "%q: генератор говорит %v, схема — %v", v, goVerdict, sqlVerdict)
		if goVerdict {
			accepted++
		} else {
			refused++
		}
	}
	t.Logf("перепись: значений %d · годных %d · негодных %d", accepted+refused, accepted, refused)
	require.Positive(t, accepted, "корпус без годных значений судит только половину")
	require.Positive(t, refused, "корпус без негодных значений судит только половину")

	// Инъекция: та же форма, записанная диапазоном и без учёта регистра, на этом
	// корпусе расходится с генератором — значит корпус способен её поймать.
	var diverged int
	for _, v := range accountIDFormCorpus() {
		var rangeVerdict bool
		require.NoError(t, db.QueryRow(`SELECT $1 ~* '^acc[0-9a-z]{17}$'`, v).Scan(&rangeVerdict))
		if rangeVerdict != ids.IsValid(v, domain.PrefixAccount) {
			diverged++
		}
	}
	require.Positive(t, diverged, "корпус не отличает форму с диапазоном от формы генератора")
}

// waitForLockWaiters — барьер: n сеансов этой базы стоят в ожидании замка.
func waitForLockWaiters(t *testing.T, db *sql.DB, n int, what string) {
	t.Helper()
	require.Eventually(t, func() bool {
		var waiting int
		if err := db.QueryRow(`
			SELECT count(*) FROM pg_stat_activity
			 WHERE datname = current_database() AND wait_event_type = 'Lock'
			   AND pid <> pg_backend_pid()`).Scan(&waiting); err != nil {
			return false
		}
		return waiting >= n
	}, 30*time.Second, 50*time.Millisecond, what)
}

// TestAccountIDCreatedDuringTheRegistryRolloutLandsInTheRegistry — заказ П4.
// Прежний под продолжает создавать аккаунты, пока новый накатывает реестр.
// (а) вставка, начатая ДО наката и зафиксированная во время него;
// (б) вставка, пришедшая, когда накат уже держит таблицу.
// Обе обязаны оказаться в реестре: триггер стоит раньше обратного заполнения.
func TestAccountIDCreatedDuringTheRegistryRolloutLandsInTheRegistry(t *testing.T) {
	db := accountIDsBeforeRegistry(t)
	owner := seedOwner(t, db, "p4")
	requireRegistryMigrationInChain(t)
	ctx := context.Background()

	early := ids.NewID(domain.PrefixAccount)
	late := ids.NewID(domain.PrefixAccount)

	// (а) прежний под: вставка в открытой транзакции.
	oldPod, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = oldPod.Rollback() }()
	_, err = oldPod.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`, early, "p4-early-"+early[len(early)-6:], owner)
	require.NoError(t, err)

	version := accountIDRegistryVersion(t)
	migrated := make(chan error, 1)
	go func() { migrated <- goose.UpTo(db, ".", version) }()
	waitForLockWaiters(t, db, 1, "накат не встал за вставкой прежнего пода")

	// (б) вставка, пришедшая после того, как накат упёрся: она встаёт за ним.
	lateDone := make(chan error, 1)
	go func() { lateDone <- insertAccountRow(db, late, "p4-late-"+late[len(late)-6:], owner) }()
	waitForLockWaiters(t, db, 2, "вставка во время наката не встала за накатом")

	require.NoError(t, oldPod.Commit())
	require.NoError(t, <-migrated, "накат реестра обязан примениться")
	require.NoError(t, <-lateDone, "вставка во время наката обязана пройти")

	for name, id := range map[string]string{"early": early, "late": late} {
		var n int
		require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.issued_account_ids WHERE id = $1`, id).Scan(&n))
		require.Equal(t, 1, n, "%s (%s): аккаунт, созданный во время наката, не попал в реестр", name, id)
	}
}
