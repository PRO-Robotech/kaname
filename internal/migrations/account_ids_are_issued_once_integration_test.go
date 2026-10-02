// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// account_ids_are_issued_once_integration_test.go — миграция реестра выданных
// идентификаторов аккаунта и правила имени (задача kaname#549, приёмка
// `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`,
// сценарии AID-17 и AID-24; решения Р5 и Р6).
//
// # Предмет
//
// Идентификатор аккаунта может прислать вызывающий. Пока его чеканил только
// генератор, повторной выдачи не было лишь потому, что у генератора 85 бит
// случайности. Теперь неповторяемость обязана держать база: реестр
// `kaname.issued_account_ids`, который не очищается удалением, и обратное
// заполнение из четырёх мест, где остаются следы удалённого аккаунта. Той же
// миграцией ставится CHECK имени: имя формы идентификатора допустимо только равным
// собственному идентификатору, а нарушитель в данных останавливает накат громко.
//
// # Почему имя файла стоит литералом
//
// Мир «база перед миграцией» строится остановкой цепи на версии ПЕРЕД ней. Версию
// задаёт имя файла, и проба обязана сломаться, если файл переедет в другую
// версию: тогда вердикт относился бы к другому состоянию схемы. До реализации
// файла в цепи нет, и пробы красны ровно этим утверждением, ПОСЛЕ того как их
// мир построен и проверен.
package migrations_test

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
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

// accountIDRegistryMigration — файл, заводящий реестр выданных идентификаторов,
// его триггер, обратное заполнение и CHECK имени (приёмка §4.1 S1 п. 3: одна
// миграция на Р5 и Р6).
const accountIDRegistryMigration = "20261002120000_account_ids_are_issued_once.sql"

// accountIDRegistryTable — реестр Р5. Ключ — столбец `id`.
const accountIDRegistryTable = "issued_account_ids"

// accountsNameCheckRefusal — текст отказа наката на нарушителе правила имени,
// дословно по AID-24 (число строк — 1, по миру пробы).
const accountsNameCheckRefusal = "accounts name check: 1 account(s) carry a name of the account id form " +
	"that is not their own id; rename them, then apply this migration"

// accountIDRegistryVersion — версия миграции реестра, выведенная из имени файла.
func accountIDRegistryVersion(t *testing.T) int64 {
	t.Helper()
	head, _, ok := strings.Cut(accountIDRegistryMigration, "_")
	require.True(t, ok, "имя файла без версии: %s", accountIDRegistryMigration)
	v, err := strconv.ParseInt(head, 10, 64)
	require.NoError(t, err)
	return v
}

// requireRegistryMigrationInChain — несущее утверждение о ПРЕДМЕТЕ: файл миграции
// реестра стоит в цепи службы. Зовётся ПОСЛЕ построения и проверки мира пробы.
func requireRegistryMigrationInChain(t *testing.T) {
	t.Helper()
	_, err := fs.Stat(migrations.FS, accountIDRegistryMigration)
	require.NoError(t, err, "миграции реестра выданных идентификаторов аккаунта нет в цепи службы "+
		"(%s): реестра Р5 и CHECK имени Р6 в схеме не появится", accountIDRegistryMigration)
}

// accountIDsBeforeRegistry — база, остановленная на версии НЕПОСРЕДСТВЕННО ПЕРЕД
// миграцией реестра. Это состояние установки, которая накатывает выпуск с реестром.
func accountIDsBeforeRegistry(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	before := accountIDRegistryVersion(t) - 1
	require.NoError(t, goose.UpTo(db, ".", before), "цепь обязана доходить до версии %d", before)

	// Предпосылка мира называется явно: реестра на версии перед миграцией нет.
	// Будь он здесь, «миграция внесла» было бы неотличимо от «уже лежало».
	require.False(t, regclassPresent(t, db, accountIDRegistryTable),
		"реестр %s есть уже на версии %d — остановка пришлась не туда", accountIDRegistryTable, before)
	return db
}

func regclassPresent(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var present bool
	require.NoError(t, db.QueryRow(`SELECT to_regclass('kaname.' || $1) IS NOT NULL`, table).Scan(&present))
	return present
}

func schemaVersion(t *testing.T, db *sql.DB) int64 {
	t.Helper()
	v, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	return v
}

// seedOwner — человек и его личный аккаунт одной транзакцией (внешний ключ
// владельца отложен до фиксации). Возвращает идентификатор человека.
func seedOwner(t *testing.T, db *sql.DB, tag string) string {
	t.Helper()
	uid := ids.NewID(domain.PrefixUser)
	personal := ids.NewID(domain.PrefixAccount)
	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		uid, personal, "ext-"+tag+"-"+uid, tag+"-"+uid+"@example.invalid", "AID "+tag)
	require.NoError(t, err)
	_, err = tx.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`, personal, "personal-"+tag+"-"+personal[len(personal)-6:], uid)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	return uid
}

func insertAccountRow(db *sql.DB, id, name, owner string) error {
	_, err := db.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`, id, name, owner)
	return err
}

func pgErrorOf(err error) *pgconn.PgError {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr
	}
	return nil
}

// auditEventID — идентификатор строки аудита формы `audit_outbox_id_check`.
func auditEventID() string {
	return "evt_" + ids.NewID("evt")[3:] + "abcde"
}

// TestAccountID17_BackfillClosesIDsIssuedBeforeTheMigration — AID-17.
func TestAccountID17_BackfillClosesIDsIssuedBeforeTheMigration(t *testing.T) {
	db := accountIDsBeforeRegistry(t)
	owner := seedOwner(t, db, "aid17")

	i1 := ids.NewID(domain.PrefixAccount) // живой аккаунт
	i2 := ids.NewID(domain.PrefixAccount) // только строка операций
	i3 := ids.NewID(domain.PrefixAccount) // только строка аудита
	i4 := ids.NewID(domain.PrefixAccount) // только журнал ресурсов: аккаунт удалён
	i5 := ids.NewID(domain.PrefixAccount) // нигде не упомянут — близнец
	const notTheForm = "acc-not-generator-form"

	require.NoError(t, insertAccountRow(db, i1, "aid17-live-"+i1[len(i1)-6:], owner))
	_, err := db.Exec(`INSERT INTO kaname.operations (id, description, account_id) VALUES ($1, $2, $3)`,
		ids.NewID(domain.PrefixOperationIAM), "Create account "+i2, i2)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO kaname.operations (id, description, account_id) VALUES ($1, $2, $3)`,
		ids.NewID(domain.PrefixOperationIAM), "Create account "+notTheForm, notTheForm)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO kaname.audit_outbox (id, event_type, tenant_account_id, event_payload)
		VALUES ($1, 'iam.account.created', $2, '{}'::jsonb)`, auditEventID(), i3)
	require.NoError(t, err)
	require.NoError(t, insertAccountRow(db, i4, "aid17-gone-"+i4[len(i4)-6:], owner))
	_, err = db.Exec(`DELETE FROM kaname.accounts WHERE id = $1`, i4)
	require.NoError(t, err)

	// Мир проверен до вопроса о предмете: след I4 лежит только в журнале, I2 и I3
	// аккаунта не имеют. Иначе «реестр внёс» говорил бы о другом мире.
	var journal, live int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.resource_journal
		WHERE resource_kind = 'account' AND resource_id = $1`, i4).Scan(&journal))
	require.Positive(t, journal, "журнал ресурсов не записал удалённый аккаунт I4 — мир пробы не построен")
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.accounts WHERE id IN ($1, $2, $3)`,
		i2, i3, i4).Scan(&live))
	require.Zero(t, live, "у I2, I3, I4 не должно быть строк accounts до наката")

	requireRegistryMigrationInChain(t)

	v := accountIDRegistryVersion(t)
	require.NoError(t, goose.UpTo(db, ".", v), "миграция реестра обязана примениться без отказа")
	require.Equal(t, v, schemaVersion(t, db))

	for name, id := range map[string]string{"I1": i1, "I2": i2, "I3": i3, "I4": i4} {
		var n int
		require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.issued_account_ids WHERE id = $1`, id).Scan(&n))
		require.Equal(t, 1, n, "%s (%s) не внесён обратным заполнением", name, id)
	}
	var odd int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.issued_account_ids WHERE id = $1`, notTheForm).Scan(&odd))
	require.Zero(t, odd, "значение не формы генератора попало в реестр")

	for name, id := range map[string]string{"I2": i2, "I3": i3, "I4": i4} {
		err := insertAccountRow(db, id, "aid17-again-"+id[len(id)-6:], owner)
		pgErr := pgErrorOf(err)
		require.NotNil(t, pgErr, "вставка аккаунта с выданным %s (%s) не отвергнута базой: %v", name, id, err)
		require.Equal(t, "23505", pgErr.Code, "%s: %v", name, err)
		require.Equal(t, accountIDRegistryTable, pgErr.TableName,
			"%s отвергнут не ключом реестра: %s", name, pgErr.ConstraintName)
	}

	// Близнец: идентификатор, не упомянутый нигде, проходит. Владелец — второй
	// человек: у первого темп заведения фикстуры (3 за окно) уже исчерпан личным
	// аккаунтом, I1 и I4, а предмет близнеца — реестр, а не темп.
	twinOwner := seedOwner(t, db, "aid17twin")
	require.NoError(t, insertAccountRow(db, i5, "aid17-fresh-"+i5[len(i5)-6:], twinOwner))
}

// TestAccountID24_NameRuleMigrationRefusesLoudlyOnAViolator — AID-24.
func TestAccountID24_NameRuleMigrationRefusesLoudlyOnAViolator(t *testing.T) {
	t.Run("world_i_violator_refuses", func(t *testing.T) {
		db := accountIDsBeforeRegistry(t)
		owner := seedOwner(t, db, "aid24i")
		id := ids.NewID(domain.PrefixAccount)
		foreignForm := ids.NewID(domain.PrefixAccount) // имя формы идентификатора, не равное своему id
		require.NoError(t, insertAccountRow(db, id, foreignForm, owner))
		before := schemaVersion(t, db)

		requireRegistryMigrationInChain(t)

		err := goose.UpTo(db, ".", accountIDRegistryVersion(t))
		require.Error(t, err, "накат с нарушителем правила имени обязан отказать")
		require.Contains(t, err.Error(), accountsNameCheckRefusal)
		require.Equal(t, before, schemaVersion(t, db), "версия схемы продвинулась на отказе")
		var name string
		require.NoError(t, db.QueryRow(`SELECT name FROM kaname.accounts WHERE id = $1`, id).Scan(&name))
		require.Equal(t, foreignForm, name, "отказ наката изменил строку арендатора")
	})

	t.Run("world_ii_check_installed", func(t *testing.T) {
		db := accountIDsBeforeRegistry(t)
		owner := seedOwner(t, db, "aid24ii")
		own := ids.NewID(domain.PrefixAccount)
		require.NoError(t, insertAccountRow(db, own, own, owner), "имя, равное своему id, законно и до наката")

		requireRegistryMigrationInChain(t)

		require.NoError(t, goose.UpTo(db, ".", accountIDRegistryVersion(t)))

		bad := ids.NewID(domain.PrefixAccount)
		err := insertAccountRow(db, bad, ids.NewID(domain.PrefixAccount), owner)
		pgErr := pgErrorOf(err)
		require.NotNil(t, pgErr, "имя формы идентификатора, не равное id, не отвергнуто базой: %v", err)
		require.Equal(t, "23514", pgErr.Code, fmt.Sprint(err))

		twin := ids.NewID(domain.PrefixAccount)
		require.NoError(t, insertAccountRow(db, twin, twin, owner), "имя, равное своему id, обязано проходить")
	})
}
