// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// account_id_string_form_integration_test.go — миграция редакции 4 приёмки
// (задача kaname#1052, приёмка
// `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`, редакция
// 7, sha256 a3dff53e9ae56e3e1fa959d6ee3b43a932aaf09d3918795a62c06377550e3e52;
// сценарий AID-33, решения Р5 и Р6а; заказ 6 (а) разбора экспозиции классов).
//
// # Предмет
//
// Реестр выданных расширяет форму с формы генератора до формы аккаунта Р2
// (а)–(г); ставится правило Р6а — строка обозначает не больше одного аккаунта:
// пары с идентификатором сравниваются после свёртки похожих знаков, пара «имя ↔
// имя» — побайтово (носитель выбирает замысел). Нарушитель Р6а в данных
// останавливает накат громко. Правило имени Р6 при этом НЕ расширяется.
// Паритет формы реестра с таблицами AID-05/AID-06 судит
// `internal/apps/kaname/api/audit/account_id_string_form_integration_test.go`
// (`TestAccountID33_RegistryFormAgreesWithTheTables`): таблицы объявлены там
// одни.
//
// # Как найдена миграция
//
// Имя файла задаёт реализация, и проба его не выписывает. Миграция задачи — это
// файл цепи службы, кроме миграции реестра редакции 3, который ссылается на эту
// приёмку: миграция называет свою санкцию (`ban01-acceptance`), как это сделала
// миграция реестра (`20261002120000`, шапка «Санкция»). Миграция задачи без
// ссылки на приёмку этой пробой не найдётся, и проба останется красной — это
// требование к реализации, а не выбор пробы. Версия перед ней — её версия минус
// один, как у проб миграции реестра.
//
// # Чем краснеет до реализации
//
// Мир строится и проверяется на голове цепи, и ТОЛЬКО ПОСЛЕ этого несущее
// утверждение о предмете называет, что миграции задачи в цепи нет. Сломанный
// мир не выдаёт себя за отсутствующую миграцию: его отказ стоит раньше.
package migrations_test

import (
	"context"
	"database/sql"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// accountIDAcceptanceDoc — приёмка, на которую ссылаются обе её миграции.
const accountIDAcceptanceDoc = "account-id-may-be-supplied-at-create.md"

// accountsHandleCheckRefusal — текст отказа наката на нарушителе Р6а, дословно по
// AID-33 редакции 7 (число строк — 1, по миру пробы).
const accountsHandleCheckRefusal = "accounts handle check: 1 account(s) carry a name or id that matches " +
	"another account's id after look-alike folding; rename or remove them, then apply this migration"

// requireConstraintRefusal — запись отвергнута ограничением базы (класс SQLSTATE
// 23, «нарушение целостности»). Носитель ключа Р6а выбирает замысел (Р6а:
// одним индексом UNIQUE правило не выражается), поэтому проба судит, что
// отвергает БАЗА, а не каким именно кодом класса.
func requireConstraintRefusal(t *testing.T, err error, what string) {
	t.Helper()
	pgErr := pgErrorOf(err)
	require.NotNil(t, pgErr, "%s: база не отвергла: %v", what, err)
	require.True(t, strings.HasPrefix(pgErr.Code, "23"), "%s: отказ не ограничением базы: %v", what, err)
}

// stringFormMigration — миграция задачи kaname#1052: имя и версия; ok=false, если
// её в цепи нет.
func stringFormMigration(t *testing.T) (name string, version int64, ok bool) {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	require.NoError(t, err)
	var found []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".sql") || n == accountIDRegistryMigration {
			continue
		}
		body, rerr := fs.ReadFile(migrations.FS, n)
		require.NoError(t, rerr)
		if strings.Contains(string(body), accountIDAcceptanceDoc) {
			found = append(found, n)
		}
	}
	sort.Strings(found)
	require.LessOrEqual(t, len(found), 1, "на приёмку ссылается больше одной новой миграции: %v", found)
	if len(found) == 0 {
		return "", 0, false
	}
	head, _, cut := strings.Cut(found[0], "_")
	require.True(t, cut, "имя файла без версии: %s", found[0])
	v, err := strconv.ParseInt(head, 10, 64)
	require.NoError(t, err)
	return found[0], v, true
}

// requireStringFormMigrationInChain — несущее утверждение о ПРЕДМЕТЕ; зовётся
// ПОСЛЕ построения и проверки мира.
func requireStringFormMigrationInChain(t *testing.T) int64 {
	t.Helper()
	_, v, ok := stringFormMigration(t)
	require.True(t, ok, "миграции kaname#1052 в цепи службы нет: ни один файл, кроме %s, не ссылается на "+
		"приёмку %s — форма реестра Р5 и ключ Р6а в схеме не появятся", accountIDRegistryMigration, accountIDAcceptanceDoc)
	return v
}

// beforeStringForm — база на версии НЕПОСРЕДСТВЕННО ПЕРЕД миграцией задачи;
// пока миграции нет — на голове цепи (состояние установки до выпуска).
func beforeStringForm(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	if _, v, ok := stringFormMigration(t); ok {
		require.NoError(t, goose.UpTo(db, ".", v-1), "цепь обязана доходить до версии %d", v-1)
	} else {
		require.NoError(t, goose.Up(db, "."), "цепь обязана доходить до головы")
	}

	// Предпосылки мира называются явно: реестр редакции 3 стоит и судит форму
	// генератора — иначе «миграция расширила» неотличимо от «уже было».
	require.True(t, regclassPresent(t, db, accountIDRegistryTable),
		"реестра %s нет на версии перед миграцией задачи — остановка пришлась не туда", accountIDRegistryTable)
	_, err = db.Exec(`INSERT INTO kaname.issued_account_ids (id) VALUES ('godjee-premise')`)
	pgErr := pgErrorOf(err)
	require.NotNil(t, pgErr, "реестр на версии перед миграцией принял строку заданной формы: %v", err)
	require.Equal(t, "23514", pgErr.Code, "реестр отверг строку не своим CHECK: %v", err)
	return db
}

func registryHas(t *testing.T, db *sql.DB, id string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.issued_account_ids WHERE id = $1`, id).Scan(&n))
	return n
}

func accountName(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var name string
	require.NoError(t, db.QueryRow(`SELECT name FROM kaname.accounts WHERE id = $1`, id).Scan(&name))
	return name
}

func requireUniqueRefusal(t *testing.T, err error, what string) {
	t.Helper()
	pgErr := pgErrorOf(err)
	require.NotNil(t, pgErr, "%s: база не отвергла: %v", what, err)
	require.Equal(t, "23505", pgErr.Code, "%s: %v", what, err)
}

// TestAccountID33_StringFormMigrationRefusesLoudlyOnAViolator — AID-33 мир (i):
// живой A1 с именем `godjee` и живой A2 с идентификатором `godjee`, вставленный в
// обход службы. Накат отказывает текстом правила с числом строк; версия не
// продвинулась, строки не изменены. Близнец — мир (ii), одно различие: имя A1 не
// равно идентификатору A2.
func TestAccountID33_StringFormMigrationRefusesLoudlyOnAViolator(t *testing.T) {
	db := beforeStringForm(t)
	a1 := ids.NewID(domain.PrefixAccount)
	require.NoError(t, insertAccountRow(db, a1, "godjee", seedOwner(t, db, "aid33i1")))
	require.NoError(t, insertAccountRow(db, "godjee", "aid33-a2", seedOwner(t, db, "aid33i2")),
		"до миграции схема допускает идентификатор заданной формы в обход службы")
	before := schemaVersion(t, db)

	v := requireStringFormMigrationInChain(t)

	err := goose.UpTo(db, ".", v)
	require.Error(t, err, "накат с нарушителем Р6а обязан отказать")
	require.Contains(t, err.Error(), accountsHandleCheckRefusal)
	require.Equal(t, before, schemaVersion(t, db), "версия схемы продвинулась на отказе")
	require.Equal(t, "godjee", accountName(t, db, a1), "отказ наката изменил строку арендатора")
	require.Equal(t, "aid33-a2", accountName(t, db, "godjee"), "отказ наката изменил строку арендатора")
}

// TestAccountID33_StringFormMigrationRefusesLoudlyOnAFoldedViolator — AID-33 мир
// (iii): тот же A2 с идентификатором `godjee` и A1 с именем `g0djee` —
// совпадает с идентификатором A2 только после свёртки Р6а. Накат отказывает тем
// же текстом. Близнец — мир (ii): имя A1 не совпадает ни как есть, ни после
// свёртки.
func TestAccountID33_StringFormMigrationRefusesLoudlyOnAFoldedViolator(t *testing.T) {
	db := beforeStringForm(t)
	a1 := ids.NewID(domain.PrefixAccount)
	require.NoError(t, insertAccountRow(db, "godjee", "aid33-a2", seedOwner(t, db, "aid33iii2")),
		"до миграции схема допускает идентификатор заданной формы в обход службы")
	require.NoError(t, insertAccountRow(db, a1, "g0djee", seedOwner(t, db, "aid33iii1")))
	before := schemaVersion(t, db)

	v := requireStringFormMigrationInChain(t)

	err := goose.UpTo(db, ".", v)
	require.Error(t, err, "накат с нарушителем Р6а после свёртки обязан отказать")
	require.Contains(t, err.Error(), accountsHandleCheckRefusal)
	require.Equal(t, before, schemaVersion(t, db), "версия схемы продвинулась на отказе")
	require.Equal(t, "g0djee", accountName(t, db, a1), "отказ наката изменил строку арендатора")
	require.Equal(t, "aid33-a2", accountName(t, db, "godjee"), "отказ наката изменил строку арендатора")
}

// TestAccountID33_StringFormMigrationWidensTheRegistryAndInstallsTheKey — AID-33
// мир (ii): накат проходит, реестр вносит строки заданной формы из источников
// обратного заполнения, ключ Р6а держит обе стороны на вставке и на правке;
// откат возвращает форму реестра к форме генератора, повторный накат снова
// вносит.
func TestAccountID33_StringFormMigrationWidensTheRegistryAndInstallsTheKey(t *testing.T) {
	db := beforeStringForm(t)
	require.NoError(t, insertAccountRow(db, "godjee", "aid33-a2", seedOwner(t, db, "aid33ii2")))
	a1 := ids.NewID(domain.PrefixAccount)
	require.NoError(t, insertAccountRow(db, a1, "godjee-x", seedOwner(t, db, "aid33ii1")))
	_, err := db.Exec(`INSERT INTO kaname.operations (id, description, account_id) VALUES ($1, $2, $3)`,
		ids.NewID(domain.PrefixOperationIAM), "Create account dlputi1u", "dlputi1u")
	require.NoError(t, err)
	require.Zero(t, registryHas(t, db, "godjee"), "«Дано»: godjee в реестре до наката")
	require.Zero(t, registryHas(t, db, "dlputi1u"), "«Дано»: dlputi1u в реестре до наката")

	v := requireStringFormMigrationInChain(t)

	require.NoError(t, goose.UpTo(db, ".", v), "накат без нарушителя обязан примениться")
	require.Equal(t, v, schemaVersion(t, db))
	require.Equal(t, 1, registryHas(t, db, "godjee"), "живой идентификатор заданной формы не внесён в реестр")
	require.Equal(t, 1, registryHas(t, db, "dlputi1u"), "след заданной формы в ленте операций не внесён в реестр")

	other := seedOwner(t, db, "aid33iio")
	requireUniqueRefusal(t, insertAccountRow(db, "godjee", "aid33-again", other), "вставка с живым godjee")
	err = insertAccountRow(db, "dlputi1u", "aid33-dl", other)
	requireUniqueRefusal(t, err, "вставка с выданным dlputi1u")
	require.Equal(t, accountIDRegistryTable, pgErrorOf(err).TableName, "dlputi1u отвергнут не ключом реестра")

	requireConstraintRefusal(t, insertAccountRow(db, ids.NewID(domain.PrefixAccount), "godjee", other),
		"имя, равное идентификатору живого аккаунта (Р6а)")
	requireConstraintRefusal(t, insertAccountRow(db, ids.NewID(domain.PrefixAccount), "g0djee", seedOwner(t, db, "aid33iif")),
		"имя, совпадающее с идентификатором живого аккаунта после свёртки (Р6а)")
	require.NoError(t, insertAccountRow(db, ids.NewID(domain.PrefixAccount), "godjee-y", seedOwner(t, db, "aid33iiy")),
		"близнец: свободное имя проходит")
	_, err = db.Exec(`UPDATE kaname.accounts SET name = 'godjee' WHERE id = $1`, a1)
	requireConstraintRefusal(t, err, "правка имени A1 на идентификатор живого аккаунта (Р6а)")
	_, err = db.Exec(`UPDATE kaname.accounts SET name = 'godjee-z' WHERE id = $1`, a1)
	require.NoError(t, err, "близнец: правка на свободное имя проходит")

	// Правило имени Р6 не расширилось (K16): правка меток A1 проходит, имя не
	// формы генератора и не равное своему идентификатору проходит, а имя ФОРМЫ
	// ГЕНЕРАТОРА, не равное своему идентификатору, по-прежнему отвергается CHECK
	// `accounts_name_is_not_a_foreign_id` (23514, как AID-24).
	_, err = db.Exec(`UPDATE kaname.accounts SET labels = '{"k": "v"}'::jsonb WHERE id = $1`, a1)
	require.NoError(t, err, "правка меток A1 (имя заданной формы, не формы генератора) отвергнута")
	require.NoError(t, insertAccountRow(db, ids.NewID(domain.PrefixAccount), "aid33-name", seedOwner(t, db, "aid33iin")),
		"имя заданной формы, не равное идентификатору, отвергнуто: правило Р6 расширилось")
	err = insertAccountRow(db, ids.NewID(domain.PrefixAccount), ids.NewID(domain.PrefixAccount), seedOwner(t, db, "aid33iig"))
	pgErr := pgErrorOf(err)
	require.NotNil(t, pgErr, "имя формы генератора, не равное своему id, принято: %v", err)
	require.Equal(t, "23514", pgErr.Code, "имя формы генератора отвергнуто не CHECK правила имени: %v", err)

	// Откат — форма реестра к форме генератора, строки заданной формы сняты.
	require.NoError(t, goose.Down(db, "."), "откат миграции обязан пройти")
	require.Less(t, schemaVersion(t, db), v, "откат не вернул версию")
	require.Zero(t, registryHas(t, db, "godjee"), "откат оставил в реестре строку заданной формы")
	_, err = db.Exec(`INSERT INTO kaname.issued_account_ids (id) VALUES ('godjee-down')`)
	require.NotNil(t, pgErrorOf(err), "после отката реестр принимает строку заданной формы: %v", err)

	require.NoError(t, goose.UpTo(db, ".", v), "повторный накат обязан пройти")
	require.Equal(t, 1, registryHas(t, db, "godjee"), "повторный накат не внёс godjee")
	require.Equal(t, 1, registryHas(t, db, "dlputi1u"), "повторный накат не внёс dlputi1u")
}

// TestAccountIDOrder6a_AccountCreatedDuringTheRolloutIsHeldByTheKey — заказ 6 (а):
// прежний под создаёт аккаунты, пока новый накатывает ключ Р6а. Вставка, начатая
// до наката и зафиксированная во время него, и вставка, пришедшая, когда накат
// держит таблицу, обе попадают под ключ: после наката их имена не принимаются
// идентификатором другого аккаунта.
func TestAccountIDOrder6a_AccountCreatedDuringTheRolloutIsHeldByTheKey(t *testing.T) {
	db := beforeStringForm(t)
	owner := seedOwner(t, db, "k18")
	ctx := context.Background()
	const earlyName, lateName = "k18-early", "k18-late"

	v := requireStringFormMigrationInChain(t)

	oldPod, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = oldPod.Rollback() }()
	_, err = oldPod.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`, ids.NewID(domain.PrefixAccount), earlyName, owner)
	require.NoError(t, err)

	migrated := make(chan error, 1)
	go func() { migrated <- goose.UpTo(db, ".", v) }()
	waitForLockWaiters(t, db, 1, "накат не встал за вставкой прежнего пода")

	lateDone := make(chan error, 1)
	go func() { lateDone <- insertAccountRow(db, ids.NewID(domain.PrefixAccount), lateName, owner) }()
	waitForLockWaiters(t, db, 2, "вставка во время наката не встала за накатом")

	require.NoError(t, oldPod.Commit())
	require.NoError(t, <-migrated, "накат обязан примениться")
	require.NoError(t, <-lateDone, "вставка во время наката обязана пройти")

	other := seedOwner(t, db, "k18o")
	for _, name := range []string{earlyName, lateName} {
		requireConstraintRefusal(t, insertAccountRow(db, name, "k18-probe", other),
			"идентификатор, равный имени аккаунта, созданного во время наката ("+name+")")
	}
	require.NoError(t, insertAccountRow(db, "k18-free", "k18-free-name", other), "близнец: свободная строка проходит")
}
