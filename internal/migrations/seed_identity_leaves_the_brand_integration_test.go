// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// seed_identity_leaves_the_brand_integration_test.go — класс C приёмки
// `docs/engineering/acceptance/seed-identity-names-its-own-service.md`
// (§2.1 класс C, §2.2, §4.1, §4.4, §8 шаг 5 и место П6; сценарии KAN-SEED-1-01,
// -03, -04, -13, -14).
//
// # ПОЧЕМУ ПРОБА, А НЕ ЧТЕНИЕ МИГРАЦИИ
//
// Имена и значения сеет свод, и править его нельзя (ban #5). Утверждение «в
// установке этого больше нет» есть утверждение о РЕЗУЛЬТАТЕ всей цепочки.
//
// # ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ СВЕРХ ИМЕНИ
//
// Идентификаторы ВЫВОДИЛИСЬ из переводимых имён. Проба поэтому спрашивает не
// «как называется строка», а «АДРЕСУЕТ ЛИ пиннутый идентификатор строку,
// носящую объявленное имя»: это и есть ban #15, снятый опытом, — имя ушло,
// координата осталась. Утверждение об имени без утверждения об идентификаторе
// зеленело бы на переходе, который завёл вторую строку рядом с первой.
package migrations_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"

	bootstraptoken "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/bootstrap_token"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// TestSeedIdentity_NamesNoLongerNameThePlatform — KAN-SEED-1-01: после цепочки
// ни аккаунт, ни служебная запись не носят имени платформы.
func TestSeedIdentity_NamesNoLongerNameThePlatform(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	id := bootstraptoken.DeriveIdentity()

	var accountName string
	require.NoError(t, db.QueryRow(
		`SELECT name FROM kaname.accounts WHERE id = 'acc1a18042d81fb438d6'`).Scan(&accountName),
		"строки системного аккаунта нет вовсе — вердикт об имени беспредметен")
	require.Equal(t, domain.SystemAccountName, accountName,
		"имя системного аккаунта называет платформу: оператор, поставивший службу одну, "+
			"видит в СВОЕЙ установке аккаунт с именем продукта, которого он не ставил")

	var saName string
	require.NoError(t, db.QueryRow(
		`SELECT name FROM kaname.service_accounts WHERE id = $1`, id.SvaID).Scan(&saName),
		"пиннутый идентификатор служебной записи не адресует ни одной строки — "+
			"переход сдвинул координату, а ban #15 запрещает ровно это")
	require.Equal(t, domain.BootstrapAdminSAName, saName)

	// Прежних написаний в таблицах нет НИ ОДНОГО — и это утверждение о СТРОКАХ,
	// а не о двух известных: вторая строка с прежним именем была бы ровно тем
	// исходом, ради которого проба написана.
	for _, q := range []struct {
		what, sql, name string
	}{
		{"аккаунт", `SELECT count(*) FROM kaname.accounts WHERE name = $1`, "kacho-system"},
		{"служебная запись", `SELECT count(*) FROM kaname.service_accounts WHERE name = $1`, "kacho-bootstrap-admin"},
	} {
		var n int
		require.NoError(t, db.QueryRow(q.sql, q.name).Scan(&n))
		require.Zerof(t, n, "%s с прежним написанием %q осталась строкой таблицы", q.what, q.name)
	}
}

// TestSeedIdentity_PinnedIDsStillAddressTheirRows — KAN-SEED-1-13/-14: имя
// ушло, ВСЕ пиннутые координаты остались на месте.
//
// Это и есть предмет пина (§2.2): пока идентификатор выводился из имени, его
// значение после перевода оставалось синтаксически верным и переставало
// находить строку — наблюдаемо только отказом чеканки у оператора, который
// ничего не менял.
func TestSeedIdentity_PinnedIDsStillAddressTheirRows(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	id := bootstraptoken.DeriveIdentity()

	var owner string
	require.NoError(t, db.QueryRow(
		`SELECT owner_user_id FROM kaname.accounts WHERE id = 'acc1a18042d81fb438d6'`).Scan(&owner))
	require.Equal(t, id.CreatedByUserID, owner,
		"владелец аккаунта адресуется не тем идентификатором, который отдаёт чеканка: "+
			"строка отображения на клиента провайдера не соберётся — внешний ключ не найдёт строки")

	var users int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.users WHERE id = $1`, id.CreatedByUserID).Scan(&users))
	require.Equal(t, 1, users)

	// Служебная запись живёт в ТОМ аккаунте, чьё имя переведено, — то есть
	// перевод не расщепил пару.
	var inAccount bool
	require.NoError(t, db.QueryRow(
		`SELECT sa.account_id = 'acc1a18042d81fb438d6' FROM kaname.service_accounts sa WHERE sa.id = $1`,
		id.SvaID).Scan(&inAccount))
	require.True(t, inAccount)
}

// TestSeedIdentity_SeededProseNoLongerNamesThePlatform — П6: три ЗНАЧЕНИЯ,
// называвшие платформу прозой, переведены той же миграцией.
//
// Предикат берётся ТОТ ЖЕ, что объявлен §7-П6 приёмки: образец бренда по
// значению, а не перечень трёх известных строк. Перечень пережил бы появление
// четвёртой строки молча.
func TestSeedIdentity_SeededProseNoLongerNamesThePlatform(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	type cell struct{ table, column, sql string }
	cells := []cell{
		{"users", "email", `SELECT email FROM kaname.users WHERE id = 'usr1a18042d81fb438d6'`},
		{"users", "display_name", `SELECT display_name FROM kaname.users WHERE id = 'usr1a18042d81fb438d6'`},
		{"clusters", "description", `SELECT description FROM kaname.clusters WHERE id = 'cluster_root'`},
	}

	// Образцы бренда — те же три написания, по которым его ищет предикат П6.
	brands := []string{"Kacho", "Kachō", "kacho"}

	read := 0
	for _, c := range cells {
		var got string
		require.NoError(t, db.QueryRow(c.sql).Scan(&got),
			"строки %s.%s нет — вердикт о значении беспредметен", c.table, c.column)
		read++
		require.NotEmpty(t, got, "%s.%s пусто — «бренда нет» зеленело бы на пустом значении",
			c.table, c.column)
		for _, brand := range brands {
			require.NotContainsf(t, got, brand,
				"%s.%s = %q несёт имя платформы: оператор, поставивший службу одну, видит его "+
					"в своей установке первым — раньше, чем откроет исходники",
				c.table, c.column, got)
		}
	}
	// Перепись: «ноль находок» обязано быть отличимо от «ноль прочитанного».
	require.Equal(t, len(cells), read)
	t.Logf("перепись: значений прочитано %d · образцов бренда %d", read, len(brands))
}

// TestSeedIdentity_MigrationWritesRenamesStatically — ПРЕДПОСЫЛКА разбора
// дерева, снятая опытом, а не объявленная.
//
// Посев служебных учёток по цепочке читает СТАТИЧЕСКИЙ оператор: динамическое
// имя через переменную разбор не узнаёт и называет форму непознанной. Миграция
// перевода пишет литералами именно поэтому — и если завтра кто-то заменит
// литерал переменной, красное придёт отсюда, а не из чужого пакета.
func TestSeedIdentity_MigrationWritesRenamesStatically(t *testing.T) {
	const file = "20260913144108_seed_identity_leaves_the_platform_brand.sql"
	body, err := migrations.FS.ReadFile(file)
	require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: миграция %s не прочитана", file)

	up := migrations.MigrationUpSection(string(body))
	require.Contains(t, up,
		"UPDATE kaname.service_accounts SET name = 'bootstrap-admin' WHERE id = 'svab91854890de887e6d'",
		"перевод имени служебной записи записан не статическим оператором с литералами — "+
			"разбор посева по цепочке такую форму не узнаёт и объявит её непознанной")
	require.NotContains(t, up, "SET name = v_",
		"перевод имени пишется переменной: форма уходит из-под наблюдения разбора молча")
}
