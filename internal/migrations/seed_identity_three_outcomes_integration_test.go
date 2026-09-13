// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// seed_identity_three_outcomes_integration_test.go — ТРИ ИСХОДА миграций
// перевода, снятые опытом (приёмка
// `docs/engineering/acceptance/seed-identity-names-its-own-service.md` §4.1,
// сценарии KAN-SEED-1-03 и -04).
//
// # ПОЧЕМУ ОТДЕЛЬНАЯ ПРОБА, А НЕ ПРОГОН ЦЕПОЧКИ
//
// Накат цепочки на свежую базу проходит РОВНО ОДНУ ветвь из трёх — «имя
// прежнее, переписываем». Две другие цепочкой недостижимы by construction:
// повторного наката goose не делает, а третье написание неоткуда взяться между
// сводом и переводом. Поэтому тело наката исполняется здесь НАПРЯМУЮ, поверх
// уже применённой цепочки: это и есть тот шов, которого накат не даёт.
//
// # ЧТО ЭТО ДОКАЗЫВАЕТ, А ЧТО НЕТ
//
// Доказывает, что ветви существуют и ведут себя как объявлено. НЕ доказывает,
// что goose позовёт их в этом порядке, — это свойство наката, и его утверждает
// прогон цепочки в соседних файлах.
package migrations_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// seedIdentityMigration — миграция перевода посевной идентичности.
const seedIdentityMigration = "20260913144108_seed_identity_leaves_the_platform_brand.sql"

// upBodyOf — исполняемая часть наката: аннотации goose сами являются
// комментариями, поэтому забеливаются вместе с прозой, а тело блока остаётся.
func upBodyOf(t *testing.T, file string) string {
	t.Helper()
	raw, err := migrations.FS.ReadFile(file)
	require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: миграция %s не прочитана", file)
	up := migrations.MigrationUpSection(string(raw))
	require.Contains(t, up, "DO $$",
		"в накате не осталось исполняемого блока — разбор отрезал не то, и проба "+
			"исполняла бы пустоту")
	return up
}

// TestSeedIdentity_SecondApplicationIsSilent — KAN-SEED-1-03: повторное
// применение проходит молча.
//
// Это ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к отказу на третьем написании: без него «миграция
// отказывает» зеленело бы на теле, которое отказывает ВСЕГДА — в том числе на
// уже переведённой установке, то есть на каждом повторном накате свода.
func TestSeedIdentity_SecondApplicationIsSilent(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	// Предпосылка: цепочка уже перевела строки, то есть тело встречает
	// ОБЪЯВЛЕННЫЕ значения.
	var name string
	require.NoError(t, db.QueryRow(
		`SELECT name FROM kaname.accounts WHERE id = 'acc1a18042d81fb438d6'`).Scan(&name))
	require.Equal(t, "system", name, "предпосылка пробы не создана: цепочка не перевела имя")

	_, err := db.Exec(upBodyOf(t, seedIdentityMigration))
	require.NoError(t, err,
		"повторное применение отказало на уже переведённой установке: тело отказывает "+
			"ВСЕГДА, и всякий повторный накат свода ронял бы пуск")

	// И ничего не сдвинуло: «прошло молча» — это про состояние, а не про
	// отсутствие исключения.
	require.NoError(t, db.QueryRow(
		`SELECT name FROM kaname.accounts WHERE id = 'acc1a18042d81fb438d6'`).Scan(&name))
	require.Equal(t, "system", name)
}

// TestSeedIdentity_ThirdSpellingIsRefused — KAN-SEED-1-04: ТРЕТЬЕ написание
// даёт ОТКАЗ, а не тихое затирание.
//
// Имя мутабельно, и оператор вправе был выбрать своё. Затереть его молча значит
// отобрать ровно ту свободу, ради которой имя и мутабельно, — и отобрать
// незаметно: в базе просто окажется другое имя.
//
// Мир пробы отличается от положительного близнеца РОВНО ОДНИМ фактом — именем
// строки. Всё остальное то же: та же цепочка, то же тело, тот же порядок.
func TestSeedIdentity_ThirdSpellingIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	const chosenByOperator = "acme-platform"
	_, err := db.Exec(
		`UPDATE kaname.accounts SET name = $1 WHERE id = 'acc1a18042d81fb438d6'`, chosenByOperator)
	require.NoError(t, err, "предпосылка пробы не создана: третье написание не завелось")

	_, err = db.Exec(upBodyOf(t, seedIdentityMigration))
	require.Error(t, err,
		"тело наката приняло ТРЕТЬЕ написание: чужой выбор был бы затёрт молча")
	require.Contains(t, err.Error(), chosenByOperator,
		"отказ не называет написания, которое встретил: оператор не узнает, что именно "+
			"миграция отказалась трогать")

	// Строка осталась НЕТРОНУТОЙ — отказ, а не «отказал и всё-таки переписал».
	var name string
	require.NoError(t, db.QueryRow(
		`SELECT name FROM kaname.accounts WHERE id = 'acc1a18042d81fb438d6'`).Scan(&name))
	require.Equal(t, chosenByOperator, name)
}

// TestSystemRoleNames_ThirdSpellingIsRefused — тот же третий исход у миграции
// класса B.
//
// Отдельная проба, а не ещё один случай в таблице: тела разные, и общий вывод
// «форма трёх исходов соблюдена» из одной миграции про другую не следует.
func TestSystemRoleNames_ThirdSpellingIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer func() { _ = db.Close() }()

	const chosenByOperator = "acme.superuser"
	_, err := db.Exec(
		`UPDATE kaname.roles SET name = $1 WHERE id = 'rol000000000sysadmin'`, chosenByOperator)
	require.NoError(t, err, "предпосылка пробы не создана")

	body := upBodyOf(t, "20260913143007_system_role_names_leave_the_platform_brand.sql")
	_, err = db.Exec(body)
	require.Error(t, err, "тело наката приняло ТРЕТЬЕ написание имени роли")
	require.True(t, strings.Contains(err.Error(), chosenByOperator),
		"отказ не называет написания, которое встретил: %v", err)
}
