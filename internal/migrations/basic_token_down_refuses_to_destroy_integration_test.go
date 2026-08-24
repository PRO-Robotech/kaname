// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// basic_token_down_refuses_to_destroy_integration_test.go — ОБРАТНЫЙ ХОД
// 20260824210000 НЕ УНИЧТОЖАЕТ УДОСТОВЕРЕНИЙ, КОТОРЫЕ НЕЧЕМ ВОССТАНОВИТЬ.
//
// Предмет. Секрет вида SECRET предъявляется арендатору ОДИН раз; в хранилище
// лежит только его свёртка. Значит удалённая строка не восстанавливается ничем:
// ни из резервной копии секрета (её не существует), ни повторной выдачей (это
// другое удостоверение с другим идентификатором). Обратный ход при этом описан
// как ШТАТНАЯ процедура развёртывания — то есть команда, которую оператор
// набирает не задумываясь.
//
// Из трёх исходов («удалять молча» · «предупредить комментарием» · «отказаться
// выполняться») выбран третий: комментарий не останавливает, а удаление
// необратимо. Отказ обязан называть ПОСЛЕДСТВИЕ, а не только факт.
//
// Отрицание стоит В ПАРЕ с положительным контролем: страж, роняющий обратный ход
// ВСЕГДА, отнял бы у оператора штатную процедуру там, где она безопасна, — и
// проба «отказ случился» зеленела бы на нём тождественно.
package migrations_test

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// downOneIAMMigration откатывает ПОСЛЕДНЮЮ миграцию цепочки и возвращает исход
// как значение: отказ здесь — предмет утверждения, а не сбой пробы.
// downToBeforeBasicTokenMigration откатывает всё, что нумеровано ВЫШЕ миграции
// вида удостоверения, и её саму.
//
// Здесь стоял откат ОДНОЙ последней миграции, и это связывало пробу не с её
// предметом, а с ПОЛОЖЕНИЕМ файла в очереди: первая же миграция, вставшая
// следом, забирала откат себе, и проба зеленела бы (или краснела) о чужой
// работе. Так и вышло — потолок числа удостоверений (#1191) сместил её предмет.
//
// Версия названа числом: вывести её из дерева можно только поиском по имени
// файла, то есть тем же действием, предмет которого проба и стережёт.
func downToBeforeBasicTokenMigration(t *testing.T, db *sql.DB) error {
	t.Helper()
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	const basicTokenVersion int64 = 20260824210000
	return goose.DownTo(db, ".", basicTokenVersion-1)
}

// credentialKindColumnExists — присутствует ли колонка вида. Ею измеряется, что
// отказавший обратный ход НЕ СНЁС ничего по дороге: страж обязан стоять до
// первого разрушающего оператора, а не после него.
func credentialKindColumnExists(t *testing.T, db *sql.DB, table string) bool {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`
SELECT count(*) FROM information_schema.columns
 WHERE table_schema = 'kacho_iam' AND table_name = $1 AND column_name = 'credential_kind'`,
		table).Scan(&n))
	return n > 0
}

func countRows(t *testing.T, db *sql.DB, query string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(query).Scan(&n))
	return n
}

// BAT-1-DOWN-1 — при живых удостоверениях вида SECRET обратный ход ОТКАЗЫВАЕТСЯ
// и не разрушает ничего.
//
// Утверждается ТРОЙКА, потому что двух утверждений мало: (а) отказ случился;
// (б) его текст называет последствие — иначе оператор прочтёт отказ как
// неисправность миграции и обойдёт его; (в) обе строки на месте И колонки на
// месте — отказ, наступивший ПОСЛЕ первого DROP, оставил бы схему разобранной.
func TestBAT1_DOWN_1_RefusesWhileSecretCredentialsExistAndDestroysNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer db.Close()
	seedCredentialOwners(t, db)

	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 3)
	}
	otherHash := make([]byte, 32)
	for i := range otherHash {
		otherHash[i] = byte(i + 9)
	}

	require.NoError(t,
		insertSACred(db, "soc_00000000000000d01", "SECRET", hash, "", "", nil, "[]", 30),
		"Given неисполним, если законная строка вида SECRET не записывается")
	require.NoError(t,
		insertUserCred(db, "uoc_00000000000000d01", "SECRET", otherHash, "", "", nil, 30),
		"Given неисполним, если законная строка вида SECRET не записывается")

	err := downToBeforeBasicTokenMigration(t, db)

	// (а) отказ случился.
	require.Error(t, err,
		"обратный ход обязан ОТКАЗАТЬСЯ при живых удостоверениях вида SECRET: их секрет "+
			"показан один раз, в хранилище лежит только свёртка, и удалённая строка не "+
			"восстанавливается ни резервной копией, ни повторной выдачей")

	// (б) текст называет ПОСЛЕДСТВИЕ и ШТАТНЫЙ ВЫХОД, причём в ОСНОВНОМ
	// сообщении.
	//
	// Почему в основном: goose оборачивает отказ и доносит до оператора только
	// его — `DETAIL` и `HINT` в вывод не попадают (проверено наблюдением, а не
	// прочитано в документации). Выход, положенный в HINT, не доехал бы ни до
	// кого, и оператор, прочитав «откат невозможен» без указания, что делать,
	// обошёл бы страж — то есть уничтожил бы ровно те удостоверения, ради
	// которых страж стоит.
	//
	// Утверждается не «есть слово», а четыре РАЗНЫХ слагаемых: что происходит ·
	// почему необратимо · сколько строк · что делать. Проверка на одно слово
	// зеленела бы на сообщении «error: SECRET».
	msg := strings.ToLower(err.Error())
	for want, why := range map[string]string{
		"irreversibl":     "последствие: удаление необратимо",
		"only its digest": "почему необратимо: секрет не хранится",
		"way out":         "штатный выход обязан быть НАЗВАН, иначе страж обходят",
		"revoke":          "штатный выход: сперва отозвать продуктовым глаголом",
	} {
		require.Contains(t, msg, want,
			"основное сообщение отказа обязано нести %s — DETAIL/HINT до оператора "+
				"не доезжают: %s", why, err)
	}
	require.Contains(t, msg, "service_account_oauth_clients 1",
		"отказ обязан называть ЧИСЛО по каждой таблице: одно общее число не говорит, "+
			"где именно лежат удостоверения, которые надо отозвать: %s", err)

	// (в) не разрушено НИЧЕГО — ни строк, ни схемы.
	require.Equal(t, 1,
		countRows(t, db, `SELECT count(*) FROM kacho_iam.service_account_oauth_clients WHERE credential_kind = 'SECRET'`),
		"строка удостоверения служебной учётки обязана пережить отказавший обратный ход")
	require.Equal(t, 1,
		countRows(t, db, `SELECT count(*) FROM kacho_iam.user_oauth_clients WHERE credential_kind = 'SECRET'`),
		"строка удостоверения человека обязана пережить отказавший обратный ход")
	require.True(t, credentialKindColumnExists(t, db, "service_account_oauth_clients"),
		"страж обязан стоять ДО первого разрушающего оператора — иначе отказ оставляет схему разобранной")
	require.True(t, credentialKindColumnExists(t, db, "user_oauth_clients"),
		"страж обязан стоять ДО первого разрушающего оператора — иначе отказ оставляет схему разобранной")
}

// BAT-1-DOWN-2 — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: без удостоверений вида SECRET обратный
// ход остаётся штатной процедурой и проходит.
//
// Таблицы намеренно НЕ ПУСТЫ: строка вида KEYPAIR стоит здесь затем, чтобы
// утверждение «прошло» не оказалось утверждением о пустой базе. Пустая база
// прошла бы и у стража, роняющего всё, где есть хоть одна строка.
func TestBAT1_DOWN_2_ProceedsWhenNoSecretCredentialsExist(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer db.Close()
	seedCredentialOwners(t, db)

	mirror := "mirror-bat-down-2"
	const pem = "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----"
	require.NoError(t,
		insertSACred(db, "soc_00000000000000d02", "KEYPAIR", noHash, pem, "ES256", &mirror, "[]", 0),
		"Given неисполним, если законная строка вида KEYPAIR не записывается")
	require.NoError(t,
		insertUserCred(db, "uoc_00000000000000d02", "KEYPAIR", noHash, pem, "ES256", nil, 0),
		"Given неисполним, если законная строка вида KEYPAIR не записывается")

	require.NoError(t, downToBeforeBasicTokenMigration(t, db),
		"обратный ход обязан проходить там, где ему нечего уничтожать: страж, "+
			"отказывающий всегда, отнял бы у оператора штатную процедуру")

	require.False(t, credentialKindColumnExists(t, db, "service_account_oauth_clients"),
		"прошедший обратный ход обязан снять колонку вида — иначе он не обратный ход")
	require.False(t, credentialKindColumnExists(t, db, "user_oauth_clients"),
		"прошедший обратный ход обязан снять колонку вида — иначе он не обратный ход")
	require.Equal(t, 1,
		countRows(t, db, `SELECT count(*) FROM kacho_iam.service_account_oauth_clients`),
		"строка вида KEYPAIR обязана пережить обратный ход: её удостоверение он не касается")
	require.Equal(t, 1,
		countRows(t, db, `SELECT count(*) FROM kacho_iam.user_oauth_clients`),
		"строка вида KEYPAIR обязана пережить обратный ход: её удостоверение он не касается")
}
