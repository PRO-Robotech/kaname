// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// basic_token_credential_kind_integration_test.go — ИНВАРИАНТЫ ВИДА
// УДОСТОВЕРЕНИЯ ДЕРЖИТ ТАБЛИЦА, А НЕ ПРОВЕРКА В КОДЕ.
//
// Приёмка BAT-1 §4, сценарии BAT-1-19, BAT-1-20, BAT-1-24, BAT-1-25.
//
// Предмет: «бессрочного секрета не бывает», «у секрета нет ключевого материала»,
// «у пары ключей нет хеша секрета» — это утверждения, которые обязан произносить
// ОПЕРАТОР БАЗЫ (ban #10). Программная проверка «прочитал → сравнил → записал»
// под конкуренцией пропускает оба входа.
//
// Каждое отрицание здесь стоит рядом с положительным контролем: перечень
// отказов зеленел бы на схеме, отвергающей вообще всё.
//
// # Здесь стояла проба ОБРАТНОГО ЗАПОЛНЕНИЯ (BAT-1-25) — предмета у неё нет
//
// Она останавливала цепочку перед `20260824210000`, сеяла три формы уже лежащих
// строк без колонки вида и требовала, чтобы миграция расклассифицировала их по
// СОДЕРЖИМОМУ в четыре ветви. Миграций сервиса теперь одна — свод, — и колонка
// `credential_kind` в нём объявлена сразу `NOT NULL`: строки без вида не
// существует ни на одной применимой ревизии, поэтому Given пробы отвергает
// продукт, а не проба.
//
// Проба снята вместе со своим предметом, а не ослаблена. То, ради чего вид
// вводился, — что схема САМА держит инварианты каждой из четырёх форм —
// утверждают пробы BAT-1-19, BAT-1-20 и BAT-1-24 ниже, и на своде они живут без
// изменений. Сценарий приёмки BAT-1-25 остался без держателя; он назван в отчёте
// линии как остаток, а не как починка.

package migrations_test

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
)

// seedCredentialOwners заводит владельцев, без которых внешние ключи обеих
// таблиц удостоверений не выполнимы.
func seedCredentialOwners(t *testing.T, db *sql.DB) {
	t.Helper()
	// Аккаунт и его владелец ссылаются друг на друга, поэтому посев идёт ОДНОЙ
	// транзакцией: внешние ключи здесь отложенные, и порядок вставки между ними
	// не определён by construction.
	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(`SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)

	_, err = tx.Exec(`
INSERT INTO kaname.accounts (id, name, owner_user_id)
VALUES ('acc00000000000000bat', 'bat-1', 'usr00000000000000bat')
ON CONFLICT DO NOTHING`)
	require.NoError(t, err, "посев аккаунта")

	_, err = tx.Exec(`
INSERT INTO kaname.users (id, external_id, email, account_id, invite_status)
VALUES ('usr00000000000000bat', 'ext-bat-1', 'bat1@example.invalid', 'acc00000000000000bat', 'ACTIVE')
ON CONFLICT DO NOTHING`)
	require.NoError(t, err, "посев человека")

	_, err = tx.Exec(`
INSERT INTO kaname.service_accounts (id, account_id, name)
VALUES ('sva00000000000000bat', 'acc00000000000000bat', 'bat-one-sa')
ON CONFLICT DO NOTHING`)
	require.NoError(t, err, "посев служебной учётки")

	seedWayIn(t, tx)
	require.NoError(t, tx.Commit(), "посев владельцев удостоверений")
}

// insertSACred — вставка строки удостоверения служебной учётки.
func insertSACred(db *sql.DB, id, kind string, secretHash []byte, publicKeyPEM, keyAlg string, trusted string, ttlDays int) error {
	expires := "NULL"
	if ttlDays > 0 {
		expires = fmt.Sprintf("now() + interval '%d days'", ttlDays)
	}
	_, err := db.Exec(fmt.Sprintf(`
INSERT INTO kaname.service_account_oauth_clients
    (id, sva_id, created_by_user_id, credential_kind, secret_hash, public_key_pem, key_algorithm, trusted_subjects, expires_at)
VALUES ($1, 'sva00000000000000bat', 'usr00000000000000bat', $2, $3, $4, $5, $6::jsonb, %s)`, expires),
		id, kind, secretHash, publicKeyPEM, keyAlg, trusted)
	return err
}

// insertUserCred — вставка строки удостоверения человека. Колонки называются
// поимённо, чтобы отказ указывал на предмет, а не на порядок значений.
func insertUserCred(db *sql.DB, id, kind string, secretHash []byte, publicKeyPEM, keyAlg string, ttlDays int) error {
	expires := "NULL"
	if ttlDays > 0 {
		expires = fmt.Sprintf("now() + interval '%d days'", ttlDays)
	}
	_, err := db.Exec(fmt.Sprintf(`
INSERT INTO kaname.user_oauth_clients
    (id, user_id, created_by_user_id, credential_kind, secret_hash, public_key_pem, key_algorithm, expires_at)
VALUES ($1, 'usr00000000000000bat', 'usr00000000000000bat', $2, $3, $4, $5, %s)`, expires),
		id, kind, secretHash, publicKeyPEM, keyAlg)
	return err
}

// BAT-1-19 — законный вход существует ПО КАЖДОЙ колонке, и он утверждается
// первым: сценарий, состояние которого схема не допускает, Given не является.
func TestBAT1_19_LawfulSecretRowInsertsAndUnlawfulOnesAreRefusedByTheDatabase(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer db.Close()
	seedCredentialOwners(t, db)

	var err error
	hash := make([]byte, 32)
	for i := range hash {
		hash[i] = byte(i + 1)
	}

	// Законная строка вида SECRET: хеш есть, ключевого материала нет, срок
	// есть.
	require.NoError(t,
		insertUserCred(db, "uoc_00000000000000001", "SECRET", hash, "", "", 30),
		"законная строка вида SECRET обязана записываться — иначе Given прочих сценариев неисполним")

	// Законная строка вида KEYPAIR записывается.
	require.NoError(t,
		insertUserCred(db, "uoc_00000000000000002", "KEYPAIR", noHash, "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----", "ES256", 0),
		"законная строка вида KEYPAIR обязана записываться")

	for name, tc := range map[string]struct {
		id     string
		kind   string
		hash   []byte
		pubKey string
		alg    string
		ttl    int
	}{
		"SECRET без хеша":              {"uoc_00000000000000010", "SECRET", noHash, "", "", 30},
		"SECRET с ключевым материалом": {"uoc_00000000000000011", "SECRET", hash, "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----", "ES256", 30},
		"SECRET без срока":             {"uoc_00000000000000012", "SECRET", hash, "", "", 0},
		"KEYPAIR с хешем секрета":      {"uoc_00000000000000013", "KEYPAIR", hash, "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----", "ES256", 0},
	} {
		err := insertUserCred(db, tc.id, tc.kind, tc.hash, tc.pubKey, tc.alg, tc.ttl)
		require.Error(t, err, "%s: строка записалась, ожидался отказ базы", name)
	}

	// Неизвестный вид — словарь закрыт. LEGACY — такой же вид вне словаря:
	// снят вместе со столбцом имени клиента у поставщика (kaname#362).
	err = insertUserCred(db, "uoc_00000000000000021", "SOMETHING", noHash, "", "", 0)
	require.Error(t, err, "вид вне закрытого словаря записался")
	err = insertUserCred(db, "uoc_00000000000000023", "LEGACY", noHash, "", "", 0)
	require.Error(t, err, "снятый вид LEGACY записался")

	// FEDERATED у личности недостижим by construction — поля, которым он
	// задаётся, в её контракте нет.
	err = insertUserCred(db, "uoc_00000000000000022", "FEDERATED", noHash, "", "", 0)
	require.Error(t, err, "FEDERATED записан в таблицу личности, где его быть не может")
}

// BAT-1-20 — правка, снимающая срок либо добавляющая ключевой материал,
// отвергается базой; законная правка проходит.
func TestBAT1_20_UpdatesThatBreakTheSecretShapeAreRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer db.Close()
	seedCredentialOwners(t, db)

	var err error
	hash := make([]byte, 32)
	hash[0] = 7
	require.NoError(t, insertUserCred(db, "uoc_00000000000000030", "SECRET", hash, "", "", 30))

	_, err = db.Exec(`UPDATE kaname.user_oauth_clients SET expires_at = NULL WHERE id = 'uoc_00000000000000030'`)
	require.Error(t, err, "срок снят правкой — бессрочный секрет стал выразим")

	_, err = db.Exec(`UPDATE kaname.user_oauth_clients SET public_key_pem = 'x', key_algorithm = 'ES256' WHERE id = 'uoc_00000000000000030'`)
	require.Error(t, err, "ключевой материал добавлен к строке вида SECRET")

	// Положительный контроль: законная правка проходит.
	_, err = db.Exec(`UPDATE kaname.user_oauth_clients SET description = 'ноутбук' WHERE id = 'uoc_00000000000000030'`)
	require.NoError(t, err, "законная правка отвергнута — ограничение шире предмета")
}

// BAT-1-24 — частичная уникальность хеша. Проба ОБЪЯВЛЯЕТ в своём тексте, что
// продуктовый путь такого входа не производит: хеш покрывает идентификатор
// вместе с секретом, а идентификаторы строк различны by construction. Это
// бэкстоп от точного дубля строки, а НЕ детектор испорченного источника
// случайности — тот меряет BAT-1-08.
func TestBAT1_24_DuplicateSecretHashIsRefusedAsABackstop(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer db.Close()
	seedCredentialOwners(t, db)

	var err error
	h1 := make([]byte, 32)
	h1[0] = 1
	h2 := make([]byte, 32)
	h2[0] = 2

	require.NoError(t, insertUserCred(db, "uoc_00000000000000040", "SECRET", h1, "", "", 30))
	err = insertUserCred(db, "uoc_00000000000000041", "SECRET", h1, "", "", 30)
	require.Error(t, err, "дубль хеша записался — бэкстопа нет")

	// Положительный контроль: разные хеши записываются оба.
	require.NoError(t, insertUserCred(db, "uoc_00000000000000042", "SECRET", h2, "", "", 30),
		"строка с ДРУГИМ хешем отвергнута — индекс шире своего предмета")
}

// BAT-1-19 — таблица служебной учётки: у каждого вида своя форма, и держит её
// база. Столбца имени клиента у внешнего поставщика больше нет (kaname#362):
// ключевая пара и федеративный ключ записываются без него, а поперечную форму
// видов держит проба снятия столбца
// (`provider_mirror_leaves_the_credential_tables_integration_test.go`).
func TestBAT1_19_ServiceAccountKindsHoldTheirShape(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	defer db.Close()
	seedCredentialOwners(t, db)

	var err error
	hash := make([]byte, 32)
	hash[0] = 9
	pem := "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----"
	trusted := `[{"issuer":"https://idp.example.invalid","subject_pattern":"^x$"}]`

	require.NoError(t,
		insertSACred(db, "soc_00000000000000001", "SECRET", hash, "", "", "[]", 30),
		"законная строка SECRET служебной учётки обязана записываться")
	require.NoError(t,
		insertSACred(db, "soc_00000000000000002", "KEYPAIR", noHash, pem, "ES256", "[]", 0),
		"законная строка KEYPAIR служебной учётки обязана записываться")
	require.NoError(t,
		insertSACred(db, "soc_00000000000000005", "FEDERATED", noHash, "", "", trusted, 0),
		"FEDERATED с непустым перечнем доверенных субъектов обязан записываться")

	// SECRET с непустым перечнем доверенных субъектов — отказ.
	err = insertSACred(db, "soc_00000000000000006", "SECRET", hash, "", "", trusted, 30)
	require.Error(t, err, "SECRET с перечнем доверенных субъектов записался")
	// Снятый вид LEGACY — отказ словаря.
	err = insertSACred(db, "soc_00000000000000007", "LEGACY", noHash, pem, "ES256", "[]", 0)
	require.Error(t, err, "снятый вид LEGACY записался")
}

// noHash — пустой хеш. Именно ПУСТОЙ, а не NULL: колонка объявлена NOT NULL
// DEFAULT ”, и «секрета нет» выражается пустым значением, а не отсутствием.
var noHash = []byte{}
