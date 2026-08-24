// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// credential_ceiling_seed_integration_test.go — ЗАТРАВКА потолка удостоверений
// (задача #1191, приёмка §7.4, сценарий CRED-CAP-35).
//
// # Почему проба живёт здесь, а не на пуле репозитория
//
// Предмет — ПЕРЕХОД СОСТОЯНИЯ, а не поведение глагола: строки удостоверений
// лежат ДО этой работы, и потолок вводится поверх них. Воспроизвести это можно
// только доведя базу до предыдущего состояния, наполнив её и применив миграцию.
//
// # Что случилось бы без затравки
//
// Триггер срабатывает на вставке; по уже лежащим строкам он не сработает by
// construction. Строка учёта, заведённая с нулём при существующих
// удостоверениях, подарила бы принципалу полный потолок СВЕРХ имеющегося —
// молча, потому что выглядит она исправной. Это самое рискованное место
// выкатки, и оно единственное трогает живое дерево.

package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// credentialCeilingVersion — версия миграции потолка. Выписана, потому что
// предмет пробы — состояние ДО неё и ПОСЛЕ; вывести её из дерева можно только
// тем же поиском по имени, который и есть предмет.
const credentialCeilingVersion int64 = 20260824230000

// upToBeforeCredentialCeiling доводит базу до всего, что нумеровано НИЖЕ
// миграции потолка.
//
// До версии-предшественницы, а не до жёсткого числа соседа: жёсткое число
// устарело бы от первой же миграции, вставшей между ними.
func upToBeforeCredentialCeiling(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(db, ".", credentialCeilingVersion-1),
		"цепочка обязана дойти до состояния ПЕРЕД потолком — иначе Given сценария не создан")
	return db
}

// CRED-CAP-35 — затравка ставит ФАКТИЧЕСКОЕ потребление, а не ноль.
func TestCredentialCeilingSeed_CountsWhatWasAlreadyThere(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upToBeforeCredentialCeiling(t, pgtest.NewEmptyDB(t))
	defer db.Close()

	// Предпосылка: потолка ещё нет ни в одном из двух мест.
	var kinds int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM kacho_iam.limits
		 WHERE kind IN ('iam.user.credential', 'iam.serviceAccount.credential')`).Scan(&kinds))
	require.Zero(t, kinds, "величина потолка уже посеяна — предпосылка сценария не создана")

	seedCredentialOwners(t, db)

	// Три удостоверения человека и два — служебной учётки, все ДО миграции.
	for i, id := range []string{"uoc_000000000000seed1", "uoc_000000000000seed2", "uoc_000000000000seed3"} {
		require.NoErrorf(t, insertUserCred(db, id, "KEYPAIR", noHash,
			"-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----", "ES256", nil, 0),
			"посев удостоверения %d", i+1)
	}
	mirrorOne, mirrorTwo := "seed-mirror-1", "seed-mirror-2"
	require.NoError(t, insertSACred(db, "soc_000000000000seed1", "KEYPAIR", noHash,
		"-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----", "ES256", &mirrorOne, "[]", 0))
	require.NoError(t, insertSACred(db, "soc_000000000000seed2", "KEYPAIR", noHash,
		"-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----", "ES256", &mirrorTwo, "[]", 0))

	// Применяется миграция потолка.
	require.NoError(t, goose.Up(db, "."), "миграция потолка обязана примениться")

	var used, limit int64
	require.NoError(t, db.QueryRow(`
		SELECT used, limit_value FROM kacho_iam.project_resource_quotas
		 WHERE carrier_type = 'iam.user' AND carrier_id = 'usr00000000000000bat'
		   AND kind = 'iam.user.credential'`).Scan(&used, &limit))
	require.EqualValues(t, 3, used,
		"затравка завела строку учёта с НУЛЁМ при трёх лежащих удостоверениях: принципал "+
			"получил бы полный потолок СВЕРХ имеющегося, и заметить это было бы нечем")
	require.EqualValues(t, 10, limit, "снимок величины взят не из авторитета")

	require.NoError(t, db.QueryRow(`
		SELECT used, limit_value FROM kacho_iam.project_resource_quotas
		 WHERE carrier_type = 'iam.serviceAccount' AND carrier_id = 'sva00000000000000bat'
		   AND kind = 'iam.serviceAccount.credential'`).Scan(&used, &limit))
	require.EqualValues(t, 2, used, "то же у служебной учётки")
	require.EqualValues(t, 20, limit)

	// Ни одна строка удостоверения не тронута: потолок не снимает выданное.
	var rows int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM kacho_iam.user_oauth_clients
		 WHERE user_id = 'usr00000000000000bat'`).Scan(&rows))
	require.Equal(t, 3, rows, "выкатка потолка удалила удостоверения")

	// Следующая выдача занимает ЧЕТВЁРТОЕ место, а не первое.
	require.NoError(t, insertUserCred(db, "uoc_000000000000seed4", "KEYPAIR", noHash,
		"-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----", "ES256", nil, 0))
	require.NoError(t, db.QueryRow(`
		SELECT used FROM kacho_iam.project_resource_quotas
		 WHERE carrier_type = 'iam.user' AND carrier_id = 'usr00000000000000bat'
		   AND kind = 'iam.user.credential'`).Scan(&used))
	require.EqualValues(t, 4, used, "списание пошло мимо затравленной строки")
}

// Положительный контроль к предыдущему: принципал БЕЗ удостоверений получает
// строку учёта с нулём. Без него «затравка считает» было бы неотличимо от
// «затравка ставит что попало, лишь бы не ноль».
func TestCredentialCeilingSeed_APrincipalWithoutCredentialsStartsAtZero(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upToBeforeCredentialCeiling(t, pgtest.NewEmptyDB(t))
	defer db.Close()

	seedCredentialOwners(t, db)
	require.NoError(t, goose.Up(db, "."))

	var used int64
	require.NoError(t, db.QueryRow(`
		SELECT used FROM kacho_iam.project_resource_quotas
		 WHERE carrier_type = 'iam.user' AND carrier_id = 'usr00000000000000bat'
		   AND kind = 'iam.user.credential'`).Scan(&used))
	require.EqualValues(t, 0, used,
		"у принципала без удостоверений потребление не ноль: затравка считает не то, что считает списание")
}
