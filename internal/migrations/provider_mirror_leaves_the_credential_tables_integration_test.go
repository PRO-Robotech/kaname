// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_mirror_leaves_the_credential_tables_integration_test.go — СТОЛБЕЦ
// ЗЕРКАЛА ПРЕЖНЕГО ИЗДАТЕЛЯ И ВИД LEGACY ПОКИДАЮТ ОБЕ ТАБЛИЦЫ УДОСТОВЕРЕНИЙ
// (задача PRO-Robotech/kaname#362; миграция
// `20260928231124_provider_mirror_leaves_the_credential_tables.sql`; порядок —
// docs/engineering/architecture/provider-mirror-column-retirement.md).
//
// Пробы написаны ДО миграции. На дереве, где предмет ещё лежит, красны пробы
// каталога (столбец стоит, LEGACY принимается, ключ служебной учётки без
// зеркала отвергается); пробы наката и отката красны тем, что файла предмета в
// цепочке нет.
//
// # Что утверждают пробы
//
//   - СТОЛБЦА НЕТ ни в одной из двух таблиц, и вместе с ним нет ни одного
//     ограничения и индекса, его называвшего. Спрашивается каталог живой базы;
//     рядом стоит якорь — столбец `id`, который обязан остаться;
//   - ОГРАНИЧЕНИЯ ВИДА И ФОРМЫ СТОЯТ ПОД ПРЕЖНИМИ ИМЕНАМИ. `DROP COLUMN` снимает
//     многостолбцовую проверку молча (измерено на Postgres 16), поэтому их
//     наличие утверждается отдельно, а не выводится из того, что накат прошёл;
//   - ФОРМА ДЕРЖИТСЯ ПО КАЖДОМУ ВИДУ: неверная форма отвергается ограничением
//     формы, законный близнец, отличающийся ОДНИМ фактом, проходит. LEGACY
//     отвергается словарём, и близнец того же состава с видом KEYPAIR проходит;
//   - НАКАТ ОТКАЗЫВАЕТ, пока лежит хоть одна строка зеркала либо вида LEGACY, по
//     каждой из четырёх величин отдельно: целиком, не сдвигая версию и не снимая
//     столбца. Строка чеканки бутстрапа — единственное названное исключение, и
//     её соседи, отличающиеся одним фактом, отказывают;
//   - НАКАТ НЕ ПРОПУСКАЕТ строку, вставленную конкурирующей транзакцией, пока он
//     ждёт захвата;
//   - ОТКАТ возвращает строение обеих таблиц ровно таким, каким оно стояло, а
//     столбец у KEYPAIR и FEDERATED — значением `id`, которое на переведённом
//     контуре и было его значением; повторный накат снимает предмет снова.
package migrations_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// mirrorLeavesMigration — файл, снимающий предмет. Имя стоит одним литералом:
// по нему вычисляется версия обратного хода.
const mirrorLeavesMigration = "20260928231124_provider_mirror_leaves_the_credential_tables.sql"

// mirrorColumn — снимаемый столбец обеих таблиц.
const mirrorColumn = "hydra_client_id"

// credentialTables — обе таблицы удостоверений. Порядок устойчив: по нему
// печатается перепись.
var credentialTables = []string{"service_account_oauth_clients", "user_oauth_clients"}

// Имена ограничений, которые обязаны стоять и после наката: по ним их читают
// пробы, ведомость ограничений и откат.
const (
	saKindConstraint    = "service_account_oauth_clients_credential_kind_ck"
	saShapeConstraint   = "service_account_oauth_clients_credential_shape_ck"
	userKindConstraint  = "user_oauth_clients_credential_kind_ck"
	userShapeConstraint = "user_oauth_clients_credential_shape_ck"
)

// Строка чеканки бутстрапа — посевная тройка, которую пишет путь запроса
// (`bootstrap_token/ids.go`). Значения выписаны литералами намеренно: ровно их
// называет исключение предохранителя, и проба сверяет исключение с ними же.
const (
	bootstrapSocID    = "soc_db27d17291ff453b6"
	bootstrapSvaID    = "svab91854890de887e6d"
	bootstrapMirror   = "kacho-bootstrap-admin"
	bootstrapOwnerUsr = "usr1a18042d81fb438d6"
)

// testPEM — открытая половина ключа по форме. Ограничения формы судят её
// непустоту, а не разбираемость.
const testPEM = "-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----"

// trustedOne — непустой перечень доверенных субъектов федеративной строки.
const trustedOne = `[{"issuer":"https://idp.example.invalid","subject_pattern":"^x$"}]`

// secretHash32 — хеш секрета объявленной длины.
func secretHash32(seed byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = seed + byte(i)
	}
	return out
}

// mirrorLeavesHead — база с головы цепочки, с владельцами удостоверений.
func mirrorLeavesHead(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
	t.Cleanup(func() { _ = db.Close() })
	seedCredentialOwners(t, db)
	return db
}

// mirrorLeavesAt — база, остановленная на названной версии цепочки.
func mirrorLeavesAt(t *testing.T, version int64) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(db, ".", version), "цепочка обязана дойти до версии %d", version)
	seedCredentialOwners(t, db)
	return db
}

// columnPresent — стоит ли столбец в таблице схемы `kaname`.
func columnPresent(t *testing.T, db *sql.DB, table, column string) bool {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM information_schema.columns
		 WHERE table_schema = 'kaname' AND table_name = $1 AND column_name = $2`,
		table, column).Scan(&n))
	return n == 1
}

// constraintDef — определение ограничения таблицы, как его печатает каталог.
// Пустая строка — ограничения нет.
func constraintDef(t *testing.T, db *sql.DB, table, name string) string {
	t.Helper()
	var def string
	err := db.QueryRow(`
		SELECT pg_get_constraintdef(c.oid)
		  FROM pg_constraint c
		  JOIN pg_class r ON r.oid = c.conrelid
		  JOIN pg_namespace n ON n.oid = r.relnamespace
		 WHERE n.nspname = 'kaname' AND r.relname = $1 AND c.conname = $2`,
		table, name).Scan(&def)
	if errors.Is(err, sql.ErrNoRows) {
		return ""
	}
	require.NoError(t, err)
	return def
}

// TestIntegration_MirrorColumnLeavesBothCredentialTables — столбца нет, его
// ограничений и индексов нет, ограничения вида и формы стоят под прежними
// именами и о снятом не говорят.
func TestIntegration_MirrorColumnLeavesBothCredentialTables(t *testing.T) {
	db := mirrorLeavesHead(t)

	for _, table := range credentialTables {
		require.True(t, columnPresent(t, db, table, "id"),
			"якорь: столбец id таблицы %s обязан стоять — иначе запрос не видит таблицу, "+
				"и отсутствие предмета ниже было бы отсутствием чтения", table)
		require.False(t, columnPresent(t, db, table, mirrorColumn),
			"столбец %s обязан покинуть таблицу %s (kaname#362)", mirrorColumn, table)

		// Всё, что называло столбец: ограничения и индексы. Спрашивается и
		// определение, и имя — ограничение, пережившее столбец под прежним
		// именем, было бы ложью каталога.
		var cons, idx int
		require.NoError(t, db.QueryRow(`
			SELECT count(*) FROM pg_constraint c
			  JOIN pg_class r ON r.oid = c.conrelid
			  JOIN pg_namespace n ON n.oid = r.relnamespace
			 WHERE n.nspname = 'kaname' AND r.relname = $1
			   AND (c.conname LIKE '%' || $2 || '%' OR pg_get_constraintdef(c.oid) LIKE '%' || $2 || '%')`,
			table, mirrorColumn).Scan(&cons))
		require.NoError(t, db.QueryRow(`
			SELECT count(*) FROM pg_indexes
			 WHERE schemaname = 'kaname' AND tablename = $1
			   AND (indexname LIKE '%' || $2 || '%' OR indexdef LIKE '%' || $2 || '%')`,
			table, mirrorColumn).Scan(&idx))
		t.Logf("перепись %s: ограничений о столбце %d, индексов о столбце %d", table, cons, idx)
		require.Zero(t, cons, "ограничений, называющих снятый столбец, у %s остаться не должно", table)
		require.Zero(t, idx, "индексов, называющих снятый столбец, у %s остаться не должно", table)
	}

	for table, names := range map[string][]string{
		"service_account_oauth_clients": {saKindConstraint, saShapeConstraint},
		"user_oauth_clients":            {userKindConstraint, userShapeConstraint},
	} {
		for _, name := range names {
			def := constraintDef(t, db, table, name)
			require.NotEmpty(t, def,
				"ограничение %s обязано стоять под прежним именем: DROP COLUMN снимает его молча", name)
			require.NotContains(t, def, "LEGACY", "%s не вправе называть снятый вид", name)
			require.NotContains(t, def, mirrorColumn, "%s не вправе называть снятый столбец", name)
		}
	}
	// Ветви вида, которой нет, у ограничения формы нет исхода «неизвестно»:
	// `ELSE NULL` пропускал бы строку неназванного вида (проверено на PG16).
	for _, name := range []string{saShapeConstraint, userShapeConstraint} {
		table := "service_account_oauth_clients"
		if name == userShapeConstraint {
			table = "user_oauth_clients"
		}
		require.Contains(t, constraintDef(t, db, table, name), "ELSE false",
			"%s обязано отвергать вид без своей ветви, а не давать NULL", name)
	}
}

// insertSAHead / insertUserHead — вставка строки удостоверения на голове: без
// снятого столбца. Колонки названы поимённо, чтобы отказ указывал на предмет.
func insertSAHead(db *sql.DB, id, kind string, hash []byte, pem, alg, trusted string, ttlDays int) error {
	_, err := db.Exec(`
INSERT INTO kaname.service_account_oauth_clients
    (id, sva_id, created_by_user_id, credential_kind, secret_hash, public_key_pem, key_algorithm, trusted_subjects, expires_at)
VALUES ($1, 'sva00000000000000bat', 'usr00000000000000bat', $2, $3, $4, $5, $6::jsonb,
        CASE WHEN $7::int > 0 THEN now() + make_interval(days => $7::int) END)`,
		id, kind, hash, pem, alg, trusted, ttlDays)
	return err
}

func insertUserHead(db *sql.DB, id, kind string, hash []byte, pem, alg string, ttlDays int) error {
	_, err := db.Exec(`
INSERT INTO kaname.user_oauth_clients
    (id, user_id, created_by_user_id, credential_kind, secret_hash, public_key_pem, key_algorithm, expires_at)
VALUES ($1, 'usr00000000000000bat', 'usr00000000000000bat', $2, $3, $4, $5,
        CASE WHEN $6::int > 0 THEN now() + make_interval(days => $6::int) END)`,
		id, kind, hash, pem, alg, ttlDays)
	return err
}

// TestIntegration_CredentialShapeHoldsWithoutTheMirror — форма каждого вида
// держится базой и без столбца зеркала: у каждого отказа есть законный близнец,
// отличающийся одним фактом, и он проходит.
func TestIntegration_CredentialShapeHoldsWithoutTheMirror(t *testing.T) {
	db := mirrorLeavesHead(t)

	type row struct {
		kind    string
		hash    []byte
		pem     string
		alg     string
		trusted string
		ttl     int
	}
	cases := []struct {
		name       string
		lawful     row
		unlawful   row
		constraint string
	}{
		{"KEYPAIR: хеш секрета у ключевой пары",
			row{"KEYPAIR", noHash, testPEM, "ES256", "[]", 0},
			row{"KEYPAIR", secretHash32(1), testPEM, "ES256", "[]", 0}, saShapeConstraint},
		{"SECRET: секрет без срока",
			row{"SECRET", secretHash32(2), "", "", "[]", 30},
			row{"SECRET", secretHash32(3), "", "", "[]", 0}, saShapeConstraint},
		{"SECRET: секрет с ключевым материалом",
			row{"SECRET", secretHash32(4), "", "", "[]", 30},
			row{"SECRET", secretHash32(5), testPEM, "ES256", "[]", 30}, saShapeConstraint},
		{"SECRET: секрет с перечнем доверенных субъектов",
			row{"SECRET", secretHash32(6), "", "", "[]", 30},
			row{"SECRET", secretHash32(7), "", "", trustedOne, 30}, saShapeConstraint},
		{"FEDERATED: пустой перечень доверенных субъектов",
			row{"FEDERATED", noHash, "", "", trustedOne, 0},
			row{"FEDERATED", noHash, "", "", "[]", 0}, saShapeConstraint},
		{"FEDERATED: свой ключевой материал",
			row{"FEDERATED", noHash, "", "", trustedOne, 0},
			row{"FEDERATED", noHash, testPEM, "", trustedOne, 0}, saShapeConstraint},
		{"LEGACY: снятый вид словаря",
			row{"KEYPAIR", noHash, testPEM, "ES256", "[]", 0},
			row{"LEGACY", noHash, testPEM, "ES256", "[]", 0}, saKindConstraint},
	}
	n := 0
	for _, tc := range cases {
		n++
		lawfulID := fmt.Sprintf("soc_%017d", 100+n)
		unlawfulID := fmt.Sprintf("soc_%017d", 200+n)
		require.NoError(t, insertSAHead(db, lawfulID, tc.lawful.kind, tc.lawful.hash, tc.lawful.pem,
			tc.lawful.alg, tc.lawful.trusted, tc.lawful.ttl),
			"%s — законный близнец обязан записываться: без него отказ ниже был бы отказом во всём", tc.name)
		requirePgRefusal(t, insertSAHead(db, unlawfulID, tc.unlawful.kind, tc.unlawful.hash, tc.unlawful.pem,
			tc.unlawful.alg, tc.unlawful.trusted, tc.unlawful.ttl),
			"23514", tc.constraint, tc.name)
	}

	userCases := []struct {
		name       string
		lawful     row
		unlawful   row
		constraint string
	}{
		{"KEYPAIR: хеш секрета у ключевой пары",
			row{"KEYPAIR", noHash, testPEM, "ES256", "", 0},
			row{"KEYPAIR", secretHash32(11), testPEM, "ES256", "", 0}, userShapeConstraint},
		{"SECRET: секрет без срока",
			row{"SECRET", secretHash32(12), "", "", "", 30},
			row{"SECRET", secretHash32(13), "", "", "", 0}, userShapeConstraint},
		{"SECRET: секрет с ключевым материалом",
			row{"SECRET", secretHash32(14), "", "", "", 30},
			row{"SECRET", secretHash32(15), testPEM, "ES256", "", 30}, userShapeConstraint},
		{"LEGACY: снятый вид словаря",
			row{"KEYPAIR", noHash, testPEM, "ES256", "", 0},
			row{"LEGACY", noHash, testPEM, "ES256", "", 0}, userKindConstraint},
		{"FEDERATED: вид, недостижимый у личности",
			row{"KEYPAIR", noHash, testPEM, "ES256", "", 0},
			row{"FEDERATED", noHash, "", "", "", 0}, userKindConstraint},
	}
	for _, tc := range userCases {
		n++
		lawfulID := fmt.Sprintf("uoc_%017d", 100+n)
		unlawfulID := fmt.Sprintf("uoc_%017d", 200+n)
		require.NoError(t, insertUserHead(db, lawfulID, tc.lawful.kind, tc.lawful.hash, tc.lawful.pem,
			tc.lawful.alg, tc.lawful.ttl),
			"%s — законный близнец обязан записываться", tc.name)
		requirePgRefusal(t, insertUserHead(db, unlawfulID, tc.unlawful.kind, tc.unlawful.hash, tc.unlawful.pem,
			tc.unlawful.alg, tc.unlawful.ttl),
			"23514", tc.constraint, tc.name)
	}
	t.Logf("перепись: пар «близнец, отказ» %d", n)
}

// seedPrevious — строка удостоверения на версии ПЕРЕД предметом, где столбец
// ещё стоит. mirror == nil — столбец пуст.
func seedPreviousSA(t *testing.T, db *sql.DB, id, sva, kind string, mirror *string) {
	t.Helper()
	pem, alg, trusted, hash, ttl := testPEM, "ES256", "[]", noHash, 0
	switch kind {
	case "FEDERATED":
		pem, alg, trusted = "", "", trustedOne
	case "SECRET":
		pem, alg, hash, ttl = "", "", secretHash32(byte(len(id))), 30
	}
	createdBy := "usr00000000000000bat"
	if sva == bootstrapSvaID {
		createdBy = bootstrapOwnerUsr
	}
	_, err := db.Exec(`
INSERT INTO kaname.service_account_oauth_clients
    (id, sva_id, hydra_client_id, created_by_user_id, credential_kind, secret_hash, public_key_pem, key_algorithm, trusted_subjects, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb,
        CASE WHEN $10::int > 0 THEN now() + make_interval(days => $10::int) END)`,
		id, sva, mirror, createdBy, kind, hash, pem, alg, trusted, ttl)
	require.NoError(t, err, "посев строки %s вида %s на версии перед предметом", id, kind)
}

func seedPreviousUser(t *testing.T, db *sql.DB, id, kind string, mirror *string) {
	t.Helper()
	_, err := db.Exec(`
INSERT INTO kaname.user_oauth_clients
    (id, user_id, hydra_client_id, created_by_user_id, credential_kind, secret_hash, public_key_pem, key_algorithm)
VALUES ($1, 'usr00000000000000bat', $2, 'usr00000000000000bat', $3, ''::bytea, $4, 'ES256')`,
		id, mirror, kind, testPEM)
	require.NoError(t, err, "посев строки %s вида %s на версии перед предметом", id, kind)
}

func strPtr(s string) *string { return &s }

// requireRefusedAndUntouched — накат отказал текстом предохранителя, версия не
// сдвинулась, столбец на месте в обеих таблицах.
func requireRefusedAndUntouched(t *testing.T, db *sql.DB, own, previous int64, table, why string) {
	t.Helper()
	err := goose.UpTo(db, ".", own)
	require.Error(t, err, "%s: накат обязан отказать", why)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr, "%s: отказ обязан прийти от базы", why)
	require.Equal(t, "P0001", pgErr.Code, "%s: отказ обязан прийти от предохранителя, а не от ограничения", why)
	require.Contains(t, pgErr.Message, table, "%s: отказ обязан назвать таблицу", why)
	require.Contains(t, pgErr.Message, ": 1", "%s: отказ обязан назвать число строк", why)
	version, verr := goose.GetDBVersion(db)
	require.NoError(t, verr)
	require.Equal(t, previous, version, "%s: отказавший накат не вправе сдвинуть версию", why)
	for _, tb := range credentialTables {
		require.True(t, columnPresent(t, db, tb, mirrorColumn),
			"%s: отказавший накат обязан откатиться целиком — столбец %s на месте", why, tb)
	}
}

// TestIntegration_MirrorLeavingRefusesWhileAMirrorOrLegacyRowLies — по каждой
// из четырёх величин предохранителя: одна строка — отказ; та же база без неё —
// накат проходит.
func TestIntegration_MirrorLeavingRefusesWhileAMirrorOrLegacyRowLies(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	own, previous := versionsOf(t, mirrorLeavesMigration)

	cases := []struct {
		name  string
		table string
		seed  func(t *testing.T, db *sql.DB)
		clear string
	}{
		{"зеркало служебной учётки: имя клиента не равно id", "service_account_oauth_clients",
			func(t *testing.T, db *sql.DB) {
				seedPreviousSA(t, db, "soc_00000000000000m01", "sva00000000000000bat", "KEYPAIR", strPtr("previous-issuer-name"))
			}, `DELETE FROM kaname.service_account_oauth_clients WHERE id = 'soc_00000000000000m01'`},
		{"вид LEGACY у служебной учётки при имени, равном id", "service_account_oauth_clients",
			func(t *testing.T, db *sql.DB) {
				seedPreviousSA(t, db, "soc_00000000000000m02", "sva00000000000000bat", "LEGACY", strPtr("soc_00000000000000m02"))
			}, `DELETE FROM kaname.service_account_oauth_clients WHERE id = 'soc_00000000000000m02'`},
		{"зеркало личности: столбец непуст", "user_oauth_clients",
			func(t *testing.T, db *sql.DB) {
				seedPreviousUser(t, db, "uoc_00000000000000m03", "KEYPAIR", strPtr("previous-issuer-user"))
			}, `DELETE FROM kaname.user_oauth_clients WHERE id = 'uoc_00000000000000m03'`},
		{"вид LEGACY у личности при пустом столбце", "user_oauth_clients",
			func(t *testing.T, db *sql.DB) {
				seedPreviousUser(t, db, "uoc_00000000000000m04", "LEGACY", nil)
			}, `DELETE FROM kaname.user_oauth_clients WHERE id = 'uoc_00000000000000m04'`},
		{"соседка бутстрапа: та же пара, другое имя клиента", "service_account_oauth_clients",
			func(t *testing.T, db *sql.DB) {
				seedPreviousSA(t, db, bootstrapSocID, bootstrapSvaID, "KEYPAIR", strPtr("kacho-bootstrap-other"))
			}, `DELETE FROM kaname.service_account_oauth_clients WHERE id = '` + bootstrapSocID + `'`},
		{"соседка бутстрапа: то же имя клиента, другая служебная учётка", "service_account_oauth_clients",
			func(t *testing.T, db *sql.DB) {
				seedPreviousSA(t, db, bootstrapSocID, "sva00000000000000bat", "KEYPAIR", strPtr(bootstrapMirror))
			}, `DELETE FROM kaname.service_account_oauth_clients WHERE id = '` + bootstrapSocID + `'`},
		{"соседка бутстрапа: тот же клиент под другим id", "service_account_oauth_clients",
			func(t *testing.T, db *sql.DB) {
				seedPreviousSA(t, db, "soc_00000000000000m07", bootstrapSvaID, "KEYPAIR", strPtr(bootstrapMirror))
			}, `DELETE FROM kaname.service_account_oauth_clients WHERE id = 'soc_00000000000000m07'`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := mirrorLeavesAt(t, previous)
			// Строки переведённого контура предметом не являются и лежат во
			// всех случаях: без них «накат прошёл» было бы истинно и на пустой
			// базе.
			seedPreviousSA(t, db, "soc_00000000000000k01", "sva00000000000000bat", "KEYPAIR", strPtr("soc_00000000000000k01"))
			seedPreviousSA(t, db, "soc_00000000000000f01", "sva00000000000000bat", "FEDERATED", strPtr("soc_00000000000000f01"))
			seedPreviousSA(t, db, "soc_00000000000000s01", "sva00000000000000bat", "SECRET", nil)
			seedPreviousUser(t, db, "uoc_00000000000000k01", "KEYPAIR", nil)

			tc.seed(t, db)
			requireRefusedAndUntouched(t, db, own, previous, tc.table, tc.name)

			// БЛИЗНЕЦ: та же база без строки предмета — накат проходит.
			_, err := db.Exec(tc.clear)
			require.NoError(t, err)
			require.NoError(t, goose.UpTo(db, ".", own), "без строки предмета накат обязан проходить")
			for _, tb := range credentialTables {
				require.False(t, columnPresent(t, db, tb, mirrorColumn), "после наката столбца в %s быть не должно", tb)
			}
			var kept int
			require.NoError(t, db.QueryRow(`
				SELECT (SELECT count(*) FROM kaname.service_account_oauth_clients)
				     + (SELECT count(*) FROM kaname.user_oauth_clients)`).Scan(&kept))
			require.Equal(t, 4, kept, "накат не вправе снимать строки переведённого контура")
		})
	}

	t.Run("строка чеканки бутстрапа — названное исключение, накат проходит", func(t *testing.T) {
		db := mirrorLeavesAt(t, previous)
		seedPreviousSA(t, db, bootstrapSocID, bootstrapSvaID, "KEYPAIR", strPtr(bootstrapMirror))
		require.NoError(t, goose.UpTo(db, ".", own),
			"строка бутстрапа, записанная прежним путём чеканки, не является зеркалом: без исключения "+
				"предохранитель отказывал бы на каждой живой базе навсегда")
		var n int
		require.NoError(t, db.QueryRow(
			`SELECT count(*) FROM kaname.service_account_oauth_clients WHERE id = $1 AND sva_id = $2`,
			bootstrapSocID, bootstrapSvaID).Scan(&n))
		require.Equal(t, 1, n, "накат не вправе снимать строку бутстрапа")
	})
}

// TestIntegration_MirrorLeavingSeesARowOfAConcurrentWriter — строка, которую
// конкурирующая транзакция вставила и ещё не закоммитила, пока накат ждёт
// захвата, накату видна: он отказывает, а не снимает столбец у строки,
// пересчитанной до её появления.
func TestIntegration_MirrorLeavingSeesARowOfAConcurrentWriter(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	own, previous := versionsOf(t, mirrorLeavesMigration)
	db := mirrorLeavesAt(t, previous)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	writer, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = writer.Rollback() }()
	_, err = writer.ExecContext(ctx, `
INSERT INTO kaname.user_oauth_clients
    (id, user_id, hydra_client_id, created_by_user_id, credential_kind, secret_hash, public_key_pem, key_algorithm)
VALUES ('uoc_00000000000000c01', 'usr00000000000000bat', 'previous-issuer-late', 'usr00000000000000bat',
        'KEYPAIR', ''::bytea, $1, 'ES256')`, testPEM)
	require.NoError(t, err, "конкурирующий писатель обязан вставить строку зеркала")

	done := make(chan error, 1)
	go func() { done <- goose.UpTo(db, ".", own) }()

	// Накат обязан ЖДАТЬ писателя: захват таблиц — первый его оператор.
	require.Eventually(t, func() bool {
		var waiting int
		if qerr := db.QueryRow(`
			SELECT count(*) FROM pg_stat_activity
			 WHERE wait_event_type = 'Lock' AND query ILIKE '%LOCK TABLE%'`).Scan(&waiting); qerr != nil {
			return false
		}
		return waiting > 0
	}, 20*time.Second, 50*time.Millisecond, "накат не встал в ожидание захвата — конкурирующая строка не проверяется")

	require.NoError(t, writer.Commit(), "писатель коммитит строку, пока накат ждёт")

	select {
	case err = <-done:
	case <-ctx.Done():
		t.Fatal("накат не завершился после коммита писателя")
	}
	require.Error(t, err, "накат обязан увидеть строку, закоммиченную, пока он ждал захвата")
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "P0001", pgErr.Code)
	require.Contains(t, pgErr.Message, "user_oauth_clients")
	require.True(t, columnPresent(t, db, "user_oauth_clients", mirrorColumn),
		"отказавший накат обязан оставить столбец на месте")
}

// mirrorStructure — строение обеих таблиц, которое трогает накат: столбцы,
// ограничения, индексы, комментарии столбцов. Столбцы перечислены по ИМЕНИ, а
// не по позиции: откат ставит столбец в конец таблицы, а позиция не читается ни
// одним писателем и читателем — все называют столбцы поимённо.
func mirrorStructure(t *testing.T, db *sql.DB) []string {
	t.Helper()
	var lines []string
	collect := func(kind, query string, args ...any) {
		rows, err := db.Query(query, args...)
		require.NoError(t, err, "строение: %s", kind)
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var a, b string
			require.NoError(t, rows.Scan(&a, &b))
			lines = append(lines, kind+" "+a+" "+b)
		}
		require.NoError(t, rows.Err())
	}
	for _, table := range credentialTables {
		collect("column", `
			SELECT column_name,
			       data_type || ' ' || is_nullable || ' ' || coalesce(column_default, '')
			  FROM information_schema.columns
			 WHERE table_schema = 'kaname' AND table_name = $1`, table)
		collect("constraint", `
			SELECT conname, pg_get_constraintdef(oid)
			  FROM pg_constraint WHERE conrelid = to_regclass('kaname.' || $1)`, table)
		collect("index", `
			SELECT indexname, indexdef FROM pg_indexes
			 WHERE schemaname = 'kaname' AND tablename = $1`, table)
		collect("comment", `
			SELECT a.attname, coalesce(col_description(a.attrelid, a.attnum), '')
			  FROM pg_attribute a
			 WHERE a.attrelid = to_regclass('kaname.' || $1) AND a.attnum > 0 AND NOT a.attisdropped`, table)
	}
	sort.Strings(lines)
	return lines
}

// TestIntegration_MirrorLeavingRollsBackToTheSameStructure — откат возвращает
// строение обеих таблиц ровно таким, каким оно стояло до наката; столбец у
// KEYPAIR и FEDERATED получает значение `id`; повторный накат снимает предмет
// снова.
func TestIntegration_MirrorLeavingRollsBackToTheSameStructure(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	own, previous := versionsOf(t, mirrorLeavesMigration)

	before := mirrorLeavesAt(t, previous)
	want := mirrorStructure(t, before)
	require.NotEmpty(t, want, "до наката строение обязано читаться — сравнивать иначе не с чем")
	var mirrorLines int
	for _, l := range want {
		if strings.Contains(l, mirrorColumn) {
			mirrorLines++
		}
	}
	t.Logf("строение до наката: фактов %d, из них о столбце зеркала %d", len(want), mirrorLines)
	require.NotZero(t, mirrorLines, "до наката строение обязано называть столбец — иначе откат сверять не с чем")

	after := mirrorLeavesHead(t)
	require.NoError(t, insertSAHead(after, "soc_00000000000000r01", "KEYPAIR", noHash, testPEM, "ES256", "[]", 0))
	require.NoError(t, insertSAHead(after, "soc_00000000000000r02", "FEDERATED", noHash, "", "", trustedOne, 0))
	require.NoError(t, insertSAHead(after, "soc_00000000000000r03", "SECRET", secretHash32(9), "", "", "[]", 30))
	require.NoError(t, insertUserHead(after, "uoc_00000000000000r04", "KEYPAIR", noHash, testPEM, "ES256", 0))

	require.NoError(t, goose.DownTo(after, ".", previous), "обратный ход обязан проходить на строках всех видов")
	require.Equal(t, want, mirrorStructure(t, after),
		"откат обязан вернуть строение ровно таким, каким оно стояло до наката")

	for id, wantMirror := range map[string]sql.NullString{
		"soc_00000000000000r01": {String: "soc_00000000000000r01", Valid: true},
		"soc_00000000000000r02": {String: "soc_00000000000000r02", Valid: true},
		"soc_00000000000000r03": {},
	} {
		var got sql.NullString
		require.NoError(t, after.QueryRow(
			`SELECT hydra_client_id FROM kaname.service_account_oauth_clients WHERE id = $1`, id).Scan(&got))
		require.Equal(t, wantMirror, got, "откат: столбец строки %s", id)
	}
	var userMirror sql.NullString
	require.NoError(t, after.QueryRow(
		`SELECT hydra_client_id FROM kaname.user_oauth_clients WHERE id = 'uoc_00000000000000r04'`).Scan(&userMirror))
	require.False(t, userMirror.Valid, "откат: у личности зеркала не было и нет")

	require.NoError(t, goose.Up(after, "."), "цепочка обязана накатываться снова")
	for _, tb := range credentialTables {
		require.False(t, columnPresent(t, after, tb, mirrorColumn), "после повторного наката столбца в %s быть не должно", tb)
	}
	version, err := goose.GetDBVersion(after)
	require.NoError(t, err)
	require.GreaterOrEqual(t, version, own, "цепочка обязана стоять не ниже предмета")
}
