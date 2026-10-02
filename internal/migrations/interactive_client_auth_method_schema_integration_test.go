// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// interactive_client_auth_method_schema_integration_test.go — СПОСОБ
// аутентификации интерактивного клиента на обмене выражается схемой
// (kaname#317, миграция
// `20260923230023_interactive_client_declares_how_it_authenticates.sql`).
//
// Санкция — одобренная приёмка LINE-A-1 (Р3: интерактивный клиент
// аутентифицируется на обмене; сценарий LINE-A-1-12).
//
// Проба идёт ПОСЛЕ миграции: предмет — сама схема. До миграции каждое
// отрицание ниже зеленеет вставкой, то есть проба красная по отсутствию
// предмета.
//
// # Что утверждают пробы
//
//   - СПОСОБ ОБЪЯВЛЕН У КАЖДОГО КЛИЕНТА, безусловно. Пустого способа нет в
//     словаре, и умолчания у колонки нет: ни вставка, ни правка не кладут
//     клиента, о котором неизвестно, чем он аутентифицируется. Условие по
//     перечню видов выдачи здесь не стоит намеренно: выдачу кода оно не держит
//     (строка клиента берётся на выдаче без суждения о видах), и исключение
//     «без видов способ не нужен» открывало бы код клиенту без способа;
//   - КОДА КЛИЕНТУ БЕЗ СПОСОБА НЕ БЫВАЕТ: клиент без видов выдачи и со
//     способом получает код, а довести его до пустого способа нельзя ни
//     вставкой, ни правкой;
//   - СЛОВАРЬ СПОСОБОВ ЗАКРЫТ: принимается ровно то, что строка способна
//     выразить целиком. Подписанное утверждение ключом строка не выражает —
//     колонки ключа у неё нет, — и способ этого вида отвергается;
//   - ПРОВЕРОЧНОЕ ЗНАЧЕНИЕ СЕКРЕТА лежит только у клиента, чей способ секрет
//     и предъявляет. Публичному клиенту (`none`) материал положить нельзя:
//     признак публичности один, и это способ, а не пустота колонки;
//   - КАТАЛОГ ГОВОРИТ ТО ЖЕ, ЧТО ОГРАНИЧЕНИЯ: описание колонки материала не
//     называет пустоту признаком публичности;
//   - ОБРАТНЫЙ ХОД снимает ровно заведённое, возвращает умолчание колонки и
//     прежние описания, и накатывается снова.
//
// У каждого отказа стоит положительный близнец, отличающийся ОДНИМ фактом, и
// утверждается ИМЯ сработавшего ограничения, а не только код: «вставка
// отвергнута» истинно и тогда, когда отвергается всё.
package migrations_test

import (
	"database/sql"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

const authMethodMigration = "20260923230023_interactive_client_declares_how_it_authenticates.sql"

// Имена ограничений предмета. Каждое — ОДИН факт, поэтому у каждого свой отказ.
const (
	amVocabularyCk = "interactive_clients_auth_method_ck"
	amVerifierCk   = "interactive_clients_secret_verifier_method_ck"
)

// amExampleGrants — пример непустого перечня видов выдачи. Это НЕ перечень,
// который назначает служба: схема перечня видов не судит, и проба от его
// состава не зависит.
var amExampleGrants = []string{"authorization_code", "refresh_token"}

// amRow — строка клиента в тех колонках, которые судит предмет.
type amRow struct {
	grants   []string
	method   string
	verifier string // "" — секрета нет; иначе момент установки ставится вместе с ним
}

// amInsert кладёт клиента сырым оператором: путь через репозиторий отсёк бы
// негодный вход до базы, а предмет — именно база.
func amInsert(db *sql.DB, tag string, r amRow) error {
	_, err := db.Exec(`
		INSERT INTO kaname.interactive_clients
		       (id, name, redirect_uris, client_id, grant_types, token_endpoint_auth_method,
		        secret_verifier, secret_verifier_set_at)
		VALUES ($1, $2, ARRAY['https://app.example.test/cb'], $3, $4::text[], $5,
		        $6::text, CASE WHEN $6::text = '' THEN NULL ELSE now() END)`,
		"ic-"+acPad(tag), "ic-"+tag, "client-"+tag, pqTextArray(r.grants), r.method, r.verifier)
	return err
}

// TestIntegration_EveryClientDeclaresHowItAuthenticates — пустой способ
// отвергается у любого клиента, какой бы ни был перечень видов выдачи; умолчания
// у колонки нет.
func TestIntegration_EveryClientDeclaresHowItAuthenticates(t *testing.T) {
	db := svDB(t)

	// ПОЛОЖИТЕЛЬНЫЕ БЛИЗНЕЦЫ: способ объявлен — клиент принимается и с видами
	// выдачи, и без них.
	require.NoError(t, amInsert(db, "am1", amRow{grants: amExampleGrants, method: "none"}),
		"строка производителя обязана приниматься")
	require.NoError(t, amInsert(db, "am2", amRow{grants: nil, method: "none"}),
		"клиент без видов выдачи со способом обязан приниматься")

	// ЭКЗЕМПЛЯР из ревью: отличается от близнеца am2 одним фактом — способ пуст.
	// Именно такой клиент получал код: исключения «без видов способ не нужен»
	// больше нет.
	requirePgRefusal(t, amInsert(db, "am3", amRow{grants: nil, method: ""}),
		"23514", amVocabularyCk, "клиент без видов выдачи и без объявленного способа")

	// КЛАСС: перечень видов на суждение не влияет — ни один вид, ни их набор.
	for i, grants := range [][]string{
		{"authorization_code"}, {"refresh_token"}, {"client_credentials"}, amExampleGrants,
	} {
		requirePgRefusal(t,
			amInsert(db, "am4"+string(rune('a'+i)), amRow{grants: grants, method: ""}),
			"23514", amVocabularyCk, "виды выдачи «"+strings.Join(grants, ",")+"» без объявленного способа")
	}

	// УМОЛЧАНИЯ НЕТ: вставка, не назвавшая способ, отвергается, а не получает
	// значение, которого никто не объявлял.
	_, err := db.Exec(`
		INSERT INTO kaname.interactive_clients (id, name, redirect_uris, client_id)
		VALUES ($1, 'ic-am5', ARRAY['https://app.example.test/cb'], 'client-am5')`, "ic-"+acPad("am5"))
	requireNotNullRefusal(t, err, "token_endpoint_auth_method", "вставка без способа")

	// ПРАВКА судится тем же ограничением.
	_, err = db.Exec(`UPDATE kaname.interactive_clients SET token_endpoint_auth_method = ''
	                    WHERE id = $1`, "ic-"+acPad("am2"))
	requirePgRefusal(t, err, "23514", amVocabularyCk, "снятие способа у клиента без видов выдачи")
	_, err = db.Exec(`UPDATE kaname.interactive_clients SET token_endpoint_auth_method = ''
	                    WHERE id = $1`, "ic-"+acPad("am1"))
	requirePgRefusal(t, err, "23514", amVocabularyCk, "снятие способа у клиента с видами выдачи")
}

// TestIntegration_CodeIsNeverIssuedToAClientWithoutAMethod — то, что наблюдал
// опыт ревью (код у клиента без видов выдачи и без способа), невыразимо.
func TestIntegration_CodeIsNeverIssuedToAClientWithoutAMethod(t *testing.T) {
	db := svDB(t)

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: сцена опыта — клиент БЕЗ видов выдачи, — но способ
	// объявлен. Код выдаётся: выдача видов не судит, и проба это не прячет.
	client, user, session, family := acScene(t, db, "amcd")
	require.NoError(t, acInsertCode(db, acDigest(0x317), family, client, user, session,
		[]string{"openid", "profile"}, "S256", acChallenge), "код клиенту со способом обязан выдаваться")

	const codesOfClientsWithoutMethod = `
		SELECT count(*) FROM kaname.authorization_codes c
		  JOIN kaname.interactive_clients ic ON ic.client_id = c.client_id
		 WHERE ic.token_endpoint_auth_method = ''`
	const codesOfScene = `SELECT count(*) FROM kaname.authorization_codes WHERE client_id = $1`
	var n int
	require.NoError(t, db.QueryRow(codesOfScene, client).Scan(&n))
	require.Equal(t, 1, n, "положительный контроль: код сцены лежит — иначе счёт ниже ничего не значит")

	// Отличается ОДНИМ фактом — способ клиента, уже держащего код, снимается.
	_, err := db.Exec(`UPDATE kaname.interactive_clients SET token_endpoint_auth_method = ''
	                    WHERE client_id = $1`, client)
	requirePgRefusal(t, err, "23514", amVocabularyCk, "снятие способа у клиента, держащего код")

	require.NoError(t, db.QueryRow(codesOfClientsWithoutMethod).Scan(&n))
	require.Zero(t, n, "кодов у клиентов без объявленного способа обязано быть 0, лежит %d", n)
}

// TestIntegration_ClientAuthMethodVocabularyIsClosed — словарь способов закрыт.
func TestIntegration_ClientAuthMethodVocabularyIsClosed(t *testing.T) {
	db := svDB(t)

	for i, lawful := range []string{"none", "client_secret_basic", "client_secret_post"} {
		require.NoError(t,
			amInsert(db, "am6"+string(rune('a'+i)), amRow{grants: amExampleGrants, method: lawful}),
			"способ «%s» строка выражает целиком и обязана принимать", lawful)
	}

	for i, foreign := range []struct{ value, why string }{
		{"private_key_jwt", "ключа подписанного утверждения строка не несёт — способ невыразим"},
		{"client_secret_jwt", "способ вне словаря"},
		{"None", "регистр — другое слово"},
		{"none ", "хвостовой пробел — другое слово"},
		{"", "пустота — не способ"},
	} {
		requirePgRefusal(t,
			amInsert(db, "am7"+string(rune('a'+i)), amRow{grants: amExampleGrants, method: foreign.value}),
			"23514", amVocabularyCk, "способ «"+foreign.value+"»: "+foreign.why)
	}
}

// TestIntegration_SecretVerifierLivesOnlyOnASecretClient — материал секрета
// лежит только у клиента, который секрет предъявляет.
func TestIntegration_SecretVerifierLivesOnlyOnASecretClient(t *testing.T) {
	db := svDB(t)
	produced := svProducedVerifier(t)

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: конфиденциальный клиент выразим — способ секретом
	// и проверочное значение производителя паролей.
	for i, secretMethod := range []string{"client_secret_basic", "client_secret_post"} {
		require.NoError(t, amInsert(db, "am8"+string(rune('a'+i)),
			amRow{grants: amExampleGrants, method: secretMethod, verifier: produced}),
			"конфиденциальный клиент способа «%s» обязан приниматься", secretMethod)
	}

	// Отличается одним фактом — способ публичный.
	requirePgRefusal(t, amInsert(db, "am9",
		amRow{grants: amExampleGrants, method: "none", verifier: produced}),
		"23514", amVerifierCk, "проверочное значение у публичного клиента")

	// ПРАВКА: конфиденциальный клиент не становится публичным, пока материал лежит.
	_, err := db.Exec(`UPDATE kaname.interactive_clients SET token_endpoint_auth_method = 'none'
	                    WHERE id = $1`, "ic-"+acPad("am8a"))
	requirePgRefusal(t, err, "23514", amVerifierCk, "перевод в публичные при лежащем материале")
}

// TestIntegration_AuthMethodMigrationRollsBackAndForward — обратный ход снимает
// ровно заведённое и возвращает то, что стояло до предмета: умолчание колонки
// способа и описания обеих колонок. Повторный накат возвращает предмет.
func TestIntegration_AuthMethodMigrationRollsBackAndForward(t *testing.T) {
	db := svDB(t)
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))

	// Описание колонки материала ДО предмета — то, что объявила миграция колонки.
	// Оно берётся из её файла, а не переписывается сюда: переписанное разошлось
	// бы с производителем молча.
	declaredBefore := amDeclaredColumnComment(t, secretVerifierMigration, "secret_verifier")
	require.Contains(t, declaredBefore, "публичный клиент",
		"посылка: миграция колонки объявила пустоту признаком публичности — иначе переописывать нечего")

	requireApplied := func(stage string) {
		t.Helper()
		s := amSchemaState(t, db)
		require.Equal(t, 2, s.ownConstraints, "%s: обязаны стоять два ограничения предмета, стоит %d", stage, s.ownConstraints)
		require.False(t, s.methodDefault.Valid, "%s: у колонки способа не должно быть умолчания, стоит %q", stage, s.methodDefault.String)
		require.True(t, s.methodComment.Valid, "%s: колонка способа обязана быть описана", stage)
		require.Contains(t, s.methodComment.String, "none", "%s: описание способа называет признак публичности", stage)
		require.True(t, s.verifierComment.Valid, "%s: колонка материала обязана быть описана", stage)
		require.NotEqual(t, declaredBefore, s.verifierComment.String,
			"%s: описание материала обязано быть переписано — прежнее называет пустоту публичностью", stage)
		require.NotContains(t, s.verifierComment.String, "публичный клиент",
			"%s: пустота материала больше не признак публичности", stage)
		require.Contains(t, s.verifierComment.String, "token_endpoint_auth_method",
			"%s: описание материала отсылает к единственному признаку публичности", stage)
	}
	requireApplied("после наката")

	version, previous := versionsOf(t, authMethodMigration)
	require.NoError(t, goose.DownTo(db, ".", previous))
	s := amSchemaState(t, db)
	require.Zero(t, s.ownConstraints, "после отката ограничений предмета остаться не должно, осталось %d", s.ownConstraints)
	require.True(t, s.methodDefault.Valid, "после отката умолчание колонки способа обязано вернуться")
	require.Equal(t, "''::text", s.methodDefault.String, "после отката умолчание — прежнее")
	require.False(t, s.methodComment.Valid, "после отката описания способа нет, как до предмета: %q", s.methodComment.String)
	require.Equal(t, declaredBefore, s.verifierComment.String,
		"после отката описание материала — ровно объявленное миграцией колонки")

	require.NoError(t, goose.Up(db, "."))
	requireApplied("после повторного наката")

	head, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.GreaterOrEqual(t, head, version, "цепочка обязана стоять не ниже предмета")
}

// amState — то в каталоге, что меняет предмет.
type amState struct {
	ownConstraints  int
	methodDefault   sql.NullString
	methodComment   sql.NullString
	verifierComment sql.NullString
}

func amSchemaState(t *testing.T, db *sql.DB) amState {
	t.Helper()
	var s amState
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM pg_constraint
		 WHERE conrelid = 'kaname.interactive_clients'::regclass
		   AND conname = ANY ($1::text[])`,
		pqTextArray([]string{amVocabularyCk, amVerifierCk})).Scan(&s.ownConstraints))
	require.NoError(t, db.QueryRow(`
		SELECT column_default FROM information_schema.columns
		 WHERE table_schema = 'kaname' AND table_name = 'interactive_clients'
		   AND column_name = 'token_endpoint_auth_method'`).Scan(&s.methodDefault))
	const comment = `
		SELECT col_description('kaname.interactive_clients'::regclass, a.attnum)
		  FROM pg_attribute a
		 WHERE a.attrelid = 'kaname.interactive_clients'::regclass AND a.attname = $1`
	require.NoError(t, db.QueryRow(comment, "token_endpoint_auth_method").Scan(&s.methodComment))
	require.NoError(t, db.QueryRow(comment, "secret_verifier").Scan(&s.verifierComment))
	return s
}

// amDeclaredColumnComment — описание колонки, объявленное названной миграцией
// (`COMMENT ON COLUMN kaname.interactive_clients.<column> IS '…';` её раздела
// наката), с раскрытием удвоенных кавычек литерала.
func amDeclaredColumnComment(t *testing.T, file, column string) string {
	t.Helper()
	raw, err := fs.ReadFile(migrations.FS, file)
	require.NoError(t, err, "файл миграции %s", file)
	up, _, _ := strings.Cut(string(raw), "-- +goose Down")
	marker := "COMMENT ON COLUMN kaname.interactive_clients." + column + " IS"
	_, rest, ok := strings.Cut(up, marker)
	require.True(t, ok, "миграция %s не описывает колонку %s", file, column)
	_, rest, ok = strings.Cut(rest, "'")
	require.True(t, ok, "описание колонки %s в %s — не литерал", column, file)
	var b strings.Builder
	for i := 0; i < len(rest); i++ {
		if rest[i] != '\'' {
			b.WriteByte(rest[i])
			continue
		}
		if i+1 < len(rest) && rest[i+1] == '\'' {
			b.WriteByte('\'')
			i++
			continue
		}
		return b.String()
	}
	require.FailNow(t, "литерал описания не закрыт", "%s, колонка %s", file, column)
	return ""
}

// requireNotNullRefusal — отказ 23502 именно по названной колонке.
func requireNotNullRefusal(t *testing.T, err error, column, why string) {
	t.Helper()
	require.Error(t, err, why)
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr), "%s: отказ обязан прийти от базы: %v", why, err)
	require.Equal(t, "23502", pgErr.Code, "%s: код состояния", why)
	require.Equal(t, column, pgErr.ColumnName, "%s: отвергнуть обязана ИМЕННО эта колонка", why)
}
