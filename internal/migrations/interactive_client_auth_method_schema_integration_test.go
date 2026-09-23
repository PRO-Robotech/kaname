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
//   - СПОСОБ ОБЪЯВЛЕН у каждого клиента, которому разрешён хоть один вид
//     выдачи: пустое значение при непустом перечне видов отвергается базой.
//     Судится КЛАСС, а не экземпляр: `authorization_code` — один из видов,
//     и отказ утверждается для каждого вида порознь;
//   - СЛОВАРЬ СПОСОБОВ ЗАКРЫТ: принимается ровно то, что строка способна
//     выразить целиком. Подписанное утверждение ключом строка не выражает —
//     колонки ключа у неё нет, — и способ этого вида отвергается;
//   - ПРОВЕРОЧНОЕ ЗНАЧЕНИЕ СЕКРЕТА лежит только у клиента, чей способ секрет
//     и предъявляет. Публичному клиенту (`none`) материал положить нельзя:
//     признак публичности один, и это способ, а не пустота колонки;
//   - ОБРАТНЫЙ ХОД снимает ровно заведённые ограничения и накатывается снова.
//
// У каждого отказа стоит положительный близнец, отличающийся ОДНИМ фактом, и
// утверждается ИМЯ сработавшего ограничения, а не только код: «вставка
// отвергнута» истинно и тогда, когда отвергается всё.
package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

const authMethodMigration = "20260923230023_interactive_client_declares_how_it_authenticates.sql"

// Имена ограничений предмета. Каждое — ОДИН факт, поэтому у каждого свой отказ.
const (
	amVocabularyCk = "interactive_clients_auth_method_ck"
	amDeclaredCk   = "interactive_clients_auth_method_declared_ck"
	amVerifierCk   = "interactive_clients_secret_verifier_method_ck"
)

// amInteractiveGrants — виды выдачи, которые служба назначает интерактивному
// клиенту (`grantTypesInteractive` use-case'а). Выписаны здесь потому, что
// проба судит СХЕМУ: сама схема перечня видов не держит.
var amInteractiveGrants = []string{"authorization_code", "refresh_token"}

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

// TestIntegration_ClientWithAGrantDeclaresHowItAuthenticates — пустой способ у
// клиента с видом выдачи отвергается; без видов выдачи он законен.
func TestIntegration_ClientWithAGrantDeclaresHowItAuthenticates(t *testing.T) {
	db := svDB(t)

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: та же строка, какую пишут оба производителя
	// (виды службы, способ `none`), принимается.
	require.NoError(t, amInsert(db, "am1", amRow{grants: amInteractiveGrants, method: "none"}),
		"строка производителя обязана приниматься")

	// ЭКЗЕМПЛЯР: отличается одним фактом — способ пуст.
	requirePgRefusal(t, amInsert(db, "am2", amRow{grants: amInteractiveGrants, method: ""}),
		"23514", amDeclaredCk,
		"клиент с authorization_code без объявленного способа аутентификации")

	// КЛАСС: каждый вид выдачи по отдельности обязан требовать способ — вид,
	// обслуживаемый токен-эндпоинтом, без способа невыразим.
	for i, grant := range []string{"authorization_code", "refresh_token", "client_credentials"} {
		requirePgRefusal(t,
			amInsert(db, "am3"+string(rune('a'+i)), amRow{grants: []string{grant}, method: ""}),
			"23514", amDeclaredCk, "вид выдачи «"+grant+"» без объявленного способа")
	}

	// Клиент без видов выдачи на токен-эндпоинт не выходит: пустой способ у
	// него законен, и лежащие строки проб дерева (умолчания колонок) им остаются.
	require.NoError(t, amInsert(db, "am4", amRow{grants: nil, method: ""}),
		"клиент без видов выдачи вправе не объявлять способ")

	// ПРАВКА судится тем же ограничением, какая бы из двух колонок ни двигалась.
	_, err := db.Exec(`UPDATE kaname.interactive_clients SET token_endpoint_auth_method = ''
	                    WHERE id = $1`, "ic-"+acPad("am1"))
	requirePgRefusal(t, err, "23514", amDeclaredCk, "снятие способа у клиента с видами выдачи")
	_, err = db.Exec(`UPDATE kaname.interactive_clients SET grant_types = $2::text[]
	                    WHERE id = $1`, "ic-"+acPad("am4"), pqTextArray(amInteractiveGrants))
	requirePgRefusal(t, err, "23514", amDeclaredCk, "вид выдачи у клиента без способа")
}

// TestIntegration_ClientAuthMethodVocabularyIsClosed — словарь способов закрыт.
func TestIntegration_ClientAuthMethodVocabularyIsClosed(t *testing.T) {
	db := svDB(t)

	for i, lawful := range []string{"none", "client_secret_basic", "client_secret_post"} {
		require.NoError(t,
			amInsert(db, "am5"+string(rune('a'+i)), amRow{grants: amInteractiveGrants, method: lawful}),
			"способ «%s» строка выражает целиком и обязана принимать", lawful)
	}

	for i, foreign := range []struct{ value, why string }{
		{"private_key_jwt", "ключа подписанного утверждения строка не несёт — способ невыразим"},
		{"client_secret_jwt", "способ вне словаря"},
		{"None", "регистр — другое слово"},
		{"none ", "хвостовой пробел — другое слово"},
	} {
		requirePgRefusal(t,
			amInsert(db, "am6"+string(rune('a'+i)), amRow{grants: amInteractiveGrants, method: foreign.value}),
			"23514", amVocabularyCk, "способ «"+foreign.value+"»: "+foreign.why)
	}
}

// TestIntegration_SecretVerifierLivesOnlyOnASecretClient — материал секрета
// лежит только у клиента, который секрет предъявляет.
func TestIntegration_SecretVerifierLivesOnlyOnASecretClient(t *testing.T) {
	db := svDB(t)
	produced := svProducedVerifier(t)

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: конфиденциальный клиент теперь выразим — способ
	// секретом и проверочное значение производителя паролей.
	for i, secretMethod := range []string{"client_secret_basic", "client_secret_post"} {
		require.NoError(t, amInsert(db, "am7"+string(rune('a'+i)),
			amRow{grants: amInteractiveGrants, method: secretMethod, verifier: produced}),
			"конфиденциальный клиент способа «%s» обязан приниматься", secretMethod)
	}

	// Отличается одним фактом — способ публичный.
	requirePgRefusal(t, amInsert(db, "am8",
		amRow{grants: amInteractiveGrants, method: "none", verifier: produced}),
		"23514", amVerifierCk, "проверочное значение у публичного клиента")

	// Способ не объявлен (видов выдачи нет) — материалу лежать не у кого.
	requirePgRefusal(t, amInsert(db, "am9", amRow{grants: nil, method: "", verifier: produced}),
		"23514", amVerifierCk, "проверочное значение у клиента без способа")

	// ПРАВКА: конфиденциальный клиент не становится публичным, пока материал лежит.
	_, err := db.Exec(`UPDATE kaname.interactive_clients SET token_endpoint_auth_method = 'none'
	                    WHERE id = $1`, "ic-"+acPad("am7a"))
	requirePgRefusal(t, err, "23514", amVerifierCk, "перевод в публичные при лежащем материале")
}

// TestIntegration_AuthMethodMigrationRollsBackAndForward — обратный ход снимает
// ровно три ограничения предмета, повторный накат их возвращает.
func TestIntegration_AuthMethodMigrationRollsBackAndForward(t *testing.T) {
	db := svDB(t)
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))

	const countOwn = `
		SELECT count(*) FROM pg_constraint
		 WHERE conrelid = 'kaname.interactive_clients'::regclass
		   AND conname = ANY ($1::text[])`
	own := pqTextArray([]string{amVocabularyCk, amDeclaredCk, amVerifierCk})

	var n int
	require.NoError(t, db.QueryRow(countOwn, own).Scan(&n))
	require.Equal(t, 3, n, "после наката обязаны стоять три ограничения предмета, стоит %d", n)

	version, previous := versionsOf(t, authMethodMigration)
	require.NoError(t, goose.DownTo(db, ".", previous))
	require.NoError(t, db.QueryRow(countOwn, own).Scan(&n))
	require.Zero(t, n, "после отката ограничений предмета остаться не должно, осталось %d", n)

	require.NoError(t, goose.Up(db, "."))
	require.NoError(t, db.QueryRow(countOwn, own).Scan(&n))
	require.Equal(t, 3, n, "после повторного наката обязаны стоять три ограничения, стоит %d", n)

	head, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.GreaterOrEqual(t, head, version, "цепочка обязана стоять не ниже предмета")
}
