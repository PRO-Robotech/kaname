// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// interactive_client_secret_verifier_schema_integration_test.go — ПРОВЕРОЧНОЕ
// ЗНАЧЕНИЕ секрета интерактивного клиента (kaname#313, миграция
// `20260920175118_interactive_client_carries_its_secret_verifier.sql`).
//
// Проба идёт ПОСЛЕ миграции: предмет — сама схема, и до неё утверждать не о чем.
//
// # Что утверждают пробы
//
//   - АЛГОРИТМ И ПАРАМЕТРЫ ТЕ ЖЕ, ЧТО У ПАРОЛЕЙ, и это проверено ПРОИЗВОДИТЕЛЕМ,
//     а не переписанной строкой: значение чеканит тот же `passwordverify.Hasher`
//     по объявлению из пола `internal/domain`, и база его принимает. Чужой
//     формат (bcrypt, быстрый хеш, сырой секрет) отвергается ограничением;
//   - ПУСТОЕ — ЭТО «В СТРОКЕ МАТЕРИАЛА НЕТ»: клиент без материала законен, а
//     момент установки стоит ровно тогда, когда значение непусто. Публичным
//     клиента делает способ `none`, а не пустота значения (kaname#317);
//   - ЗНАЧЕНИЕ НЕ ИДЁТ В СТАТИСТИКУ планировщика;
//   - ОБРАТНЫЙ ХОД снимается и накатывается снова.
package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

const secretVerifierMigration = "20260920175118_interactive_client_carries_its_secret_verifier.sql"

func svDB(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	return upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
}

// svClient заводит интерактивного клиента и возвращает его id.
//
// Клиент объявлен способом СЕКРЕТОМ: материал лежит только у клиента, который
// секрет предъявляет (`interactive_clients_secret_verifier_method_ck`,
// kaname#317). У клиента другого способа отказ пришёл бы от этого ограничения,
// и пробы формы и отметки судили бы не свой предмет.
func svClient(t *testing.T, db *sql.DB, tag string) string {
	t.Helper()
	id := "ic-" + acPad(tag)
	_, err := db.Exec(`
		INSERT INTO kaname.interactive_clients (id, name, redirect_uris, client_id, token_endpoint_auth_method)
		VALUES ($1, $2, ARRAY['https://app.example.test/cb'], $3, 'client_secret_basic')`,
		id, "ic-"+tag, "client-"+tag)
	require.NoError(t, err, "посев клиента %s", tag)
	return id
}

// svProducedVerifier — значение, вычеканенное ТЕМ ЖЕ производителем, каким
// пишутся пароли, по объявлению из пола перечня форматов. Переписанной строки
// здесь нет намеренно: переписанная разошлась бы с производителем молча.
func svProducedVerifier(t *testing.T) string {
	t.Helper()
	record, ok := domain.PasswordHashFormatByMarker(string(domain.PasswordHashFormatArgon2id))
	require.True(t, ok, "формат argon2id обязан стоять в перечне")
	hasher, err := passwordverify.NewHasher(passwordverify.Declared{
		Format: domain.PasswordHashFormatArgon2id,
		Params: record.Floor,
	})
	require.NoError(t, err, "хешер объявленного формата")
	verifier, err := hasher.Hash("s3cret-of-the-interactive-client")
	require.NoError(t, err)
	// Выход материала зовётся из ФАЙЛА ПРОБЫ: гейт сдерживания
	// `TestLoginVerifierStaysInside` судит только прод-корпус
	// (`check.ProductionGoFile`), и разрешения этому файлу не требуется.
	return verifier.Reveal()
}

// TestIntegration_ClientSecretVerifierTakesThePasswordProducersValue — значение
// производителя паролей принимается базой, чужое — нет.
func TestIntegration_ClientSecretVerifierTakesThePasswordProducersValue(t *testing.T) {
	db := svDB(t)
	id := svClient(t, db, "svmatch")

	produced := svProducedVerifier(t)
	t.Logf("перепись: значение производителя длиной %d знаков, признак формата %.10s",
		len(produced), produced)

	_, err := db.Exec(`
		UPDATE kaname.interactive_clients
		   SET secret_verifier = $2, secret_verifier_set_at = now()
		 WHERE id = $1`, id, produced)
	require.NoError(t, err,
		"значение, вычеканенное производителем паролей, обязано приниматься: "+
			"алгоритм и параметры колонки обязаны быть ТЕМИ ЖЕ")

	// Чужие форматы отвергаются базой, а не только вкусом писателя.
	for _, foreign := range []struct{ name, value string }{
		{"bcrypt популяции переноса", "$2a$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV"},
		{"быстрый хеш", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"сырой секрет", "s3cret-of-the-interactive-client"},
		{"argon2id чужой версии", "$argon2id$v=16$m=65536,t=3,p=4$" +
			"c2FsdHNhbHRzYWx0c2Fs$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"},
	} {
		_, err := db.Exec(`
			UPDATE kaname.interactive_clients
			   SET secret_verifier = $2, secret_verifier_set_at = now()
			 WHERE id = $1`, id, foreign.value)
		requirePgRefusal(t, err, "23514", "interactive_clients_secret_verifier_form_ck",
			"значение вида «"+foreign.name+"» обязано быть отвергнуто базой")
	}
}

// TestIntegration_ClientWithoutSecretIsLegalAndItsStampAgrees — клиент без
// секрета законен, а отметка установки согласована со значением.
func TestIntegration_ClientWithoutSecretIsLegalAndItsStampAgrees(t *testing.T) {
	db := svDB(t)
	id := svClient(t, db, "svstamp")

	// Умолчание: секрета нет, отметки нет — положительный контроль.
	var verifier string
	var setAt *string
	require.NoError(t, db.QueryRow(
		`SELECT secret_verifier, secret_verifier_set_at::text FROM kaname.interactive_clients WHERE id = $1`,
		id).Scan(&verifier, &setAt))
	require.Equal(t, "", verifier, "лежащая строка обязана перейти в «секрета нет»")
	require.Nil(t, setAt, "отметки установки у клиента без секрета быть не должно")

	// Значение без отметки — отказ.
	_, err := db.Exec(
		`UPDATE kaname.interactive_clients SET secret_verifier = $2 WHERE id = $1`,
		id, svProducedVerifier(t))
	requirePgRefusal(t, err, "23514", "interactive_clients_secret_verifier_stamp_ck",
		"значение без момента установки обязано быть отвергнуто")

	// Отметка без значения — тот же отказ.
	_, err = db.Exec(
		`UPDATE kaname.interactive_clients SET secret_verifier_set_at = now() WHERE id = $1`, id)
	requirePgRefusal(t, err, "23514", "interactive_clients_secret_verifier_stamp_ck",
		"момент установки без значения обязан быть отвергнут")
}

// TestIntegration_ClientSecretVerifierLeavesPlannerStatistics — значение не идёт
// в статистику планировщика.
func TestIntegration_ClientSecretVerifierLeavesPlannerStatistics(t *testing.T) {
	db := svDB(t)
	var target int
	require.NoError(t, db.QueryRow(`
		SELECT a.attstattarget
		  FROM pg_attribute a
		  JOIN pg_class c ON c.oid = a.attrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'kaname' AND c.relname = 'interactive_clients'
		   AND a.attname = 'secret_verifier'`).Scan(&target))
	require.Zero(t, target,
		"цель статистики по проверочному значению обязана быть 0: иначе ANALYZE кладёт "+
			"сами значения в pg_statistic — вторую копию материала в каталоге")
}

// TestIntegration_ClientSecretVerifierMigrationRollsBackAndForward — обратный ход.
func TestIntegration_ClientSecretVerifierMigrationRollsBackAndForward(t *testing.T) {
	db := svDB(t)
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))

	own, previous := versionsOf(t, secretVerifierMigration)
	require.NoError(t, goose.DownTo(db, ".", previous))

	var columns int
	const countColumns = `
		SELECT count(*) FROM information_schema.columns
		 WHERE table_schema = 'kaname' AND table_name = 'interactive_clients'
		   AND column_name IN ('secret_verifier','secret_verifier_set_at')`
	require.NoError(t, db.QueryRow(countColumns).Scan(&columns))
	require.Zero(t, columns, "после отката колонок остаться не должно, осталось %d", columns)

	require.NoError(t, goose.Up(db, "."))
	require.NoError(t, db.QueryRow(countColumns).Scan(&columns))
	require.Equal(t, 2, columns, "после повторного наката обязаны стоять обе колонки, стоит %d", columns)

	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.GreaterOrEqual(t, version, own, "цепочка обязана стоять не ниже предмета")
}
