// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// family_revocation_reason_client_revoke_integration_test.go — ОТЗЫВ КЛИЕНТОМ
// ПОЛУЧАЕТ СВОЁ СЛОВО в словаре причин отзыва семейства (задача
// PRO-Robotech/kaname#406; приёмка
// `docs/engineering/acceptance/client-revocation-has-its-own-family-revocation-reason.md`,
// сценарии KN-FRV-07, 09, 10; решения Р4, Р5, Р6).
//
// Проба написана ДО миграции и красна на дереве, где слово объявлено доменом,
// а ограничение `token_families_revoked_reason_ck` его ещё отвергает: база
// отказывает отзыву семейства с причиной `client-revoke` (07), а файла
// предмета в цепочке нет (09 и 10 — `versionsOf`).
//
// # Что утверждают пробы
//
//   - 07: база принимает четыре слова словаря и отвергает написание,
//     отличающееся одним знаком (`client_revoke`), снятое #404
//     `consent-withdrawn` и два слова, снятых #339 (`logout`,
//     `client-removed`; приёмка §7). Отказ — пара «23514, имя ограничения».
//     Каждая пара судится своим подслучаем: иначе первый отказ скрыл бы цвет
//     пар, стоящих после него;
//   - 09: накат лежащих строк не трогает, и версия после него — версия новой
//     миграции. Второе несущее: без него проба зеленела бы и там, где миграции
//     нет, — строки остались бы нетронутыми по пустой причине;
//   - 10: откат ОТКАЗЫВАЕТ, пока лежит семейство со словом, — целиком, не
//     сдвигая версию и не оживляя семейство. Близнец отличается одной причиной у
//     той же строки: откатывается, возвращает определение наката #404 и
//     сходится повторным накатом.
//
// # Почему сырыми операторами
//
// Предмет проб — СХЕМА. Путь через слой доступа отсёк бы негодный вход до базы
// (`RevokeFamily` судит слово доменом), и проба судила бы писателя, а не
// ограничение. Оператор — `revokeFamilySQL`, та же форма, что у слоя доступа.
//
// # Сцены одной базы — метками РАЗНОЙ длины
//
// Свёртка носителя сессии у `acScene` выводится из ДЛИНЫ метки: две сцены
// одной длины в одной базе сталкиваются на уникальности носителя, и вторая не
// заводится (приёмка §0.9).
package migrations_test

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// clientRevokeMigration — файл, вводящий слово. Имя стоит одним литералом: по
// нему `versionsOf` выводит версию предмета и версию перед ним.
const clientRevokeMigration = "20260927001324_family_revocation_reason_names_the_client_revocation.sql"

// clientRevokeReason — слово отзыва клиентом. Объявляет его домен; написание —
// дословно причина фундамента (приёмка §0.1, Р1).
const clientRevokeReason = string(domain.FamilyRevokedByClientRevocation)

// clientRevokeNearSpelling — отличается от слова ОДНИМ знаком. Отказ ему
// утверждает дословное написание — контракт с фундаментом, — а отказ
// произвольному слову утверждал бы только, что словарь закрыт.
const clientRevokeNearSpelling = "client_revoke"

// priorFamilyReasons — пять слов словаря до миграции #406: столько принимает
// версия перед ней. Перечень, выведенный из домена, включал бы испытуемое
// слово и сделал бы вопрос «прежние слова проходят» тождественным. Три слова
// стоят по имени константы домена; два, снятых #339, — литералом прежнего
// словаря: констант у них больше нет, а версия перед #406 их принимает
// (приёмка §7.6 п.8).
var priorFamilyReasons = []string{
	string(domain.FamilyRevokedByCodeReplay),
	string(domain.FamilyRevokedByRefreshReplay),
	removedLogoutReason,
	string(domain.FamilyRevokedBySessionEnd),
	removedClientRemovalReason,
}

// frvOpenAt — пустая база, накатанная ровно до названной версии цепочки.
func frvOpenAt(t *testing.T, version int64) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.UpTo(db, ".", version), "Дано: цепочка доходит до версии %d", version)
	got, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, version, got, "Дано: база стоит на версии %d", version)
	return db
}

// frvFamily — отметка, причина и живость строки семейства одной строкой
// текста: сравнение «до» и «после» называет расхождение целиком.
func frvFamily(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var (
		at     sql.NullTime
		reason sql.NullString
		live   bool
	)
	require.NoError(t, db.QueryRow(
		`SELECT revoked_at, revoked_reason, live FROM kaname.token_families WHERE id = $1`, id).
		Scan(&at, &reason, &live), "чтение семейства %s", id)
	atText, reasonText := "<NULL>", "<NULL>"
	if at.Valid {
		atText = at.Time.UTC().Format(time.RFC3339Nano)
	}
	if reason.Valid {
		reasonText = reason.String
	}
	return fmt.Sprintf("revoked_at=%s revoked_reason=%s live=%t", atText, reasonText, live)
}

// frvConstraintDef — определение ограничения словаря, как его печатает
// каталог живой базы.
func frvConstraintDef(t *testing.T, db *sql.DB) string {
	t.Helper()
	var def string
	require.NoError(t, db.QueryRow(`
		SELECT pg_get_constraintdef(c.oid)
		  FROM pg_constraint c
		  JOIN pg_class r ON r.oid = c.conrelid
		  JOIN pg_namespace n ON n.oid = r.relnamespace
		 WHERE n.nspname = 'kaname' AND r.relname = 'token_families'
		   AND c.conname = $1`, revokedReasonConstraint).Scan(&def),
		"ограничение %s не найдено", revokedReasonConstraint)
	return def
}

// TestTokenFamilySchema_KN_FRV_07_TheBaseAcceptsTheVocabularyAndRefusesTheRest
// — база принимает четыре слова словаря и отвергает близкое написание и
// снятые слова. Строка одна, оператор один: каждая проба идёт в своей
// транзакции, которая откатывается, и каждая пара — своим подслучаем.
//
// Пары и их доводы (приёмка §4 KN-FRV-07): `client-revoke` против
// `client_revoke` — отказ утверждает дословное написание, контракт с
// фундаментом; `session-ended` против `logout` — снято слово, а не повод:
// выход отзывает семейство своим словом; `client-revoke` против
// `client-removed` — ограничение судит слово целиком, а не приставку клиента.
// Без принятых близнецов отказы были бы истинны и на базе, отвергающей всё.
func TestTokenFamilySchema_KN_FRV_07_TheBaseAcceptsTheVocabularyAndRefusesTheRest(t *testing.T) {
	db := consentLeavesDB(t)
	_, _, _, family := acScene(t, db, "frv7")
	require.Contains(t, frvFamily(t, db, family), "live=true", "Дано: семейство живо")

	accepts := func(word string) {
		t.Run("accepts_"+word, func(t *testing.T) {
			require.NoError(t, reasonAccepted(t, db, family, word),
				"база обязана принимать отзыв семейства словом %q", word)
		})
	}
	refuses := func(word, why string) {
		t.Run("refuses_"+word, func(t *testing.T) {
			requirePgRefusal(t, reasonAccepted(t, db, family, word), "23514", revokedReasonConstraint, why)
		})
	}

	accepts(clientRevokeReason)
	refuses(clientRevokeNearSpelling, "написание, отличающееся одним знаком, обязано отвергаться ограничением словаря")
	accepts(string(domain.FamilyRevokedBySessionEnd))
	refuses(removedLogoutReason, "слово, снятое #339, обязано отвергаться: выход отзывает семейство словом session-ended")
	refuses(removedClientRemovalReason, "слово, снятое #339, обязано отвергаться: снятие клиента уносит семейство каскадом")
	accepts(string(domain.FamilyRevokedByCodeReplay))
	accepts(string(domain.FamilyRevokedByRefreshReplay))
	refuses(withdrawnReason, "слово, снятое #404, в словарь не возвращается")

	require.Contains(t, frvFamily(t, db, family), "live=true",
		"каждая проба откатывалась: семейство обязано остаться живым")
}

// TestTokenFamilyMigration_KN_FRV_09_UpLeavesLyingRowsUntouched — накат не
// переписывает ни отозванных, ни живых строк, и версия после него — новая.
func TestTokenFamilyMigration_KN_FRV_09_UpLeavesLyingRowsUntouched(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	own, previous := versionsOf(t, clientRevokeMigration)
	db := frvOpenAt(t, previous)

	// Шесть сцен, метки разной длины. Пять семейств отозваны по одному каждым
	// прежним словом, шестое живо.
	tags := []string{"fr9", "fr9a", "fr9ab", "fr9abc", "fr9abcd", "fr9abcde"}
	families := make([]string, len(tags))
	for i, tag := range tags {
		_, _, _, families[i] = acScene(t, db, tag)
	}
	for i, reason := range priorFamilyReasons {
		_, err := db.Exec(revokeFamilySQL, families[i], reason)
		require.NoError(t, err, "Дано: семейство %s отзывается словом %q на версии %d", families[i], reason, previous)
	}
	before := make(map[string]string, len(families))
	for _, f := range families {
		before[f] = frvFamily(t, db, f)
	}
	require.Contains(t, before[families[len(families)-1]], "live=true", "Дано: шестое семейство живо")

	require.NoError(t, goose.UpTo(db, ".", own), "накат до версии новой миграции")
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, own, version, "версия базы после наката обязана быть версией новой миграции (%s)", clientRevokeMigration)

	for _, f := range families {
		require.Equal(t, before[f], frvFamily(t, db, f), "накат переписал лежащую строку семейства %s", f)
	}
}

// TestTokenFamilyMigration_KN_FRV_10_DownRefusesWhileAFamilyCarriesTheWord —
// откат отказывает, пока лежит семейство со словом; без него откатывается,
// возвращает определение наката #404 и сходится повторным накатом.
func TestTokenFamilyMigration_KN_FRV_10_DownRefusesWhileAFamilyCarriesTheWord(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	own, previous := versionsOf(t, clientRevokeMigration)

	// Эталон отката — определение на базе, поднятой ровно до версии перед
	// предметом: это определение наката #404. Сам эталон проверяется: пять
	// значений и ни одного испытуемого, иначе «равно эталону» ничего не значит.
	reference := frvOpenAt(t, previous)
	want := frvConstraintDef(t, reference)
	refValues := dbRevocationReasons(t, reference)
	require.Len(t, refValues, len(priorFamilyReasons), "Дано: эталон несёт пять слов: %s", want)
	require.NotContains(t, refValues, clientRevokeReason, "Дано: эталон слова отзыва клиентом не знает")

	db := consentLeavesDB(t)
	_, _, _, a := acScene(t, db, "fr10")
	_, _, _, b := acScene(t, db, "fr10b")
	_, _, _, c := acScene(t, db, "fr10cc")
	_, err := db.Exec(revokeFamilySQL, a, clientRevokeReason)
	require.NoError(t, err, "Дано: A отозвано словом %q на голове", clientRevokeReason)
	_, err = db.Exec(revokeFamilySQL, b, string(domain.FamilyRevokedByCodeReplay))
	require.NoError(t, err, "Дано: B отозвано повтором кода")
	aBefore, bBefore, cBefore := frvFamily(t, db, a), frvFamily(t, db, b), frvFamily(t, db, c)
	require.Contains(t, aBefore, "revoked_reason="+clientRevokeReason+" live=false", "Дано: A отозвано словом")
	require.Contains(t, cBefore, "live=true", "Дано: C живо")

	// 10/1: семейство со словом лежит — откат отказывает целиком.
	requirePgRefusal(t, goose.DownTo(db, ".", previous), "23514", revokedReasonConstraint,
		"10/1: откат обязан отказать, пока лежит семейство со словом "+clientRevokeReason)
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, own, version, "10/1: отказавший откат не вправе сдвинуть версию")
	require.Equal(t, aBefore, frvFamily(t, db, a),
		"10/1: отказавший откат не вправе ни переписать причину A, ни оживить семейство")
	require.Equal(t, bBefore, frvFamily(t, db, b), "10/1: B то же, что до попытки")
	require.Equal(t, cBefore, frvFamily(t, db, c), "10/1: C то же, что до попытки")

	// 10/2: та же строка, другая причина — дельта ровно один факт.
	_, err = db.Exec(`UPDATE kaname.token_families SET revoked_reason = $2 WHERE id = $1`,
		a, string(domain.FamilyRevokedByCodeReplay))
	require.NoError(t, err, "10/2: причина A заменяется прямым оператором")
	require.NoError(t, goose.DownTo(db, ".", previous), "10/2: без строки со словом откат обязан проходить")
	version, err = goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, previous, version, "10/2: база после отката стоит на версии перед предметом")
	require.Equal(t, want, frvConstraintDef(t, db), "10/2: откат обязан вернуть определение наката #404")

	_, err = db.Exec(revokeFamilySQL, c, clientRevokeReason)
	requirePgRefusal(t, err, "23514", revokedReasonConstraint,
		"10/2: на откаченной базе отзыв живого C словом обязан отвергаться тем же ограничением")
	// После #339 откат с головы проходит и раздел #339: база снова принимает
	// два слова, которых домен уже не знает, и не знает слова, которое домен
	// объявляет (приёмка §7.5). Каждое расхождение — поимённо, со стороной.
	require.ElementsMatch(t, []string{
		onlyInDomain(clientRevokeReason),
		onlyInBase(removedLogoutReason),
		onlyInBase(removedClientRemovalReason),
	}, revocationVocabularyFindings(dbRevocationReasons(t, db), domainRevocationReasons()),
		"10/2: на откаченной базе расхождений ровно три, и каждое называет слово и сторону")

	require.NoError(t, goose.Up(db, "."), "10/2: повторный накат")
	_, err = db.Exec(revokeFamilySQL, c, clientRevokeReason)
	require.NoError(t, err, "10/2: после повторного наката отзыв C словом снова принимается")
	require.Empty(t, revocationVocabularyFindings(dbRevocationReasons(t, db), domainRevocationReasons()),
		"10/2: после повторного наката словари обязаны совпадать")
}
