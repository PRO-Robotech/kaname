// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// family_revocation_vocabulary_narrows_integration_test.go — ИЗ СЛОВАРЯ
// ПРИЧИН ОТЗЫВА СЕМЕЙСТВА УХОДЯТ ДВА СЛОВА БЕЗ ПИСАТЕЛЯ, `logout` и
// `client-removed` (задача PRO-Robotech/kaname#339; приёмка
// `docs/engineering/acceptance/client-revocation-has-its-own-family-revocation-reason.md`,
// §7, сценарии KN-FRV-15 и 16; решения Р9, Р10, Р11).
//
// Проба написана ДО миграции и красна на дереве, где файла предмета в цепочке
// нет: `versionsOf` не находит его и не выводит ни версии предмета, ни версии
// перед ним.
//
// # Что утверждают пробы
//
//   - 15: накат ОТКАЗЫВАЕТ, пока лежит семейство со снятым словом, — целиком,
//     не сдвигая версию и не трогая строк. Каждое из двух слов отказывает само
//     по себе: базы разные, и в каждой лежит ровно одно снятое слово. Близнец —
//     та же строка с одной заменённой причиной — накатывается, и первое его
//     «Тогда» (версия — версия предмета) несущее: без него близнец зеленел бы и
//     там, где миграции нет;
//   - 16: откат возвращает ровно определение наката #406 — эталон берётся с
//     базы, поднятой до версии перед предметом, и сам проверяется. Сверка
//     словарей на откаченной базе обязана назвать ДВА расхождения поимённо, со
//     стороной; повторный накат сходится, и последняя пара отличается одним
//     словом отзыва у той же строки.
//
// # Почему сырыми операторами и литералами
//
// Предмет проб — СХЕМА. Слой доступа отсёк бы снятое слово доменом до базы, и
// проба судила бы писателя, а не ограничение. Оператор — `revokeFamilySQL`,
// та же форма, что у слоя доступа. Снятые слова стоят литералом: констант
// домена у них больше нет, и «Дано» здесь требует именно прежнего словаря,
// который версия перед предметом принимает.
//
// # Сцены одной базы — метками РАЗНОЙ длины
//
// Свёртка носителя сессии у `acScene` выводится из ДЛИНЫ метки: две сцены
// одной длины в одной базе сталкиваются на уникальности носителя (приёмка §0.9).
package migrations_test

import (
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// narrowingMigration — файл, снимающий два слова. Имя стоит одним литералом:
// по нему `versionsOf` выводит версию предмета и версию перед ним.
const narrowingMigration = "20260927072645_family_revocation_reason_leaves_the_words_without_a_writer.sql"

// Слова, которые изменение #339 снимает. Литералом, а не константой домена:
// констант больше нет, а «Дано» проб, которым нужен прежний словарь, строится
// на версиях, где эти слова принимаются.
const (
	removedLogoutReason        = "logout"
	removedClientRemovalReason = "client-removed"
)

// TestTokenFamilyMigration_KN_FRV_15_UpRefusesWhileAFamilyCarriesARemovedWord —
// накат отказывает на каждом снятом слове по отдельности; близнец с одной
// заменённой причиной накатывается и строк не трогает.
func TestTokenFamilyMigration_KN_FRV_15_UpRefusesWhileAFamilyCarriesARemovedWord(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	own, previous := versionsOf(t, narrowingMigration)
	clientRevokeOwn, _ := versionsOf(t, clientRevokeMigration)
	require.Equal(t, clientRevokeOwn, previous,
		"Дано: версия перед предметом — версия миграции #406 (%s)", clientRevokeMigration)

	cases := []struct {
		name    string
		removed string
		twin    string
		tags    []string
	}{
		// 15/1 и 15/2: P отозвано снятым `logout`, R живо; близнец — `session-ended`.
		{"logout", removedLogoutReason, string(domain.FamilyRevokedBySessionEnd), []string{"f15p", "f15rr"}},
		// 15/3 и 15/4: Q отозвано снятым `client-removed`; близнец — `client-revoke`.
		{"client-removed", removedClientRemovalReason, string(domain.FamilyRevokedByClientRevocation), []string{"f15qqq"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := frvOpenAt(t, previous)
			families := make([]string, len(tc.tags))
			for i, tag := range tc.tags {
				_, _, _, families[i] = acScene(t, db, tag)
			}
			revoked := families[0]
			_, err := db.Exec(revokeFamilySQL, revoked, tc.removed)
			require.NoError(t, err, "Дано: на версии %d слово %q принимается — иначе отказывать нечему",
				previous, tc.removed)
			before := make(map[string]string, len(families))
			for _, f := range families {
				before[f] = frvFamily(t, db, f)
			}
			require.Contains(t, before[revoked], "revoked_reason="+tc.removed+" live=false",
				"Дано: семейство отозвано снятым словом")
			for _, f := range families[1:] {
				require.Contains(t, before[f], "live=true", "Дано: соседнее семейство живо")
			}

			// Отказ: лежит семейство со снятым словом.
			requirePgRefusal(t, goose.UpTo(db, ".", own), "23514", revokedReasonConstraint,
				"накат обязан отказать, пока лежит семейство со словом "+tc.removed)
			version, err := goose.GetDBVersion(db)
			require.NoError(t, err)
			require.Equal(t, previous, version, "отказавший накат не вправе сдвинуть версию")
			for _, f := range families {
				require.Equal(t, before[f], frvFamily(t, db, f),
					"отказавший накат не вправе ни переписать причину, ни оживить семейство (%s)", f)
			}

			// Близнец: та же строка, одна заменённая причина — дельта ровно один факт.
			_, err = db.Exec(`UPDATE kaname.token_families SET revoked_reason = $2 WHERE id = $1`,
				revoked, tc.twin)
			require.NoError(t, err, "близнец: причина заменяется прямым оператором на %q", tc.twin)
			twinBefore := frvFamily(t, db, revoked)
			require.Contains(t, twinBefore, "revoked_reason="+tc.twin+" live=false",
				"близнец: семейство отозвано, причина заменена")

			require.NoError(t, goose.UpTo(db, ".", own), "без строки со снятым словом накат обязан проходить")
			version, err = goose.GetDBVersion(db)
			require.NoError(t, err)
			require.Equal(t, own, version,
				"версия после наката обязана быть версией предмета (%s)", narrowingMigration)
			require.Equal(t, twinBefore, frvFamily(t, db, revoked),
				"накат не вправе трогать отозванное семейство: отметка, причина и живость те же")
			for _, f := range families[1:] {
				require.Equal(t, before[f], frvFamily(t, db, f), "накат не вправе трогать живое семейство %s", f)
			}
		})
	}
}

// TestTokenFamilyMigration_KN_FRV_16_DownRestoresTheClientRevokeDefinition —
// откат возвращает определение наката #406, сверка на откаченной базе
// называет оба снятых слова, повторный накат сходится.
func TestTokenFamilyMigration_KN_FRV_16_DownRestoresTheClientRevokeDefinition(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	own, previous := versionsOf(t, narrowingMigration)
	clientRevokeOwn, _ := versionsOf(t, clientRevokeMigration)
	require.Equal(t, clientRevokeOwn, previous,
		"Дано: версия перед предметом — версия миграции #406 (%s)", clientRevokeMigration)

	// Эталон — определение на базе, поднятой ровно до версии миграции #406. Сам
	// эталон проверяется: шесть слов, среди них оба снятых и слово отзыва
	// клиентом. Иначе «равно эталону» ничего не значит.
	reference := frvOpenAt(t, previous)
	want := frvConstraintDef(t, reference)
	refValues := dbRevocationReasons(t, reference)
	require.Len(t, refValues, 6, "Дано: эталон несёт шесть слов: %s", want)
	for _, w := range []string{removedLogoutReason, removedClientRemovalReason, clientRevokeReason} {
		require.Contains(t, refValues, w, "Дано: эталон несёт слово %q", w)
	}

	// Рабочая база на голове. Семейства отозваны по одному каждым словом
	// словаря, последнее (L) живо; метки разной длины.
	db := consentLeavesDB(t)
	vocabulary := domainRevocationReasons()
	families := make([]string, len(vocabulary)+1)
	for i := range families {
		_, _, _, families[i] = acScene(t, db, "f16"+strings.Repeat("a", i))
	}
	for i, word := range vocabulary {
		_, err := db.Exec(revokeFamilySQL, families[i], word)
		require.NoError(t, err, "Дано: семейство %s отзывается словом %q на голове", families[i], word)
	}
	live := families[len(families)-1]
	before := make(map[string]string, len(families))
	for _, f := range families {
		before[f] = frvFamily(t, db, f)
	}
	require.Contains(t, before[live], "live=true", "Дано: L живо")

	require.NoError(t, goose.DownTo(db, ".", previous), "откат до версии перед предметом обязан проходить")
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, previous, version, "после отката база стоит на версии миграции #406")
	require.Equal(t, want, frvConstraintDef(t, db), "откат обязан вернуть определение наката #406")
	for _, f := range families {
		require.Equal(t, before[f], frvFamily(t, db, f), "откат не вправе трогать семейство %s", f)
	}
	require.ElementsMatch(t, []string{
		onlyInBase(removedLogoutReason),
		onlyInBase(removedClientRemovalReason),
	}, revocationVocabularyFindings(dbRevocationReasons(t, db), domainRevocationReasons()),
		"на откаченной базе расхождений ровно два, и каждое называет слово и сторону")

	require.NoError(t, goose.UpTo(db, ".", own), "повторный накат до версии предмета")
	version, err = goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, own, version, "после повторного наката база стоит на версии предмета")
	require.Empty(t, revocationVocabularyFindings(dbRevocationReasons(t, db), domainRevocationReasons()),
		"после повторного наката словари обязаны совпадать")

	// Последняя пара: одна строка, одно слово — дельта ровно один факт.
	requirePgRefusal(t, reasonAccepted(t, db, live, removedLogoutReason), "23514", revokedReasonConstraint,
		"после повторного наката отзыв L снятым словом обязан отвергаться")
	require.NoError(t, reasonAccepted(t, db, live, string(domain.FamilyRevokedBySessionEnd)),
		"близнец: отзыв L словом словаря обязан приниматься")
}
