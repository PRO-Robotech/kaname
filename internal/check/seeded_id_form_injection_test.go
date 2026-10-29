// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Доказательство способности гейта посева УПАСТЬ — и СМОЛЧАТЬ.
//
// Гейт рядом зелен на настоящем дереве, и это не говорит ничего о том, умеет ли
// он краснеть. Здесь ему подаются СИНТЕТИЧЕСКИЕ миграции: по одному дефекту на
// ось, и рядом с каждым — законный близнец. Инъекция снимает РОВНО одно
// свойство: остальные оси в каждой пробе целы, иначе красное приходило бы от
// соседнего требования.
//
// Законных близнецов здесь ДВА, и оба обязательны:
//   - `cag_…` длиной 21 — форма префикса через подчёркивание. Гейт со своим
//     правилом «ровно 20» покраснел бы на исправном посеве;
//   - `cluster_root` — семейство, таблицей форм не названное. Судить его
//     нечем, и молчание тут — не слепота, а граница предмета.

const (
	// synthGoodSeed — законный посев: слитная форма 20 символов, тело в алфавите
	// фундамента. Прежний литерал здесь (рукописный id системной роли admin) был
	// годен лишь пути запроса: судья фундамента отвергает его букву тела, и
	// «законным» после второй оси судьи (kaname#543) он быть перестал.
	synthGoodSeed = "INSERT INTO kaname.roles (id, name, permissions) " +
		"VALUES ('rol0123456789abcdefg', 'kacho-system.admin', '[]');\n"
	// synthUnderscoreSeed — ЗАКОННЫЙ близнец: форма через подчёркивание, 21 символ.
	synthUnderscoreSeed = "INSERT INTO kaname.cluster_admin_grants (id, cluster_id) " +
		"VALUES ('cag_5f4510f927a011885', 'cluster_root');\n"
	// synthForeignFamilySeed — ЗАКОННЫЙ близнец: семейство таблицей не названо.
	synthForeignFamilySeed = "INSERT INTO kaname.clusters (id, name) " +
		"VALUES ('cluster_root', 'root');\n"
	// synthBadSeedID — ДЕФЕКТ: слитная форма длиной 21, тело в алфавите — дефект
	// ровно одной оси (длины).
	//
	// Инъектируемый литерал обязан быть отвергнут НАСТОЯЩЕЙ проверкой пути запроса:
	// литерал, который она принимает, сделал бы инъекцию вакуумной. Это
	// утверждается ниже, а не подразумевается.
	synthBadSeedID = "rol0123456789abcdefgh"
	// synthBadSeed — тот же дефект в форме посева.
	synthBadSeed = "INSERT INTO kaname.roles (id, name, permissions) " +
		"VALUES ('" + synthBadSeedID + "', 'kacho-system.viewer', '[]');\n"
)

// TestSeededIDInjectionInjectsSomethingStillUnlawful — предпосылка инъекций ниже:
// инъектируемый литерал отвергается проверкой пути запроса, а законный —
// принимается и ею, и судьёй фундамента. Иначе инъекция зеленела бы и ничего
// не доказывала.
func TestSeededIDInjectionInjectsSomethingStillUnlawful(t *testing.T) {
	require.Error(t, shared.ValidateResourceID(synthBadSeedID, domain.PrefixRole, "role"),
		"инъектируемый литерал принят проверкой пути запроса — инъекция стала вакуумной")
	require.Len(t, synthBadSeedID, 21, "дефект оси длины обязан остаться дефектом длины")
	const good = "rol0123456789abcdefg"
	require.NoError(t, shared.ValidateResourceID(good, domain.PrefixRole, "role"), "законный посев отвергнут путём запроса")
	require.True(t, ids.HasKnownPrefix(good), "законный посев отвергнут судьёй фундамента")
	require.Contains(t, synthGoodSeed, good, "законный близнец разошёлся с посевом положительного контроля")
}

func synthMigrationCorpus() map[string]string {
	return map[string]string{
		"0001_initial.sql":     synthGoodSeed + synthUnderscoreSeed + synthForeignFamilySeed,
		"20260101000000_x.sql": synthGoodSeed,
	}
}

// TestSeededIDGateIsSilentOnTheLawfulCorpus — положительный контроль.
// Без него отрицания ниже зеленели бы на чём угодно.
func TestSeededIDGateIsSilentOnTheLawfulCorpus(t *testing.T) {
	findings, c := auditSeededIDs(synthMigrationCorpus(), nil)

	require.Empty(t, findings, "гейт краснеет на законном посеве — отрицания ниже ничего не докажут")
	require.Equal(t, 4, c.idValues, "значения колонки id обязаны быть извлечены")
	require.Equal(t, 3, c.judged, "судимы обязаны быть только названные таблицей семейства")
	require.Equal(t, 1, c.unknownFamily, "неназванное семейство обязано быть СОСЧИТАНО, а не невидимо")
}

// TestSeededIDGateRedsOnAMalformedSeed — несущая ось.
func TestSeededIDGateRedsOnAMalformedSeed(t *testing.T) {
	corpus := synthMigrationCorpus()
	corpus["20260101000000_x.sql"] = synthGoodSeed + synthBadSeed

	findings, c := auditSeededIDs(corpus, nil)

	require.Len(t, findings, 1, "негодный посев оставил гейт зелёным")
	require.Contains(t, findings[0], synthBadSeedID)
	require.Contains(t, findings[0], "20260101000000_x.sql")
	require.Contains(t, findings[0], "недостижим по id")
	// Законные близнецы целы: красное пришло РОВНО от снятого.
	require.Equal(t, 1, c.unknownFamily)
}

// TestSeededIDGateForgivesOnlyTheNamedPair — ведомость применяется к ПАРЕ
// «файл ↔ литерал», а не к файлу целиком.
func TestSeededIDGateForgivesOnlyTheNamedPair(t *testing.T) {
	corpus := synthMigrationCorpus()
	corpus["0001_initial.sql"] += synthBadSeed
	ledger := []seededSeedException{{
		file: "0001_initial.sql", literal: synthBadSeedID, reason: "синтетика инъекции",
	}}

	findings, c := auditSeededIDs(corpus, ledger)

	require.Empty(t, findings, "запись ведомости не применилась к своей паре")
	require.Equal(t, 1, c.ledgerApplied)

	// Тот же литерал в ДРУГОМ файле не прощается: ведомость про пару, а не про имя.
	corpus["20260101000000_x.sql"] = synthGoodSeed + synthBadSeed
	findings, _ = auditSeededIDs(corpus, ledger)
	require.Len(t, findings, 1, "ведомость простила посев в файле, которого не называла")
	require.Contains(t, findings[0], "20260101000000_x.sql")
}

// TestSeededIDLedgerSelfExpires — послабление обязано ИСТЕЧЬ САМО.
func TestSeededIDLedgerSelfExpires(t *testing.T) {
	ledger := []seededSeedException{{
		file: "0001_initial.sql", literal: synthBadSeedID, reason: "синтетика инъекции",
	}}

	findings, c := auditSeededIDs(synthMigrationCorpus(), ledger)

	require.Len(t, findings, 1, "ведомость пережила свой предмет молча")
	require.Contains(t, findings[0], "ВЕДОМОСТИ НЕЧЕГО ПРОЩАТЬ")
	require.Zero(t, c.ledgerApplied)
}

// TestSeededIDGateCountsWhatItCouldNotParse — «ноль находок» обязано быть
// отличимо от «ноль разобранного».
func TestSeededIDGateCountsWhatItCouldNotParse(t *testing.T) {
	corpus := map[string]string{
		"20260101000000_x.sql": synthGoodSeed +
			"INSERT INTO kaname.roles\n       (id, name)\nSELECT '" + synthBadSeedID + "', 'x';\n",
	}

	findings, c := auditSeededIDs(corpus, nil)

	require.Empty(t, findings, "многострочная вставка подана находкой — разбор её не берёт")
	require.Equal(t, 2, c.insertsSeen, "встреченные вставки обязаны быть сосчитаны все")
	require.Equal(t, 1, c.insertsParsed, "неразобранное обязано быть ВИДНО как разница двух чисел")
}
