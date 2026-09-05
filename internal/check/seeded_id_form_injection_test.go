// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
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
//   - `cluster_kacho_root` — семейство, таблицей форм не названное. Судить его
//     нечем, и молчание тут — не слепота, а граница предмета.

const (
	// synthGoodSeed — законный посев: слитная форма 20 символов.
	synthGoodSeed = "INSERT INTO kacho_iam.roles (id, name, permissions) " +
		"VALUES ('rol000000000sysadmin', 'kacho-system.admin', '[]');\n"
	// synthUnderscoreSeed — ЗАКОННЫЙ близнец: форма через подчёркивание, 21 символ.
	synthUnderscoreSeed = "INSERT INTO kacho_iam.cluster_admin_grants (id, cluster_id) " +
		"VALUES ('cag_5f4510f927a011885', 'cluster_kacho_root');\n"
	// synthForeignFamilySeed — ЗАКОННЫЙ близнец: семейство таблицей не названо.
	synthForeignFamilySeed = "INSERT INTO kacho_iam.clusters (id, name) " +
		"VALUES ('cluster_kacho_root', 'root');\n"
	// synthBadSeedID — ДЕФЕКТ: слитная форма длиной 21, НИ ОДНОЙ миграцией не
	// посеянная и потому перечнем `domain.SeededResourceIDs()` не названная.
	//
	// Здесь стоял `rol000000000sysviewer` — и он перестал быть дефектом, когда
	// исход #1808 был выбран: посеянный литерал теперь ПРИНИМАЕТСЯ проверкой пути
	// запроса. Инъекция на нём стала бы вакуумной, доказывая способность падать
	// тем, что падать больше не обязано. Отсюда правило: инъектируемый литерал
	// обязан быть ВНЕ перечня, и это утверждается ниже, а не подразумевается.
	synthBadSeedID = "rol000000000sysvi3w3r"
	// synthBadSeed — тот же дефект в форме посева.
	synthBadSeed = "INSERT INTO kacho_iam.roles (id, name, permissions) " +
		"VALUES ('" + synthBadSeedID + "', 'kacho-system.viewer', '[]');\n"
)

// TestSeededIDInjectionInjectsSomethingStillUnlawful — предпосылка инъекций ниже.
// Литерал, названный закрытым перечнем посеянного, проверкой ПРИНИМАЕТСЯ; подай
// его инъекция — она зеленела бы и ничего не доказывала.
func TestSeededIDInjectionInjectsSomethingStillUnlawful(t *testing.T) {
	require.False(t, domain.IsSeededResourceID(synthBadSeedID),
		"инъектируемый литерал назван перечнем посеянного — инъекция стала вакуумной")
	require.Len(t, synthBadSeedID, 21, "дефект оси длины обязан остаться дефектом длины")
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
			"INSERT INTO kacho_iam.roles\n       (id, name)\nSELECT '" + synthBadSeedID + "', 'x';\n",
	}

	findings, c := auditSeededIDs(corpus, nil)

	require.Empty(t, findings, "многострочная вставка подана находкой — разбор её не берёт")
	require.Equal(t, 2, c.insertsSeen, "встреченные вставки обязаны быть сосчитаны все")
	require.Equal(t, 1, c.insertsParsed, "неразобранное обязано быть ВИДНО как разница двух чисел")
}
