// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Доказательство способности гейта датировки УПАСТЬ — и СМОЛЧАТЬ.
//
// Гейт рядом зелен на настоящем дереве, и это не говорит ничего о том, умеет ли
// он краснеть. Здесь ему подаются СИНТЕТИЧЕСКИЕ тексты: по одному дефекту на
// каждую ось, и рядом с каждым — законный близнец, на котором гейт обязан
// молчать. Инъекция снимает РОВНО одно свойство: остальные оси в каждой пробе
// целы, иначе красное приходило бы от соседнего требования.

const (
	// synthDated — законное объявление: ревизия названа хешем.
	synthDated = "## 4. Полосы\n\n**Замер на ревизии `1234abc`** (единица счёта — вызовы):\n\n" +
		"```sh\ngit grep -c foo -- 'services/iam/**'   # 7\n```\n"
	// synthUndated — тот же замер, датированный самоссылкой.
	synthUndated = "## 4. Полосы\n\n**Замер на ревизии записи** (единица счёта — вызовы):\n\n" +
		"```sh\ngit grep -c foo -- 'services/iam/**'   # 7\n```\n"
	// synthForeign — ревизия названа, но в историю дерева не входит.
	synthForeign = "Замер на ревизии `deadbee` — таких мест **2**.\n"
	// synthQuoted — ПРОЗА О ФОРМЕ: законный близнец, замером не является.
	synthQuoted = "> Здесь стояло «замер на ревизии записи» — самоссылкой, восстановимой\n" +
		"> только раскопками. Оборот «замер на ревизии записи» назван, чтобы его узнавали.\n"
	// synthNoMarker — соседний документ без предмета.
	synthNoMarker = "## 1. Норма\n\nПеречень выводится из дерева, а не выписывается.\n"
)

// ancestryAll — все ревизии в истории (законное дерево).
func ancestryAll(string) ancestryVerdict { return ancestryYes }

// ancestryForeign — `deadbee` резолвится, но предком не является: ровно тот
// случай, на котором предикат «резолвится» отвечает «да», а годный — «нет».
func ancestryForeign(hash string) ancestryVerdict {
	if hash == "deadbee" {
		return ancestryNo
	}
	return ancestryYes
}

func synthDocs() map[string]string {
	return map[string]string{
		"architecture/known-divergences.md": synthDated,
		"acceptance/roles.md":               synthNoMarker,
	}
}

// TestDatingGateIsSilentOnTheLawfulCorpus — положительный контроль.
// Без него отрицания ниже зеленели бы на чём угодно.
func TestDatingGateIsSilentOnTheLawfulCorpus(t *testing.T) {
	findings, c := auditMeasurementDating(synthDocs(), map[string]string{}, ancestryAll)

	require.Empty(t, findings, "гейт краснеет на законном корпусе — отрицания ниже ничего не докажут")
	require.Equal(t, 2, c.docsRead)
	require.Equal(t, 1, c.markers, "объявление замера обязано быть найдено")
	require.Equal(t, 1, c.dated)
	require.Zero(t, c.undated)
	require.Zero(t, c.foreign)
}

// TestDatingGateRedsOnSelfReference — ось «самоссылка».
func TestDatingGateRedsOnSelfReference(t *testing.T) {
	docs := synthDocs()
	docs["architecture/known-divergences.md"] = synthUndated

	findings, c := auditMeasurementDating(docs, map[string]string{}, ancestryAll)

	require.Len(t, findings, 1, "недатированный замер оставил гейт зелёным")
	require.Contains(t, findings[0], "САМОССЫЛКА")
	require.Contains(t, findings[0], "architecture/known-divergences.md")
	require.Equal(t, 1, c.undated)
	require.Zero(t, c.dated, "вторая ось цела: красное пришло РОВНО от снятого")
}

// TestDatingGateRedsOnAForeignLineRevision — ось «резолвится, но не предок».
// Это и есть предмет находки B задачи #1805.
func TestDatingGateRedsOnAForeignLineRevision(t *testing.T) {
	docs := synthDocs()
	docs["architecture/known-divergences.md"] = synthForeign

	findings, c := auditMeasurementDating(docs, map[string]string{}, ancestryForeign)

	require.Len(t, findings, 1, "ревизия чужой линии оставила гейт зелёным")
	require.Contains(t, findings[0], "ЧУЖАЯ ЛИНИЯ")
	require.Contains(t, findings[0], "deadbee")
	require.Equal(t, 1, c.foreign)
	require.Zero(t, c.undated, "вторая ось цела")
}

// TestDatingGateIsSilentOnProseAboutTheForm — ЗАКОННЫЙ БЛИЗНЕЦ.
// Проверка, краснеющая на собственном объяснении, и есть ловимый здесь класс.
func TestDatingGateIsSilentOnProseAboutTheForm(t *testing.T) {
	docs := synthDocs()
	docs["acceptance/roles.md"] = synthNoMarker + synthQuoted

	findings, c := auditMeasurementDating(docs, map[string]string{}, ancestryAll)

	require.Empty(t, findings, "гейт покраснел на прозе О ФОРМЕ — он судит слово, а не объявление")
	require.Equal(t, 2, c.quoted, "цитаты обязаны быть СОСЧИТАНЫ, а не невидимы")
	require.Equal(t, 1, c.markers, "объявление соседнего документа осталось видимым")
}

// TestDatingGateForgivesOnlyWhatTheLedgerNames — ведомость применяется.
func TestDatingGateForgivesOnlyWhatTheLedgerNames(t *testing.T) {
	docs := synthDocs()
	docs["acceptance/roles.md"] = synthUndated
	ledger := map[string]string{"acceptance/roles.md": "APPROVED-приёмка, задача #0000"}

	findings, c := auditMeasurementDating(docs, ledger, ancestryAll)

	require.Empty(t, findings, "запись ведомости не применилась к своему предмету")
	require.Equal(t, 1, c.ledgerApplied)
	require.Equal(t, 1, c.undated)
}

// TestDatingLedgerSelfExpires — послабление обязано ИСТЕЧЬ САМО.
// Запись, которой больше нечего прощать, — находка, а не тишина.
func TestDatingLedgerSelfExpires(t *testing.T) {
	ledger := map[string]string{"acceptance/roles.md": "APPROVED-приёмка, задача #0000"}

	findings, c := auditMeasurementDating(synthDocs(), ledger, ancestryAll)

	require.Len(t, findings, 1, "ведомость пережила свой предмет молча")
	require.Contains(t, findings[0], "ВЕДОМОСТИ НЕЧЕГО ПРОЩАТЬ")
	require.Zero(t, c.ledgerApplied)
	require.Equal(t, 1, c.ledgerEntries)
}

// TestDatingGateCountsUnjudgedAncestrySeparately — ТРЕТЬЯ КАТЕГОРИЯ.
// «Не выполнилось» не вычитается из вердикта и не зачитывается в успех.
func TestDatingGateCountsUnjudgedAncestrySeparately(t *testing.T) {
	docs := synthDocs()
	docs["architecture/known-divergences.md"] = synthForeign

	findings, c := auditMeasurementDating(docs, map[string]string{},
		func(string) ancestryVerdict { return ancestryUnjudged })

	require.Empty(t, findings, "невынесенный вердикт о предке подан как находка")
	require.Equal(t, 1, c.ancestryUnjudged, "невынесенный вердикт обязан быть НАЗВАН, а не проглочен")
	require.Equal(t, 1, c.dated, "хеш назван — эта ось пройдена независимо от вердикта о предке")
}
