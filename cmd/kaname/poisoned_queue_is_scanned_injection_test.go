// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// Доказательство способности гейта наблюдаемости УПАСТЬ — и СМОЛЧАТЬ.
//
// Гейт рядом зелен на настоящем дереве, и это не говорит ничего о том, умеет ли
// он краснеть. Здесь ему подаются СИНТЕТИЧЕСКИЕ исходники: по одному снятому
// свойству на пробу, рядом с каждым — законный близнец. Инъекция снимает РОВНО
// одно свойство, иначе красное приходило бы от соседнего требования.

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	// synthPoisoner — собственный оператор травления внутри строкового литерала.
	synthPoisoner = "package pg\n\nconst q = `UPDATE kaname.demo_outbox\n" +
		"   SET attempt_count = attempt_count + 1, last_error = $2\n WHERE id = $1`\n"

	// synthScanOfDemo — скан состояния над той же таблицей, имя — константой корня.
	synthScanOfDemo = "package main\n\nconst demoTable = \"kaname.demo_outbox\"\n\n" +
		"func run() { _ = outboxmetrics.NewCollector(p, r, outboxmetrics.CollectorConfig{" +
		"Table: demoTable, MaxAttempts: 10}) }\n"

	// synthScanOfAnother — ЗАКОННЫЙ близнец: скан над ДРУГОЙ таблицей. Он не
	// обязан закрывать чужую очередь и не должен считаться её покрытием.
	synthScanOfAnother = "package main\n\nconst otherTable = \"kaname.other_outbox\"\n\n" +
		"func run2() { _ = outboxmetrics.NewCollector(p, r, outboxmetrics.CollectorConfig{" +
		"Table: otherTable}) }\n"

	// synthScanUnresolvable — скан, чьё имя таблицы живёт в ЧУЖОМ пакете.
	// Граница распознавателя, а не дефект дерева: не покрытие, но и не находка.
	synthScanUnresolvable = "package main\n\nfunc run3() { " +
		"_ = outboxmetrics.NewCollector(p, r, outboxmetrics.CollectorConfig{" +
		"Table: clients.SomeTable}) }\n"

	// synthPoisonerInComment — ЗАКОННЫЙ близнец: тот же оператор в КОММЕНТАРИИ.
	// Гейт судит разобранные строковые литералы, поэтому проза об операторе
	// (а её в дереве не одна строка) не имеет права читаться как его наличие.
	synthPoisonerInComment = "package pg\n\n" +
		"// UPDATE kaname.prose_outbox SET attempt_count = attempt_count + 1 — так\n" +
		"// выглядел бы учёт попытки, если бы он здесь был.\nfunc nothing() {}\n"
)

// TestPoisonScanGateIsSilentOnTheLawfulCorpus — положительный контроль.
// Без него отрицания ниже зеленели бы на чём угодно.
func TestPoisonScanGateIsSilentOnTheLawfulCorpus(t *testing.T) {
	findings, c := auditPoisonedQueuesAreScanned(
		map[string]string{"outbox.go": synthPoisoner},
		map[string]string{"wiring.go": synthScanOfDemo},
	)

	require.Empty(t, findings, "гейт краснеет на исправной провязке — отрицания ниже ничего не докажут")
	require.Equal(t, 1, c.poisoners, "очередь с собственным травлением обязана быть найдена")
	require.Equal(t, 1, c.scanned, "скан состояния обязан быть засчитан")
	require.Zero(t, c.unresolved)
}

// TestPoisonScanGateRedsOnAnUnobservedQueue — несущая ось.
func TestPoisonScanGateRedsOnAnUnobservedQueue(t *testing.T) {
	findings, c := auditPoisonedQueuesAreScanned(
		map[string]string{"outbox.go": synthPoisoner},
		map[string]string{"wiring.go": "package main\n\nfunc nothing() {}\n"},
	)

	require.Len(t, findings, 1, "очередь травит строки и молчит — гейт остался зелёным")
	require.Contains(t, findings[0], "kaname.demo_outbox")
	require.Contains(t, findings[0], "outbox.go", "находка обязана назвать координату")
	require.Equal(t, 1, c.poisoners)
	require.Zero(t, c.scanned)
}

// TestPoisonScanGateDoesNotAcceptAForeignTableAsCoverage — законный близнец:
// скан над ДРУГОЙ очередью покрытием не является и ложной находки не даёт.
func TestPoisonScanGateDoesNotAcceptAForeignTableAsCoverage(t *testing.T) {
	findings, c := auditPoisonedQueuesAreScanned(
		map[string]string{"outbox.go": synthPoisoner},
		map[string]string{"wiring.go": synthScanOfAnother},
	)

	require.Len(t, findings, 1, "чужой скан засчитан покрытием")
	require.Contains(t, findings[0], "kaname.demo_outbox")
	require.NotContains(t, findings[0], "kaname.other_outbox",
		"наблюдаемая очередь попала в находку — красное пришло бы не от снятого")
	require.Equal(t, 1, c.scanned)
}

// TestPoisonScanGateCountsWhatItCouldNotResolve — «ноль находок» обязано быть
// отличимо от «ноль разобранного».
func TestPoisonScanGateCountsWhatItCouldNotResolve(t *testing.T) {
	findings, c := auditPoisonedQueuesAreScanned(
		map[string]string{"outbox.go": synthPoisoner},
		map[string]string{"wiring.go": synthScanUnresolvable},
	)

	require.Equal(t, 1, c.unresolved, "неразрешённое имя таблицы обязано быть СОСЧИТАНО, а не невидимо")
	require.Zero(t, c.scanned, "неразрешённый скан засчитан покрытием — гейт решает не в сторону осторожности")
	require.Len(t, findings, 1, "очередь без доказанного покрытия обязана остаться находкой")
	require.NotContains(t, findings[0], "clients.SomeTable",
		"граница распознавателя подана находкой — это обвинение дерева в дефекте, которого нет")
}

// TestPoisonScanGateReadsLiteralsNotProse — гейт судит разобранное, а не текст.
func TestPoisonScanGateReadsLiteralsNotProse(t *testing.T) {
	findings, c := auditPoisonedQueuesAreScanned(
		map[string]string{"prose.go": synthPoisonerInComment},
		map[string]string{"wiring.go": "package main\n\nfunc nothing() {}\n"},
	)

	require.Empty(t, findings, "комментарий об операторе прочитан как сам оператор")
	require.Zero(t, c.poisoners)
}

// TestPoisonScanGateOnAnEmptyCorpusIsSubjectless — пустой обход обязан быть
// ВИДЕН числами; несущая проба на таком корпусе отказывает.
func TestPoisonScanGateOnAnEmptyCorpusIsSubjectless(t *testing.T) {
	findings, c := auditPoisonedQueuesAreScanned(nil, nil)

	require.Empty(t, findings)
	require.Zero(t, c.repoFiles)
	require.Zero(t, c.rootFiles)
	require.Zero(t, c.poisoners, "на пустом обходе «ноль травителей» означает «ничего не прочитано»")
}
