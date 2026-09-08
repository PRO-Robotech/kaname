// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// install_surfaces_injection_test.go — доказательство того, что гейт таблицы
// слушателей СПОСОБЕН УПАСТЬ и падает ровно на своём предмете.
//
// # Осей четыре, у каждой законный близнец
//
//  1. ПРОПУСК     строка снята → красное с ИМЕНЕМ поверхности и её портом;
//     полная таблица → молчание.
//  2. ПЕРЕЖИТОК   строка о слушателе, которого процесс не поднимает, → красное;
//     строка о поднимаемом → молчание.
//  3. ДОСЯГАЕМОСТЬ внешняя дверь названа внутренней → красное; названная верно →
//     молчание. Судится ТОЛЬКО там, где досягаемость объявил процесс.
//  4. ПУСТОТА     таблица не прочитана вовсе → отказ, а не «названы все».
//
// Вход инъекции — НАСТОЯЩАЯ таблица дерева, испорченная по одной оси за прогон:
// синтетическая доказывала бы о своей копии.
package operatordocs_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/tools/surfaceroster"
)

// liveInstallRows — таблица слушателей, как она лежит в дереве.
func liveInstallRows(t *testing.T) (surfaceroster.Roster, map[string]installRow) {
	t.Helper()
	root, err := surfaceroster.IAMRoot("..")
	require.NoError(t, err)
	roster, err := surfaceroster.Read(root)
	require.NoError(t, err)
	raw, err := os.ReadFile(filepath.Join(root, "INSTALL.md"))
	require.NoError(t, err)
	rows := parseListenerRows(string(raw))
	require.NotEmpty(t, rows, "таблица слушателей обязана читаться — иначе инъекции нечего портить")
	return roster, rows
}

// ── ось 1: пропуск ───────────────────────────────────────────────────────────

func TestInstallSurfaceCensusCanFail(t *testing.T) {
	roster, rows := liveInstallRows(t)

	// Возвращаем документ в состояние ДО починки: обеих дверей REST-фронтов нет.
	delete(rows, "9098")
	delete(rows, "9099")

	declared, named, findings := judgeInstallSurfaces(t, roster, rows)
	require.Equal(t, 8, declared, "процесс поднимает восемь поверхностей")
	require.Equal(t, 6, named, "до починки документ называл шесть")
	require.Len(t, findings, 2, "неназванных дверей ровно две")

	joined := strings.Join(findings, "\n")
	require.Contains(t, joined, "собственный публичный REST-фронт",
		"находка обязана НАЗВАТЬ поверхность, а не только посчитать расхождение")
	require.Contains(t, joined, "собственный внутренний REST-фронт")
	require.Contains(t, joined, ":9098")
	require.Contains(t, joined, ":9099")
	require.Contains(t, joined, "решать, открыть её или закрыть, ему",
		"находка обязана назвать, ЧЕМ пропуск дорог оператору")
}

// ЗАКОННЫЙ БЛИЗНЕЦ: полная таблица дерева — молчание (утверждает сам гейт).
func TestInstallSurfaceStaysSilentOnTheLiveTable(t *testing.T) {
	roster, rows := liveInstallRows(t)
	declared, named, findings := judgeInstallSurfaces(t, roster, rows)
	require.Empty(t, findings, "таблица дерева называет все поверхности — молчание верно")
	require.Equal(t, declared, named)
}

// ── ось 2: пережиток ─────────────────────────────────────────────────────────

func TestInstallSurfaceCatchesARowThatOutlivedItsListener(t *testing.T) {
	roster, rows := liveInstallRows(t)
	rows["9123"] = installRow{port: "9123", purpose: "слушатель, которого нет", reach: docReachInternal}

	_, _, findings := judgeInstallSurfaces(t, roster, rows)
	require.NotEmpty(t, findings,
		"строка о слушателе, которого процесс не поднимает, посылает оператора открывать "+
			"дверь, которой нет, — гейт, судящий только пропуски, промолчал бы")
	joined := strings.Join(findings, "\n")
	require.Contains(t, joined, ":9123")
	require.Contains(t, joined, "пережила свой слушатель")
}

// ── ось 3: досягаемость ──────────────────────────────────────────────────────

func TestInstallSurfaceCatchesAnExternalDoorCalledInternal(t *testing.T) {
	roster, rows := liveInstallRows(t)
	row := rows["9098"]
	row.reach = docReachInternal
	rows["9098"] = row

	_, _, findings := judgeInstallSurfaces(t, roster, rows)
	require.NotEmpty(t, findings,
		"внешне досягаемая дверь, названная внутренней, — та же ложь, только тише: "+
			"оператор не защитит её и не выведет наружу")
	joined := strings.Join(findings, "\n")
	require.Contains(t, joined, ":9098")
	require.Contains(t, joined, "external")
	require.NotContains(t, joined, ":9099",
		"соседняя дверь названа верно — законный близнец обязан молчать")
}

// ЗАКОННЫЙ БЛИЗНЕЦ ОСИ 3: досягаемость, которую процесс НЕ объявляет, гейт не
// судит — иначе он проверял бы перечень собственным утверждением и краснел бы
// на верном тексте документа.
func TestInstallSurfaceDoesNotJudgeReachItAssertedItself(t *testing.T) {
	roster, rows := liveInstallRows(t)
	row := rows["9090"]
	row.reach = "через ваш край, не напрямую"
	rows["9090"] = row

	_, _, findings := judgeInstallSurfaces(t, roster, rows)
	require.Empty(t, findings,
		"у публичного gRPC оси досягаемости процесс не объявляет: документ вправе "+
			"описать её своими словами, и гейт, покрасневший здесь, судил бы себя собой")

	var grpcFromProcess bool
	for _, s := range roster.Surfaces {
		if s.GRPC && s.ReachFromProcess {
			grpcFromProcess = true
		}
	}
	require.False(t, grpcFromProcess,
		"перечень обязан помечать досягаемость gRPC-ног как НЕ объявленную процессом — "+
			"иначе послабление выше стало бы маской для настоящего расхождения")
}

// ── ось 4: пустота ───────────────────────────────────────────────────────────

func TestInstallSurfaceRefusesAnUnreadTable(t *testing.T) {
	_, rows := liveInstallRows(t)
	require.NoError(t, listenerTablePresent(rows), "законный близнец: таблица дерева читается")

	err := listenerTablePresent(map[string]installRow{})
	require.Error(t, err,
		"не прочитав ни строки, гейт обязан ОТКАЗАТЬ, а не объявить «все поверхности названы»")
	require.Contains(t, err.Error(), "неотличимо",
		"отказ обязан называть, чем пустой обход опасен")
}
