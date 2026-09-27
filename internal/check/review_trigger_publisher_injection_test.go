// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// review_trigger_publisher_injection_test.go — ОСЬ 2 ЗНАЕТ ПУБЛИКУЮЩЕГО:
// производитель образа идёт по `push` в ствол И в ветки линии, процесс
// проверки — только в ствол (задача PRO-Robotech/kaname#429).
//
// Инъекция идёт НАСТОЯЩИМ входом: объявление производителя образа читается из
// дерева, и в копии меняется ровно запись `on.push.branches` — одна, какой бы
// она ни была в дереве. Предмет и довод — в шапке `review_trigger_scope.go`,
// раздел «ОСЬ 2: ПРОВЕРКА И ПУБЛИКАЦИЯ».
package check_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// imageInjectRel — объявление ПУБЛИКУЮЩЕГО процесса: образ службы.
const imageInjectRel = "docker-build.yml"

// imagePushBranches — запись фильтра веток `push` в объявлении образа.
// Образец берёт запись строкой-списком любого содержания до конца строки —
// элемент `'[0-9]+'` сам несёт `]`, — поэтому инъекция не зависит от того, что
// в дереве стоит сейчас; ровно одно совпадение — условие предметности
// (imageAudit).
var imagePushBranches = regexp.MustCompile(`(?m)^  push:\n    branches: \[.*\]\n`)

// imageAudit — вердикт о корпусе, где у образа службы фильтр веток `push`
// заменён строкой `line` (пустая — фильтр веток снят, метки остаются).
func imageAudit(t *testing.T, line string) ([]string, check.ReviewTriggerCensus) {
	t.Helper()
	corpus := trunkCorpusSource(t)
	raw, ok := corpus[imageInjectRel]
	require.Truef(t, ok, "инъекция беспредметна: %s не прочитан", imageInjectRel)
	locs := imagePushBranches.FindAllStringIndex(raw, -1)
	require.Lenf(t, locs, 1, "инъекция беспредметна: записей фильтра веток `push` в %s %d, нужна одна",
		imageInjectRel, len(locs))
	repl := "  push:\n"
	if line != "" {
		repl += "    branches: " + line + "\n"
	}
	corpus[imageInjectRel] = raw[:locs[0][0]] + repl + raw[locs[0][1]:]
	findings, census, err := check.AuditReviewTriggers(corpus)
	require.NoError(t, err, "инъекция доказывала бы разбор, а не гейт")
	return findings, census
}

// TestReviewTriggerGateKnowsTheImagePublisher — у производителя образа `push`
// РАВЕН посаженному множеству {ствол, линия}, у процесса проверки — {ствол}.
func TestReviewTriggerGateKnowsTheImagePublisher(t *testing.T) {
	t.Parallel()

	// ЗАКОННЫЙ БЛИЗНЕЦ: ровно та запись, которую задача вносит в дерево.
	t.Run("близнец: образ публикует ствол и линию — не находка", func(t *testing.T) {
		got, census := imageAudit(t, "[main, '[0-9]+']")
		require.Emptyf(t, got, "публикация головы линии объявлена нарушением: %v", got)
		require.Contains(t, census.String(), "публикующих посаженное объявлено 1 · прочитано 1 · "+
			"из них по push в {main, [0-9]+} 1")
	})

	t.Run("близнец: то же множество в другом порядке — не находка", func(t *testing.T) {
		got, _ := imageAudit(t, "['[0-9]+', main]")
		require.Empty(t, got, "законная запись того же множества объявлена нарушением")
	})

	// ДЕФЕКТ ЗАДАЧИ: состояние до #429 — голова ветки эпика без образа.
	t.Run("образ сужен до ствола — голова линии без образа", func(t *testing.T) {
		got, census := imageAudit(t, "[main]")
		require.Len(t, got, 1)
		require.Contains(t, got[0], imageInjectRel)
		require.Contains(t, got[0], "недостаёт {`[0-9]+`}")
		require.Contains(t, got[0], "голова линии остаётся без образа")
		require.Contains(t, census.String(), "из них по push в {main, [0-9]+} 0")
	})

	t.Run("[0-9]* вместо [0-9]+ — захват хвоста", func(t *testing.T) {
		got, _ := imageAudit(t, "[main, '[0-9]*']")
		require.Len(t, got, 1)
		require.Contains(t, got[0], "недостаёт {`[0-9]+`}")
		require.Contains(t, got[0], "лишние {`[0-9]*`}")
	})

	t.Run("образ расширен до всех веток", func(t *testing.T) {
		got, _ := imageAudit(t, "[main, '[0-9]+', '**']")
		require.Len(t, got, 1)
		require.Contains(t, got[0], "лишние {`**`}")
	})

	t.Run("образ без ствола", func(t *testing.T) {
		got, _ := imageAudit(t, "['[0-9]+']")
		require.Len(t, got, 1)
		require.Contains(t, got[0], "недостаёт {`main`}")
	})

	// Фильтр веток снят, метки версий остаются: так провайдер читает тело как
	// «только метки», и производитель перестаёт публиковать посаженное вовсе.
	t.Run("образ только по меткам — ни ствола, ни линии", func(t *testing.T) {
		got, _ := imageAudit(t, "")
		require.Len(t, got, 1)
		require.Contains(t, got[0], imageInjectRel)
		require.Contains(t, got[0], "по push в ветки не идёт")
	})

	// Послабление принадлежит ПРОИЗВОДИТЕЛЮ, а не оси: процесс проверки с тем же
	// фильтром — по-прежнему находка (половина «push расширен на ветки линии» в
	// review_trigger_scope_injection_test.go), и новый процесс — тоже.
	t.Run("новый процесс с push в линию — находка", func(t *testing.T) {
		corpus := trunkCorpusSource(t)
		corpus["newflow.yml"] = "name: новый\non:\n  push:\n    branches: [main, '[0-9]+']\n" +
			"  pull_request:\n    branches: [main, '[0-9]+']\n" +
			"jobs:\n  work:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
		findings, _, err := check.AuditReviewTriggers(corpus)
		require.NoError(t, err)
		joined := strings.Join(findings, "\n")
		require.Contains(t, joined, "newflow.yml")
		require.Contains(t, joined, "`push` расширен за ствол: {`[0-9]+`}")
	})

	// Запись перечня без объявления — исключение без предмета.
	t.Run("перечень называет процесс, которого в корпусе нет", func(t *testing.T) {
		corpus := trunkCorpusSource(t)
		delete(corpus, imageInjectRel)
		findings, census, err := check.AuditReviewTriggers(corpus)
		require.NoError(t, err)
		require.Len(t, findings, 1)
		require.Contains(t, findings[0], imageInjectRel)
		require.Contains(t, findings[0], "без предмета")
		require.Contains(t, census.String(), "публикующих посаженное объявлено 1 · прочитано 0")
	})
}
