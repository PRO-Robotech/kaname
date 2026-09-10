// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// known_failing_expiry_test.go — записи прощения в `tests/newman/docs/RESULTS.md`
// истекают САМИ.
//
// Норма и границы распознавателей — в шапке пакета `tools/knownfailingexpiry`;
// здесь только провязка к дереву и сверка с трекером.
package tools_regression

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/tools/knownfailingexpiry"
)

// knownFailingResultsDoc — путь от каталога проб к документу результатов набора.
const knownFailingResultsDoc = "../tests/newman/docs/RESULTS.md"

// knownFailingTrackerKnob — ручка сверки, в СОБСТВЕННОМ написании службы.
//
// Платформенная ручка сетевых измерений дерева здесь НЕ читается, и это решение,
// а не небрежность. Служба — отдельный продукт, и её ручки уже носят своё имя
// (`KANAME_*`); имя платформы в этом дереве — остаток, который снимает линия
// дебрендинга, и держатель `internal/repohygiene` судит полосу «переменная
// окружения» по тому, ВЫРОС ли он. Прочитать здесь платформенное имя значило бы
// добавить ему работы ради одной буквы совпадения.
//
// Цена названа честно: платформенный конвейер эту ручку не ставит, поэтому сверка
// по умолчанию НЕ идёт. Она и не обязана идти молча — состояние ручки печатается на
// КАЖДОМ прогоне, поэтому «сверено 0» никогда не выглядит как «сверено», а решение
// про закрытую задачу доказано инъекцией без сети.
const knownFailingTrackerKnob = "KANAME_ISSUE_TRACKER_CHECK"

// knownFailingIssueMissing — ответ трекера, доказывающий, что номера НЕТ. Всё
// прочее (сеть, 5xx, отсутствие прав) — не отказ трекера, а несостоявшееся
// измерение: оно считается отдельно и печатается, а не проглатывается.
const knownFailingIssueMissing = "Could not resolve to an issue or pull request"

func readResultsDoc(t *testing.T) knownfailingexpiry.Census {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(knownFailingResultsDoc))
	if err != nil {
		t.Fatalf("документ результатов не читается (%s): %v — судить срок годности "+
			"записей прощения стало бы не по чему", knownFailingResultsDoc, err)
	}
	c := knownfailingexpiry.Parse(string(raw))
	if c.Lines == 0 || c.Paragraphs == 0 {
		t.Fatalf("документ прочитан пустым (строк %d, абзацев %d) — «ноль находок» "+
			"здесь означало бы «ноль прочитанного»", c.Lines, c.Paragraphs)
	}
	return c
}

// TestKnownFailingRecordsDeclareThemselves — прощение прозой без маркера.
//
// Проверка ЛОКАЛЬНАЯ и не зависит от сети: она спрашивает не «открыта ли задача»,
// а «объявила ли себя запись». Без неё формат маркера остался бы тем, о чём никто
// не знает, и следующее прощение прошло бы мимо сверки молча.
func TestKnownFailingRecordsDeclareThemselves(t *testing.T) {
	t.Parallel()
	c := readResultsDoc(t)
	findings := knownfailingexpiry.UndeclaredForgiveness(c)

	t.Logf("осмотрено: строк %d, абзацев %d; записей прощения объявлено %d, "+
		"прощений прозой без маркера %d",
		c.Lines, c.Paragraphs, len(c.Records), len(c.Undeclared))

	for _, f := range findings {
		t.Error(f)
	}
}

// TestKnownFailingRecordIssuesAreStillOpen — сверка объявленных записей с трекером.
//
// # Пустой перечень — ЦЕЛЬ, а не поломка
//
// Ноль записей прощения означает, что набор ничем не прощён. Гейт на этом
// ПРОХОДИТ и печатает перепись: падение здесь подталкивало бы держать запись ради
// зелёного — ровно тот класс, против которого гейт и написан (`testing.md`
// §«Проба не имеет права падать на достижении своей цели»).
//
// # Выключенная ручка НАЗЫВАЕТСЯ, а не молчит
//
// При выключенной сверке проба не «пропускается»: она печатает, что сверено НОЛЬ.
// Молчание сделало бы «сверено ноль» неотличимым от «сверено и всё в порядке».
func TestKnownFailingRecordIssuesAreStillOpen(t *testing.T) {
	t.Parallel()
	c := readResultsDoc(t)
	issues := c.Issues()

	if len(issues) == 0 {
		t.Logf("осмотрено: строк %d, абзацев %d; записей прощения 0 — набор ничем не "+
			"прощён. Это ЦЕЛЬ, а не поломка: гейт взведён для следующей записи, а "+
			"решение про закрытую задачу проверено инъекцией без сети "+
			"(TestInjection_ClosedIssueUnderALiveRecordIsAFinding)",
			c.Lines, c.Paragraphs)
		return
	}

	if os.Getenv(knownFailingTrackerKnob) != "1" {
		t.Logf("сверка с трекером ВЫКЛЮЧЕНА (ручка %s=1): записей прощения %d (задачи %v), "+
			"сверено 0. Решение проверено инъекцией без сети",
			knownFailingTrackerKnob, len(c.Records), issues)
		return
	}

	states, checked, unresolved, cfgErr := resolveKnownFailingIssues(issues)
	if cfgErr != "" {
		t.Fatalf("%s", cfgErr)
	}
	t.Logf("сверка с трекером: записей прощения %d, задач %d, сверено %d, не удалось %d",
		len(c.Records), len(issues), checked, unresolved)
	if unresolved > 0 {
		t.Errorf("состояние %d задач из %d выяснить не удалось: измерение объявлено "+
			"включённым и не выполнено. «Не сверено» не засчитывается в «сверено и в "+
			"порядке»", unresolved, len(issues))
	}
	for _, f := range knownfailingexpiry.ClosedUnderALiveRecord(c, states) {
		t.Error(f)
	}
}

// resolveKnownFailingIssues спрашивает трекер про состояние каждой задачи.
func resolveKnownFailingIssues(issues []int) (map[int]string, int, int, string) {
	if _, err := exec.LookPath("gh"); err != nil {
		return nil, 0, len(issues),
			"сверка запрошена ручкой " + knownFailingTrackerKnob + "=1, но `gh` в PATH " +
				"нет — это НАСТРОЙКА, а не сбой: измерение объявлено включённым и не выполняется"
	}
	states := map[int]string{}
	checked, unresolved := 0, 0
	for _, n := range issues {
		out, err := exec.Command("gh", "issue", "view", strconv.Itoa(n),
			"--repo", "PRO-Robotech/kacho", "--json", "state").CombinedOutput()
		switch {
		case err == nil:
			var got struct {
				State string `json:"state"`
			}
			if json.Unmarshal(out, &got) != nil || got.State == "" {
				unresolved++
				continue
			}
			checked++
			states[n] = got.State
		case strings.Contains(string(out), knownFailingIssueMissing):
			// Номера нет вовсе — это НЕ «состояние неизвестно», а запись,
			// ссылающаяся в пустоту: истечь она не может никогда.
			checked++
			states[n] = "CLOSED"
		default:
			unresolved++
		}
	}
	return states, checked, unresolved, ""
}
