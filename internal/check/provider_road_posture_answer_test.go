// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_road_posture_answer_test.go — ГЕЙТ ПО ДЕРЕВУ: ни один потребитель
// строителя административной дороги не уносит её, не приняв ответа о посадке
// (задача kaname#313).
//
// Разбор предмета и то, чего он не видит, — в шапке
// `provider_road_posture_answer.go`. Здесь — обход, перепись и потолок.
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const (
	// postureAnswerBuilder — ИМЯ предмета. Подаётся гейтом, а не выводится из
	// дерева: выведенный предмет сменился бы вместе с деревом молча.
	postureAnswerBuilder = "mustProviderAdminClient"

	// postureAnswerCensusFloor — нижняя граница обхода. Обход, принёсший
	// меньше, дерева не читал.
	postureAnswerCensusFloor = 300

	// postureAnswerCeiling — ПОТОЛОК вызовов, не связавших ответ о посадке.
	//
	// Он равен НУЛЮ, и это замер по факту, а не желаемое: на дереве этой
	// задачи каждый из потребителей ответ принимает. Ноль здесь — не
	// умолчание: пока строитель возвращал одно значение, потолок был бы 4, и
	// гейт заводился ИМЕННО на том числе.
	postureAnswerCeiling = 0
)

type postureAnswerScan struct {
	Calls  []check.ProviderRoadCall
	Parsed int
	Census check.ProviderRoadCallCensus
}

func scanPostureAnswerTree(t *testing.T) postureAnswerScan {
	t.Helper()
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}
	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("состав дерева: %v — вердикт беспредметен", err)
	}

	var out postureAnswerScan
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(rel, "_test.go") {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь из состава дерева этого модуля
		if rderr != nil {
			continue
		}
		out.Parsed++
		calls, c, serr := check.ScanProviderRoadCalls(rel, src, postureAnswerBuilder)
		if serr != nil {
			t.Fatalf("разбор %s: %v", rel, serr)
		}
		out.Calls = append(out.Calls, calls...)
		out.Census.Funcs += c.Funcs
		out.Census.Calls += c.Calls
		out.Census.Bound += c.Bound
	}
	return out
}

// TestProviderRoadConsumersTakeThePostureAnswer — сам гейт.
func TestProviderRoadConsumersTakeThePostureAnswer(t *testing.T) {
	t.Parallel()
	scan := scanPostureAnswerTree(t)
	ignoring := check.ProviderRoadCallsIgnoringTheAnswer(scan.Calls)

	t.Logf("перепись: прод-файлов Go разобрано %d · функций с телом осмотрено %d · "+
		"вызовов строителя %s найдено %d — ответ о посадке принят в %d, отброшен в %d "+
		"(потолок %d)",
		scan.Parsed, scan.Census.Funcs, postureAnswerBuilder,
		scan.Census.Calls, scan.Census.Bound, len(ignoring), postureAnswerCeiling)

	if err := check.ProviderRoadCallPremise(scan.Parsed, postureAnswerCensusFloor,
		scan.Census, postureAnswerBuilder); err != nil {
		t.Fatalf("вердикт беспредметен: %v", err)
	}

	if len(ignoring) > postureAnswerCeiling {
		var where []string
		for _, c := range ignoring {
			where = append(where, fmt.Sprintf("%s:%d  %s() — %s", c.File, c.Line, c.Func, c.Form))
		}
		sort.Strings(where)
		t.Fatalf("потребителей, унёсших дорогу БЕЗ ответа о посадке, %d при потолке %d:\n  %s\n\n"+
			"На посадке без внешнего поставщика строитель отдаёт клиента БЕЗ АДРЕСА, и "+
			"всякий его вызов отказывает терминально. Потребитель, не принявший ответа, "+
			"уносит такого клиента МОЛЧА — отказ приходит позже, на пути запроса, и "+
			"называет чужой глагол.\n"+
			"Исход один: связать второе возвращаемое значение с именем и принять по нему "+
			"решение. Позвать предикат посадки рядом, ничего с его ответом не делая, "+
			"исходом НЕ является — это зеленит гейт, оставляя дорогу там же, где она была.",
			len(ignoring), postureAnswerCeiling, strings.Join(where, "\n  "))
	}
}
