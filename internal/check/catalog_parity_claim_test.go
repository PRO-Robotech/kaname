// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_parity_claim_test.go — проза Makefile, утверждающая побайтовое
// совпадение копий каталога прав, называет ДЕЙСТВУЮЩЕГО держателя этого дерева.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (kacho#2620)
//
// Блок над целью синхронизации утверждал в настоящем времени: копия каталога у
// службы ОБЯЗАНА побайтово совпадать с копией края, «и гейт
// `make -C <корень дерева>/gateway permission-catalog-check` роняет сборку при
// расхождении».
//
// Названный гейт существует и исполняется — но сверяет каталог КРАЯ с
// ПОРОЖДЁННЫМ ИЗ КОНТРАКТА, а не с копией службы; его собственный комментарий в
// дереве платформы говорит это прямо. То есть утверждение ложно не отсутствием
// предмета, а ПОДМЕНОЙ ПРЕДМЕТА, и это худший из двух случаев: читатель
// проверяет, что цель есть, находит её и на этом останавливается.
//
// Хуже прочего то, что действующий держатель был объявлен ЧЕТЫРНАДЦАТЬЮ
// СТРОКАМИ НИЖЕ в том же файле — цель `check-permission-catalog` и гейт её
// провязки. Два места об одном предмете внутри одного файла, и верным было то,
// которое читают реже.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ, И ПОЧЕМУ УСЛОВНО
//
// Ось УСЛОВНА: требование возникает только там, где проза утверждение делает.
// Блок без утверждения о побайтовом совпадении ось не судит вовсе — и это не
// послабление, а единственная форма, которая самоистекает: снимут утверждение —
// снимется и требование к нему, без записи в ведомости и без чьей-либо памяти.
//
// Блок, утверждение несущий, обязан:
//
//  1. назвать цель-держателя, ОБЪЯВЛЕННУЮ в этом же Makefile (иначе держатель
//     назван и не существует — то же обещание, что и подмена);
//  2. а если её не назвал — не подставлять вместо неё цель края
//     `permission-catalog-check`: она сверяет другое.
//
// ПОРЯДОК ЗДЕСЬ НЕСУЩИЙ, И ЦЕНА ЕГО ИЗМЕРЕНА. Первая редакция запрещала имя
// цели края в блоке БЕЗУСЛОВНО — и покраснела на исправленном блоке, чей
// разбор эту самую ошибку объясняет. Тот же класс, что корпус ловит в гейтах:
// проверка по подстроке краснеет на собственном объяснении. Починен
// РАСПОЗНАВАТЕЛЬ, а не документ: подмена есть там, где своего держателя не
// назвали, — упоминание соседнего дерева рядом с названным своим подменой не
// является.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо
//
//  1. Она НЕ судит, что названный держатель действительно проверяет обещанное:
//     это суждение о чужом рецепте и о смысле прозы. Она судит, что держатель
//     назван, объявлен здесь и не подменён целью другого дерева.
//  2. Блок, называющий ОБА имени, ось пропускает: различить «держатель» от
//     «упоминание» внутри одного блока машинно нечем, а выбор в пользу строгости
//     дал бы красное на верной прозе — то есть проверку, которую отключат первой.
//  3. Побайтовое совпадение самих копий — предмет рецепта
//     `check-permission-catalog`, а не этой оси.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/stretchr/testify/require"
)

// serviceRootFromCheck — корень дерева службы от каталога этого пакета.
const serviceRootFromCheck = "../.."

// edgeCatalogTarget — цель ДРУГОГО дерева. Она сверяет каталог края с
// порождённым из контракта; держателем совпадения копий она не является.
const edgeCatalogTarget = "permission-catalog-check"

// parityClaimMarkers — признаки утверждения о побайтовом совпадении копий. Оба
// обязаны стоять в одном блоке: «побайтово» встречается и в рассказе о том, как
// устроена сверка, а «совпад» — в любой прозе о каталоге.
var parityClaimMarkers = []string{"побайтов", "совпад"}

// commentBlock — непрерывный пробег строк-комментариев Makefile.
type commentBlock struct {
	firstLine int
	body      string
}

// parityClaimFinding — одно попадание: координата блока и чем он неверен.
type parityClaimFinding struct {
	firstLine int
	reason    string
}

// parityClaimCensus — объём осмотренного. «Ноль находок» обязано быть отличимо
// от «ноль прочитанного», а «ноль блоков с утверждением» — от «распознаватель
// ослеп».
type parityClaimCensus struct {
	linesScanned   int
	blocksSeen     int
	claimingBlocks int
}

// makefileCommentBlocks — пробеги строк-комментариев. Рецепт не комментарий:
// его строки начинаются с табуляции и в блок не входят.
func makefileCommentBlocks(makefile string) ([]commentBlock, int) {
	var (
		blocks  []commentBlock
		current []string
		start   int
		lines   int
	)
	flush := func() {
		if len(current) > 0 {
			blocks = append(blocks, commentBlock{firstLine: start, body: strings.Join(current, "\n")})
			current = nil
		}
	}
	for idx, line := range strings.Split(makefile, "\n") {
		lines++
		if strings.HasPrefix(strings.TrimSpace(line), "#") && !strings.HasPrefix(line, "\t") {
			if len(current) == 0 {
				start = idx + 1
			}
			current = append(current, line)
			continue
		}
		flush()
	}
	flush()
	return blocks, lines
}

// blockClaimsParity — блок утверждает побайтовое совпадение копий.
func blockClaimsParity(body string) bool {
	for _, marker := range parityClaimMarkers {
		if !strings.Contains(body, marker) {
			return false
		}
	}
	return true
}

// scanCatalogParityClaims — разбор над ПРОИЗВОЛЬНЫМ текстом Makefile. Вынесено
// из теста затем, чтобы способность гейта упасть доказывалась подачей входа.
func scanCatalogParityClaims(makefile string) (parityClaimCensus, []parityClaimFinding) {
	var census parityClaimCensus

	blocks, lines := makefileCommentBlocks(makefile)
	census.linesScanned = lines
	census.blocksSeen = len(blocks)

	var findings []parityClaimFinding
	for _, b := range blocks {
		if !blockClaimsParity(b.body) {
			continue
		}
		census.claimingBlocks++

		switch {
		case strings.Contains(b.body, check.CatalogCheckTarget):
			// Свой держатель назван — остаётся спросить, существует ли он.
			if !check.MakefileDeclaresTarget(makefile, check.CatalogCheckTarget) {
				findings = append(findings, parityClaimFinding{
					firstLine: b.firstLine,
					reason:    "названный держатель " + check.CatalogCheckTarget + " в этом Makefile НЕ объявлен",
				})
			}
		case strings.Contains(b.body, edgeCatalogTarget):
			findings = append(findings, parityClaimFinding{
				firstLine: b.firstLine,
				reason: "своего держателя блок не называет, а вместо него названа цель другого дерева " +
					edgeCatalogTarget + " — она сверяет каталог края с порождённым из контракта, " +
					"а копия службы в ней не участвует вовсе",
			})
		default:
			findings = append(findings, parityClaimFinding{
				firstLine: b.firstLine,
				reason:    "держатель не назван вовсе — утверждение читается как исполняемое, и проверять его нечем",
			})
		}
	}
	return census, findings
}

func TestCatalogParityClaimNamesAHolderThisTreeDeclares(t *testing.T) {
	t.Parallel()

	path := filepath.Join(serviceRootFromCheck, "Makefile")
	raw, err := os.ReadFile(path)
	require.NoErrorf(t, err, "корневой Makefile службы не прочитан: %s", path)

	census, findings := scanCatalogParityClaims(string(raw))

	t.Logf("перепись: строк Makefile %d · блоков комментария %d · из них утверждают совпадение копий %d · находок %d",
		census.linesScanned, census.blocksSeen, census.claimingBlocks, len(findings))

	require.NotZero(t, census.linesScanned, "обход пуст: строк не осмотрено ни одной — вердикт беспредметен")
	require.NotZero(t, census.blocksSeen, "обход пуст: блоков комментария не распознано — распознаватель ослеп")
	require.NotZero(t, census.claimingBlocks,
		"обход пуст: блоков с утверждением о побайтовом совпадении не найдено — "+
			"либо утверждение снято (тогда снимается и ось), либо распознаватель ослеп")

	for _, f := range findings {
		t.Errorf("Makefile:%d — блок утверждает побайтовое совпадение копий каталога прав, но %s. "+
			"Читатель проверяет, что цель есть, находит её и на этом останавливается",
			f.firstLine, f.reason)
	}
}
