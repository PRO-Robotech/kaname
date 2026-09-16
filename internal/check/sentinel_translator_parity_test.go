// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// sentinel_translator_parity_test.go — переводчик отказа домена различает те же
// полосы, что канонический (задача kaname#114).
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `sentinel_translator_parity_injection_test.go`.
//
// # ЧТО ИМЕННО УТВЕРЖДАЕТСЯ — И ЧТО НЕТ
//
// Утверждается НАБОР различаемых полос, а не текст и не код. Текст терминального
// INTERNAL у домена свой и остаётся своим: он часть контракта. Полоса, которой
// переводчик не знает, уезжает в этот терминальный INTERNAL — то есть отказ,
// ПОВТОРЯЕМЫЙ по своей природе, приходит клиенту как поломка платформы.
//
// # КАНОН НЕ ВЫПИСАН, А ПРОЧИТАН
//
// Требуемый набор берётся у `shared.MapRepoErr` разбором — тем же, которым гейт
// читает копии. Выписанный перечень был бы вторым местом об одном предмете и
// разошёлся бы с каноном молча: ровно так разошлись сами копии.
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

// sentinelCanonFile / sentinelCanonFunc — дом канонического переводчика.
const (
	sentinelCanonFile = "internal/apps/kaname/shared/errors.go"
	sentinelCanonFunc = "MapRepoErr"
)

// sentinelCensusFloor — порог переписи: ниже него «ноль находок» означало бы
// «ноль прочитанного».
const sentinelCensusFloor = 300

// sentinelWalkable — что гейт осматривает. Вынесено функцией: инъекция обязана
// проверять ТОТ ЖЕ отбор, которым судит гейт.
func sentinelWalkable(rel string) bool {
	return strings.HasSuffix(rel, ".go") &&
		!strings.HasSuffix(rel, "_test.go") &&
		!strings.HasPrefix(rel, "pkg/api/")
}

// sentinelParityFindings — полосы канона, которых копия не различает. Тот же
// предикат зовёт инъекция.
func sentinelParityFindings(canon check.SentinelTranslator, copies []check.SentinelTranslator) []string {
	var out []string
	for _, c := range copies {
		var missing []string
		for _, s := range canon.Sentinels {
			if !c.Has(s) {
				missing = append(missing, s)
			}
		}
		if len(missing) == 0 {
			continue
		}
		sort.Strings(missing)
		out = append(out, fmt.Sprintf("%s:%d %s — не различает %s (различает %d из %d)",
			c.File, c.Line, c.Func, strings.Join(missing, ", "),
			len(c.Sentinels), len(canon.Sentinels)))
	}
	sort.Strings(out)
	return out
}

// TestEveryDomainTranslatorKnowsTheCanonicalLanes — сам гейт.
func TestEveryDomainTranslatorKnowsTheCanonicalLanes(t *testing.T) {
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}
	canonFile := platformtree.Under(modulePrefix, sentinelCanonFile)

	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан: %v", err)
	}

	var (
		parsed      int
		total       check.SentinelTranslatorCensus
		translators []check.SentinelTranslator
		canon       check.SentinelTranslator
		canonFound  bool
	)
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if !sentinelWalkable(rel) {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь взят индексом git, не вводом снаружи
		if rderr != nil {
			continue
		}
		ts, census, serr := check.ScanSentinelTranslators(rel, src)
		if serr != nil {
			t.Errorf("разбор %s: %v", rel, serr)
			continue
		}
		parsed++
		total.Funcs += census.Funcs
		total.WithSentinels += census.WithSentinels
		total.Translators += census.Translators
		for _, tr := range ts {
			if rel == canonFile && tr.Func == sentinelCanonFunc {
				canon, canonFound = tr, true
				continue
			}
			translators = append(translators, tr)
		}
	}

	t.Logf("перепись: не-тестовых файлов Go разобрано %d, функций прочитано %d, "+
		"из них различающих %s.Err* %d, из них переводчиков %d (канон + %d копий)",
		parsed, total.Funcs, check.SentinelIAMPackage, total.WithSentinels,
		total.Translators, len(translators))

	if parsed < sentinelCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d файлов при пороге %d — на таком объёме "+
			"«ноль находок» означало бы «ноль прочитанного»", parsed, sentinelCensusFloor)
	}
	if !canonFound {
		t.Fatalf("канонический переводчик %s.%s разбором НЕ опознан. Либо он переехал, либо "+
			"перестал отвечать признакам переводчика — и тогда гейт сверял бы копии с пустым "+
			"набором, то есть молчал при любом расхождении", sentinelCanonFile, sentinelCanonFunc)
	}
	t.Logf("канон %s.%s различает %d полос: %s",
		canon.File, canon.Func, len(canon.Sentinels), strings.Join(canon.Sentinels, ", "))
	for _, c := range translators {
		t.Logf("  копия %s:%d %s — %d полос", c.File, c.Line, c.Func, len(c.Sentinels))
	}
	if len(translators) == 0 {
		t.Fatalf("копий переводчика не найдено ни одной — предмет гейта исчез, и его " +
			"молчание сказано ни о чём. Снимать вместе с предметом, а не оставлять")
	}

	if findings := sentinelParityFindings(canon, translators); len(findings) > 0 {
		t.Fatalf("переводчик домена не различает полос, которые различает канон — %d место(а):\n  %s\n\n"+
			"Полоса, которой переводчик не знает, уезжает в терминальный INTERNAL: отказ, "+
			"ПОВТОРЯЕМЫЙ по своей природе, приходит клиенту как поломка платформы, и клиент "+
			"его не повторит; отказ в правах, поданный тем же INTERNAL, прячет от вызывающего, "+
			"что чинить повтором нечего.\n"+
			"Класс закрывался ОДНАЖДЫ и вернулся — годок канона называет те же два sentinel'а.\n"+
			"Снятие: добавить ветви (текст терминального INTERNAL остаётся СВОИМ — он часть "+
			"контракта домена) либо свести копию к канону.",
			len(findings), strings.Join(findings, "\n  "))
	}
}
