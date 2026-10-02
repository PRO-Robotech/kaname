// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// published_key_rule_home_test.go — правило выбора ключа проверки из
// публикуемого набора живёт в прод-дереве ОДИН раз: обращение к правилу
// критичных параметров заголовка (`tokenpolicy.CriticalHeadersUnderstood`)
// стоит только в его доме, `internal/publishedkey` (задача
// PRO-Robotech/kaname#396).
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `published_key_rule_home_injection_test.go`.
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

// publishedKeyRuleHome — единственный дом правила.
const publishedKeyRuleHome = "internal/publishedkey/"

// publishedKeyRuleCensusFloor — порог переписи: ниже него «ноль находок»
// означало бы «ноль прочитанного».
const publishedKeyRuleCensusFloor = 300

// publishedKeyRuleWalkable — что гейт осматривает. Тот же отбор зовёт
// инъекция.
func publishedKeyRuleWalkable(rel string) bool {
	return strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go")
}

// publishedKeyRuleFindings — обращения ВНЕ дома. Тот же предикат зовёт
// инъекция.
func publishedKeyRuleFindings(sites []check.CriticalHeaderRuleSite, home string) []string {
	var out []string
	for _, s := range sites {
		if strings.HasPrefix(s.File, home) {
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d  (%s.%s, форма %s)",
			s.File, s.Line, check.CriticalHeaderRulePackage, check.CriticalHeaderRuleFunc, s.Form))
	}
	sort.Strings(out)
	return out
}

// TestPublishedKeyRuleHasOneHome — сам гейт.
func TestPublishedKeyRuleHasOneHome(t *testing.T) {
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}
	home := platformtree.Under(modulePrefix, publishedKeyRuleHome)

	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан: %v", err)
	}

	var (
		parsed, selectors, imports int
		sites                      []check.CriticalHeaderRuleSite
	)
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if !publishedKeyRuleWalkable(rel) {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь взят индексом git, не вводом снаружи
		if rderr != nil {
			continue
		}
		s, census, serr := check.ScanCriticalHeaderRule(rel, src)
		if serr != nil {
			t.Fatalf("разбор %s: %v", rel, serr)
		}
		parsed++
		selectors += census.Selectors
		imports += census.PolicyImports
		sites = append(sites, s...)
	}

	byForm := map[string]int{}
	for _, s := range sites {
		byForm[s.Form]++
	}
	t.Logf("перепись: не-тестовых файлов Go разобрано %d, выражений выбора прочитано %d, "+
		"импортов %s %d, обращений к правилу найдено %d (по формам: %v)",
		parsed, selectors, check.CriticalHeaderRulePackage, imports, len(sites), byForm)

	if parsed < publishedKeyRuleCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d файлов при пороге %d — на таком объёме "+
			"«ноль находок» означало бы «ноль прочитанного»", parsed, publishedKeyRuleCensusFloor)
	}
	if selectors == 0 || imports == 0 {
		t.Fatalf("прочитано выражений выбора %d и импортов правила %d на %d файлах — разбор "+
			"перестал видеть предмет, и его молчание сказано ни о чём", selectors, imports, parsed)
	}

	// (1) Находка: правило вызвано ВНЕ дома — у набора появилась вторая копия
	// выбора ключа.
	if findings := publishedKeyRuleFindings(sites, home); len(findings) > 0 {
		t.Fatalf("правило критичных параметров заголовка вызвано ВНЕ %s — %d место(а):\n  %s\n\n"+
			"Каждое такое место — своя копия выбора ключа проверки из публикуемого набора "+
			"(форма kid → ключ по kid → алгоритм, закреплённый за ключом → crit → открытая "+
			"половина). Копии расходятся МОЛЧА: обе отвечают «подпись сошлась».\n"+
			"Снятие: звать `publishedkey.Parse`, а не писать выбор ключа своей рукой.",
			home, len(findings), strings.Join(findings, "\n  "))
	}

	// (2) Предпосылка: дом существует и правило в нём вызвано. Перечень выше
	// пуст и тогда, когда дом переехал, — и гейт молчал бы, ничего не удержав.
	var owned int
	for _, s := range sites {
		if strings.HasPrefix(s.File, home) {
			owned++
		}
	}
	if owned == 0 {
		t.Fatalf("в доме %s обращений к правилу не найдено, а находок нет — правило переехало "+
			"либо снято, и гейт стережёт координату, которой больше нет", home)
	}
	t.Logf("единственный дом правила: %s (%d обращение(й))", home, owned)
}
