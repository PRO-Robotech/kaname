// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// derived_id_single_source_test.go — деривация детерминированного
// идентификатора объявлена в прод-дереве РОВНО ОДИН РАЗ (приёмка
// `docs/engineering/acceptance/roles-come-as-data-not-migrations.md` §3.3;
// держатель, названный `seed-identity-names-its-own-service.md` §6).
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `derived_id_single_source_injection_test.go`.
//
// # Почему обход — СОБСТВЕННЫЙ модуль, а не дерево платформы
//
// Формула и её единственный дом (`internal/domain/derived_id.go`) лежат целиком
// внутри службы: платформа об этом предмете ничего не знает и участия в нём не
// принимает. `platformtree.RequireCorpus` поэтому не пропускает пробу в
// самостоятельном клоне — предмет её композиции — собственный состав модуля, а
// не дерево платформы, которого рядом может не быть (см. её же годок).
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// derivedIDOwner — единственный дом деривации.
const derivedIDOwner = "internal/domain/derived_id.go"

// derivedIDCensusFloor — порог переписи: ниже него «ноль находок» означало бы
// «ноль прочитанного».
const derivedIDCensusFloor = 300

// derivedIDWalkable — что гейт вообще осматривает. Вынесено функцией, а не
// оставлено в теле обхода: инъекция обязана проверять ТОТ ЖЕ отбор, которым
// судит гейт, — отбор, переписанный на стороне пробы, остаётся зелёным, когда
// гейт отбирает иначе.
func derivedIDWalkable(rel string) bool {
	return strings.HasSuffix(rel, ".go") && !strings.HasSuffix(rel, "_test.go")
}

// derivedIDFindings — находки по осмотренным местам. Тот же предикат зовёт
// инъекция.
func derivedIDFindings(sites []check.DerivedIDImportSite, owner string) []string {
	var out []string
	for _, s := range sites {
		if s.File == owner {
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d  (импорт %s, форма %s)",
			s.File, s.Line, check.DerivedIDPackage, s.Form))
	}
	sort.Strings(out)
	return out
}

// TestDeterministicIDDerivationIsDeclaredOnce — сам гейт.
func TestDeterministicIDDerivationIsDeclaredOnce(t *testing.T) {
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}
	owner := platformtree.Under(modulePrefix, derivedIDOwner)

	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан: %v", err)
	}

	var (
		parsed, imports int
		sites           []check.DerivedIDImportSite
	)
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if !derivedIDWalkable(rel) {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь взят индексом git, не вводом снаружи
		if rderr != nil {
			continue
		}
		s, census, serr := check.ScanDerivedIDDeclarations(rel, src)
		if serr != nil {
			t.Fatalf("разбор %s: %v", rel, serr)
		}
		parsed++
		imports += census.Imports
		sites = append(sites, s...)
	}

	byForm := map[string]int{}
	for _, s := range sites {
		byForm[s.Form]++
	}
	t.Logf("перепись: не-тестовых файлов Go разобрано %d, объявлений импорта прочитано %d, "+
		"импортов %s найдено %d (по формам: %v)",
		parsed, imports, check.DerivedIDPackage, len(sites), byForm)

	if parsed < derivedIDCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d файлов при пороге %d — на таком объёме "+
			"«ноль находок» означало бы «ноль прочитанного»", parsed, derivedIDCensusFloor)
	}
	if imports == 0 {
		t.Fatalf("прочитано ноль объявлений импорта на %d файлах — разбор перестал видеть "+
			"предмет, и его молчание сказано ни о чём", parsed)
	}

	// (1) Предпосылка: деривация вообще ЕСТЬ. Ноль означает, что дома у формулы
	// нет — и гейт молчал бы одинаково и тогда, когда предмет исчез, и тогда,
	// когда сломался он сам.
	if len(sites) == 0 {
		t.Fatalf("объявлений деривации (%s) в прод-дереве НОЛЬ — формулы нет ни в одном "+
			"месте, а идентификаторы применённых миграций ею адресованы. Гейт беспредметен.",
			check.DerivedIDPackage)
	}

	// (2) Находка: объявление ВНЕ единственного дома.
	findings := derivedIDFindings(sites, owner)
	if len(findings) > 0 {
		t.Fatalf("деривация детерминированного идентификатора объявлена ВНЕ %s — %d место(а):\n  %s\n\n"+
			"Две копии одной формулы расходятся МОЛЧА: обе отвечают «идентификатор вычислен», "+
			"полученное значение остаётся синтаксически верным и перестаёт находить строку. "+
			"Наблюдаемо это только по отказу в доступе у арендатора, у которого право не отзывали.\n"+
			"Снятие: звать `domain.DerivedIDSuffix`, а не писать формулу своей рукой.",
			owner, len(findings), strings.Join(findings, "\n  "))
	}

	// (3) Дом обязан существовать: перечень выше пуст и тогда, когда дом
	// переименовали, — и тогда гейт молчит, ничего не удержав.
	var owned int
	for _, s := range sites {
		if s.File == owner {
			owned++
		}
	}
	if owned == 0 {
		t.Fatalf("дом деривации %s в прод-дереве не найден, а находок нет — значит формула "+
			"переехала, и гейт стережёт координату, которой больше нет", owner)
	}
	t.Logf("единственное объявление деривации: %s (%d импорт(ов))", owner, owned)
}
