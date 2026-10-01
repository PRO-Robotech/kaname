// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// servicesubjectwriter_test.go — ПИСАТЕЛЬ КОРТЕЖЕЙ СО СЛУЖЕБНЫМ СУБЪЕКТОМ ОДИН:
// применитель манифеста (приёмка NTF-1, NTF1-M10; замысел З17).
//
// Предмет, формы производства и названная слепая зона — в годке
// `service_subject_writer.go`; здесь они не пересказываются. Способность гейта
// упасть и смолчать доказана инъекцией — `servicesubjectwriter_injection_test.go`.
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

// serviceSubjectCensusFloor — порог переписи: ниже него «ноль находок» означало
// бы «ноль прочитанного».
const serviceSubjectCensusFloor = 300

// serviceSubjectScanner — файл самого разбора: образец, который он ищет, он
// обязан назвать литералом, и этот литерал не производство субъекта.
const serviceSubjectScanner = "internal/check/service_subject_writer.go"

// serviceSubjectWalkable — что гейт осматривает. Инъекция обязана проверять ТОТ
// ЖЕ отбор. Пробы исключены: им положено строить субъект для утверждений.
// Исключён поимённо и файл разбора (см. serviceSubjectScanner).
func serviceSubjectWalkable(rel string) bool {
	return rel != serviceSubjectScanner &&
		strings.HasSuffix(rel, ".go") &&
		!strings.HasSuffix(rel, "_test.go") &&
		!strings.HasSuffix(rel, ".pb.go")
}

// serviceSubjectFindings — находки: места производства вне разрешённого файла.
// Тот же предикат зовёт инъекция.
func serviceSubjectFindings(sites []check.ServiceSubjectSite) []string {
	var out []string
	for _, s := range sites {
		if s.File == check.ServiceSubjectWriterFile {
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d  %s", s.File, s.Line, s.Form))
	}
	sort.Strings(out)
	return out
}

// TestOnlyTheManifestApplierWritesServiceSubjectTuples — сам гейт.
func TestOnlyTheManifestApplierWritesServiceSubjectTuples(t *testing.T) {
	t.Parallel()

	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}
	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан: %v", err)
	}

	var parsed, strs, authzRefs int
	var sites []check.ServiceSubjectSite
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if !serviceSubjectWalkable(rel) {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь взят индексом git, не вводом снаружи
		if rderr != nil {
			t.Fatalf("файл индекса %s не прочитан (%v) — гейт не вправе считать его «без записей»", rel, rderr)
		}
		s, census, serr := check.ScanServiceSubjectProducers(rel, src)
		if serr != nil {
			t.Fatalf("разбор %s не удался (%v) — неразобранный файл не есть «записей нет»", rel, serr)
		}
		parsed++
		strs += census.Strings
		authzRefs += census.AuthzSelectors
		sites = append(sites, s...)
	}

	own := 0
	for _, s := range sites {
		if s.File == check.ServiceSubjectWriterFile {
			own++
		}
	}
	t.Logf("перепись: непроверочных файлов Go разобрано %d, строковых литералов прочитано %d, "+
		"обращений к пакету authz фундамента %d; мест производства `service:` %d, из них в "+
		"применителе (%s) %d", parsed, strs, authzRefs, len(sites), check.ServiceSubjectWriterFile, own)

	if parsed < serviceSubjectCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d файлов при пороге %d", parsed, serviceSubjectCensusFloor)
	}
	if strs == 0 || authzRefs == 0 {
		t.Fatalf("литералов прочитано %d, обращений к authz %d — разбор перестал видеть предмет", strs, authzRefs)
	}
	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ и истечение разрешения: применитель обязан
	// производить субъект. Ноль здесь — либо производство переехало (тогда правь
	// check.ServiceSubjectWriterFile вместе с ним), либо разбор перестал его
	// видеть; и то и другое не есть «нарушений нет».
	if own == 0 {
		t.Fatalf("в %s не найдено ни одного места производства `service:` — разрешение "+
			"гейта пережило свой предмет либо разбор ослеп", check.ServiceSubjectWriterFile)
	}

	for _, f := range serviceSubjectFindings(sites) {
		t.Errorf("%s — производство субъекта `service:` вне применителя манифеста.\n"+
			"Служебный субъект заводит ТОЛЬКО строка `notifications` манифеста (З17): тенантская "+
			"поверхность, производящая его, выдала бы службе право, которого манифест не "+
			"объявлял, — и отозвать его было бы нечем", f)
	}
}
