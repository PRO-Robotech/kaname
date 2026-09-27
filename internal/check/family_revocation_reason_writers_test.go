// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// family_revocation_reason_writers_test.go — гейт на РЕАЛЬНОМ дереве: у
// каждого слова словаря причин отзыва семейства есть писатель (приёмка
// `docs/engineering/acceptance/client-revocation-has-its-own-family-revocation-reason.md`,
// KN-FRV-17; задача kaname#339, п.1 предиката снятия).
//
// Предмет, две ветви писателя и границы разбора — в шапке
// `family_revocation_reason_writers.go`. Способность упасть по каждой ветви и
// смолчать на законном близнеце доказана инъекцией —
// `family_revocation_reason_writers_injection_test.go`.
package check_test

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/oauthceremony"
	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/ceremonyport"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// familyReasonDomainImport — путь импорта пакета домена: по нему, а не по
// имени пакета, судится селектор.
const familyReasonDomainImport = "github.com/PRO-Robotech/kaname/internal/domain"

// familyReasonDomainDir — дом объявлений словаря. Ссылки изнутри домена
// писателями не считаются: перечень и `Validate` называют каждое слово по
// построению.
const familyReasonDomainDir = "internal/domain"

// familyReasonConjugated — ветвь сопряжения на настоящем адаптере: причина
// фундамента того же написания (словарь фундамента — по пину `go.mod`)
// сопрягается `ceremonyport.FamilyReasonOf` именно с этим словом.
func familyReasonConjugated(word string) bool {
	for _, r := range oauthceremony.RevocationReasons() {
		if string(r) != word {
			continue
		}
		got, ok := ceremonyport.FamilyReasonOf(r)
		return ok && string(got) == word
	}
	return false
}

// TestFamilyRevocationVocabulary_KN_FRV_17_EveryWordHasAWriter — у каждого
// слова перечня домена есть писатель: ссылка на константу в коде либо
// сопряжение по значению.
func TestFamilyRevocationVocabulary_KN_FRV_17_EveryWordHasAWriter(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)
	paths, err := treecorpus.UnderWithSuffix(root, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обход %s: %v", root, err)
	}

	files := map[string]string{}
	domainFiles := map[string]string{}
	for _, p := range paths {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: путь %s вне корня %s: %v", p, root, err)
		}
		rel = filepath.ToSlash(rel)
		// Пробы — законные писатели сцены, а не продукта; testdata — не код
		// сборки.
		if strings.HasSuffix(rel, "_test.go") || strings.Contains("/"+rel, "/testdata/") {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: чтение %s: %v", p, err)
		}
		if path.Dir(rel) == familyReasonDomainDir {
			domainFiles[rel] = string(b)
			continue
		}
		files[rel] = string(b)
	}
	if len(domainFiles) == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: в %s не прочитано ни одного файла — объявлений словаря "+
			"читать не из чего", familyReasonDomainDir)
	}

	constants, err := check.FamilyReasonConstants(domainFiles, "FamilyRevocationReason")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	var vocabulary []string
	for _, r := range domain.FamilyRevocationReasons() {
		vocabulary = append(vocabulary, string(r))
	}

	census, err := check.FamilyReasonWriters(files, familyReasonDomainImport, constants, vocabulary,
		familyReasonConjugated)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Logf("перепись: файлов домена %d, констант словаря %d · %s", len(domainFiles), len(constants), census)

	for _, f := range check.FamilyReasonWriterFindings(census) {
		t.Error(f)
	}
}
