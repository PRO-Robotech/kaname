// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// doc_header_names_its_declaration_test.go — шапка прод-объявления называет ТО
// объявление, над которым стоит (задача kaname#118).
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `doc_header_names_its_declaration_injection_test.go`.
//
// # Почему обход — СОБСТВЕННЫЙ модуль
//
// Предмет — шапки этого дерева и его же соглашение о форме «Имя — текст».
// Дерево платформы пишет свои шапки само и этому гейту не подсудно.
//
// # Граница названа числом, а не умолчанием
//
// Гейт судит ПРОД-код: пробы из обхода исключены. Это не значит, что там класса
// нет, — на день заведения он там был, и перепись это называет ЧИСЛОМ, снятым
// ЭТИМ ЖЕ распознавателем: прод-дерево — 766 файлов, 3910 шапок, 24 расхождения
// (закрыты здесь); пробы — 1782 файла, 7587 шапок, 57 расхождений.
//
// Вторая половина заведена СВОЕЙ задачей (kaname#152), а не прощена молча:
// расширить обход отсюда значило бы завести гейт, краснеющий на 57 местах
// сразу, — у такого не будет читателя, и снимут его первым.
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

// docHeaderCensusFloor — порог переписи: ниже него «ноль находок» означало бы
// «ноль прочитанного».
const docHeaderCensusFloor = 400

// docHeaderWalkable — что гейт осматривает. Вынесено функцией, а не оставлено в
// теле обхода: инъекция обязана проверять ТОТ ЖЕ отбор, которым судит гейт.
//
// `pkg/api/` исключён по предмету, а не по удобству: это порождённые стабы, их
// шапки пишет генератор, и правка там уедет при следующей генерации.
func docHeaderWalkable(rel string) bool {
	return strings.HasSuffix(rel, ".go") &&
		!strings.HasSuffix(rel, "_test.go") &&
		!strings.HasPrefix(rel, "pkg/api/")
}

// docHeaderFindings — находки по прочитанным шапкам. Тот же предикат зовёт
// инъекция.
func docHeaderFindings(sites []check.DocHeaderSite) []string {
	var out []string
	for _, s := range sites {
		if s.Matches() {
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d  шапка называет %q, объявлено %q (форма %s)",
			s.File, s.Line, s.Named, strings.Join(s.Declared, ", "), s.Form))
	}
	sort.Strings(out)
	return out
}

// TestDocHeaderNamesItsOwnDeclaration — сам гейт.
func TestDocHeaderNamesItsOwnDeclaration(t *testing.T) {
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}

	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан: %v", err)
	}

	var (
		parsed int
		total  check.DocHeaderCensus
		sites  []check.DocHeaderSite
		byForm = map[string]int{}
	)
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if !docHeaderWalkable(rel) {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь взят индексом git, не вводом снаружи
		if rderr != nil {
			continue
		}
		s, census, serr := check.ScanDocHeaders(rel, src)
		if serr != nil {
			// Файл, который не разбирается, — не находка этого гейта: его ловит
			// сборка. Но и молча пропускать его нельзя, иначе обход сужается
			// незаметно.
			t.Errorf("разбор %s: %v", rel, serr)
			continue
		}
		parsed++
		total.Decls += census.Decls
		total.Documented += census.Documented
		total.Headers += census.Headers
		sites = append(sites, s...)
	}
	for _, s := range sites {
		byForm[s.Form]++
	}

	t.Logf("перепись: не-тестовых файлов Go разобрано %d, объявлений прочитано %d, "+
		"из них с шапкой %d, из них формы «Имя — текст» %d (по формам: %v)",
		parsed, total.Decls, total.Documented, total.Headers, byForm)

	if parsed < docHeaderCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d файлов при пороге %d — на таком объёме "+
			"«ноль находок» означало бы «ноль прочитанного»", parsed, docHeaderCensusFloor)
	}
	if total.Headers == 0 {
		t.Fatalf("прочитано ноль шапок формы «Имя — текст» на %d файлах и %d объявлениях — "+
			"распознаватель перестал видеть предмет, и его молчание сказано ни о чём",
			parsed, total.Decls)
	}

	findings := docHeaderFindings(sites)
	if len(findings) > 0 {
		t.Fatalf("шапка стоит над ЧУЖИМ объявлением — %d место(а):\n  %s\n\n"+
			"Шапка этого дерева называет своё объявление первым словом, и по нему его "+
			"находят, не разбирая тело. Отвязавшись, она продолжает выглядеть исправной: "+
			"`go doc` печатает чужой текст у одного имени и НИ ОДНОГО у другого, при том "+
			"что обе шапки на месте и дословно верны.\n"+
			"Снятие: вернуть блок к своему объявлению (обычно между ними потеряна пустая "+
			"строка, и Go склеил две группы в одну) либо назвать в шапке то имя, которое "+
			"объявление носит теперь.",
			len(findings), strings.Join(findings, "\n  "))
	}
}
