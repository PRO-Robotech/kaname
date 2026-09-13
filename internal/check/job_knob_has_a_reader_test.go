// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// job_knob_has_a_reader_test.go — ГЕЙТ КЛАССА: у каждой величины секции фоновых
// заданий есть читатель в композиционном корне (задача #2647).
//
// Предмет, граница «секция, переданная целиком» и довод в пользу разбора узлов
// вместо поиска имени — в шапке `job_knob_has_a_reader.go`; здесь они не
// пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// job_knob_has_a_reader_injection_test.go.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// JobSectionsFile — где объявлены секции фоновых заданий.
const jobSectionsFile = "internal/apps/kaname/config/jobs.go"

// jobReaderRoot — каталог, в котором ищется читатель. Композиционный корень и
// есть то место, где величина попадает в механизм.
const jobReaderRoot = "cmd"

func TestJobSectionKnobHasAReaderOutsideItsOwnValidation(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}

	src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(jobSectionsFile)))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: объявление секций не прочитано (%s): %v",
			jobSectionsFile, err)
	}
	sections, err := check.JobSectionsIn(string(src))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if len(sections) == 0 {
		t.Fatalf("предпосылка гейта не выполнена: в %s не найдено ни одной секции "+
			"фоновых заданий — форма объявления изменилась, и гейт судит пустоту",
			jobSectionsFile)
	}

	names := map[string]bool{}
	for _, s := range sections {
		names[s.Name] = true
	}

	files, err := treecorpus.UnderWithSuffix(filepath.Join(root, jobReaderRoot), ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав композиционного корня: %v", err)
	}

	var (
		reads  []check.JobFieldRead
		whole  []string
		parsed int
	)
	for _, abs := range files {
		if strings.HasSuffix(abs, "_test.go") {
			continue
		}
		body, rerr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git своего дерева
		if rerr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s: %v", abs, rerr)
		}
		rel, _ := filepath.Rel(root, abs)
		r, w, perr := check.JobFieldReadsIn(filepath.ToSlash(rel), string(body), names)
		if perr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", perr)
		}
		parsed++
		reads = append(reads, r...)
		whole = append(whole, w...)
	}
	if parsed == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО прод-файла корня (%s) — вердикт "+
			"беспредметен: «находок ноль» неотличимо от «прочитано ноль»", jobReaderRoot)
	}

	census := check.JudgeJobKnobReaders(sections, reads, whole, parsed)
	t.Logf("перепись: %s", census.Summary())
	if census.Fields == 0 {
		t.Fatalf("предпосылка гейта не выполнена: у секций не найдено ни одной величины " +
			"с тегом настроек — разбор перестал их видеть, и гейт судит пустоту")
	}

	if len(census.Findings) > 0 {
		t.Fatalf("величин секций фоновых заданий без читателя: %d\n  %s",
			len(census.Findings), strings.Join(census.Findings, "\n  "))
	}
}
