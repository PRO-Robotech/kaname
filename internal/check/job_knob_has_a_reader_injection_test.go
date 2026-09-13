// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// job_knob_has_a_reader_injection_test.go — доказательство, что гейт
// `TestJobSectionKnobHasAReaderOutsideItsOwnValidation` способен упасть И
// способен смолчать.
//
// У КАЖДОГО нарушителя стоит ЗАКОННЫЙ БЛИЗНЕЦ — та же форма записи,
// отличающаяся РОВНО ОДНИМ фактом. Инъекция роняет ТОЛЬКО проверяемое: близнец
// и нарушитель отличаются прочтением ОДНОЙ величины, а не заведением лишней.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// injJobsDecl — объявление секций. Одно на все случаи: предмет инъекции —
// ЧИТАТЕЛЬ, а не форма объявления.
const injJobsDecl = `package config

type JobsConfig struct {
	Sweep SweepConfig ` + "`mapstructure:\"sweep\"`" + `
}

type SweepConfig struct {
	Interval time.Duration ` + "`mapstructure:\"interval\"`" + `
	Grace    time.Duration ` + "`mapstructure:\"grace\"`" + `
	notATag  time.Duration
}
`

// injReaderAlias — ЗАКОННЫЙ БЛИЗНЕЦ: обе величины прочитаны через псевдоним —
// ровно та форма, которой пользуется корень.
const injReaderAlias = `package main

func run(cfg config.Config) {
	c := cfg.Jobs.Sweep
	use(c.Interval)
	use(c.Grace)
}
`

// injReaderMissesOne — ДЕФЕКТ: ровно один факт против близнеца — величина
// Grace не прочитана.
const injReaderMissesOne = `package main

func run(cfg config.Config) {
	c := cfg.Jobs.Sweep
	use(c.Interval)
}
`

// injReaderDirectChain — ВТОРАЯ ЗАКОННАЯ ФОРМА: прямая цепочка без псевдонима.
// Распознаватель обязан знать обе: форма, о которой он не знает, даёт не
// красное и не зелёное, а МОЛЧАНИЕ.
const injReaderDirectChain = `package main

func run(cfg config.Config) {
	use(cfg.Jobs.Sweep.Interval)
	use(cfg.Jobs.Sweep.Grace)
}
`

// injReaderNamesakeField — ГРАНИЦА: одноимённое поле ЧУЖОЙ структуры читателем
// НЕ является. Без этой оси гейт зеленел бы на любом дереве, где слово
// `Interval` встречается хоть раз.
const injReaderNamesakeField = `package main

func run(cfg config.Config, other retention) {
	c := cfg.Jobs.Sweep
	use(c.Interval)
	use(other.Grace)
}
`

// injReaderWholeSection — ГРАНИЦА: секция уехала в вызов ЦЕЛИКОМ. Это не
// находка и не прощение: о полях вердикта нет, и секция обязана быть НАЗВАНА
// переписью.
const injReaderWholeSection = `package main

func run(cfg config.Config) {
	start(cfg.Jobs.Sweep)
}
`

func injJudge(t *testing.T, root string) check.JobKnobCensus {
	t.Helper()
	sections, err := check.JobSectionsIn(injJobsDecl)
	if err != nil {
		t.Fatalf("разобрать секции: %v", err)
	}
	names := map[string]bool{}
	for _, s := range sections {
		names[s.Name] = true
	}
	reads, whole, err := check.JobFieldReadsIn("serve.go", root, names)
	if err != nil {
		t.Fatalf("разобрать корень: %v", err)
	}
	return check.JudgeJobKnobReaders(sections, reads, whole, 1)
}

func TestJobKnobInjection_RedsTheUnreadKnobAndKeepsQuietWhenAllAreRead(t *testing.T) {
	t.Parallel()

	twin := injJudge(t, injReaderAlias)
	if len(twin.Findings) != 0 {
		t.Fatalf("ЗАКОННЫЙ БЛИЗНЕЦ окрашен: %v (%s)", twin.Findings, twin.Summary())
	}
	if twin.Fields != 2 || twin.Read != 2 {
		t.Fatalf("близнец сосчитан неверно: %s", twin.Summary())
	}

	defect := injJudge(t, injReaderMissesOne)
	if len(defect.Findings) != 1 {
		t.Fatalf("величина без читателя НЕ найдена (%d находок) — ручка, которую "+
			"принимают и не читают, проехала бы молча: %s", len(defect.Findings), defect.Summary())
	}
	if !strings.Contains(defect.Findings[0], "Sweep.Grace") {
		t.Errorf("находка не называет КООРДИНАТУ величины: %q", defect.Findings[0])
	}
	// Инъекция роняет ТОЛЬКО проверяемое: прочитанная величина осталась прочитанной.
	if defect.Read != 1 || defect.Fields != 2 {
		t.Errorf("инъекция уронила заодно соседа: %s", defect.Summary())
	}
}

func TestJobKnobInjection_KnowsBothLegalFormsOfTheRead(t *testing.T) {
	t.Parallel()

	direct := injJudge(t, injReaderDirectChain)
	if len(direct.Findings) != 0 {
		t.Fatalf("ПРЯМАЯ ЦЕПОЧКА не опознана читателем: %v — форма, о которой "+
			"распознаватель не знает, выводит величину из-под наблюдения МОЛЧА: %s",
			direct.Findings, direct.Summary())
	}
	if direct.Read != 2 {
		t.Errorf("прямая цепочка сосчитана неверно: %s", direct.Summary())
	}
}

func TestJobKnobInjection_NamesakeFieldOfAnotherStructIsNotAReader(t *testing.T) {
	t.Parallel()

	c := injJudge(t, injReaderNamesakeField)
	if len(c.Findings) != 1 {
		t.Fatalf("одноимённое поле ЧУЖОЙ структуры засчитано читателем (%d находок): "+
			"тогда гейт зеленеет на любом дереве, где это слово встречается: %s",
			len(c.Findings), c.Summary())
	}
	if !strings.Contains(c.Findings[0], "Sweep.Grace") {
		t.Errorf("находка не та: %q", c.Findings[0])
	}
}

func TestJobKnobInjection_WholeSectionIsNamedNotForgiven(t *testing.T) {
	t.Parallel()

	c := injJudge(t, injReaderWholeSection)
	if len(c.Findings) != 0 {
		t.Fatalf("секция, переданная целиком, объявлена находкой: о её полях вердикта "+
			"нет, и выдавать отсутствие вердикта за находку нельзя: %v", c.Findings)
	}
	if len(c.WholeSection) != 1 || c.WholeSection[0] != "Sweep" {
		t.Fatalf("секция, переданная целиком, НЕ НАЗВАНА переписью (%v) — «поле "+
			"прочитано» и «секция уехала целиком» стали бы одним вердиктом: %s",
			c.WholeSection, c.Summary())
	}
	if !strings.Contains(c.Summary(), "Sweep") {
		t.Errorf("перепись молчит о секции, переданной целиком: %s", c.Summary())
	}
}

func TestJobKnobInjection_EmptyWalkIsRefusedByThePremise(t *testing.T) {
	t.Parallel()

	sections, err := check.JobSectionsIn("package config\n")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if len(sections) != 0 {
		t.Fatalf("секции найдены там, где их нет: %v", sections)
	}
	c := check.JudgeJobKnobReaders(nil, nil, nil, 0)
	if c.Fields != 0 || len(c.Findings) != 0 {
		t.Fatalf("пустой вход дал непустой вердикт: %s", c.Summary())
	}
	// Живой гейт на такой переписи зовёт Fatalf ДВАЖДЫ — по нулю секций и по нулю
	// разобранных файлов. Здесь проверена ПРЕДПОСЫЛКА отказа, а не его текст.
	t.Logf("пустой вход: %s — живой гейт на такой переписи ОТКАЗЫВАЕТ", c.Summary())
}
