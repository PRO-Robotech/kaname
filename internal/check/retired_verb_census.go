// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_verb_census.go — ПЕРЕПИСЬ СЛЕДОВ СНЯТОГО ГЛАГОЛА ПО ИМЕНИ (kaname#929).
//
// ПРЕДМЕТ. Глагол, снятый с контракта, оставляет следы не только в контракте:
// проводка, запись каталога прав, манифест, политика вызывающих, документация.
// Компилятор ловит лишь те, что ссылались на порождённый тип; запись каталога,
// строка манифеста или абзац документа переживают снятие молча и продолжают
// утверждать о глаголе, которого нет. Приёмка `active-identity-has-a-way-in.md`
// (AWI-09) требует переписи по имени глагола без учёта регистра вне
// порождённого кода — 0 файлов, и контроля в обратную сторону: та же перепись по
// имени соседнего глагола печатает ненулевое число.
//
// ЕДИНИЦА — отслеживаемый файл дерева службы; перечень выводится обходом индекса
// git (`TrackedPathsOfTree`), а не выписывается.
//
// ИСКЛЮЧЕНИЙ ШЕСТЬ, перечень ЗАКРЫТ, у каждого признак, вычисляемый по пути либо
// содержимому (`retiredVerbExemption`):
//
//	И1 порождённое — строка `Code generated … DO NOT EDIT.`: адрес правки — его
//	   исходник, а исходник перепись судит сама;
//	И2 перечень объявленных разрывов `proto/declared-breaks.yaml` — разрыв
//	   объявляется символом снятого, иначе конвейер не простит его;
//	И3 журнал изменений `CHANGELOG.md` — интегратору снятие называется по имени;
//	И4 приёмки и записи их вердиктов (`docs/engineering/acceptance/`,
//	   `docs/specs/reviews/`) — текст под вердиктом по отпечатку, правка сняла бы
//	   одобрение; требование «глагола нет» называет глагол по построению;
//	И5 держатели наблюдаемого — проба поверхности внутреннего слушателя и файлы
//	   этой переписи: они зовут снятое имя, чтобы утверждать его отсутствие;
//	И6 окно копии края — `internal/check/catalog_copy_parity.go`: запись снятого
//	   службой глагола, который край ещё называет по пину, живёт до подъёма пина
//	   платформой и снимается самоистечением сверки копий.
//
// ПУСТОЙ ОБХОД — ОТКАЗ, а не успех; контроль соседним глаголом, давший ноль, —
// тоже отказ: перепись, не видящая и живого имени, о снятом не говорит ничего.
package check

import (
	"fmt"
	"sort"
	"strings"
)

// RetiredVerb — снятый глагол и соседний живой глагол той же службы, по имени
// которого перепись доказывает, что видит дерево.
type RetiredVerb struct {
	// Name — короткое имя снятого метода.
	Name string
	// Control — короткое имя живого соседнего метода; его перепись обязана дать
	// ненулевое число.
	Control string
	// Refs — где предмет ведётся.
	Refs string
}

// retiredVerbs — ЗАКРЫТЫЙ перечень глаголов, чьё отсутствие держит перепись.
var retiredVerbs = []RetiredVerb{
	{
		Name:    "UpsertFromIdentity",
		Control: "LookupSubject",
		Refs:    "PRO-Robotech/kaname#929 (AWI-09, active-identity-has-a-way-in.md)",
	},
}

// RetiredVerbs — объявленный перечень (копия: вызывающий его не правит).
func RetiredVerbs() []RetiredVerb {
	out := make([]RetiredVerb, len(retiredVerbs))
	copy(out, retiredVerbs)
	return out
}

// retiredVerbHolders — держатели наблюдаемого (И5): файлы, которые зовут снятое
// имя, чтобы утверждать его отсутствие.
var retiredVerbHolders = map[string]bool{
	"cmd/kaname/internal_user_service_surface_test.go":     true,
	"internal/check/retired_verb_census.go":                true,
	"internal/check/retired_verb_census_test.go":           true,
	"internal/check/retired_verb_census_injection_test.go": true,
}

// retiredVerbExemption — признак исключения либо "" (файл судится).
func retiredVerbExemption(path, content string) string {
	switch {
	case isGeneratedSource(content):
		return "И1"
	case path == "proto/declared-breaks.yaml":
		return "И2"
	case path == "CHANGELOG.md":
		return "И3"
	case strings.HasPrefix(path, "docs/engineering/acceptance/"),
		strings.HasPrefix(path, "docs/specs/reviews/"):
		return "И4"
	case retiredVerbHolders[path]:
		return "И5"
	case path == "internal/check/catalog_copy_parity.go":
		return "И6"
	}
	return ""
}

// isGeneratedSource — строка-маркер порождённого кода по соглашению Go
// (`^// Code generated .* DO NOT EDIT\.$`), а не подстрока где угодно.
func isGeneratedSource(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "// Code generated ") && strings.HasSuffix(line, " DO NOT EDIT.") {
			return true
		}
	}
	return false
}

// RetiredVerbCensus — исход переписи по одному глаголу.
type RetiredVerbCensus struct {
	Verb RetiredVerb
	// Read — сколько файлов прочитано.
	Read int
	// Exempted — сколько файлов, называющих глагол, снято исключением, по признаку.
	Exempted map[string]int
	// Findings — файлы, называющие снятый глагол вне исключений.
	Findings []string
	// ControlFiles — файлы, называющие живой соседний глагол (без исключений).
	ControlFiles int
}

// Refusal — почему перепись беспредметна, либо "".
func (c RetiredVerbCensus) Refusal() string {
	if c.Read == 0 {
		return "обход пуст: прочитано 0 файлов, и «следов ноль» означало бы «ничего не читали»"
	}
	if c.ControlFiles == 0 {
		return fmt.Sprintf("контроль молчит: живой глагол %q не найден ни в одном из %d файлов — "+
			"перепись не видит и живого имени, о снятом она не говорит ничего", c.Verb.Control, c.Read)
	}
	return ""
}

// String — печать переписи числами.
func (c RetiredVerbCensus) String() string {
	keys := make([]string, 0, len(c.Exempted))
	for k := range c.Exempted {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ex := make([]string, 0, len(keys))
	for _, k := range keys {
		ex = append(ex, fmt.Sprintf("%s %d", k, c.Exempted[k]))
	}
	return fmt.Sprintf("глагол %s: прочитано файлов %d · следов вне исключений %d · снято исключениями [%s] · "+
		"контроль %s: файлов %d", c.Verb.Name, c.Read, len(c.Findings), strings.Join(ex, ", "),
		c.Verb.Control, c.ControlFiles)
}

// JudgeRetiredVerb — перепись по имени без учёта регистра над картой «путь →
// содержимое». Ядро одно для живого дерева и для инъекции.
func JudgeRetiredVerb(files map[string]string, verb RetiredVerb) RetiredVerbCensus {
	c := RetiredVerbCensus{Verb: verb, Exempted: map[string]int{}}
	name := strings.ToLower(verb.Name)
	control := strings.ToLower(verb.Control)
	for path, content := range files {
		c.Read++
		low := strings.ToLower(content)
		if strings.Contains(low, control) {
			c.ControlFiles++
		}
		if !strings.Contains(low, name) {
			continue
		}
		if ex := retiredVerbExemption(path, content); ex != "" {
			c.Exempted[ex]++
			continue
		}
		c.Findings = append(c.Findings, path)
	}
	sort.Strings(c.Findings)
	return c
}
