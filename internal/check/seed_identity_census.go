// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// seed_identity_census.go — разбор ДВУХ текстов об одном предмете: вывода
// переписи посевной идентичности и чисел, объявленных приёмкой
// `docs/engineering/acceptance/seed-identity-names-its-own-service.md` §0.
//
// # ПРЕДМЕТ
//
// У приёмки есть исполняемый предикат, лежащий рядом с ней
// (`seed-identity-names-its-own-service.py`), и числа §0 — его вывод. Пока
// предиката никто не зовёт, эти два текста расходятся МОЛЧА: документ
// продолжает называть числа, верные для ревизии, которой в стволе уже нет, и
// отличить «перемерено» от «переписано по памяти» нечем.
//
// # ПРИЗНАК — ИЗМЕРЕН, А НЕ ПРЕДПОЛОЖЕН
//
// Расхождение наступило до заведения этого гейта и было найдено вручную:
// объявление называло по ведру ПРЕДМЕТА `130 · 54 ф.`, предикат на стволе давал
// `130 · 56 ф.`. Вхождений СТОЛЬКО ЖЕ — двигались файлы, — поэтому расхождение
// не видно ни по одному числу в отдельности и обнаруживается только сверкой
// обоих текстов целиком.
//
// # ЕДИНСТВЕННЫЙ ИСТОЧНИК ПЕРЕЧНЯ ВЁДЕР — САМ ПРЕДИКАТ
//
// Перечень вёдер здесь НЕ выписан. Он берётся из того, что предикат напечатал:
// выписанный был бы вторым местом об одном предмете и разошёлся бы с предикатом
// ровно тогда, когда тот заведёт новое ведро, — то есть остался бы зелёным на
// ведре, о котором никто не спросил.
//
// # ЧЕГО ЭТОТ РАЗБОР НЕ СУДИТ
//
//   - ИСТИННОСТЬ вёдер. Правильно ли предикат раскладывает вхождение по вёдрам —
//     вопрос его собственной адъюдикации, и машинного предиката у него нет;
//   - ПРОЗУ §0. Числа, названные прозой в тексте, здесь не ищутся: их формы
//     столько же, сколько предложений, и разбор по образцу нашёл бы собственное
//     объяснение. Судится ОБЪЯВЛЕНИЕ — блок, названный ревизией измерения.
package check

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// SeedCensusCell — одна клетка переписи: вхождений и файлов.
type SeedCensusCell struct {
	Hits  int
	Files int
}

func (c SeedCensusCell) String() string { return fmt.Sprintf("%d · %d ф.", c.Hits, c.Files) }

// SeedCensusReport — то, что напечатал предикат.
type SeedCensusReport struct {
	Revision string
	Indexed  int
	Read     int
	Binary   int
	Buckets  map[string]SeedCensusCell
	Order    []string
}

// SeedCensusDeclaration — то, что объявила приёмка.
type SeedCensusDeclaration struct {
	// Revision — ревизия измерения, названная ОДНОЙ строкой документа.
	Revision string
	// Buckets — объявленные величины, по ведру.
	Buckets map[string]SeedCensusCell
	// BlockLines — сколько строк объявляющего блока прочитано (перепись:
	// «ноль находок» обязано быть отличимо от «ноль прочитанного»).
	BlockLines int
}

var (
	// cellPattern — клетка переписи в любом из двух текстов.
	cellPattern = regexp.MustCompile(`(\d+)\s*·\s*(\d+)\s*ф\.`)
	// scanPattern — строка объёма осмотренного в выводе предиката.
	scanPattern = regexp.MustCompile(`осмотрено:\s*в индексе\s+(\d+)\s*·\s*прочитано\s+(\d+)\s*·\s*двоичных\s+(\d+)`)
	// revPattern — хеш ревизии в обратных кавычках.
	revPattern = regexp.MustCompile("`([0-9a-f]{7,40})`")
	// bucketLinePattern — «<имя ведра> <число> · <число> ф.» в выводе предиката.
	bucketLinePattern = regexp.MustCompile(`^(\S.*?)\s{2,}(\d+)\s*·\s*(\d+)\s*ф\.\s*$`)
)

// ParseSeedCensusOutput разбирает вывод предиката.
//
// Отказ — не пустой отчёт: предикат, не напечатавший ни объёма осмотренного, ни
// одного ведра, о дереве не сказал ничего, и выдавать это за ноль находок
// нельзя.
func ParseSeedCensusOutput(out string) (SeedCensusReport, error) {
	rep := SeedCensusReport{Buckets: map[string]SeedCensusCell{}}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, " \t\r")
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "ревизия:"); ok {
			rep.Revision = strings.TrimSpace(rest)
			continue
		}
		if m := scanPattern.FindStringSubmatch(line); m != nil {
			rep.Indexed, _ = strconv.Atoi(m[1])
			rep.Read, _ = strconv.Atoi(m[2])
			rep.Binary, _ = strconv.Atoi(m[3])
			continue
		}
		if m := bucketLinePattern.FindStringSubmatch(line); m != nil {
			name := strings.TrimSpace(m[1])
			hits, _ := strconv.Atoi(m[2])
			files, _ := strconv.Atoi(m[3])
			if _, seen := rep.Buckets[name]; !seen {
				rep.Order = append(rep.Order, name)
			}
			rep.Buckets[name] = SeedCensusCell{Hits: hits, Files: files}
		}
	}
	if rep.Read == 0 {
		return rep, fmt.Errorf("предикат не назвал объёма осмотренного: прочитано 0 — " +
			"вердикт беспредметен")
	}
	if len(rep.Buckets) == 0 {
		return rep, fmt.Errorf("предикат не напечатал ни одного ведра — сверять нечего")
	}
	return rep, nil
}

// ParseSeedCensusDeclaration читает объявление приёмки.
//
// Блок ищется ПО РЕВИЗИИ, а не по порядку: в документе живёт и второй блок тех
// же вёдер — замер в монорепо, объявленный историческим свидетельством. Разбор
// «первый попавшийся блок» сверял бы величины ЧУЖОГО дерева и был бы при этом
// зелёным ровно до тех пор, пока кто-нибудь не тронет здешние числа.
//
// Внутри строки берётся ПОСЛЕДНЯЯ клетка: столбцов у блока два — монорепо и
// это дерево, — и здешний стоит правым.
func ParseSeedCensusDeclaration(doc string, buckets []string) SeedCensusDeclaration {
	decl := SeedCensusDeclaration{Buckets: map[string]SeedCensusCell{}}

	lines := strings.Split(doc, "\n")
	for _, line := range lines {
		if !strings.Contains(line, "Ревизия измерения") {
			continue
		}
		if m := revPattern.FindStringSubmatch(line); m != nil {
			decl.Revision = m[1]
		}
		break
	}
	if decl.Revision == "" {
		return decl
	}

	// Имена вёдер — от длинного к короткому: «ПРЕДМЕТ» есть приставка
	// «ПРЕДМЕТ: манифесты», и короткое, примеренное первым, съело бы длинное.
	names := append([]string(nil), buckets...)
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })

	inBlock, blockLines, matched := false, []string(nil), false
	for _, raw := range lines {
		line := strings.TrimPrefix(strings.TrimSpace(raw), "> ")
		line = strings.TrimPrefix(line, ">")
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			if inBlock {
				if matched {
					break // блок с объявленной ревизией прочитан целиком
				}
				blockLines, matched = nil, false
			}
			inBlock = !inBlock
			continue
		}
		if !inBlock {
			continue
		}
		blockLines = append(blockLines, line)
		if strings.Contains(line, decl.Revision) {
			matched = true
		}
	}
	if !matched {
		return decl
	}
	decl.BlockLines = len(blockLines)
	for _, line := range blockLines {
		trimmed := strings.TrimSpace(line)
		for _, name := range names {
			if !strings.HasPrefix(trimmed, name) {
				continue
			}
			cells := cellPattern.FindAllStringSubmatch(trimmed, -1)
			if len(cells) == 0 {
				break
			}
			last := cells[len(cells)-1]
			hits, _ := strconv.Atoi(last[1])
			files, _ := strconv.Atoi(last[2])
			decl.Buckets[name] = SeedCensusCell{Hits: hits, Files: files}
			break
		}
	}
	return decl
}

// AdjudicateSeedCensus сверяет объявленное с произведённым ПО КАЖДОМУ ведру
// предиката. Ведро, которое предикат напечатал, а объявление не называет, —
// находка: иначе новое ведро уехало бы из-под наблюдения молча.
func AdjudicateSeedCensus(decl SeedCensusDeclaration, rep SeedCensusReport) []string {
	var findings []string
	for _, name := range rep.Order {
		produced := rep.Buckets[name]
		declared, named := decl.Buckets[name]
		switch {
		case !named:
			findings = append(findings, fmt.Sprintf(
				"ведро %q предикат печатает (%s), а объявление §0 его не называет", name, produced))
		case declared != produced:
			findings = append(findings, fmt.Sprintf(
				"ведро %q: объявлено %s, предикат даёт %s", name, declared, produced))
		}
	}
	return findings
}
