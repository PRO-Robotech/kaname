// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package knownfailingexpiry — самоистечение записей прощения в
// `tests/newman/docs/RESULTS.md`.
//
// # Предмет
//
// Запись прощения объявляет набор (или кейс) красным, пока открыт названный ею
// дефект. Пока дефект открыт, запись говорит правду. После его закрытия она
// продолжает утверждать, что продукт сломан, — и утверждение это ДОЛГОВЕЧНОЕ:
// следующий читатель либо планирует работу вокруг дефекта, которого нет, либо
// принимает настоящее красное за «то самое известное».
//
// Класс не гипотетический (#2546): запись «набор `kaname-own-rest-front` красен
// целиком, пока не закрыт #2191» пережила закрытие #2191 и продолжала прощать
// набор, чья причина быть красным уже снята.
//
// # Два распознавателя, и их границы названы
//
//  1. ОБЪЯВЛЕНИЕ — маркер `<!-- known-failing: #N … -->`. Точен by construction:
//     запись объявляет себя сама, гадать не о чем.
//
//  2. ПОДСТРАХОВКА — проза, объявляющая живое условие («пока не закрыт #N») БЕЗ
//     маркера. Нужна затем, чтобы формат не оказался тем, о чём никто не знает:
//     без неё следующий автор напишет прощение прозой, и гейт промолчит.
//
// Граница подстраховки объявлена честно: она знает ОДИН оборот живого условия и
// ищет номер в пределах АБЗАЦА. Прощение, написанное иным оборотом, она не
// увидит — поэтому она подстраховка, а не замена объявлению. Расширять её надо
// переписью (сколько абзацев осмотрено), а не памятью: оборот «known failing»
// сюда НЕ взят намеренно — в этом документе он стоит в заголовках снятых записей
// («СНЯТО … was: known failing»), и подстраховка краснела бы на истории.
//
// # Решение отделено от измерения
//
// Состояние задачи — измерение СЕТЕВОЕ. Вердикт не вправе быть функцией
// доступности трекера, поэтому разбор и решение здесь — чистые функции, а сверка
// живёт в пробе за явной ручкой.
package knownfailingexpiry

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	// markerRe — объявленная запись прощения.
	markerRe = regexp.MustCompile(`<!--\s*known-failing:\s*#(\d+)([^>]*)-->`)
	// issueRe — номер задачи в любом обрамлении (в том числе в обратных кавычках).
	issueRe = regexp.MustCompile(`#(\d+)`)
)

// blockingPhrases — обороты, объявляющие условие ЖИВЫМ. Перечень намеренно узок:
// широкий ловил бы историю («СНЯТО … was: known failing»), а проверка, все находки
// которой ложны, перестаёт читаться и вместе с собой уносит настоящую.
var blockingPhrases = []string{
	"пока не закрыт",
	"пока не закрыта",
	"пока не закрыто",
	"пока не закрыты",
}

// Record — объявленная маркером запись прощения.
type Record struct {
	Line  int
	Issue int
	Note  string
}

// Undeclared — прощение прозой, себя не объявившее.
type Undeclared struct {
	Line  int
	Issue int
	Quote string
}

// Census — объём осмотренного. «Ноль находок» обязано быть отличимо от «ноль
// прочитанного», поэтому перепись — отдельное утверждение.
type Census struct {
	Lines      int
	Paragraphs int
	Records    []Record
	Undeclared []Undeclared
}

// Issues — номера объявленных записей, по одному разу и в порядке документа.
func (c Census) Issues() []int {
	seen := map[int]bool{}
	var out []int
	for _, r := range c.Records {
		if !seen[r.Issue] {
			seen[r.Issue] = true
			out = append(out, r.Issue)
		}
	}
	return out
}

// Parse читает документ. Разбор ЧИСТЫЙ: ни файловой системы, ни сети.
func Parse(doc string) Census {
	lines := strings.Split(doc, "\n")
	c := Census{Lines: len(lines)}

	for i, line := range lines {
		for _, m := range markerRe.FindAllStringSubmatch(line, -1) {
			n, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			c.Records = append(c.Records, Record{
				Line: i + 1, Issue: n, Note: strings.TrimSpace(m[2]),
			})
		}
	}

	declared := map[int]bool{}
	for _, r := range c.Records {
		declared[r.Issue] = true
	}

	// Подстраховка идёт по АБЗАЦАМ: номер живого условия часто стоит не на той
	// строке, где оборот. Абзац — блок между пустыми строками.
	start := 0
	flush := func(end int) {
		if end <= start {
			start = end + 1
			return
		}
		c.Paragraphs++
		block := strings.Join(lines[start:end], " ")
		lower := strings.ToLower(block)
		blocking := false
		for _, p := range blockingPhrases {
			if strings.Contains(lower, p) {
				blocking = true
				break
			}
		}
		if blocking {
			for _, m := range issueRe.FindAllStringSubmatch(block, -1) {
				n, err := strconv.Atoi(m[1])
				if err != nil || declared[n] {
					continue
				}
				c.Undeclared = append(c.Undeclared, Undeclared{
					Line: start + 1, Issue: n, Quote: strings.TrimSpace(block),
				})
			}
		}
		start = end + 1
	}
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			flush(i)
		}
	}
	flush(len(lines))
	return c
}

// ClosedUnderALiveRecord — РЕШЕНИЕ, отделённое от измерения: запись, чья задача
// закрыта, прощать больше нечего.
//
// Номер, которого в трекере нет вовсе, приходит сюда как CLOSED: запись,
// ссылающаяся в пустоту, не истечёт никогда и потому находка того же рода.
func ClosedUnderALiveRecord(c Census, states map[int]string) []string {
	var findings []string
	for _, r := range c.Records {
		state, known := states[r.Issue]
		if !known || !strings.EqualFold(state, "CLOSED") {
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"RESULTS.md:%d: запись прощения называет задачу #%d, а она ЗАКРЫТА — "+
				"прощать больше нечего, и запись продолжает утверждать, что продукт "+
				"сломан. Исходов три: набор зелен — снимите запись вместе с предметом; "+
				"набор красен по ДРУГОЙ причине — перепишите запись на неё, с новым "+
				"номером и предикатом; набор не исполняется — это «не выполнилось», и "+
				"пишется оно счётным долгом, а не строкой прощения",
			r.Line, r.Issue))
	}
	return findings
}

// UndeclaredForgiveness — прощение прозой без маркера.
func UndeclaredForgiveness(c Census) []string {
	var findings []string
	for _, u := range c.Undeclared {
		// Обрезка по РУНАМ, а не по байтам: корпус русский, и байтовый срез
		// рассекает букву — находка тогда сама печатает мусор.
		quote := u.Quote
		if r := []rune(quote); len(r) > 160 {
			quote = string(r[:160]) + "…"
		}
		findings = append(findings, fmt.Sprintf(
			"RESULTS.md:%d: абзац объявляет условие ЖИВЫМ и называет задачу #%d, но "+
				"записью прощения себя не объявляет. Маркер `<!-- known-failing: #%d -->` "+
				"обязателен: без него срок годности записи не проверяется ничем, и она "+
				"переживёт свой дефект молча. Абзац: «%s»",
			u.Line, u.Issue, u.Issue, quote))
	}
	return findings
}
