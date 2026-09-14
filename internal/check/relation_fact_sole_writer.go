// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// relation_fact_sole_writer.go — разбор «кто пишет в таблицу прямого факта».
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Таблица `kaname.relation_fact` — то, из чего реляционная форма собирает
// безусловное основание вердикта. Наполняет её ТРИГГЕР на журнале намерений
// (`kaname.fga_outbox`, `relation_fact_follows_journal`), и это выбор схемы, а
// не привычка: производителей кортежа много и они разной природы (use-case,
// реконсайлер, посев старта, сырой SQL миграции), поэтому писатель, добавленный
// в код, не покрывает SQL вовсе, а перечень «кто ещё обязан писать факт»
// расходится с деревом при первой же новой миграции — молча.
//
// Пока производитель ОДИН, появление нового происходит by construction: он
// кладёт строку журнала, и проекция подхватывает её, не зная о нём. Стоит
// завести второго писателя из кода — и инвариант ломается ровно в ту сторону,
// которую не видно: факт ЕСТЬ, и вердикт по нему выносится, а журнала за ним
// нет — то есть нет ни порядка применения, ни снятия, ни разбора оснований.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ УЗЕЛ РАЗБОРА, А НЕ ПОДСТРОКА ПО ТЕЛУ ФАЙЛА
//
// Перенесённая из монорепо форма читала ТЕЛО файла целиком и сверяла подстроку.
// В этом дереве так нельзя: имя таблицы стоит в КОММЕНТАРИЯХ десятка прод-файлов
// (`module_seed_writer.go`, `fga_outbox/emitter.go`, `authzmodel.go` и другие) —
// ровно там, где объясняют, что пишет её триггер, а не код. Подстрочный разбор
// дал бы находку на объяснении инварианта, то есть гейт краснел бы на
// собственном предмете.
//
// Поэтому запись ищется ТОЛЬКО в строковых литералах (узел ast.BasicLit вида
// token.STRING), а комментарии считаются ОТДЕЛЬНО и печатаются переписью: их
// ненулевое число — свидетельство, что разбор дошёл до мест, где о таблице
// говорят, и промолчал по существу, а не по слепоте.
//
// ─────────────────────────────────────────────────────────────────────────────
// ФОРМЫ ЗАПИСИ — ПЕРЕЧИСЛЕНЫ
//
// SQL в этом дереве пишется многострочными литералами с отступами, поэтому
// глагол и имя таблицы разделены произвольным пробелом, включая перевод строки.
// Совпадение ищется по образцу, терпимому к пробелу и регистру:
//
//	INSERT INTO kaname.relation_fact      одной строкой
//	insert into kaname.relation_fact      нижним регистром
//	INSERT INTO\n\t\tkaname.relation_fact переносом и отступом
//	DELETE FROM kaname.relation_fact      снятие
//	UPDATE kaname.relation_fact           правка
//
// Чтение (`SELECT`) законно и в перечень глаголов НЕ входит: форма его и делает.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦА НАЗВАНА, А НЕ УМОЛЧАНА
//
// Разбор НЕ видит: SQL миграций (там запись законна — миграция и есть схема),
// проб (им положено готовить состояние) и ДИНАМИЧЕСКИ СОБРАННОГО имени таблицы
// (склейка из кусков, fmt.Sprintf, константа из другого пакета). Последнее —
// настоящая слепая зона: имя, собранное из частей, не ловится образцом ничем, и
// молчание гейта на нём не является доказательством.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
)

// FactTable — таблица прямого факта.
const FactTable = "kaname.relation_fact"

// FactMutationVerbs — глаголы записи. SELECT сюда не входит намеренно.
var FactMutationVerbs = []string{"INSERT INTO", "UPDATE", "DELETE FROM"}

// FactWriteSite — координата записи в таблицу прямого факта.
type FactWriteSite struct {
	File string
	Line int
	Verb string
}

// FactScanCensus — объём осмотренного одним файлом.
type FactScanCensus struct {
	// Strings — строковых литералов прочитано.
	Strings int
	// Comments — узлов-комментариев прочитано.
	Comments int
	// TableInStrings — литералов, называющих таблицу.
	TableInStrings int
	// TableInComments — комментариев, называющих таблицу. Печатается переписью:
	// ненулевое число доказывает, что разбор дошёл до мест, где о таблице
	// говорят, и промолчал ПО СУЩЕСТВУ, а не по слепоте.
	TableInComments int
}

// factWritePattern — образец «глагол, пробел, имя таблицы», терпимый к
// переводу строки и регистру.
func factWritePattern(verb, table string) *regexp.Regexp {
	return regexp.MustCompile(`(?is)\b` + regexp.QuoteMeta(verb) + `\s+` + regexp.QuoteMeta(table) + `\b`)
}

// ScanFactWrites разбирает один файл и возвращает записи в таблицу прямого
// факта, найденные В СТРОКОВЫХ ЛИТЕРАЛАХ, вместе с объёмом осмотренного.
func ScanFactWrites(path string, src []byte, table string, verbs []string) ([]FactWriteSite, FactScanCensus, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, FactScanCensus{}, err
	}

	pats := make(map[string]*regexp.Regexp, len(verbs))
	for _, v := range verbs {
		pats[v] = factWritePattern(v, table)
	}

	var census FactScanCensus
	var out []FactWriteSite

	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		census.Strings++
		text := lit.Value
		if unq, uerr := strconv.Unquote(lit.Value); uerr == nil {
			text = unq
		}
		if !strings.Contains(strings.ToLower(text), strings.ToLower(table)) {
			return true
		}
		census.TableInStrings++
		for _, v := range verbs {
			if pats[v].MatchString(text) {
				out = append(out, FactWriteSite{
					File: path,
					Line: fset.Position(lit.Pos()).Line,
					Verb: v,
				})
			}
		}
		return true
	})

	// Комментарии — ОТДЕЛЬНЫМ проходом и только в перепись: упоминание таблицы
	// в объяснении записью не является.
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			census.Comments++
			if strings.Contains(strings.ToLower(c.Text), strings.ToLower(table)) {
				census.TableInComments++
			}
		}
	}
	return out, census, nil
}
