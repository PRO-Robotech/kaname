// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// assurance_method_vocabulary.go — разбор «где ещё объявлен перечень имён
// способов предъявления» (приёмка Ф11, Р8; гейт §8 «словарь один»).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Словарь способов — password · totp · lookup_secret · webauthn · recovery_code
// — объявлен ОДИН раз, в `internal/assurance`, вместе с правилом вывода уровня.
// Всякий, кому нужен перечень, читает `assurance.Methods()`. Второе объявление
// перечня в прод-коде службы расходится с первым молча: способ, заведённый в
// одном и не заведённый в другом, доезжает до сессии безуровневым либо
// отвергается хранилищем, которое правило о нём не спрашивало.
//
// ─────────────────────────────────────────────────────────────────────────────
// СУДИТСЯ ОБЪЯВЛЕНИЕ ПЕРЕЧНЯ, А НЕ СЛОВО
//
// Строковый литерал, совпадающий с именем способа, находкой НЕ является: он
// бывает именем поля запроса, областью токена (`"webauthn"` в области
// удостоверения и в условии модели прав), меткой в перечне секретов. Перечнем
// считается УЗЕЛ разбора, несущий два и более РАЗЛИЧНЫХ имени словаря
// строковыми литералами (ast.BasicLit вида token.STRING). Комментарии в счёт
// не идут by construction: разбор ходит по узлам, а не по тексту.
//
// ─────────────────────────────────────────────────────────────────────────────
// ФОРМЫ ЗАПИСИ ПЕРЕЧНЯ — ПЕРЕЧИСЛЕНЫ
//
//	[]string{"password", "totp"}                  составной литерал (среза, карты,
//	                                              структур — литералы собираются
//	                                              по всему поддереву литерала)
//	const ( a = "password"; b = "totp" )          группа const/var, включая
//	var ( p = kind{"password"}; t = kind{"totp"} ) локальную в теле функции и
//	                                              форму дома — структуры со
//	                                              строкой внутри
//	case "password", "recovery_code":             перечень ветви case
//
// Форма, о которой разбор не знает, даёт не красное и не зелёное, а молчание;
// поэтому каждая из названных доказана инъекцией
// (assurance_method_vocabulary_injection_test.go).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЛОВИНА ПО СХЕМЕ
//
// Ограничение схемы, перечисляющее значения столбца (`IN (…)` либо
// `= ANY (ARRAY[…])`), среди которых есть имя словаря, обязано быть его
// ПОДМНОЖЕСТВОМ. Перечень без единого имени словаря — не предмет: состояния,
// алгоритмы, виды удостоверений у него свои. Чего разбор не видит — те же три
// границы, что у соседа по пакету (`key_algorithm_dictionary.go`): ограничение
// функцией или триггером, словарь из справочной таблицы, значение выражением.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"strings"
)

const (
	// AssuranceHomeImport — путь пакета, где словарь и правило объявлены.
	AssuranceHomeImport = "github.com/PRO-Robotech/kaname/internal/assurance"
	// AssuranceHomeRel — его каталог от корня модуля.
	AssuranceHomeRel = "internal/assurance"
)

// VocabularyListSite — объявление перечня имён способов в Go-коде.
type VocabularyListSite struct {
	File string
	Line int
	// Form — форма объявления (составной литерал · группа const/var · case).
	Form string
	// Names — имена словаря, найденные в узле, без повторов.
	Names []string
}

func (s VocabularyListSite) String() string {
	return fmt.Sprintf("%s:%d %s: %s", s.File, s.Line, s.Form, strings.Join(s.Names, ", "))
}

// VocabularyScanCensus — объём осмотренного.
type VocabularyScanCensus struct {
	// Files — файлов прочитано (заполняет вызывающий).
	Files int
	// Strings — строковых литералов прочитано.
	Strings int
	// VocabularyStrings — литералов, совпавших с именем словаря (в любом узле).
	VocabularyStrings int
	// Lists — объявлений перечня найдено.
	Lists int
}

// ScanMethodVocabularyLists разбирает один Go-файл и возвращает узлы, несущие
// два и более различных имени словаря строковыми литералами.
func ScanMethodVocabularyLists(path string, src []byte, vocabulary []string) ([]VocabularyListSite, VocabularyScanCensus, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, VocabularyScanCensus{}, err
	}
	vocab := map[string]bool{}
	for _, v := range vocabulary {
		vocab[v] = true
	}

	var (
		census VocabularyScanCensus
		sites  []VocabularyListSite
	)

	// Перепись литералов — по ВСЕМУ файлу, независимо от того, вошли ли они в
	// перечень: «слов словаря прочитано N» доказывает, что разбор дошёл до
	// одиночных литералов и промолчал по существу, а не по слепоте.
	ast.Inspect(f, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			census.Strings++
			if v, err := strconv.Unquote(lit.Value); err == nil && vocab[v] {
				census.VocabularyStrings++
			}
		}
		return true
	})

	namesIn := func(n ast.Node) []string {
		seen := map[string]bool{}
		ast.Inspect(n, func(m ast.Node) bool {
			if lit, ok := m.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if v, err := strconv.Unquote(lit.Value); err == nil && vocab[v] {
					seen[v] = true
				}
			}
			return true
		})
		out := make([]string, 0, len(seen))
		for v := range seen {
			out = append(out, v)
		}
		sort.Strings(out)
		return out
	}
	record := func(n ast.Node, form string) bool {
		names := namesIn(n)
		if len(names) < 2 {
			return false
		}
		census.Lists++
		sites = append(sites, VocabularyListSite{
			File:  path,
			Line:  fset.Position(n.Pos()).Line,
			Form:  form,
			Names: names,
		})
		return true
	}

	// Узел, признанный перечнем, дальше не обходится: вложенный литерал внутри
	// группы var дал бы ту же находку дважды.
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.GenDecl:
			if x.Tok != token.CONST && x.Tok != token.VAR {
				return true
			}
			return !record(x, "группа "+x.Tok.String())
		case *ast.CompositeLit:
			return !record(x, "составной литерал")
		case *ast.CaseClause:
			seen := map[string]bool{}
			for _, e := range x.List {
				if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, err := strconv.Unquote(lit.Value); err == nil && vocab[v] {
						seen[v] = true
					}
				}
			}
			if len(seen) >= 2 {
				names := make([]string, 0, len(seen))
				for v := range seen {
					names = append(names, v)
				}
				sort.Strings(names)
				census.Lists++
				sites = append(sites, VocabularyListSite{
					File: path, Line: fset.Position(x.Pos()).Line, Form: "перечень ветви case", Names: names,
				})
			}
			return true
		}
		return true
	})
	return sites, census, nil
}

// SchemaValueListSite — ограничение схемы, перечисляющее значения столбца,
// среди которых есть имя словаря.
type SchemaValueListSite struct {
	File string
	Line int
	// Constraint — имя ограничения, если объявлено.
	Constraint string
	// Values — значения перечня как записаны.
	Values []string
}

func (s SchemaValueListSite) String() string {
	name := s.Constraint
	if name == "" {
		name = "(безымянное ограничение)"
	}
	return fmt.Sprintf("%s:%d %s: %s", s.File, s.Line, name, strings.Join(s.Values, ", "))
}

// ScanSchemaValueLists — перечни значений в накате миграции (`IN (…)`,
// `= ANY (ARRAY[…])`), пересекающиеся со словарём.
//
// Разбор читает накат с ЗАБЕЛЁННЫМИ комментариями — забеливает вызывающий тем
// же средством, что у соседей по пакету (`migrations.MigrationUpSection`).
func ScanSchemaValueLists(path, upSection string, vocabulary []string) []SchemaValueListSite {
	vocab := map[string]bool{}
	for _, v := range vocabulary {
		vocab[v] = true
	}
	lower := strings.ToLower(upSection)
	var out []SchemaValueListSite
	for idx := 0; idx < len(lower); {
		open, next, ok := nextValueListOpen(lower, idx)
		if !ok {
			break
		}
		idx = next
		values, end := sqlQuotedListAt(upSection, open)
		if end < 0 || len(values) == 0 {
			continue
		}
		touches := false
		for _, v := range values {
			if vocab[v] {
				touches = true
				break
			}
		}
		if !touches {
			continue
		}
		out = append(out, SchemaValueListSite{
			File:       path,
			Line:       1 + strings.Count(upSection[:open], "\n"),
			Constraint: sqlConstraintNameBefore(upSection, open),
			Values:     values,
		})
		idx = end
	}
	return out
}

// nextValueListOpen — позиция скобки следующего перечня значений начиная с from:
// `in (` целым словом либо `= any (`. Возвращает позицию скобки и позицию,
// с которой искать дальше.
func nextValueListOpen(lower string, from int) (open, next int, ok bool) {
	for i := from; i < len(lower); i++ {
		if strings.HasPrefix(lower[i:], "in") && sqlWholeWordAt(lower, i, 2) {
			j := sqlSkipSpace(lower, i+2)
			if j < len(lower) && lower[j] == '(' {
				return j, j + 1, true
			}
			continue
		}
		if lower[i] == '=' {
			j := sqlSkipSpace(lower, i+1)
			if strings.HasPrefix(lower[j:], "any") && sqlWholeWordAt(lower, j, 3) {
				k := sqlSkipSpace(lower, j+3)
				if k < len(lower) && lower[k] == '(' {
					return k, k + 1, true
				}
			}
		}
	}
	return 0, len(lower), false
}
