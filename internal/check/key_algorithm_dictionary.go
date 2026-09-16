// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// key_algorithm_dictionary.go — разбор словаря зарегистрированного алгоритма в
// СХЕМЕ.
//
// # Предмет
//
// Словарь алгоритмов ключа объявлен дважды: ограничением схемы и закрытым
// перечнем кода. Совпадение двух объявлений держится ГЕЙТОМ, а не совпадением
// формулировок: разойдясь, они дают либо строку, которую схема примет, а
// проверяющий не признает, либо алгоритм, который проверяющий считает
// допустимым, а вставить его нельзя.
//
// # Пустое значение — ЗАКОННЫЙ вход, и означает оно «ключа нет»
//
// Ограничение допускает пустую строку, и это не расхождение с кодом: пустое
// значение означает «ключа нет», а не «любой алгоритм». Клиент с пустым
// зарегистрированным алгоритмом аутентифицироваться утверждением не может — и
// это свойство держится проверкой на непустоту, а не словарём. Разбор поэтому
// выносит пустое значение отдельно, а не считает его алгоритмом.
//
// # Что здесь считается ДЕЙСТВУЮЩИМ объявлением
//
// Миграции применяются по порядку и не правятся (ban #5), поэтому действует
// ПОСЛЕДНЕЕ объявление ограничения с этим именем, а снятое `DROP CONSTRAINT` не
// действует вовсе. Разбор читает файлы в том же порядке, в котором их применяет
// накат.
//
// # Какие формы записи словаря разбор ЗНАЕТ
//
// Их две, и обе законны в этом дереве (предмет [dictionaryListOpensAt]):
//
//	key_algorithm IN ('', 'ES256', 'RS256', 'EdDSA')                       -- рука
//	key_algorithm = ANY (ARRAY[''::text, 'ES256'::text, 'RS256'::text])    -- снимок
//
// Вторую производит сведённый свод миграций: свод написан инструментом, и
// членство он записывает только так. Разбор, знавший одну форму, не краснел и
// не молчал, а ОСЛЕП: находил ноль объявлений и сообщал об этом словами
// «столбец не сужен ничем» — утверждение о СЕБЕ, сказанное о схеме.
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
//  1. **ограничение, наложенное функцией или триггером**, а не перечнем
//     значений. Форма другая, и предмет у неё другой.
//  2. **словарь, собранный из значений другой таблицы** (внешний ключ на
//     справочник): тогда объявления в тексте миграции нет вовсе, и сверять
//     нечего — счётчик найденных ограничений это покажет.
//  3. **значение, собранное выражением** — конкатенация, вызов функции.
//     Приведение типа на литерале в этот пункт НЕ входит: имя типа стоит за
//     кавычками, поэтому значением оно не становится.
//  4. **перечень ЗАПРЕЩЁННОГО** — не по слепоте, а по решению: гейт сверяет
//     словарь с перечнем ДОПУСТИМОГО кода, и засчитать дополнение множества
//     значило бы сравнить его с самим множеством.
//
// # Порт с монорепо — пара файлов названа, а не умолчана
//
// Перенесено с `PRO-Robotech/kacho:internal/repohygiene/keyalgorithmdictionary.go`
// (снято вынесением службы — `kacho#2598`; предмет жив здесь, задача #17).
// Изменилось: накат миграции подаёт ВЫЗЫВАЮЩИЙ (та же форма, что у соседа по
// пакету — `SQLCreateTableBody`), поэтому зависимости на пакет миграций у
// разбора нет; помощник чтения идентификатора переименован, чтобы не
// переобъявлять соседского. Осталось дословно: имя гейта, обе формы словаря и
// граница «пустое — не алгоритм».
//
// Близнеца в платформе нет: семейство снято там вместе со службой (ban #20).
package check

import (
	"sort"
	"strings"
)

// AlgorithmConstraint — объявление словаря алгоритма ограничением схемы.
type AlgorithmConstraint struct {
	File string
	Line int
	// Name — имя ограничения: им же оно снимается, и по нему разбор понимает,
	// какое объявление какое переобъявляет.
	Name string
	// Values — значения словаря в том виде, в каком они записаны, включая
	// пустое.
	Values []string
}

// AlgorithmDictionaryCensus — объём осмотренного.
type AlgorithmDictionaryCensus struct {
	// Files — файлов миграций прочитано.
	Files int
	// Statements — объявлений ограничения с этим столбцом найдено (включая
	// переобъявленные позднее).
	Statements int
	// Drops — снятий ограничения найдено.
	Drops int
}

// ScanKeyAlgorithmConstraints разбирает один файл миграции.
//
// column — имя столбца, чей словарь стережётся.
func ScanKeyAlgorithmConstraints(path, upSection, column string) (
	found []AlgorithmConstraint, dropped []string, census AlgorithmDictionaryCensus,
) {
	up := upSection
	lower := strings.ToLower(up)
	lowerColumn := strings.ToLower(column)

	for idx := 0; ; {
		rel := strings.Index(lower[idx:], lowerColumn)
		if rel < 0 {
			break
		}
		at := idx + rel
		after := at + len(lowerColumn)
		idx = after
		// Имя столбца берётся ЦЕЛИКОМ: `old_key_algorithm IN (…)` объявляет
		// словарь другого столбца, и засчитать его значило бы сверять с кодом
		// не тот предмет.
		if !sqlWholeWordAt(lower, at, len(lowerColumn)) {
			continue
		}
		open, ok := dictionaryListOpensAt(lower, after)
		if !ok {
			continue
		}
		values, end := sqlQuotedListAt(up, open)
		if end < 0 {
			continue
		}
		census.Statements++
		found = append(found, AlgorithmConstraint{
			File:   path,
			Line:   1 + strings.Count(up[:at], "\n"),
			Name:   sqlConstraintNameBefore(up, at),
			Values: values,
		})
		idx = end
	}

	for idx := 0; ; {
		rel := strings.Index(lower[idx:], "drop constraint")
		if rel < 0 {
			break
		}
		at := idx + rel + len("drop constraint")
		name := sqlIdentifierAtPos(up, at)
		if name != "" {
			census.Drops++
			dropped = append(dropped, name)
		}
		idx = at
	}
	return found, dropped, census
}

// dictionaryListOpensAt — стоит ли сразу за именем столбца объявление словаря, и
// где открывается его скобка.
//
// Форм ДВЕ, и обе законны в этом дереве:
//
//	key_algorithm IN ('', 'ES256', 'RS256', 'EdDSA')                       -- рука
//	key_algorithm = ANY (ARRAY[''::text, 'ES256'::text, 'RS256'::text])    -- pg_dump
//
// Вторая пришла со сводом миграций iam 2026-09-04: свод написан `pg_dump`, и
// членство он записывает только так. Разбор, знавший одну форму, объявлял словарь
// невыраженным — то есть говорил о СЕБЕ, а не о схеме, и говорил это словами
// «столбец не сужен ничем».
//
// Форма `<> ALL (ARRAY[…])` словарём НЕ является намеренно: она перечисляет
// запрещённое, а сверяется гейт с перечнем допустимого. Засчитав её, гейт сравнил
// бы дополнение множества с самим множеством.
func dictionaryListOpensAt(lower string, i int) (int, bool) {
	j := sqlSkipSpace(lower, i)
	switch {
	case strings.HasPrefix(lower[j:], "in"):
		if !sqlWholeWordAt(lower, j, len("in")) {
			return 0, false
		}
		j = sqlSkipSpace(lower, j+len("in"))
	case strings.HasPrefix(lower[j:], "="):
		j = sqlSkipSpace(lower, j+1)
		if !strings.HasPrefix(lower[j:], "any") || !sqlWholeWordAt(lower, j, len("any")) {
			return 0, false
		}
		j = sqlSkipSpace(lower, j+len("any"))
	default:
		return 0, false
	}
	if j >= len(lower) || lower[j] != '(' {
		return 0, false
	}
	return j, true
}

// sqlWholeWordAt — стоит ли в [i, i+n) слово ЦЕЛИКОМ, а не часть идентификатора.
func sqlWholeWordAt(s string, i, n int) bool {
	ident := func(c byte) bool {
		return c == '_' || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
	}
	if i > 0 && ident(s[i-1]) {
		return false
	}
	return i+n >= len(s) || !ident(s[i+n])
}

// sqlSkipSpace — позиция за пробельными символами.
func sqlSkipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}

// sqlQuotedListAt читает список строковых литералов из скобки, открытой в
// позиции open. Возвращает значения и позицию сразу за закрывающей скобкой.
//
// Приведение типа на литерале (`'ES256'::text`, форма `pg_dump`) значением не
// является и в список не попадает: разбор собирает только то, что стоит В
// КАВЫЧКАХ, а имя типа стоит за ними.
func sqlQuotedListAt(s string, open int) ([]string, int) {
	if open >= len(s) || s[open] != '(' {
		return nil, -1
	}
	var (
		values []string
		depth  int
	)
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return values, i + 1
			}
		case '\'':
			// Строковый литерал Postgres: удвоенная кавычка внутри означает саму
			// кавычку, а не конец литерала.
			var sb strings.Builder
			i++
			for i < len(s) {
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						sb.WriteByte('\'')
						i += 2
						continue
					}
					break
				}
				sb.WriteByte(s[i])
				i++
			}
			values = append(values, sb.String())
		}
	}
	return nil, -1
}

// sqlConstraintNameBefore — имя ближайшего слева объявления ограничения.
func sqlConstraintNameBefore(s string, at int) string {
	lower := strings.ToLower(s[:at])
	i := strings.LastIndex(lower, "constraint")
	if i < 0 {
		return ""
	}
	return sqlIdentifierAtPos(s, i+len("constraint"))
}

// sqlIdentifierAtPos — первый идентификатор начиная с позиции i.
func sqlIdentifierAtPos(s string, i int) string {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	start := i
	for i < len(s) && (s[i] == '_' || s[i] == '.' ||
		(s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') ||
		(s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	return s[start:i]
}

// SplitAlgorithmValues делит значения словаря на алгоритмы и пустое.
//
// Пустое выносится отдельно намеренно: оно означает «ключа нет», а не «любой
// алгоритм», и складывать его с алгоритмами значило бы объявить отсутствие
// ключа одним из них.
func SplitAlgorithmValues(values []string) (algorithms []string, hasEmpty bool) {
	seen := map[string]bool{}
	for _, v := range values {
		if v == "" {
			hasEmpty = true
			continue
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		algorithms = append(algorithms, v)
	}
	sort.Strings(algorithms)
	return algorithms, hasEmpty
}
