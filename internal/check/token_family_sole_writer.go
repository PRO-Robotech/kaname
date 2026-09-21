// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_family_sole_writer.go — разбор «кто заводит семейство выданного»
// (задача PRO-Robotech/kaname#313).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ И ПОЧЕМУ ОН ГЕЙТ, А НЕ ВНИМАНИЕ
//
// Семейство нельзя заводить в сессию, которой больше нет. Держится это НЕ
// ключом: истечение сессии ключом невыразимо в принципе — производная колонка
// от `now()` движком отвергается, а обёрнутая замерзает на вставке и говорит
// «жива» об истёкшей строке. Поэтому условие живости стоит В САМОМ ОПЕРАТОРЕ
// вставки, вместе с записью.
//
// Цена такой границы названа честно: непредставимость держится ЭТИМ писателем,
// а не построением. Второй писатель — любая другая вставка в
// `kaname.token_families` — обойдёт условие молча: он скомпилируется, он
// пройдёт все пробы церемонии, и он заведёт живое семейство в снятой сессии.
//
// Границе, которая держится писателем, нужен ПРЕДИКАТ, а не внимание. Вот он.
//
// ─────────────────────────────────────────────────────────────────────────────
// СУДИТСЯ СТРОКОВЫЙ ЛИТЕРАЛ В РАЗОБРАННОМ ДЕРЕВЕ, А НЕ ТЕКСТ ФАЙЛА
//
// Разбор идёт по узлам: каждый непроверочный `.go` разбирается, и осматриваются
// только строковые литералы. Поиск по тексту файла считал бы находкой
// упоминание в комментарии — в том числе в этом.
//
// Классификация литерала, несущего вставку в таблицу семейств:
//
//	несёт условие живости сессии (`ended_at IS NULL` и `expires_at >`)  — ОХРАНЯЕМЫЙ
//	не несёт                                                            — НАХОДКА
//
// ─────────────────────────────────────────────────────────────────────────────
// ПУСТОЙ ОБХОД — ОТДЕЛЬНЫЙ ИСХОД
//
// Ноль охраняемых писателей означает не «чисто», а «гейт потерял предмет»:
// константу переименовали, оператор собрали из кусков, таблицу переназвали.
// Такой обход обязан быть КРАСНЫМ, иначе гейт зеленеет ровно тогда, когда
// перестаёт смотреть.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦА НАЗВАНА
//
// Оператор, собранный конкатенацией или `fmt.Sprintf` из частей, разбор по
// литералу не видит — это довод держать оператор ОДНОЙ константой, каким он и
// написан. Вставка, пришедшая из внешнего файла или сгенерированная, тоже
// невидима; в дереве таких путей к этой таблице нет.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// TokenFamilyWriterKind — род найденного писателя.
type TokenFamilyWriterKind string

const (
	// TokenFamilyWriterGuarded — вставка несёт условие живости сессии.
	TokenFamilyWriterGuarded TokenFamilyWriterKind = "охраняемый"
	// TokenFamilyWriterBare — вставка без условия живости: второй писатель.
	TokenFamilyWriterBare TokenFamilyWriterKind = "без условия живости"
)

// TokenFamilyWriter — найденный писатель с координатой.
type TokenFamilyWriter struct {
	Kind TokenFamilyWriterKind
	File string
	Line int
}

// TokenFamilyCensus — перепись обхода. Объём осмотренного печатается, потому
// что «находок ноль» без него неотличимо от «не смотрели».
type TokenFamilyCensus struct {
	FilesParsed  int
	LiteralsSeen int
	Writers      []TokenFamilyWriter
	GuardedCount int
	BareCount    int
}

// familyTableMarkers — признаки вставки в таблицу семейств. Имя таблицы
// принимается и со схемой, и без неё: `search_path` у части операторов дерева
// уже кладёт `kaname` первым.
var familyTableMarkers = []string{
	"kaname.token_families",
	" token_families",
}

// livenessMarkers — признаки условия живости сессии в том же операторе.
// Требуются ОБА: одна отметка снятия без срока оставляла бы истечение
// неотсечённым, а срок без отметки — снятие.
var livenessMarkers = []string{
	"ended_at IS NULL",
	"expires_at >",
}

// carriesFamilyInsert — несёт ли литерал вставку в таблицу семейств.
func carriesFamilyInsert(lit string) bool {
	up := strings.ToUpper(lit)
	if !strings.Contains(up, "INSERT INTO") {
		return false
	}
	for _, m := range familyTableMarkers {
		if strings.Contains(lit, m) {
			return true
		}
	}
	return false
}

// carriesLivenessCondition — несёт ли литерал условие живости сессии целиком.
func carriesLivenessCondition(lit string) bool {
	for _, m := range livenessMarkers {
		if !strings.Contains(lit, m) {
			return false
		}
	}
	return true
}

// TokenFamilyWriters разбирает названные файлы и переписывает писателей.
//
// Файлы подаются вызывающим уже отфильтрованными от проверочных: проба —
// законный писатель этой таблицы, и судить её этим гейтом значило бы запретить
// пробам строить сцену.
func TokenFamilyWriters(files map[string]string) (TokenFamilyCensus, error) {
	var out TokenFamilyCensus
	fset := token.NewFileSet()

	for name, src := range files {
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			return out, fmt.Errorf("разбор %s: %w", name, err)
		}
		out.FilesParsed++

		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			out.LiteralsSeen++

			// Значение литерала берётся с разбором кавычек: сырые строки в
			// обратных кавычках несут оператор как есть.
			text := lit.Value
			if len(text) >= 2 {
				text = text[1 : len(text)-1]
			}
			if !carriesFamilyInsert(text) {
				return true
			}

			kind := TokenFamilyWriterBare
			if carriesLivenessCondition(text) {
				kind = TokenFamilyWriterGuarded
			}
			pos := fset.Position(lit.Pos())
			out.Writers = append(out.Writers, TokenFamilyWriter{
				Kind: kind, File: name, Line: pos.Line,
			})
			if kind == TokenFamilyWriterGuarded {
				out.GuardedCount++
			} else {
				out.BareCount++
			}
			return true
		})
	}
	return out, nil
}
