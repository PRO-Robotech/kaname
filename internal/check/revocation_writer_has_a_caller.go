// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// revocation_writer_has_a_caller.go — ПУТЬ СНЯТИЯ ДОСТУПА, НЕ ДОСТИГАЮЩИЙ
// НОСИТЕЛЯ, КОТОРЫМ СУДИТ ЧИТАТЕЛЬ (задача kaname#313).
//
// ─────────────────────────────────────────────────────────────────────────────
// ФОРМА ДЕФЕКТА, А НЕ ЕГО ЭКЗЕМПЛЯР
//
// Записей отсечки в службе больше одной. У каждой свой ключ, свой круг
// читателей и своя величина сравнения, и взаимозаменяемыми они не являются.
// Отсюда форма: запись ОБЪЯВЛЕНА, писатель для неё НАПИСАН, а позвать его
// некому — и тогда контроль существует в виде кода, не исполняясь ни при каком
// входе. Отличить это от работающего контроля чтением нельзя: «не отозван» и
// «отзыв не доехал» дают один и тот же наблюдаемый ответ.
//
// Гейт судит ДЕРЕВО, а не ведомость записей: ведомость ослепла бы ровно тогда,
// когда опустеет, а множество таблиц отсечки ВЫВОДИТСЯ обходом — по имени,
// оканчивающемуся на суффикс отсечки, — и печатается переписью.
//
// ─────────────────────────────────────────────────────────────────────────────
// НАПРАВЛЕНИЕ ОШИБКИ ВЫБРАНО, А НЕ ПОЛУЧИЛОСЬ
//
// Вызов опознаётся ПО ИМЕНИ функции или метода где угодно в не-тестовом дереве.
// Это заведомо ЩЕДРО к писателю: вызов через интерфейс с тем же именем метода
// засчитывается, хотя разбор не доказывает, что реализация именно эта. Выбрано
// так намеренно: ложная находка у гейта, судящего безопасность, заставляет
// снимать сам гейт, а пропуск оставляет предмет видимым другим приборам.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО РАЗБОР НЕ ВИДИТ — НАЗВАНО, А НЕ СПРЯТАНО
//
//  1. писатель, чей единственный вызывающий — тоже мёртвый код: цепочку
//     достижимости от композиционного корня разбор не строит;
//
//  2. писатель на SQL, собранном из кусков во время исполнения: разбор читает
//     строковый ЛИТЕРАЛ, а не результат конкатенации;
//
//  3. писатель в схеме (триггер, функция) — он не Go и здесь не судится;
//     именно такие писатели и создают вид работающего контроля;
//
//  4. ПИСАТЕЛЬ ОДНОЙ ЗАПИСИ ОТСЕЧКИ ИЗ ДВУХ — у него исполнитель ЕСТЬ, и этот
//     гейт о нём молчит законно. Свойство независимое, и судит его отдельный
//     гейт `TestSubjectCutoffWritersWriteBothRecords` в этом же пакете.
//
//     Перечень границ, названный не полностью, хуже отсутствующего: он создаёт
//     уверенность. Эта граница названа здесь потому, что именно её отсутствие
//     позволило дефекту уцелеть — гейт был зелён, а четыре писателя полосы
//     входа клали одну запись из двух.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strings"
)

// RevocationWriter — функция либо метод, пишущий в запись отсечки.
type RevocationWriter struct {
	File  string
	Line  int
	Name  string
	Table string
	// Tables — ВСЕ записи отсечки, которых касается тело, а не только первая.
	// Множество, а не одна: предмет соседнего гейта — писатель ОДНОЙ записи из
	// двух, и увидеть его можно только по множеству.
	Tables []string
	// Calls — имена, вызванные телом. Нужны, чтобы достроить множество таблиц
	// ЧЕРЕЗ ВЫЗОВ: дверь, кладущая вторую запись вызовом помощника, пишет её
	// ровно так же, как назвавшая оператор, и разбор, видящий только литерал,
	// объявил бы её писателем одной записи (ложная находка, измерена).
	Calls []string
	// Why — почему писатель стал находкой. Находка обязана называть ПРИЧИНУ, а
	// не только координату: «его не зовут» и «по имени не разобрать, зовут ли»
	// требуют разного, и слитые в одно они читаются одинаково.
	Why string
}

// RevocationWriterCensus — объём осмотренного.
type RevocationWriterCensus struct {
	// Funcs — функций с телом осмотрено.
	Funcs int
	// Writers — писателей найдено.
	Writers int
	// Tables — таблицы отсечки, выведенные обходом.
	Tables map[string]struct{}
	// Statements — объявлений операторов записи, вынесенных из тела, осмотрено.
	// Печатается отдельно: «форм записи известно две» обязано быть видно, иначе
	// сужение разбора до одной формы прошло бы молча.
	Statements int
}

// revocationTableRe — ЗАПИСЬ в таблицу, чьё имя оканчивается суффиксом отсечки.
//
// Суффикс, а не перечень имён: перечень — та же ведомость, которая ослепнет,
// когда в дерево придёт запись с новым именем.
var revocationTableRe = regexp.MustCompile(
	`(?is)\b(?:INSERT\s+INTO|UPDATE)\s+(?:kaname\.)?([a-z_]*_revocations)\b`)

// ScanRevocationStatements собирает ОБЪЯВЛЕНИЯ операторов записи, вынесенные из
// тела, — имя константы либо переменной → таблица.
//
// ФОРМА ЭТА НЕ РЕДКОСТЬ, А НОРМА ЭТОГО ДЕРЕВА: оператор выносят ровно затем,
// чтобы исполнителей у него стало двое (пул и транзакция), и не иметь двух
// копий. Разбор, знающий только литерал В ТЕЛЕ, не видел бы именно тех
// писателей, которых делят между собой две полосы, — и «находок ноль» у него
// означало бы «эту форму я не читаю».
//
// Объявление живёт в любом файле ПАКЕТА, поэтому обход идёт в два прохода:
// сперва объявления по всему дереву, затем писатели.
func ScanRevocationStatements(path string, src []byte, into map[string]string) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return err
	}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, val := range vs.Values {
				lit, ok := val.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING || i >= len(vs.Names) {
					continue
				}
				if m := revocationTableRe.FindStringSubmatch(lit.Value); m != nil {
					into[vs.Names[i].Name] = m[1]
				}
			}
		}
	}
	return nil
}

// ScanRevocationWriters разбирает ОДИН файл.
//
// statements — объявления операторов, собранные первым проходом: функция,
// назвавшая такое объявление, есть писатель ровно так же, как назвавшая литерал.
func ScanRevocationWriters(path string, src []byte, statements map[string]string) (
	[]RevocationWriter, RevocationWriterCensus, error,
) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, RevocationWriterCensus{}, err
	}
	census := RevocationWriterCensus{Tables: map[string]struct{}{}}
	var out []RevocationWriter

	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		census.Funcs++
		table := ""
		touched := map[string]struct{}{}
		calls := map[string]struct{}{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.BasicLit:
				if node.Kind != token.STRING {
					return true
				}
				m := revocationTableRe.FindStringSubmatch(node.Value)
				if m == nil {
					return true
				}
				census.Tables[m[1]] = struct{}{}
				touched[m[1]] = struct{}{}
				if table == "" {
					table = m[1]
				}
			case *ast.CallExpr:
				switch fun := node.Fun.(type) {
				case *ast.Ident:
					calls[fun.Name] = struct{}{}
				case *ast.SelectorExpr:
					calls[fun.Sel.Name] = struct{}{}
				}
				return true
			case *ast.Ident:
				tbl, ok := statements[node.Name]
				if !ok {
					return true
				}
				census.Tables[tbl] = struct{}{}
				touched[tbl] = struct{}{}
				if table == "" {
					table = tbl
				}
			}
			return true
		})
		if table == "" {
			continue
		}
		census.Writers++
		out = append(out, RevocationWriter{
			File: path, Line: fset.Position(fn.Pos()).Line,
			Name: fn.Name.Name, Table: table, Tables: sortedTableSet(touched),
			Calls: sortedTableSet(calls),
		})
	}
	return out, census, nil
}

// CollectDeclaredNames собирает имена ОБЪЯВЛЕННЫХ функций и методов файла.
//
// Нужны они затем, чтобы отличить «писателя не зовут» от «по имени не
// разобрать»: имя, объявленное в дереве не один раз, вызовом по имени не
// прослеживается, и молчание гейта на нём означало бы «я не смотрел».
func CollectDeclaredNames(path string, src []byte, into map[string]int) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return err
	}
	_ = fset
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			into[fn.Name.Name]++
		}
	}
	return nil
}

// CollectCalledNames собирает имена, вызванные в ОДНОМ файле, — и функции, и
// методы (по последнему сегменту селектора).
func CollectCalledNames(path string, src []byte, into map[string]struct{}) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return err
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			into[fun.Name] = struct{}{}
		case *ast.SelectorExpr:
			into[fun.Sel.Name] = struct{}{}
		}
		return true
	})
	return nil
}

// RevocationWritersWithoutACaller — писатели, про которых НЕЛЬЗЯ СКАЗАТЬ, что
// их зовут.
//
// Исходов находки ДВА, и они не сливаются:
//
//   - имени писателя нет среди вызванных — его не зовёт никто;
//   - имя писателя объявлено в дереве НЕ ОДИН раз — по имени не разобрать, зовут
//     ли именно его. Это тоже находка, и вот почему: ровно так дефект и прятался.
//     Писатель записи, по которой судит читатель предъявления, назывался общим
//     словом, это слово звали пятеро посторонних, и прибор молчал с той же
//     уверенностью, с какой молчит на работающем контроле.
//
// Второй исход снимается ИМЕНЕМ: писатель отсечки обязан называться так, чтобы
// его можно было проследить. Это требование к форме, и оно дешевле любого
// разбора достижимости — а главное, оно не может замолчать.
func RevocationWritersWithoutACaller(
	writers []RevocationWriter, called map[string]struct{}, declared map[string]int,
) []RevocationWriter {
	var out []RevocationWriter
	for _, w := range writers {
		if declared[w.Name] > 1 {
			w.Why = fmt.Sprintf("имя объявлено в дереве %d раз — по имени не разобрать, "+
				"зовут ли ИМЕННО его; писателю отсечки нужно прослеживаемое имя", declared[w.Name])
			out = append(out, w)
			continue
		}
		if _, ok := called[w.Name]; ok {
			continue
		}
		w.Why = "имени нет среди вызванных — писателя не зовёт никто"
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}

// sortedTableSet — множество имён таблиц, отсортированное.
func sortedTableSet(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PropagateTablesThroughCalls достраивает множество таблиц КАЖДОГО писателя
// таблицами тех писателей, которых он зовёт, — до неподвижной точки.
//
// Без этого дверь, кладущая вторую запись вызовом помощника, читалась бы как
// писатель одной записи. Это не догадка: первая редакция гейта дала ровно такую
// ложную находку на собственной двери.
//
// Достраивание ЩЕДРО к писателю — по имени, без разбора типов. Направление
// ошибки то же, что у соседнего гейта, и по той же причине: ложная находка у
// гейта, судящего безопасность, заставляет снимать сам гейт.
func PropagateTablesThroughCalls(writers []RevocationWriter) []RevocationWriter {
	byName := map[string]map[string]struct{}{}
	for _, w := range writers {
		if byName[w.Name] == nil {
			byName[w.Name] = map[string]struct{}{}
		}
		for _, t := range w.Tables {
			byName[w.Name][t] = struct{}{}
		}
	}
	for changed := true; changed; {
		changed = false
		for _, w := range writers {
			for _, callee := range w.Calls {
				for t := range byName[callee] {
					if _, has := byName[w.Name][t]; !has {
						byName[w.Name][t] = struct{}{}
						changed = true
					}
				}
			}
		}
	}
	out := make([]RevocationWriter, 0, len(writers))
	for _, w := range writers {
		w.Tables = sortedTableSet(byName[w.Name])
		out = append(out, w)
	}
	return out
}

// PairedCutoffFinding — писатель ОДНОЙ записи отсечки из пары.
type PairedCutoffFinding struct {
	Writer  RevocationWriter
	Missing string
}

// WritersOfOneCutoffWithoutTheOther — писатели, коснувшиеся `first` и не
// коснувшиеся `second`.
//
// # ПОЧЕМУ ЭТОТ ГЕЙТ ОТДЕЛЬНЫЙ ОТ СОСЕДНЕГО
//
// Соседний спрашивает, есть ли у писателя исполнитель. Этот — пишет ли писатель
// ОБЕ записи. Свойства независимы: у писателя одной записи исполнитель может
// быть, и соседний гейт о нём молчит законно. Ровно так дефект и уцелел: четыре
// писателя полосы входа исполнялись и клали одну запись из двух.
func WritersOfOneCutoffWithoutTheOther(
	writers []RevocationWriter, first, second string,
) []PairedCutoffFinding {
	var out []PairedCutoffFinding
	for _, w := range writers {
		touchesFirst, touchesSecond := false, false
		for _, t := range w.Tables {
			if t == first {
				touchesFirst = true
			}
			if t == second {
				touchesSecond = true
			}
		}
		if touchesFirst && !touchesSecond {
			out = append(out, PairedCutoffFinding{Writer: w, Missing: second})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Writer.File != out[j].Writer.File {
			return out[i].Writer.File < out[j].Writer.File
		}
		return out[i].Writer.Line < out[j].Writer.Line
	})
	return out
}

// SortedTables — таблицы отсечки переписью, отсортированные.
func SortedTables(c RevocationWriterCensus) []string {
	out := make([]string, 0, len(c.Tables))
	for t := range c.Tables {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// RevocationWriterPremise — предпосылка вердикта.
func RevocationWriterPremise(parsed, floor int, c RevocationWriterCensus) error {
	if parsed < floor {
		return fmt.Errorf("прод-файлов Go разобрано %d при пороге %d — обход не добрался до дерева",
			parsed, floor)
	}
	if c.Funcs == 0 {
		return fmt.Errorf("функций с телом осмотрено 0 — разбор ничего не читал")
	}
	if len(c.Tables) == 0 {
		return fmt.Errorf("записей отсечки в дереве не найдено ни одной: предмета нет, " +
			"и «находок ноль» здесь означает «прочитано ноль». Суффикс имени сменился " +
			"либо записи снялись — гейт обязан уйти вместе с предметом, а не молчать")
	}
	if c.Writers == 0 {
		return fmt.Errorf("таблицы отсечки найдены (%s), а писателей ноль — разбор видит "+
			"имена и не видит записи", strings.Join(SortedTables(c), ", "))
	}
	return nil
}
