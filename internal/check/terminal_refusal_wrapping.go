// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// terminal_refusal_wrapping.go — разбор для двух гейтов приёмки #2439:
// репозиторий операций попадает в use-case только ОБЁРНУТЫМ, и тексты отказа
// объявлены в одном месте.
//
// Приёмка: `docs/engineering/acceptance/refusal-text-names-the-lane-that-can-retry.md`,
// сценарии KN-RTX-06 и KN-RTX-08.
//
// # Что предикат устанавливает, а что НЕТ — сказано здесь, а не в заголовке
//
// Он устанавливает ОДНО: всякий сырой конструктор репозитория операций в
// прод-коде обёрнут надстройкой прямо на месте вызова. Всеобщности вида «всякий
// терминальный исход проходит надстройку» он НЕ устанавливает и не обязан:
// четвёртый писатель терминального исхода — реконсайлер осиротевших операций —
// идёт мимо контракта репозитория и вынесен исключением приёмки (§2.3).
//
// Различие несущее. Две первые редакции приёмки были отвергнуты ровно за
// заголовок шире предиката: читатель пишет гейт по заголовку, а не по телу.
//
// # Почему разбор синтаксический, а не по подстроке
//
// Имя конструктора встречается в комментариях — в этом дереве четыре вхождения,
// из которых настоящий вызов ОДИН. Проверка по подстроке краснела бы на
// собственном объяснении соседнего файла; разбор судит узел ВЫЗОВА.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

const (
	// rawOperationsRepoCtor — сырой конструктор репозитория операций.
	rawOperationsRepoCtor = "NewRepo"
	// rawOperationsRepoPkg — пакет, которому конструктор принадлежит. Проверяется
	// вместе с именем: `NewRepo` — имя частое, и без пакета разбор считал бы
	// чужие конструкторы.
	rawOperationsRepoPkg = "operations"
	// terminalRefusalWrapper — надстройка, которой сырой конструктор обязан быть
	// обёрнут ПРЯМО НА МЕСТЕ вызова.
	terminalRefusalWrapper = "NewTerminalRefusalRepo"
)

// RawOperationsRepoSite — один вызов сырого конструктора с координатой.
type RawOperationsRepoSite struct {
	Where   string // путь:строка
	Wrapped bool   // обёрнут ли надстройкой прямо здесь
}

// TerminalRefusalCensus — объём осмотренного.
type TerminalRefusalCensus struct {
	Tracked  int // элементов в индексе дерева
	Read     int // прочитано файлов Go
	Parsed   int // из них разобрано
	Ctors    int // найдено вызовов сырого конструктора
	Wrapped  int // из них обёрнуто на месте
	Mentions int // упоминаний имени вне вызова (комментарий, строка)
}

// String — перепись одной строкой.
func (c TerminalRefusalCensus) String() string {
	return fmt.Sprintf(
		"перепись: в индексе %d, файлов Go прочитано %d, разобрано %d; вызовов %s.%s "+
			"найдено %d, из них обёрнуто %d; упоминаний имени ВНЕ вызова %d "+
			"(они вызовами не считаются)",
		c.Tracked, c.Read, c.Parsed, rawOperationsRepoPkg, rawOperationsRepoCtor,
		c.Ctors, c.Wrapped, c.Mentions)
}

// terminalRefusalSkip — что под разбор не идёт.
//
// Тестовый корпус вычтен, потому что фикстура гейта ОБЯЗАНА уметь написать
// форму дефекта: без этого гейт нечем проверить инъекцией. Сама надстройка
// вычтена по координате — она конструктор и оборачивает, а не оборачивается.
func terminalRefusalSkip(rel string) bool {
	return strings.HasSuffix(rel, "_test.go") ||
		strings.Contains(rel, "/testdata/") ||
		strings.HasPrefix(rel, "pkg/api/")
}

// ScanRawOperationsRepo обходит отслеживаемое дерево и находит вызовы сырого
// конструктора репозитория операций, отмечая обёрнутые.
func ScanRawOperationsRepo(root string) ([]RawOperationsRepoSite, TerminalRefusalCensus, error) {
	var census TerminalRefusalCensus
	var sites []RawOperationsRepoSite

	tracked, terr := treecorpus.Under(root)
	if terr != nil {
		return nil, census, fmt.Errorf("состав дерева: %w", terr)
	}
	census.Tracked = len(tracked)

	for _, abs := range tracked {
		rel, rerr := filepath.Rel(root, abs)
		if rerr != nil {
			return nil, census, fmt.Errorf("путь %s: %w", abs, rerr)
		}
		slashed := filepath.ToSlash(rel)
		if !strings.HasSuffix(slashed, ".go") || terminalRefusalSkip(slashed) {
			continue
		}
		raw, berr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git ЭТОГО дерева
		if berr != nil {
			return nil, census, fmt.Errorf("чтение %s: %w", slashed, berr)
		}
		census.Read++

		fset := token.NewFileSet()
		// Комментарии разбираются НАМЕРЕННО: перепись обязана назвать, сколько
		// упоминаний имени она НЕ сочла вызовом, — иначе «вызов один» неотличимо
		// от «разбор видит один из четырёх».
		f, perr := parser.ParseFile(fset, slashed, raw, parser.ParseComments)
		if perr != nil {
			return nil, census, fmt.Errorf("разбор %s: %w", slashed, perr)
		}
		census.Parsed++

		found := map[int]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if !isRawOperationsRepoCall(call) {
				return true
			}
			line := fset.Position(call.Pos()).Line
			found[line] = true
			census.Ctors++
			wrapped := false
			// Обёрнут ЗДЕСЬ ЖЕ: вызов надстройки, чьим аргументом стоит этот
			// конструктор. Оборачивание «где-то дальше» предикатом не считается —
			// между вызовом и обёрткой помещается сколько угодно кода, и
			// проверить это разбором одного узла нельзя.
			ast.Inspect(f, func(m ast.Node) bool {
				outer, ok := m.(*ast.CallExpr)
				if !ok || !isWrapperCall(outer) {
					return true
				}
				for _, arg := range outer.Args {
					if inner, ok := arg.(*ast.CallExpr); ok && inner == call {
						wrapped = true
					}
				}
				return true
			})
			if wrapped {
				census.Wrapped++
			}
			sites = append(sites, RawOperationsRepoSite{
				Where:   fmt.Sprintf("%s:%d", slashed, line),
				Wrapped: wrapped,
			})
			return true
		})

		// Упоминания имени вне вызова — комментарии и строки. Считаются, чтобы
		// разрыв между «сколько раз имя встречается» и «сколько это вызовов» был
		// назван числом, а не оставлен читателю.
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if strings.Contains(c.Text, rawOperationsRepoCtor) &&
					!found[fset.Position(c.Pos()).Line] {
					census.Mentions++
				}
			}
		}
	}

	sort.Slice(sites, func(i, j int) bool { return sites[i].Where < sites[j].Where })
	return sites, census, nil
}

// isRawOperationsRepoCall — узел есть вызов `operations.NewRepo(...)`.
func isRawOperationsRepoCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != rawOperationsRepoCtor {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == rawOperationsRepoPkg
}

// isWrapperCall — узел есть вызов надстройки, под любым именем пакета.
func isWrapperCall(call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name == terminalRefusalWrapper
	case *ast.SelectorExpr:
		return fun.Sel.Name == terminalRefusalWrapper
	}
	return false
}

// RefusalTextDecl — одно объявление текста отказа с координатой.
type RefusalTextDecl struct {
	Where string
	Name  string
}

// ScanRefusalTextLiterals ищет ЛИТЕРАЛЫ обоих текстов отказа в прод-дереве.
//
// Предмет KN-RTX-08: у каждого текста ровно одно объявление. Литерал, написанный
// вторым местом, заводит копию, которая разойдётся с первой молча — на всяком
// входе, кроме сериализационного конфликта, обе стороны отвечают одинаково.
func ScanRefusalTextLiterals(root string, texts []string) (
	map[string][]RefusalTextDecl, TerminalRefusalCensus, error,
) {
	var census TerminalRefusalCensus
	out := map[string][]RefusalTextDecl{}
	for _, t := range texts {
		out[t] = nil
	}

	tracked, terr := treecorpus.Under(root)
	if terr != nil {
		return nil, census, fmt.Errorf("состав дерева: %w", terr)
	}
	census.Tracked = len(tracked)

	for _, abs := range tracked {
		rel, rerr := filepath.Rel(root, abs)
		if rerr != nil {
			return nil, census, fmt.Errorf("путь %s: %w", abs, rerr)
		}
		slashed := filepath.ToSlash(rel)
		if !strings.HasSuffix(slashed, ".go") || terminalRefusalSkip(slashed) {
			continue
		}
		raw, berr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git ЭТОГО дерева
		if berr != nil {
			return nil, census, fmt.Errorf("чтение %s: %w", slashed, berr)
		}
		census.Read++

		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, slashed, raw, 0)
		if perr != nil {
			return nil, census, fmt.Errorf("разбор %s: %w", slashed, perr)
		}
		census.Parsed++

		// Судится узел-ЛИТЕРАЛ, а не подстрока файла: тот же текст стоит в
		// комментариях-объяснениях и в самой приёмке, и разбор по подстроке
		// краснел бы на прозе, объясняющей этот же запрет.
		//
		// СКЛЕЙКА сворачивается — это ВТОРАЯ законная форма записи того же
		// текста, и без неё разбор её не видит вовсе: не краснеет и не зеленеет,
		// а МОЛЧИТ. Найдено не вычиткой: собственное объявление этих текстов
		// написано склейкой по ширине строки, и гейт на первом же прогоне сказал
		// «не объявлен НИ РАЗУ» о константе, лежащей в трёх строках выше по
		// дереву.
		seen := map[ast.Node]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			val, pos, ok := foldedStringLiteral(n, seen)
			if !ok {
				return true
			}
			if _, watched := out[val]; !watched {
				return true
			}
			census.Ctors++
			out[val] = append(out[val], RefusalTextDecl{
				Where: fmt.Sprintf("%s:%d", slashed, fset.Position(pos).Line),
			})
			return true
		})
	}
	for _, v := range out {
		sort.Slice(v, func(i, j int) bool { return v[i].Where < v[j].Where })
	}
	return out, census, nil
}

// foldedStringLiteral сворачивает узел в строковое значение, если он есть
// строковый литерал ЛИБО склейка строковых литералов.
//
// Склейка помечается в `seen` целиком, чтобы её части не были засчитаны ещё раз
// как самостоятельные литералы: иначе одно объявление в две строки читалось бы
// как три (склейка плюс две половины), и «объявлено один раз» стало бы
// недостижимым by construction.
func foldedStringLiteral(n ast.Node, seen map[ast.Node]bool) (string, token.Pos, bool) {
	if seen[n] {
		return "", token.NoPos, false
	}
	switch x := n.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", token.NoPos, false
		}
		v, err := strconv.Unquote(x.Value)
		if err != nil {
			return "", token.NoPos, false
		}
		return v, x.Pos(), true
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", token.NoPos, false
		}
		l, _, lok := foldedStringLiteral(x.X, seen)
		r, _, rok := foldedStringLiteral(x.Y, seen)
		if !lok || !rok {
			return "", token.NoPos, false
		}
		markFolded(x, seen)
		return l + r, x.Pos(), true
	}
	return "", token.NoPos, false
}

// markFolded помечает склейку и все её части как учтённые.
func markFolded(n ast.Node, seen map[ast.Node]bool) {
	ast.Inspect(n, func(m ast.Node) bool {
		if m != nil {
			seen[m] = true
		}
		return true
	})
	seen[n] = true
}
