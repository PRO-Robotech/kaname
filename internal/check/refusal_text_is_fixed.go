// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// refusal_text_is_fixed.go — ЯДРО гейта: текст отказа на полосах, чья цепочка
// ведёт к ЧУЖОМУ производителю, фиксирован (задача PRO-Robotech/kacho#2464).
//
// # Предмет
//
// Признак недоступности и внутренний отказ ставят база, сосед и гейт прав.
// Незамапленная ошибка драйвера несёт в себе строку подключения, и переводчик,
// подставивший в текст статуса текст ПОЛУЧЕННОЙ ошибки, отдаёт её вызывающему.
// Канонический переводчик службы был переведён на фиксированный текст; четыре
// его копии остались на тексте цепочки, и расхождение никем не решалось.
//
// # Почему гейт ДЕРЕВА, а не проба службы
//
// «Ни один переводчик не отдаёт причину» — свойство ДЕРЕВА. Проба переводчика
// утверждает о ОДНОМ переводчике и зелена при любом числе непокрытых соседей —
// именно так класс и прожил полтора месяца при исправленном каноне и четырёх
// неисправленных копиях.
//
// # Гейт требует ФИКСИРОВАННОСТИ, а не отсутствия известных форм эха
//
// Это несущее решение, а не оттенок. Перечень способов положить ошибку в текст
// не ограничен: разбор цепочки, `Error()`, подстановка в формат, переменная,
// хранящая любое из этого. Запрет по перечню имеет СЛЕПУЮ ЗОНУ by construction:
// форма, о которой распознаватель не знает, даёт не красное и не зелёное, а
// молчание. Требование «текст обязан быть доказуемо фиксирован» слепой зоны не
// имеет: всё, что не доказано фиксированным, — находка.
//
// Законного близнеца, вычисляющего текст на этих полосах, не существует: норма
// и говорит, что текст фиксирован. Поэтому белый список не даёт ложных находок
// не по счастливой случайности, а по предмету.
//
// # Что признаётся фиксированным
//
//   - строковый литерал и склейка строковых литералов;
//   - имя пакетной константы, чьё значение фиксировано, — в том числе из
//     ЧУЖОГО пакета (`shared.UnavailableMessage`). Имя разрешается по ВСЕМУ
//     осмотренному корпусу, и достаточно ОДНОГО объявления с нефиксированным
//     значением, чтобы имя перестало считаться фиксированным.
//
// `status.Errorf` с подстановками фиксированным не является никогда: формат с
// аргументами и есть вычисление.
//
// # Граница популяции названа ЧИСЛОМ, а не умолчанием
//
// Код отказа берётся СИНТАКСИЧЕСКИ. Конструкция, чей код — переменная
// (`status.New(code, msg)` у сборщика отказа учёта), в популяцию не входит:
// какой код там окажется, разбор без типов не знает. Это слепая зона, и она
// ПЕЧАТАЕТСЯ отдельным числом переписи — иначе «ноль находок» было бы неотличимо
// от «не смотрели». Сегодня таких конструкций в дереве службы две, и обе
// доказуемо безопасны иначе: одна собирает отказ учёта (коды `RESOURCE_EXHAUSTED`
// и `FAILED_PRECONDITION`, текст производителя — контракт), вторая берёт текст у
// канонического переводчика, то есть уже фиксированный.
//
// # Гейт судит УЗЕЛ РАЗБОРА, а не слово
//
// Имена `StripSentinel`, `codes.Unavailable` и `status.Error` встречаются в
// этом дереве в комментариях сотнями — в том числе в комментарии, объясняющем
// сам запрет, и в абзаце выше. Гейт по подстроке краснел бы на собственном
// объяснении. Псевдоним импорта учитывается: гейт, знающий только написание
// `codes.`, не увидел бы `c "…/codes"` — форму столь же законную, и всё
// записанное в ней оказалось бы вне наблюдения.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	codesImportPath  = "google.golang.org/grpc/codes"
	statusImportPath = "google.golang.org/grpc/status"
)

// foreignCauseCodes — полосы, чья цепочка ведёт к ЧУЖОМУ производителю, и
// потому её текст вызывающему не адресован.
//
// Прочие полосы сюда НЕ входят намеренно: «Project %s not found» и
// «Illegal argument …» производит сама служба, текст адресован вызывающему и
// является контрактом. Запретить его значило бы отобрать у отказа то, ради чего
// он существует.
var foreignCauseCodes = map[string]bool{
	"Unavailable": true,
	"Internal":    true,
}

// RefusalTextCensus — перепись одного обхода. Печатается ВСЕГДА: «ноль находок»
// обязано быть отличимо от «ноль прочитанного».
type RefusalTextCensus struct {
	Files          int // файлов Go (не-тестовых) разобрано
	Constructions  int // конструкций статуса найдено всего
	Population     int // из них на полосах чужой причины (код назван синтаксически)
	Fixed          int // из них с доказуемо фиксированным текстом
	CodeNotLiteral int // конструкций с ВЫЧИСЛЯЕМЫМ кодом — вне популяции (слепая зона)
	Constants      int // пакетных строковых констант проиндексировано
}

func (c RefusalTextCensus) String() string {
	return fmt.Sprintf(
		"перепись: файлов Go %d · конструкций статуса %d · констант проиндексировано %d · "+
			"в популяции (%s) %d · из них текст фиксирован %d · "+
			"код вычисляем ⇒ вне популяции %d",
		c.Files, c.Constructions, c.Constants,
		strings.Join(sortedForeignCauseCodes(foreignCauseCodes), "/"),
		c.Population, c.Fixed, c.CodeNotLiteral)
}

// RefusalTextFinding — одна конструкция, чей текст не доказан фиксированным.
type RefusalTextFinding struct {
	File string // путь относительно названного корня
	Line int
	Code string // Unavailable / Internal
	Expr string // выражение текста, как оно записано
}

// ScanFixedRefusalTexts разбирает названные файлы и называет конструкции
// статуса на полосах чужой причины, чей текст не доказан фиксированным.
//
// root служит только для печати координат. Пустой обход ошибкой ЗДЕСЬ не
// объявляется: пустоту судит вызывающий — у гейта дерева и у пробы инъекции
// законные пороги пустоты разные.
func ScanFixedRefusalTexts(root string, files []string) (RefusalTextCensus, []RefusalTextFinding, error) {
	var census RefusalTextCensus

	fset := token.NewFileSet()
	type parsed struct {
		path string
		file *ast.File
	}
	var all []parsed
	for _, p := range files {
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return census, nil, fmt.Errorf("разбор %s: %w", p, err)
		}
		census.Files++
		all = append(all, parsed{path: p, file: f})
	}

	// Индекс пакетных строковых констант — ПО ВСЕМУ корпусу, потому что текст
	// законно берётся у соседнего пакета (единственный производитель контракта).
	fixedConst := map[string]bool{}
	for _, p := range all {
		indexStringConsts(p.file, fixedConst)
	}
	for _, ok := range fixedConst {
		if ok {
			census.Constants++
		}
	}

	var findings []RefusalTextFinding
	for _, p := range all {
		codesName := localImportName(p.file, codesImportPath, "codes")
		statusName := localImportName(p.file, statusImportPath, "status")
		if statusName == "" {
			continue
		}
		ast.Inspect(p.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			verb, ok := selectorOn(call.Fun, statusName)
			if !ok {
				return true
			}
			if verb != "Error" && verb != "Errorf" && verb != "New" {
				return true
			}
			if len(call.Args) < 2 {
				return true
			}
			census.Constructions++

			code, named := selectorOn(call.Args[0], codesName)
			if !named {
				census.CodeNotLiteral++
				return true
			}
			if !foreignCauseCodes[code] {
				return true
			}
			census.Population++

			// Формат с подстановками — вычисление по определению.
			fixed := len(call.Args) == 2 && isFixedText(call.Args[1], fixedConst)
			if fixed {
				census.Fixed++
				return true
			}
			rel := p.path
			if r, err := filepath.Rel(root, p.path); err == nil {
				rel = filepath.ToSlash(r)
			}
			findings = append(findings, RefusalTextFinding{
				File: rel,
				Line: fset.Position(call.Pos()).Line,
				Code: code,
				Expr: exprText(call.Args[1:]),
			})
			return true
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})
	return census, findings, nil
}

// indexStringConsts заносит пакетные строковые константы файла в индекс.
// Имя, у которого хотя бы одно объявление НЕ фиксировано, помечается ложью и
// больше фиксированным не станет.
func indexStringConsts(f *ast.File, out map[string]bool) {
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs, ok := sp.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				// Индекс строится ДО индекса — вложенные константы разрешаются
				// только через литералы, и это намеренно: цепочка «константа на
				// константу» разрешалась бы порядком файлов, а он не определён.
				fixed := isLiteralText(vs.Values[i])
				if prev, seen := out[name.Name]; seen && !prev {
					continue
				}
				out[name.Name] = fixed
			}
		}
	}
}

// isFixedText — доказуемо ли выражение фиксированным текстом.
func isFixedText(e ast.Expr, fixedConst map[string]bool) bool {
	switch x := e.(type) {
	case *ast.BasicLit:
		return x.Kind == token.STRING
	case *ast.BinaryExpr:
		return x.Op == token.ADD &&
			isFixedText(x.X, fixedConst) && isFixedText(x.Y, fixedConst)
	case *ast.ParenExpr:
		return isFixedText(x.X, fixedConst)
	case *ast.Ident:
		return fixedConst[x.Name]
	case *ast.SelectorExpr:
		// `shared.UnavailableMessage` — имя разрешается по корпусу.
		return x.Sel != nil && fixedConst[x.Sel.Name]
	}
	return false
}

// isLiteralText — фиксированность БЕЗ обращения к индексу (для его построения).
func isLiteralText(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.BasicLit:
		return x.Kind == token.STRING
	case *ast.BinaryExpr:
		return x.Op == token.ADD && isLiteralText(x.X) && isLiteralText(x.Y)
	case *ast.ParenExpr:
		return isLiteralText(x.X)
	}
	return false
}

// selectorOn — имя символа в выражении `<pkg>.<Symbol>`, если пакет назван
// именно локальным именем pkg. Пустое pkg означает «файл его не импортирует».
func selectorOn(e ast.Expr, pkg string) (string, bool) {
	if pkg == "" {
		return "", false
	}
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil {
		return "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != pkg {
		return "", false
	}
	return sel.Sel.Name, true
}

// localImportName — ЛОКАЛЬНОЕ имя, под которым файл импортировал путь.
// Псевдоним учитывается: гейт, знающий только каноническое написание, не увидел
// бы переименованный импорт, и записанное в нём было бы не нарушением, а
// невидимостью.
func localImportName(f *ast.File, path, fallback string) string {
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != path {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				// Пустой импорт статуса не собирает; точечный выражения выбора
				// не даёт и потому этим гейтом неразличим — формы в дереве нет,
				// а появившись, она обязана быть запрещена СВОИМ изменением, а
				// не проглочена этим.
				return ""
			}
			return imp.Name.Name
		}
		return fallback
	}
	return ""
}

// exprText — выражения текста в том виде, в каком они записаны: находка обязана
// называть, ЧТО именно она нашла, а не только где.
func exprText(args []ast.Expr) string {
	var parts []string
	for _, a := range args {
		parts = append(parts, briefExpr(a))
	}
	return strings.Join(parts, ", ")
}

func briefExpr(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.BasicLit:
		return x.Value
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return briefExpr(x.X) + "." + x.Sel.Name
	case *ast.CallExpr:
		var as []string
		for _, a := range x.Args {
			as = append(as, briefExpr(a))
		}
		return briefExpr(x.Fun) + "(" + strings.Join(as, ", ") + ")"
	case *ast.BinaryExpr:
		return briefExpr(x.X) + " " + x.Op.String() + " " + briefExpr(x.Y)
	case *ast.ParenExpr:
		return "(" + briefExpr(x.X) + ")"
	}
	return fmt.Sprintf("%T", e)
}

func sortedForeignCauseCodes(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
