// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authz_wrapper_outcome_lanes.go — булева ОБЁРТКА вопроса о правах не
// вызывается там, где у неё есть парная форма с исходом (задача #1045).
//
// Порт с монорепо (`internal/repohygiene/authzwrapperoutcomelanes_test.go`,
// снят вынесением службы — `kacho#2597`). В кaname живёт как минимум одна
// такая пара: `authzguard.SubjectIsClusterAdmin` (bool) рядом с
// `SubjectIsClusterAdminE`/`SubjectIsClusterAdminPlainE` (bool, error) — то
// есть предмет ЖИВ, и гейт переносится. Изменилось: перечень «прод-корней» и
// путь модуля читаются из СВОЕГО дерева, а не из монорепо; имя гейта сохранено
// дословно.
//
// # Что ищется — СВОЙСТВО, и оно ВЫВОДИТСЯ ИЗ ДЕРЕВА
//
// Перечня имён у этого гейта нет и быть не может: пары выводятся —
//
//	F  — экспортированная функция пакета, возвращающая РОВНО `bool`;
//	FE — функция ТОГО ЖЕ пакета с именем `F`+`E` либо `F`+`PlainE`,
//	     возвращающая `(bool, error)`.
//
// Есть пара ⇒ автор пакета УЖЕ объявил, что у этого вопроса три исхода, а не
// два. Значит вызов булевой половины из ЧУЖОГО пакета — выбор, а не
// необходимость, и выбран он в пользу формы, из которой «хранилище не
// ответило» достать нельзя.
//
// # Граница названа честно
//
// Вызовы ВНУТРИ пакета, объявившего пару, под гейт не подпадают: там булева
// половина и есть тело обёртки. Узнавание идёт по ИМЕНИ ИМПОРТА файла, а не
// по типам.
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
)

// TreeModulePath — путь модуля, чтобы импорт файла сопоставлялся с каталогом
// дерева. Читается из go.mod, а не выписывается.
func TreeModulePath(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "go.mod")) // #nosec G304 -- корень резолвлен обходчиком дерева, не вводом снаружи
	if err != nil {
		return "", fmt.Errorf("go.mod не читается: %w", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(rest), nil
		}
	}
	return "", fmt.Errorf("в go.mod нет строки module")
}

// WrapperPair — вопрос, у которого автор пакета объявил ОБЕ формы.
type WrapperPair struct {
	PkgDir   string
	BoolName string
	ENames   []string
}

// OutcomeForms — половины с исходом, перечисленные для сообщения.
func (p WrapperPair) OutcomeForms() string { return strings.Join(p.ENames, " либо ") }

// BoolWrapperCall — одно употребление булевой половины из чужого пакета.
type BoolWrapperCall struct {
	File string
	Line int
	Pair WrapperPair
}

// WrapperScanReport — что именно осмотрено. Печатается ВСЕГДА.
type WrapperScanReport struct {
	Roots      []string
	Files      int
	Generated  int
	DotImports int
	Pairs      []WrapperPair
	Found      []BoolWrapperCall
}

// ProdGoRoots — верхнеуровневые каталоги дерева, несущие отслеживаемый
// не-тестовый Go-код. Выведены обходом, а не выписаны.
func ProdGoRoots(root string, tracked []string) ([]string, error) {
	seen := map[string]struct{}{}
	for _, path := range tracked {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil, fmt.Errorf("относительный путь для %s: %w", path, rerr)
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 2 {
			continue
		}
		seen[parts[0]] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out, nil
}

// IsGeneratedFile — узел разбора несёт отметку `Code generated … DO NOT EDIT.`
func IsGeneratedFile(f *ast.File) bool {
	for _, g := range f.Comments {
		for _, c := range g.List {
			line := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(c.Text, "//"), "/*"))
			if strings.HasPrefix(line, "Code generated ") && strings.Contains(line, "DO NOT EDIT.") {
				return true
			}
		}
	}
	return false
}

// parsedProdFile — один прочитанный не-тестовый файл дерева.
type parsedProdFile struct {
	rel  string
	dir  string
	file *ast.File
}

func pathDirOf(rel string) string {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[:i]
	}
	return "."
}

type pkgFuncs map[string]map[string]*ast.FuncDecl

func exportedFuncsByDir(corpus []parsedProdFile) pkgFuncs {
	out := pkgFuncs{}
	for _, p := range corpus {
		if out[p.dir] == nil {
			out[p.dir] = map[string]*ast.FuncDecl{}
		}
		for _, d := range p.file.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() {
				continue
			}
			out[p.dir][fn.Name.Name] = fn
		}
	}
	return out
}

func derivePairs(byDir pkgFuncs) []WrapperPair {
	var out []WrapperPair
	dirs := make([]string, 0, len(byDir))
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		funcs := byDir[dir]
		names := make([]string, 0, len(funcs))
		for n := range funcs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			if !returnsExactlyBool(funcs[name]) {
				continue
			}
			var eNames []string
			for _, suffix := range []string{"E", "PlainE"} {
				if cand, ok := funcs[name+suffix]; ok && returnsBoolAndError(cand) {
					eNames = append(eNames, name+suffix)
				}
			}
			if len(eNames) > 0 {
				out = append(out, WrapperPair{PkgDir: dir, BoolName: name, ENames: eNames})
			}
		}
	}
	return out
}

func returnsExactlyBool(fn *ast.FuncDecl) bool {
	res := fn.Type.Results
	if res == nil || len(res.List) != 1 || len(res.List[0].Names) > 1 {
		return false
	}
	return identNamed(res.List[0].Type, "bool")
}

func returnsBoolAndError(fn *ast.FuncDecl) bool {
	res := fn.Type.Results
	if res == nil {
		return false
	}
	var types []ast.Expr
	for _, f := range res.List {
		n := len(f.Names)
		if n == 0 {
			n = 1
		}
		for i := 0; i < n; i++ {
			types = append(types, f.Type)
		}
	}
	return len(types) == 2 && identNamed(types[0], "bool") && identNamed(types[1], "error")
}

func identNamed(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// boolWrapperCallsInFile — вызовы булевых половин ЧУЖИХ пакетов в одном файле.
func boolWrapperCallsInFile(
	fset *token.FileSet, f *ast.File, rel, dir, mod string, byDir map[string][]WrapperPair,
) (dotImports int, found []BoolWrapperCall) {
	local := map[string]string{}
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		if imp.Name != nil && imp.Name.Name == "." {
			dotImports++
			continue
		}
		pkgDir, ok := strings.CutPrefix(path, mod+"/")
		if !ok {
			continue
		}
		alias := ""
		switch {
		case imp.Name != nil && imp.Name.Name != "_":
			alias = imp.Name.Name
		default:
			alias = path[strings.LastIndex(path, "/")+1:]
		}
		if alias != "" {
			local[alias] = pkgDir
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		pkgDir, ok := local[pkgIdent.Name]
		if !ok {
			return true
		}
		if pkgDir == dir {
			return true
		}
		for _, p := range byDir[pkgDir] {
			if p.BoolName == sel.Sel.Name {
				found = append(found, BoolWrapperCall{
					File: rel, Line: fset.Position(call.Pos()).Line, Pair: p,
				})
				break
			}
		}
		return true
	})
	return dotImports, found
}

// ScanBoolWrapperCalls — два прохода по одному корпусу: сперва вывести пары,
// затем найти их употребления. under — обходчик поддерева (обычно
// `treecorpus.Under`), подаётся вызывающим, чтобы инъекция могла подставить
// синтетическое дерево без записи в рабочую копию.
func ScanBoolWrapperCalls(root string, roots []string, under func(string) ([]string, error)) (WrapperScanReport, error) {
	var rep WrapperScanReport

	mod, err := TreeModulePath(root)
	if err != nil {
		return rep, err
	}

	var corpus []parsedProdFile
	fset := token.NewFileSet()

	for _, dir := range roots {
		abs := filepath.Join(root, dir)
		if st, serr := os.Stat(abs); serr != nil || !st.IsDir() {
			continue
		}
		rep.Roots = append(rep.Roots, dir)
		tracked, terr := under(abs)
		if terr != nil {
			return WrapperScanReport{}, fmt.Errorf("состав дерева под %s не читается: %w", dir, terr)
		}
		for _, file := range tracked {
			if !strings.HasSuffix(file, ".go") || strings.HasSuffix(file, "_test.go") {
				continue
			}
			rel, rerr := filepath.Rel(root, file)
			if rerr != nil {
				return WrapperScanReport{}, fmt.Errorf("относительный путь для %s: %w", file, rerr)
			}
			rel = filepath.ToSlash(rel)
			f, perr := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution|parser.ParseComments)
			if perr != nil {
				return WrapperScanReport{}, fmt.Errorf("разбор %s: %w", rel, perr)
			}
			if IsGeneratedFile(f) {
				rep.Generated++
				continue
			}
			rep.Files++
			corpus = append(corpus, parsedProdFile{rel: rel, dir: pathDirOf(rel), file: f})
		}
	}

	rep.Pairs = derivePairs(exportedFuncsByDir(corpus))
	byDir := map[string][]WrapperPair{}
	for _, p := range rep.Pairs {
		byDir[p.PkgDir] = append(byDir[p.PkgDir], p)
	}

	for _, p := range corpus {
		dots, calls := boolWrapperCallsInFile(fset, p.file, p.rel, p.dir, mod, byDir)
		rep.DotImports += dots
		rep.Found = append(rep.Found, calls...)
	}
	return rep, nil
}
