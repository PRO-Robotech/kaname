// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ids_owner_scope_test.go — ГЕЙТ по дереву на границу применимости строгой
// проверки формата идентификатора (`ValidateResourceID`, ids.go).
//
// ЧТО ОН ДЕРЖИТ. `api-conventions.md` §«By-lane code-split» разрешает сервису
// судить ФОРМУ только у СВОЕГО идентификатора; тип чужого решает владелец, и
// потребитель об этом типе не утверждает ничего. Отступление iam — строгая
// сверка префикса вместо платформенного family-agnostic маршрутизатора —
// записано решением: services/iam/docs/engineering/architecture/
// known-divergences.md, §19. Решение опирается ровно на одну посылку:
// КАЖДЫЙ идентификатор, судимый строго, принадлежит iam. Посылка не вечна —
// её и стережёт этот гейт.
//
// Признак нарушения выражен МАШИННО и без ведомости: константа префикса,
// переданная строгой проверке, обязана быть объявлена в СОБСТВЕННОМ пакете
// domain сервиса iam. Префикс из платформенного каталога (pkg/ids) либо строкой
// в кавычках означает, что строгую проверку навели на чужой идентификатор, —
// то самое, что конвенция запрещает прямо.
//
// Почему «объявлена в своём domain», а не список из семи имён: перечень имён
// был бы вторым местом об одном предмете и разошёлся бы с деревом молча.
// Владение ВЫВОДИТСЯ — новый ресурс iam заводит свою константу там же и
// проходит гейт сам, а чужой префикс не пройдёт никогда.
//
// Гейт судит РАЗОБРАННЫЙ исходник, а не текст: имя функции стоит и в
// комментариях, и в приёмках, поэтому проверка по подстроке краснела бы на
// собственном объяснении. Печатает объём осмотренного и падает на пустом
// обходе — «ноль находок» обязано быть отличимо от «ноль прочитанного».
// Способность падать и молчать доказана инъекцией в обе стороны
// (ids_owner_scope_injection_test.go).
package shared_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// serviceRoot — корень сервиса относительно каталога пакета shared.
const serviceRoot = "../../../.."

// domainPkgSuffix — хвост пути СОБСТВЕННОГО пакета domain сервиса iam. Хвост, а
// не полный путь: гейт не обязан знать имя модуля.
// Хвост пути ИМПОРТА собственного домена. Служба получила свой модуль
// (`github.com/PRO-Robotech/kaname`), и сегмент `services/iam` из пути
// импорта пропал — прежний хвост перестал совпадать НИ С ОДНИМ импортом, то
// есть гейт объявил чужими все собственные префиксы сразу.
const domainPkgSuffix = "kaname/internal/domain"

// strictValidatorName — имя строгой проверки формата (ids.go этого пакета).
const strictValidatorName = "ValidateResourceID"

// prefixConstPrefix — приставка имён констант-префиксов в пакете domain.
const prefixConstPrefix = "Prefix"

// sourceFile — разобранный файл вместе со своим путём: путь нужен и переписи, и
// тексту находки.
type sourceFile struct {
	Path string
	AST  *ast.File
}

// ownerScopeCensus — перепись обхода. Печатается ВСЕГДА: без неё «находок нет»
// неотличимо от «читать было нечего».
type ownerScopeCensus struct {
	FilesWalked   int
	Calls         int
	OwnedSelector int
	ResolvedIdent int
	Findings      []string
	OwnedPrefixes []string
	PrefixesUsed  map[string]int
}

// parseProdTree разбирает непроверочные файлы Go поддерева.
func parseProdTree(t *testing.T, root string) []sourceFile {
	t.Helper()
	var out []sourceFile
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Каталоги без прод-кода Go — обходить их значило бы тратить время
			// и рисковать разбором чужих фикстур.
			switch d.Name() {
			case "testdata", "node_modules", "docs":
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		out = append(out, sourceFile{Path: path, AST: f})
		return nil
	})
	if err != nil {
		t.Fatalf("обход дерева сервиса не состоялся: %v", err)
	}
	return out
}

// collectOwnedPrefixes собирает имена констант-префиксов, ОБЪЯВЛЕННЫХ в
// собственном пакете domain сервиса. Это и есть машинное выражение владения:
// перечня имён здесь нет, он выводится из дерева.
func collectOwnedPrefixes(files []sourceFile) map[string]struct{} {
	owned := map[string]struct{}{}
	for _, sf := range files {
		if sf.AST.Name == nil || sf.AST.Name.Name != "domain" {
			continue
		}
		for _, decl := range sf.AST.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, n := range vs.Names {
					if strings.HasPrefix(n.Name, prefixConstPrefix) && n.Name != prefixConstPrefix {
						owned[n.Name] = struct{}{}
					}
				}
			}
		}
	}
	return owned
}

// importPathOf возвращает путь импорта, к которому в этом файле привязан
// идентификатор пакета. Именно он отличает СВОЙ domain от платформенного ids:
// оба дают селектор вида `<pkg>.Prefix<X>`, и по имени они неразличимы.
func importPathOf(f *ast.File, pkgIdent string) (string, bool) {
	for _, imp := range f.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := ""
		if imp.Name != nil {
			name = imp.Name.Name
		} else {
			seg := strings.Split(path, "/")
			name = seg[len(seg)-1]
		}
		if name == pkgIdent {
			return path, true
		}
	}
	return "", false
}

// ownedSelector сообщает, что выражение — константа префикса СОБСТВЕННОГО
// пакета domain сервиса.
func ownedSelector(f *ast.File, expr ast.Expr, owned map[string]struct{}) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	path, ok := importPathOf(f, pkg.Name)
	if !ok || !strings.HasSuffix(path, domainPkgSuffix) {
		return false
	}
	_, isOwned := owned[sel.Sel.Name]
	return isOwned
}

// emptyStringLit сообщает, что выражение — пустой строковый литерал: это
// законный возврат производителя на полосе отказа (префикса нет, потому что
// нет и вида субъекта).
func emptyStringLit(expr ast.Expr) bool {
	bl, ok := expr.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return false
	}
	s, err := strconv.Unquote(bl.Value)
	return err == nil && s == ""
}

// funcDeclsByName собирает функции пакета по имени — для разрешения префикса,
// пришедшего переменной.
func funcDeclsByName(pkgFiles []sourceFile) map[string]*ast.FuncDecl {
	out := map[string]*ast.FuncDecl{}
	for _, sf := range pkgFiles {
		for _, decl := range sf.AST.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Name == nil {
				continue
			}
			out[fd.Name.Name] = fd
		}
	}
	return out
}

// producerReturnsOwned проверяет, что на позиции idx функция возвращает ТОЛЬКО
// собственные константы префикса (либо пустую строку на полосе отказа), и что
// возвратов вообще есть хоть один: разрешение без единого возврата было бы
// вакуумным — оно молчало бы о функции, которая ничего не возвращает.
func producerReturnsOwned(host *ast.File, fd *ast.FuncDecl, idx int, owned map[string]struct{}) bool {
	if fd == nil || fd.Body == nil {
		return false
	}
	seen := 0
	allOwned := true
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		rs, ok := n.(*ast.ReturnStmt)
		if !ok || idx >= len(rs.Results) {
			return true
		}
		seen++
		if !ownedSelector(host, rs.Results[idx], owned) && !emptyStringLit(rs.Results[idx]) {
			allOwned = false
		}
		return true
	})
	return seen > 0 && allOwned
}

// resolvePrefixIdent разрешает префикс, пришедший переменной: находит в теле
// вызывающей функции присваивание этой переменной и требует, чтобы источником
// была функция ТОГО ЖЕ пакета, возвращающая только собственные префиксы.
// Неразрешимое — находка, а не послабление: гейт закрывается наглухо.
func resolvePrefixIdent(
	host *ast.File, caller *ast.FuncDecl, name string,
	byName map[string]*ast.FuncDecl, owned map[string]struct{},
) bool {
	if caller == nil || caller.Body == nil {
		return false
	}
	resolved := false
	ast.Inspect(caller.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		idx := -1
		for i, lhs := range as.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && id.Name == name {
				idx = i
			}
		}
		if idx < 0 {
			return true
		}
		// Прямое присваивание константы: `p := domain.PrefixAccount`.
		if len(as.Rhs) == len(as.Lhs) {
			if ownedSelector(host, as.Rhs[idx], owned) {
				resolved = true
			}
			return true
		}
		// Раздача из одного вызова: `p, n, err := producer(...)`.
		if len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		fnIdent, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if producerReturnsOwned(host, byName[fnIdent.Name], idx, owned) {
			resolved = true
		}
		return true
	})
	return resolved
}

// prefixArgIndex — позиция префикса в сигнатуре ValidateResourceID(id, prefix, resourceName).
const prefixArgIndex = 1

// isStrictValidatorCall распознаёт вызов строгой проверки в обеих законных
// формах записи: через квалификатор пакета из соседнего пакета и голым именем
// внутри самого пакета shared. Форма, о которой распознаватель не знает, была
// бы не редкостью, а слепой зоной.
func isStrictValidatorCall(f *ast.File, call *ast.CallExpr) bool {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		pkg, ok := fun.X.(*ast.Ident)
		if !ok {
			return false
		}
		path, ok := importPathOf(f, pkg.Name)
		if !ok || !strings.HasSuffix(path, "/shared") {
			return false
		}
		return fun.Sel.Name == strictValidatorName
	case *ast.Ident:
		return f.Name != nil && f.Name.Name == "shared" && fun.Name == strictValidatorName
	}
	return false
}

// inspectOwnerScope — ТЕЛО гейта. Чистая функция над разобранным деревом:
// инъекция зовёт ровно её, поэтому доказательство относится к тому, что
// исполняется на дереве, а не к своей копии предиката.
func inspectOwnerScope(files []sourceFile) ownerScopeCensus {
	c := ownerScopeCensus{FilesWalked: len(files), PrefixesUsed: map[string]int{}}
	owned := collectOwnedPrefixes(files)
	for name := range owned {
		c.OwnedPrefixes = append(c.OwnedPrefixes, name)
	}
	sort.Strings(c.OwnedPrefixes)

	byDir := map[string][]sourceFile{}
	for _, sf := range files {
		dir := filepath.Dir(sf.Path)
		byDir[dir] = append(byDir[dir], sf)
	}

	for _, sf := range files {
		pkgFuncs := funcDeclsByName(byDir[filepath.Dir(sf.Path)])
		for _, decl := range sf.AST.Decls {
			fd, _ := decl.(*ast.FuncDecl)
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !isStrictValidatorCall(sf.AST, call) {
					return true
				}
				if len(call.Args) <= prefixArgIndex {
					c.Calls++
					c.Findings = append(c.Findings, sf.Path+": вызов без аргумента префикса")
					return true
				}
				c.Calls++
				arg := call.Args[prefixArgIndex]
				if ownedSelector(sf.AST, arg, owned) {
					c.OwnedSelector++
					// Имя достаётся ПРОВЕРЯЕМЫМ приведением, а не безусловным:
					// гейт, падающий паникой вместо вердикта, снимают первым.
					if sel, ok := arg.(*ast.SelectorExpr); ok {
						c.PrefixesUsed[sel.Sel.Name]++
					}
					return true
				}
				if id, ok := arg.(*ast.Ident); ok &&
					resolvePrefixIdent(sf.AST, fd, id.Name, pkgFuncs, owned) {
					c.ResolvedIdent++
					return true
				}
				c.Findings = append(c.Findings,
					sf.Path+": префикс не принадлежит собственному пакету domain сервиса")
				return true
			})
		}
	}
	sort.Strings(c.Findings)
	return c
}

// TestStrictIDFormatCheckStaysOwnerScoped — гейт: строгая проверка формата
// применяется ТОЛЬКО к идентификатору, чей тип принадлежит iam.
func TestStrictIDFormatCheckStaysOwnerScoped(t *testing.T) {
	if _, err := os.Stat(serviceRoot); err != nil {
		t.Fatalf("корень сервиса не найден (%s): гейт судил бы о непрочитанном: %v", serviceRoot, err)
	}
	files := parseProdTree(t, serviceRoot)
	c := inspectOwnerScope(files)

	// ПЕРЕПИСЬ — печатается всегда и до вердикта.
	used := make([]string, 0, len(c.PrefixesUsed))
	for k, v := range c.PrefixesUsed {
		used = append(used, k+"="+strconv.Itoa(v))
	}
	sort.Strings(used)
	t.Logf("перепись: непроверочных файлов Go прочитано %d · вызовов строгой проверки %d "+
		"(константой префикса %d, переменной %d) · собственных констант префикса объявлено %d · по префиксам: %s",
		c.FilesWalked, c.Calls, c.OwnedSelector, c.ResolvedIdent, len(c.OwnedPrefixes), strings.Join(used, " "))

	if c.FilesWalked == 0 {
		t.Fatal("обход пуст: непроверочных файлов Go не прочитано — вердикт беспредметен")
	}
	if len(c.OwnedPrefixes) == 0 {
		t.Fatal("в собственном пакете domain не найдено ни одной константы префикса — " +
			"предпосылка гейта не выполняется, и молчание означало бы «не с чем сверять»")
	}
	if c.Calls == 0 {
		t.Fatal("вызовов строгой проверки не найдено ни одного: либо она снята — тогда " +
			"снимите и этот гейт вместе с её записью решения, — либо распознаватель " +
			"перестал знать форму записи вызова")
	}
	if len(c.Findings) > 0 {
		t.Fatalf("строгая проверка формата наведена на идентификатор, чей тип решает НЕ iam "+
			"(конвенция запрещает это прямо — api-conventions.md §By-lane code-split):\n%s",
			strings.Join(c.Findings, "\n"))
	}
}
