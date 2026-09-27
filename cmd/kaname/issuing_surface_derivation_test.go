// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// issuing_surface_derivation_test.go — ОБЪЯВЛЕНИЕ АУТЕНТИФИКАЦИИ ПОВЕРХНОСТИ
// ВЫДАЧИ ВЫВОДИТСЯ ИЗ ТОГО ОБРАБОТЧИКА, КОТОРЫЙ ОНА ОБСЛУЖИВАЕТ (задача
// PRO-Robotech/kaname#423, возврат проверяющего сборки 425, опыт 423F2).
//
// # Предмет
//
// Церемония монтирует на поверхность выдачи эндпоинт авторизации и метаданные
// обнаружения, а объявление поверхности обязано их назвать. Прежде объявление
// собиралось из ФЛАГА, который композиционный корень ставил рядом с монтажом:
// флаг и монтаж — два места об одном факте, и снятая строка флага (423F2)
// оставляла объявление прежним при смонтированной церемонии, а пробы оставались
// зелёными — проба объявления звала производителя напрямую.
//
// Теперь объявление ВЫВОДИТСЯ из обработчика (`issuingSurfaceAuthOf`), и гейт
// держит провязку: у поверхности, чей обработчик несёт монтаж церемонии, ось
// Auth — вызов `issuingSurfaceAuthOf` от ТОГО ЖЕ выражения, что поле Handler, и
// флаговой формы (`issuingSurfaceAuth`) вне производителя не зовёт никто.
//
// # Как опознаётся поверхность церемонии — по роли, а не по имени
//
// Получатели вызовов `.Handle(ceremonyhttp.AuthorizePath|DiscoveryPath, …)` —
// обработчики с монтажом церемонии; множество расширяется простыми
// присваиваниями (`registryTokenHandler = mux`). Объявление поверхности
// (`servicecontract.Surface{…}`), чьё поле Handler — член множества, и есть
// поверхность церемонии. Имя переменной и имя поверхности гейт не читает.
//
// # Границы, названные вслух
//
// Судится один пакет композиционного корня. Монтаж через посредника в чужом
// пакете этим гейтом не виден; такой формы в дереве нет, и появившись, она
// обязана прийти со своим гейтом. То, что производитель верно читает
// обработчик, держит проба `TestIssuingSurfaceAuthFollowsTheMountedHandler`.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

const (
	servicecontractPkgPath = "github.com/PRO-Robotech/corelib/servicecontract"
	ceremonyhttpPkgPath    = "github.com/PRO-Robotech/kaname/internal/handler/ceremonyhttp"
	// issuingAuthDerived — производитель, выводящий объявление из обработчика.
	issuingAuthDerived = "issuingSurfaceAuthOf"
	// issuingAuthByFlag — флаговая форма; зовёт её только производитель.
	issuingAuthByFlag = "issuingSurfaceAuth"
)

// issuingDerivationCensus — объём осмотренного; печатается всегда.
type issuingDerivationCensus struct {
	Files, Surfaces, CeremonyMounts, CeremonySurfaces int
}

func (c issuingDerivationCensus) Summary() string {
	return fmt.Sprintf("прод-файлов корня %d · объявлений поверхности %d · монтажей путей церемонии %d · "+
		"поверхностей с монтажом церемонии %d", c.Files, c.Surfaces, c.CeremonyMounts, c.CeremonySurfaces)
}

// judgeIssuingSurfaceDerivation судит ПЕРЕЧЕНЬ файлов композиционного корня:
// путь → исходник. Состав приходит параметром: в живом дереве — индекс git,
// у инъекции — синтетика.
func judgeIssuingSurfaceDerivation(files map[string]string) (c issuingDerivationCensus, findings []string, err error) {
	fset := token.NewFileSet()
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, path := range paths {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, path, files[path], parser.SkipObjectResolution)
		if perr != nil {
			return c, nil, fmt.Errorf("разобрать %s: %w", path, perr)
		}
		c.Files++
		sc := localImportName(file, servicecontractPkgPath, "servicecontract")
		ch := localImportName(file, ceremonyhttpPkgPath, "ceremonyhttp")

		// Обработчики с монтажом церемонии и их простые переприсваивания.
		mounted := map[string]bool{}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || ch == "" || len(call.Args) != 2 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Handle" {
				return true
			}
			if !isSelector(call.Args[0], ch, "AuthorizePath") && !isSelector(call.Args[0], ch, "DiscoveryPath") {
				return true
			}
			if recv, ok := sel.X.(*ast.Ident); ok {
				c.CeremonyMounts++
				mounted[recv.Name] = true
			}
			return true
		})
		for grew := true; grew; {
			grew = false
			ast.Inspect(file, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok || len(as.Lhs) != len(as.Rhs) {
					return true
				}
				for i, rhs := range as.Rhs {
					r, rok := rhs.(*ast.Ident)
					l, lok := as.Lhs[i].(*ast.Ident)
					if rok && lok && mounted[r.Name] && !mounted[l.Name] {
						mounted[l.Name] = true
						grew = true
					}
				}
				return true
			})
		}

		// Флаговая форма вне производителя.
		for _, decl := range file.Decls {
			fn, isFunc := decl.(*ast.FuncDecl)
			if isFunc && fn.Recv == nil && fn.Name.Name == issuingAuthDerived {
				continue
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok && id.Name == issuingAuthByFlag {
					findings = append(findings, fmt.Sprintf("%s: объявление поверхности выдачи собрано флаговой формой %s(%s) — "+
						"флаг рядом с монтажом есть второе место об одном факте; выведите объявление из обработчика (%s)",
						fset.Position(call.Pos()), issuingAuthByFlag, exprText(fset, call.Args...), issuingAuthDerived))
				}
				return true
			})
		}

		// Объявления поверхностей.
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || sc == "" || !isSelector(lit.Type, sc, "Surface") {
				return true
			}
			c.Surfaces++
			handler, auth := fieldValue(lit, "Handler"), fieldValue(lit, "Auth")
			h, isIdent := handler.(*ast.Ident)
			if !isIdent || !mounted[h.Name] {
				return true
			}
			c.CeremonySurfaces++
			call, isCall := auth.(*ast.CallExpr)
			if isCall {
				if fn, ok := call.Fun.(*ast.Ident); ok && fn.Name == issuingAuthDerived {
					if len(call.Args) == 1 && exprText(fset, call.Args[0]) == h.Name {
						return true
					}
					findings = append(findings, fmt.Sprintf("%s: поверхность обслуживает %s, а её объявление выведено из %s — "+
						"объявление обязано говорить о том, что смонтировано на ЭТОМ обработчике",
						fset.Position(lit.Pos()), h.Name, exprText(fset, call.Args...)))
					return true
				}
			}
			findings = append(findings, fmt.Sprintf("%s: поверхность с монтажом церемонии (обработчик %s) объявляет аутентификацию "+
				"выражением %s, а не выводит её из обработчика (%s(%s))",
				fset.Position(lit.Pos()), h.Name, exprText(fset, auth), issuingAuthDerived, h.Name))
			return true
		})
	}
	if c.Files == 0 || c.Surfaces == 0 {
		return c, nil, fmt.Errorf("обход пуст: прод-файлов %d, объявлений поверхности %d — «находок 0» было бы "+
			"неотличимо от «ничего не прочитано»", c.Files, c.Surfaces)
	}
	if c.CeremonyMounts == 0 || c.CeremonySurfaces == 0 {
		findings = append(findings, fmt.Sprintf("предпосылка не выполнена: монтажей путей церемонии %d, поверхностей, "+
			"чей обработчик их несёт, %d — судить провязку объявления не с чем", c.CeremonyMounts, c.CeremonySurfaces))
	}
	sort.Strings(findings)
	return c, findings, nil
}

// fieldValue — значение поля составного литерала по имени ключа; nil — поля нет.
func fieldValue(lit *ast.CompositeLit, key string) ast.Expr {
	for _, e := range lit.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if k, ok := kv.Key.(*ast.Ident); ok && k.Name == key {
			return kv.Value
		}
	}
	return nil
}

// exprText — выражения исходником, через запятую; отсутствие — «(нет)».
func exprText(fset *token.FileSet, es ...ast.Expr) string {
	parts := make([]string, 0, len(es))
	for _, e := range es {
		if e == nil {
			parts = append(parts, "(нет)")
			continue
		}
		var b strings.Builder
		if err := printer.Fprint(&b, fset, e); err != nil {
			parts = append(parts, "(не печатается)")
			continue
		}
		parts = append(parts, b.String())
	}
	return strings.Join(parts, ", ")
}

// localImportName — локальное имя пакета в файле; псевдоним учитывается.
func localImportName(file *ast.File, path, dflt string) string {
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != path {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				return ""
			}
			return imp.Name.Name
		}
		return dflt
	}
	return ""
}

func TestIssuingSurfaceAuthIsDerivedFromItsMountedHandler(t *testing.T) {
	root := iamServiceRoot(t)
	paths, err := treecorpus.UnderWithSuffix(filepath.Join(root, "cmd", "kaname"), ".go")
	if err != nil {
		t.Fatalf("перечень файлов композиционного корня: %v", err)
	}
	files := map[string]string{}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		b, rerr := os.ReadFile(p) // #nosec G304 -- путь из индекса git дерева
		if rerr != nil {
			t.Fatalf("чтение %s: %v", p, rerr)
		}
		files[p] = string(b)
	}
	census, findings, err := judgeIssuingSurfaceDerivation(files)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Logf("перепись: %s · находок %d", census.Summary(), len(findings))
	if len(findings) > 0 {
		t.Fatalf("объявление поверхности выдачи не выведено из обработчика, который она обслуживает — находок %d:\n%s",
			len(findings), strings.Join(findings, "\n"))
	}
}
