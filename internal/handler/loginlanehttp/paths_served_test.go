// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package loginlanehttp

// paths_served_test.go — сличение перечня `Paths()` с тем, что слушатель
// действительно обслуживает (kaname#280). Множество путей полосы объявлено
// дважды: перечнем `Paths()` и регистрациями `h.mux.HandleFunc` в `New`.
// Проба держит равенство в обе стороны и называет путь:
//
//   - путь только в `Paths()` — слушатель отвечает на него 404;
//   - путь только в `New` — слушатель его обслуживает, а перечня, страницы
//     и края он не достигает.
//
// Кандидаты в «обслуживаемые» берутся разбором `handler.go` (регистрация —
// первый довод вызова `HandleFunc`/`Handle` на мультиплексоре): перечислить
// пути у `http.ServeMux` нельзя. «Обслуживается» судится исходом: запрос
// методом, которого не принимает ни один глагол полосы, на путь мимо
// мультиплексора даёт 404, на зарегистрированный — отказ по методу.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"
)

// probeMethod — метод, которого не принимает ни один глагол полосы: запрос им
// не доходит до глагола ни на одном пути, и исход отличает «путь
// зарегистрирован» (отказ по методу) от «пути нет» (404).
const probeMethod = "PROPFIND"

// registeredLanePaths — пути, которые `handler.go` регистрирует у
// мультиплексора. Форма регистрации, которую разбор не опознал (путь — не
// константа файла), — находка, а не пропуск: иначе путь, заведённый иной
// записью, выпал бы из сличения молча.
func registeredLanePaths(src string) (paths []string, findings []string) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "handler.go", src, parser.SkipObjectResolution)
	if err != nil {
		return nil, []string{"разбор handler.go: " + err.Error()}
	}
	consts := map[string]string{}
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
			for i, n := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				if bl, ok := vs.Values[i].(*ast.BasicLit); ok && bl.Kind == token.STRING {
					if v, err := strconv.Unquote(bl.Value); err == nil {
						consts[n.Name] = v
					}
				}
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") || len(call.Args) != 2 {
			return true
		}
		at := fset.Position(call.Pos())
		switch a := call.Args[0].(type) {
		case *ast.Ident:
			v, known := consts[a.Name]
			if !known {
				findings = append(findings, "регистрация handler.go:"+strconv.Itoa(at.Line)+": путь "+a.Name+" — не строковая константа файла")
				return true
			}
			paths = append(paths, v)
		case *ast.BasicLit:
			v, err := strconv.Unquote(a.Value)
			if err != nil {
				findings = append(findings, "регистрация handler.go:"+strconv.Itoa(at.Line)+": путь не разобран")
				return true
			}
			paths = append(paths, v)
		default:
			findings = append(findings, "регистрация handler.go:"+strconv.Itoa(at.Line)+": путь записан формой, которую сличение не читает")
		}
		return true
	})
	return paths, findings
}

// pathsServedFindings — расхождения перечня `declared` с обслуживаемым
// `serve` на множестве кандидатов (перечень ∪ регистрации исходника).
func pathsServedFindings(declared, registered []string, serve http.Handler) (inspected, served int, findings []string) {
	candidates := map[string]bool{}
	for _, p := range declared {
		candidates[p] = true
	}
	for _, p := range registered {
		candidates[p] = true
	}
	names := make([]string, 0, len(candidates))
	for p := range candidates {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		inspected++
		rec := httptest.NewRecorder()
		serve.ServeHTTP(rec, httptest.NewRequest(probeMethod, p, nil))
		isServed := rec.Code != http.StatusNotFound
		if isServed {
			served++
		}
		inDeclared := slices.Contains(declared, p)
		inSource := slices.Contains(registered, p)
		switch {
		case inDeclared && !isServed:
			findings = append(findings, "путь "+p+" объявлен в Paths(), а слушатель отвечает на него 404")
		case !inDeclared && (isServed || inSource):
			findings = append(findings, "путь "+p+" зарегистрирован в New, но не объявлен в Paths()")
		}
	}
	return inspected, served, findings
}

// laneMux — мультиплексор настоящего слушателя: регистрации из `New`, без
// яруса допуска (сличается таблица маршрутов, а не допуск). Глаголы не
// зовутся: метод пробы отвергается раньше глагола.
func laneMux(t *testing.T) *http.ServeMux {
	t.Helper()
	h, err := New(Config{
		SessionTTL:  time.Hour,
		TrustDomain: grpcsrv.NewTrustDomain("kacho.cloud"),
		Logger:      slog.New(slog.DiscardHandler),
	}, unusedLane{})
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: слушатель не построен: %v", err)
	}
	return h.mux
}

// unusedLane — глаголы, которых проба не зовёт; вызов любого — паника, то
// есть красное, а не молчаливый успех.
type unusedLane struct{ Lane }

// TestLaneServesExactlyItsDeclaredPaths — `Paths()` равен множеству путей,
// которые слушатель обслуживает (kaname#280).
func TestLaneServesExactlyItsDeclaredPaths(t *testing.T) {
	registered, parseFindings := registeredLanePaths(handlerSource(t))
	if len(registered) == 0 {
		t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ: регистраций путей в handler.go не найдено — обход пуст (%v)", parseFindings)
	}
	inspected, served, findings := pathsServedFindings(Paths(), registered, laneMux(t))
	t.Logf("перепись: кандидатов %d · обслуживается %d · в Paths() %d · регистраций в handler.go %d",
		inspected, served, len(Paths()), len(registered))
	for _, f := range append(parseFindings, findings...) {
		t.Error(f)
	}
}

// TestLanePathsComparisonInjection — путь только в `Paths()` и путь только в
// `New` краснеют и называют путь; законный близнец (путь в обоих) молчит.
func TestLanePathsComparisonInjection(t *testing.T) {
	const probe = "/iam/v1/auth/probe"
	src := handlerSource(t)
	registered, _ := registeredLanePaths(src)
	mux := laneMux(t)

	// Путь только в Paths(): объявлен, слушатель отвечает 404.
	_, _, f := pathsServedFindings(append(slices.Clone(Paths()), probe), registered, mux)
	if len(f) != 1 || !strings.Contains(f[0], probe) || !strings.Contains(f[0], "404") {
		t.Fatalf("путь только в Paths() не назван: %v", f)
	}

	// Путь только в New: регистрация в исходнике и обслуживание, перечень прежний.
	withPath := strings.Replace(src,
		"\th.mux.HandleFunc(PathStepUp, h.method(http.MethodPost, h.stepUp))",
		"\th.mux.HandleFunc(PathStepUp, h.method(http.MethodPost, h.stepUp))\n\th.mux.HandleFunc(PathProbe, h.method(http.MethodPost, h.stepUp))", 1)
	withPath = strings.Replace(withPath,
		"PathStepUp                  = \"/iam/v1/auth/step-up\"",
		"PathStepUp                  = \"/iam/v1/auth/step-up\"\n\tPathProbe = \""+probe+"\"", 1)
	if withPath == src {
		t.Fatal("НЕ-ВЫПОЛНИЛОСЬ: инъекция регистрации не легла")
	}
	injected, pf := registeredLanePaths(withPath)
	if len(pf) != 0 || !slices.Contains(injected, probe) {
		t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ: разбор не увидел инъецированную регистрацию: %v %v", injected, pf)
	}
	served := http.NewServeMux()
	served.Handle("/", mux)
	served.HandleFunc(probe, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusMethodNotAllowed) })
	_, _, f = pathsServedFindings(Paths(), injected, served)
	if len(f) != 1 || !strings.Contains(f[0], probe) || !strings.Contains(f[0], "не объявлен в Paths()") {
		t.Fatalf("путь только в New не назван: %v", f)
	}

	// Форма регистрации, которую разбор не читает, — находка, а не пропуск.
	odd := strings.Replace(src, "h.mux.HandleFunc(PathStepUp,", "h.mux.HandleFunc(\"/iam/v1/auth/\"+\"step-up\",", 1)
	if odd == src {
		t.Fatal("НЕ-ВЫПОЛНИЛОСЬ: инъекция формы не легла")
	}
	if _, pf = registeredLanePaths(odd); len(pf) != 1 || !strings.Contains(pf[0], "формой") {
		t.Fatalf("неопознанная форма регистрации не названа: %v", pf)
	}

	// Законный близнец: путь в обоих объявлениях — молчание.
	twin := http.NewServeMux()
	twin.Handle("/", mux)
	twin.HandleFunc(probe, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusMethodNotAllowed) })
	if _, _, f = pathsServedFindings(append(slices.Clone(Paths()), probe), injected, twin); len(f) != 0 {
		t.Fatalf("законный близнец дал находки: %v", f)
	}
	if _, _, f = pathsServedFindings(Paths(), registered, mux); len(f) != 0 {
		t.Fatalf("чистое дерево дало находки: %v", f)
	}
}
