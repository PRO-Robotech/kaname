// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_surface_injection_test.go — падучесть гейта единственности
// поверхности церемонии в обе стороны (kaname#320).
//
// # Вход — настоящий
//
// Каждая инъекция правит КОПИЮ живого пакета (композиционного корня, а где
// предмет того требует — пакета регистрации) в t.TempDir() ровно на один
// факт. Место правки находится РАЗБОРОМ: оператор ищется по его печатной
// форме в синтаксическом дереве, и вставка ложится на его позицию, а не на
// совпадение строки. Не нашлось места — падает фикстура, а не гейт: это
// «условие не создано», и оно не выдаётся ни за красное, ни за зелёное.
//
// # Законный пример — фикстурный, и это граница
//
// Живой корень монтирует обе координаты церемонии производителем
// `ceremonyhttp` (kaname#423), и живой положительный контроль — все три
// координаты (ceremony_surface_test.go, Т14). «Законный пример» инъекций
// (F-cer) всё же синтетический: пакет authorizehttp с постоянными
// AuthorizePath и DiscoveryPath несёт формы, которые нужны близнецам и которых
// у живого производителя нет (обработчик со своим мультиплексором для
// двухуровневого монтажа, псевдоним импорта, локальная постоянная). Поэтому
// F-cer снимает с копии корня живой монтаж (liveCeremonyMounts) и ставит
// синтетический ОДИН раз на поверхности выдачи рядом с токен-эндпоинтом:
// координата в фикстуре смонтирована ровно одним производителем.
//
// # Прогонов три
//
// Контроль (F-cer молчит) — TestCeremonySurfaceInjectionControlIsSilent;
// новая инъекция — каждый подслучай TestCeremonySurfaceInjections; старая
// инъекция — I16: вторая регистрация ЖИВОЙ координаты, которую ловила и
// прежняя текстовая проба.
package check_test

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
)

// Координаты фикстуры. Одно значение на два места: синтетический пакет
// порождается из них же.
const (
	fixtureAuthorizePath = "/iam/v1/authorize"
	fixtureDiscoveryPath = "/.well-known/oauth-authorization-server"
	fixtureCeremonyPkg   = "internal/handler/authorizehttp"
)

// fixtureCeremonySource — синтетический пакет церемонии.
//
// Handler — конечная точка. Routed — обработчик с СОБСТВЕННЫМ закрытым
// мультиплексором (форма полосы входа): для двухуровневого монтажа (Т10).
var fixtureCeremonySource = fmt.Sprintf(`package authorizehttp

import "net/http"

// AuthorizePath — координата эндпоинта авторизации фикстуры.
const AuthorizePath = %q

// DiscoveryPath — координата метаданных обнаружения фикстуры.
const DiscoveryPath = %q

// Handler — конечная точка церемонии фикстуры.
type Handler struct{}

func (Handler) ServeHTTP(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

// New — обработчик церемонии.
func New() http.Handler { return Handler{} }

// Routed — обработчик со своим закрытым мультиплексором.
type Routed struct{ mux *http.ServeMux }

// NewRouted регистрирует обе координаты на СВОЁМ мультиплексоре.
func NewRouted() *Routed {
	r := &Routed{mux: http.NewServeMux()}
	r.mux.Handle(AuthorizePath, Handler{})
	r.mux.Handle(DiscoveryPath, Handler{})
	return r
}

func (r *Routed) ServeHTTP(w http.ResponseWriter, req *http.Request) { r.mux.ServeHTTP(w, req) }
`, fixtureAuthorizePath, fixtureDiscoveryPath)

// fixtureCeremonyCoordinates — координаты прогона по фикстуре: все три взяты
// у производителя (синтетический пакет их объявляет).
func fixtureCeremonyCoordinates() []check.CeremonyCoordinate {
	return []check.CeremonyCoordinate{
		{Name: "токен-эндпоинт", Path: clienttokenhttp.TokenPath, Anchor: true},
		{Name: "эндпоинт авторизации", Path: fixtureAuthorizePath},
		{Name: "метаданные обнаружения", Path: fixtureDiscoveryPath},
	}
}

// Опорные операторы живого корня. Их печатная форма — адрес вставки.
const (
	anchorTokenMount  = "mux.Handle(clienttokenhttp.TokenPath, clientTokenHandler)"
	anchorIntrospect  = "jwksMux.Handle(tokenintrospecthttp.IntrospectPath, introspect)"
	anchorMetrics     = `metricsMux.Handle("/metrics", metricsReg.Handler())`
	anchorBinding     = "binding, berr := jwksproxyhttp.NewBinding(records)"
	anchorSurfaces    = "httpSurfaces := []raisedSurface{"
	anchorCeremonyImp = `"github.com/PRO-Robotech/kaname/internal/handler/authorizehttp"`
)

// fixturePkg — копия одного пакета.
type fixturePkg struct {
	rel   string
	files map[string][]byte
}

// ceremonyFixture — копия живых пакетов с правками.
type ceremonyFixture struct {
	t          *testing.T
	root       string
	modulePath string
	pkgs       map[string]*fixturePkg
}

// newRootCopyFixture — копия живого корня без правок.
func newRootCopyFixture(t *testing.T) *ceremonyFixture {
	t.Helper()
	root := ceremonyModuleRoot(t)
	f := &ceremonyFixture{t: t, root: root, modulePath: ceremonyModulePath(t, root), pkgs: map[string]*fixturePkg{}}
	f.copy(ceremonyRootDir)
	return f
}

// liveCeremonyMounts — монтаж координат церемонии живым корнем (serve.go):
// F-cer его снимает, чтобы координата стояла одним производителем.
var liveCeremonyMounts = []string{
	"mux.Handle(ceremonyhttp.AuthorizePath, ceremony.Authorize)",
	"mux.Handle(ceremonyhttp.DiscoveryPath, ceremony.Discovery)",
}

// newCeremonyFixture — F-cer: копия корня без живого монтажа церемонии,
// синтетический пакет церемонии и ОДИН монтаж каждой его координаты на
// поверхности выдачи.
func newCeremonyFixture(t *testing.T) *ceremonyFixture {
	t.Helper()
	f := newRootCopyFixture(t)
	for _, live := range liveCeremonyMounts {
		f.removeStmt(ceremonyRootDir, "serve.go", "", live)
	}
	f.add(fixtureCeremonyPkg, "authorizehttp.go", fixtureCeremonySource)
	f.addImport(ceremonyRootDir, "serve.go", anchorCeremonyImp)
	f.insertAfter(ceremonyRootDir, "serve.go", "", anchorTokenMount,
		"mux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())\n"+
			"mux.Handle(authorizehttp.DiscoveryPath, authorizehttp.New())")
	return f
}

// copy берёт не-тестовые .go живого пакета.
func (f *ceremonyFixture) copy(rel string) *fixturePkg {
	f.t.Helper()
	if p, ok := f.pkgs[rel]; ok {
		return p
	}
	dir := filepath.Join(f.root, rel)
	entries, err := os.ReadDir(dir)
	if err != nil {
		f.t.Fatalf("фикстура: пакет %s: %v", rel, err)
	}
	p := &fixturePkg{rel: rel, files: map[string][]byte{}}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(dir, name))
		if rerr != nil {
			f.t.Fatalf("фикстура: %s/%s: %v", rel, name, rerr)
		}
		p.files[name] = data
	}
	if len(p.files) == 0 {
		f.t.Fatalf("фикстура: в пакете %s нет ни одного прод-файла — условие не создано", rel)
	}
	f.pkgs[rel] = p
	return p
}

// add кладёт файл в пакет (новый пакет заводится).
func (f *ceremonyFixture) add(rel, name, src string) {
	p, ok := f.pkgs[rel]
	if !ok {
		p = &fixturePkg{rel: rel, files: map[string][]byte{}}
		f.pkgs[rel] = p
	}
	p.files[name] = []byte(src)
}

// source — файл пакета (копируется при первом обращении).
func (f *ceremonyFixture) source(rel, name string) []byte {
	f.t.Helper()
	p := f.copy(rel)
	src, ok := p.files[name]
	if !ok {
		f.t.Fatalf("фикстура: файла %s/%s нет", rel, name)
	}
	return src
}

// splice заменяет [start,end) файла текстом.
func (f *ceremonyFixture) splice(rel, name string, start, end int, text string) {
	src := f.source(rel, name)
	out := make([]byte, 0, len(src)+len(text))
	out = append(out, src[:start]...)
	out = append(out, text...)
	out = append(out, src[end:]...)
	f.pkgs[rel].files[name] = out
}

// printed — печатная форма узла одной строкой.
func printed(fset *token.FileSet, n ast.Node) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, n); err != nil {
		return ""
	}
	return strings.Join(strings.Fields(buf.String()), " ")
}

// locate — позиции первого узла, чья печатная форма равна want (либо
// начинается с want при prefix), внутри функции inFunc (пусто — где угодно).
func (f *ceremonyFixture) locate(rel, name, inFunc, want string, prefix bool, stmt bool) (start, end int) {
	f.t.Helper()
	src := f.source(rel, name)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		f.t.Fatalf("фикстура: разбор %s/%s: %v", rel, name, err)
	}
	norm := strings.Join(strings.Fields(want), " ")
	found := -1
	ast.Inspect(file, func(n ast.Node) bool {
		if found >= 0 || n == nil {
			return found < 0
		}
		if fd, ok := n.(*ast.FuncDecl); ok && inFunc != "" && fd.Name.Name != inFunc {
			return false
		}
		_, isStmt := n.(ast.Stmt)
		_, isExpr := n.(ast.Expr)
		if (stmt && !isStmt) || (!stmt && !isExpr) {
			return true
		}
		got := printed(fset, n)
		if got == norm || (prefix && strings.HasPrefix(got, norm)) {
			found = fset.Position(n.Pos()).Offset
			end = fset.Position(n.End()).Offset
			return false
		}
		return true
	})
	if found < 0 {
		f.t.Fatalf("фикстура: в %s/%s не найден узел «%s» — место правки не существует, условие не создано", rel, name, want)
	}
	return found, end
}

// insertAfter вставляет текст новой строкой за оператором.
func (f *ceremonyFixture) insertAfter(rel, name, inFunc, stmtSrc, text string) {
	f.t.Helper()
	_, end := f.locate(rel, name, inFunc, stmtSrc, false, true)
	f.splice(rel, name, end, end, "\n"+text)
}

// insertBefore вставляет текст отдельной строкой перед оператором.
func (f *ceremonyFixture) insertBefore(rel, name, inFunc, stmtPrefix, text string) {
	f.t.Helper()
	start, _ := f.locate(rel, name, inFunc, stmtPrefix, true, true)
	f.splice(rel, name, start, start, text+"\n")
}

// removeStmt снимает оператор по его позиции в разборе.
func (f *ceremonyFixture) removeStmt(rel, name, inFunc, stmtSrc string) {
	f.t.Helper()
	start, end := f.locate(rel, name, inFunc, stmtSrc, false, true)
	f.splice(rel, name, start, end, "")
}

// replaceExpr заменяет выражение.
func (f *ceremonyFixture) replaceExpr(rel, name, inFunc, exprSrc, text string) {
	f.t.Helper()
	start, end := f.locate(rel, name, inFunc, exprSrc, false, false)
	f.splice(rel, name, start, end, text)
}

// addImport добавляет спецификацию импорта в блок импорта файла.
func (f *ceremonyFixture) addImport(rel, name, spec string) {
	f.t.Helper()
	src := f.source(rel, name)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.ImportsOnly)
	if err != nil {
		f.t.Fatalf("фикстура: разбор импорта %s/%s: %v", rel, name, err)
	}
	for _, d := range file.Decls {
		if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.IMPORT && g.Lparen.IsValid() {
			off := fset.Position(g.Lparen).Offset + 1
			f.splice(rel, name, off, off, "\n\t"+spec)
			return
		}
	}
	f.t.Fatalf("фикстура: в %s/%s нет блока импорта", rel, name)
}

// appendRaised добавляет элемент в срез подъёма поверхностей.
func (f *ceremonyFixture) appendRaised(elem string) {
	f.t.Helper()
	src := f.source(ceremonyRootDir, "serve.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", src, 0)
	if err != nil {
		f.t.Fatalf("фикстура: разбор корня: %v", err)
	}
	var off = -1
	ast.Inspect(file, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || off >= 0 || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return off < 0
		}
		if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name == "httpSurfaces" {
			if lit, ok := as.Rhs[0].(*ast.CompositeLit); ok {
				off = fset.Position(lit.Rbrace).Offset
			}
		}
		return off < 0
	})
	if off < 0 {
		f.t.Fatalf("фикстура: среза подъёма в корне нет — условие не создано")
	}
	f.splice(ceremonyRootDir, "serve.go", off, off, "\t"+elem+",\n\t")
}

// lineOf — строка оператора с печатной формой stmtSrc.
func (f *ceremonyFixture) lineOf(rel, name, stmtSrc string) int {
	f.t.Helper()
	start, _ := f.locate(rel, name, "", stmtSrc, false, true)
	return bytes.Count(f.source(rel, name)[:start], []byte("\n")) + 1
}

// judge пишет копии в t.TempDir() и судит их.
func (f *ceremonyFixture) judge(coords []check.CeremonyCoordinate) (check.CeremonySurfaceReport, error) {
	f.t.Helper()
	base := f.t.TempDir()
	overlay := map[string]string{}
	for rel, p := range f.pkgs {
		dir := filepath.Join(base, filepath.FromSlash(rel))
		if err := os.MkdirAll(dir, 0o750); err != nil {
			f.t.Fatalf("фикстура: %v", err)
		}
		for name, data := range p.files {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
				f.t.Fatalf("фикстура: %v", err)
			}
		}
		overlay[f.modulePath+"/"+rel] = dir
	}
	return check.JudgeCeremonySurfaces(f.t.Context(), check.CeremonySurfaceSpec{
		ModuleRoot:  f.root,
		RootPackage: f.modulePath + "/" + ceremonyRootDir,
		Overlay:     overlay,
		Unresolved:  liveUnresolvedLedger(),
	}, coords)
}

// mustJudge — прогон, который обязан исполниться.
func (f *ceremonyFixture) mustJudge(coords []check.CeremonyCoordinate) check.CeremonySurfaceReport {
	f.t.Helper()
	report, err := f.judge(coords)
	if err != nil {
		f.t.Fatalf("гейт не исполнился на фикстуре — условие не создано либо фикстура не собирается: %v", err)
	}
	return report
}

// requireFinding — среди находок есть одна, несущая все фрагменты.
func requireFinding(t *testing.T, report check.CeremonySurfaceReport, want ...string) string {
	t.Helper()
	for _, f := range report.Findings {
		ok := true
		for _, w := range want {
			if !strings.Contains(f, w) {
				ok = false
				break
			}
		}
		if ok {
			return f
		}
	}
	t.Fatalf("ИНЪЕКЦИЯ НЕ ПОЙМАНА: нет находки со всеми фрагментами %q\nперепись: %s\nнаходки (%d):\n%s",
		want, report.Census.Summary(), len(report.Findings), strings.Join(report.Findings, "\n"))
	return ""
}

// requireSilent — близнец молчит, и молчит не по слепоте: перепись непуста,
// а разбор дошёл до неподвижной точки.
func requireSilent(t *testing.T, report check.CeremonySurfaceReport) {
	t.Helper()
	if report.Census.Files == 0 || report.Census.SurfaceDecls == 0 {
		t.Fatalf("близнец «молчит» на пустом обходе — это не вердикт: %s", report.Census.Summary())
	}
	if r := report.Census.SolveRounds; r == 0 || r >= check.CeremonySolveRoundLimit {
		t.Fatalf("близнец «молчит» на разборе, не дошедшем до неподвижной точки (раундов %d при пределе %d) — "+
			"это не вердикт: %s", r, check.CeremonySolveRoundLimit, report.Census.Summary())
	}
	if len(report.Findings) > 0 {
		t.Fatalf("законный близнец дал находки (%d):\n%s", len(report.Findings), strings.Join(report.Findings, "\n"))
	}
}

// coordinateSurfaces — на скольких поверхностях резолвится координата.
func coordinateSurfaces(t *testing.T, report check.CeremonySurfaceReport, name string) int {
	t.Helper()
	for _, c := range report.Coordinates {
		if c.Name == name {
			return len(c.Surfaces)
		}
	}
	t.Fatalf("координата «%s» не судилась", name)
	return 0
}

// TestCeremonySurfaceInjectionControlIsSilent — контроль (Т1): F-cer молчит,
// и каждая координата насчитана ровно на одной поверхности.
func TestCeremonySurfaceInjectionControlIsSilent(t *testing.T) {
	f := newCeremonyFixture(t)
	report := f.mustJudge(fixtureCeremonyCoordinates())
	requireSilent(t, report)
	for _, name := range []string{"токен-эндпоинт", "эндпоинт авторизации", "метаданные обнаружения"} {
		if n := coordinateSurfaces(t, report, name); n != 1 {
			t.Errorf("«%s»: поверхностей %d, в контроле ожидалась одна", name, n)
		}
	}
	if report.Census.PositiveControls != 3 {
		t.Errorf("положительных контролей %d, ожидалось 3", report.Census.PositiveControls)
	}
}

// ceremonySurfaceBlock — лишняя поверхность с обработчиком handler.
func ceremonySurfaceBlock(varName, handler string) string {
	return varName + `, err := iamHTTPSurface(servicecontract.Surface{
		Name:    "лишняя поверхность пробы",
		Mode:    surfaceMode,
		Logger:  logger,
		Addr:    addrAxis("", "поверхность пробы"),
		Handler: ` + handler + `,
		Reach:   servicecontract.ReachClusterInternal,
		Auth:    servicecontract.NotApplicable[servicecontract.SurfaceAuthMech]("проба"),
	})
	if err != nil {
		return err
	}`
}

// ceremonyWrapSource — обёртка корня, делегирующая дальше (I5).
const ceremonyWrapSource = `package main

import "net/http"

func ceremonyProbeWrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(w, r) })
}
`

// ceremonyChainSelfSource — рекурсивная фабрика мультиплексора: значение
// рождается на дне и возвращается СКВОЗЬ самовызов. Регистрация —
// параметр: близнец регистрирует путь пробы заглушкой, инъекция — координату
// конечной точкой церемонии.
func ceremonyChainSelfSource(imports, path, handler string) string {
	return `package main

import (
	"net/http"` + imports + `
)

func ceremonyChainSelf(depth int) *http.ServeMux {
	if depth == 0 {
		mux := http.NewServeMux()
		mux.Handle(` + path + `, ` + handler + `)
		return mux
	}
	return ceremonyChainSelf(depth - 1)
}
`
}

// ceremonyChainMutualSource — то же сквозь ВЗАИМНЫЙ вызов: мультиплексор
// рождается в Even, а регистрацию несёт Odd — на значении, пришедшем к нему
// из рекурсии.
func ceremonyChainMutualSource(imports, basePath, oddPath, oddHandler string) string {
	return `package main

import (
	"net/http"` + imports + `
)

func ceremonyChainEven(depth int) *http.ServeMux {
	if depth == 0 {
		mux := http.NewServeMux()
		mux.Handle(` + basePath + `, http.NotFoundHandler())
		return mux
	}
	return ceremonyChainOdd(depth - 1)
}

func ceremonyChainOdd(depth int) *http.ServeMux {
	mux := ceremonyChainEven(depth)
	mux.Handle(` + oddPath + `, ` + oddHandler + `)
	return mux
}
`
}

// ceremonyImportLine — импорт синтетического пакета для исходников пробы.
const ceremonyImportLine = "\n\t" + anchorCeremonyImp

// ceremonyDeepChainSource — цепочка из n функций, каждая возвращает результат
// следующей; мультиплексор рождается в последней. Объявлены сверху вниз:
// разбор продвигает значение на одно звено за раунд.
func ceremonyDeepChainSource(n int) string {
	var b strings.Builder
	b.WriteString("package main\n\nimport \"net/http\"\n\n")
	for i := 0; i < n-1; i++ {
		fmt.Fprintf(&b, "func ceremonyDeep%d() *http.ServeMux { return ceremonyDeep%d() }\n\n", i, i+1)
	}
	fmt.Fprintf(&b, "func ceremonyDeep%d() *http.ServeMux {\n\tmux := http.NewServeMux()\n"+
		"\tmux.Handle(\"/probe-deep/x\", http.NotFoundHandler())\n\treturn mux\n}\n", n-1)
	return b.String()
}

// ceremonyLayersSource — n РАЗНЫХ обёрток, каждая делегирует дальше.
func ceremonyLayersSource(n int) string {
	var b strings.Builder
	b.WriteString("package main\n\nimport \"net/http\"\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "\nfunc ceremonyLayer%d(next http.Handler) http.Handler {\n"+
			"\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(w, r) })\n}\n", i)
	}
	return b.String()
}

// ceremonyLayersCall — вложение n обёрток вокруг inner.
func ceremonyLayersCall(n int, inner string) string {
	out := inner
	for i := n - 1; i >= 0; i-- {
		out = fmt.Sprintf("ceremonyLayer%d(%s)", i, out)
	}
	return out
}

// ceremonyEighthSurface — I3: восьмая поверхность со своим мультиплексором.
func ceremonyEighthSurface(f *ceremonyFixture) {
	f.insertBefore(ceremonyRootDir, "serve.go", "", anchorSurfaces,
		"ceremonyMux := http.NewServeMux()\n"+
			"ceremonyMux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())\n"+
			ceremonySurfaceBlock("ceremonyExtraSurface", "ceremonyMux"))
	f.appendRaised("{knobMetrics, ceremonyExtraSurface}")
}

// ceremonyManualSource — обёртка, решающая маршрут по пути запроса в своём
// теле: pre — операторы до обработчика, cond — условие, onHit — ответ.
func ceremonyManualSource(imports, pre, cond, onHit string) string {
	return "package main\n\nimport (\n\t\"net/http\"" + imports + "\n)\n\n" +
		"func ceremonyProbeManual(next http.Handler) http.Handler {\n" + pre +
		"\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n" +
		"\t\t" + cond + " {\n\t\t\t" + onHit + "\n\t\t\treturn\n\t\t}\n\t\tnext.ServeHTTP(w, r)\n\t})\n}\n"
}

// ceremonyManualOnMetrics — обёртка ceremonyProbeManual на поверхности диагностики.
func ceremonyManualOnMetrics(f *ceremonyFixture, src string) {
	f.add(ceremonyRootDir, "ceremony_probe_manual.go", src)
	f.replaceExpr(ceremonyRootDir, "serve.go", "", "Handler: metricsMux", "Handler: ceremonyProbeManual(metricsMux)")
}

// ceremonyRootFile — файл корня пробы с импортами и телом.
func ceremonyRootFile(f *ceremonyFixture, name, imports, body string) {
	f.add(ceremonyRootDir, name, "package main\n\nimport (\n"+imports+"\n)\n\n"+body+"\n")
}

// ceremonyLayersRegDecls — регистратор за встроенными интерфейсами: слой
// встраивает интерфейс регистратора, пустышка его реализует, ничего не
// регистрируя.
const ceremonyLayersRegDecls = "type ceremonyReg interface{ Handle(string, http.Handler) }\n\n" +
	"type ceremonyLayer struct{ ceremonyReg }\n\n" +
	"type ceremonyNop struct{}\n\nfunc (ceremonyNop) Handle(string, http.Handler) {}"

// ceremonyLayeredRegistrar — вызов регистрации через n слоёв вокруг inner;
// nop — у той же переменной есть и пустышка.
func ceremonyLayeredRegistrar(f *ceremonyFixture, n int, nop bool, inner string) {
	ceremonyRootFile(f, "ceremony_probe_layers_reg.go", "\t\"net/http\"", ceremonyLayersRegDecls)
	layers := strings.Repeat("ceremonyLayer{", n) + inner + strings.Repeat("}", n)
	code := "var ceremonyX ceremonyReg = " + layers + "\n"
	if nop {
		code = "var ceremonyX ceremonyReg = ceremonyNop{}\nceremonyX = " + layers + "\n"
	}
	code += "ceremonyX.Handle(authorizehttp.AuthorizePath, authorizehttp.New())"
	f.insertAfter(ceremonyRootDir, "serve.go", "", anchorIntrospect, code)
}

// ceremonyRegAdapterDecls — регистратор за слоями и адаптер: функциональный
// тип, чей метод Handle зовёт саму функцию. Значение адаптера над методом
// мультиплексора — получатель не своего типа-структуры: реализация метода у
// него не выводится.
const ceremonyRegAdapterDecls = ceremonyLayersRegDecls + "\n\ntype ceremonyRegFunc func(string, http.Handler)\n\n" +
	"func (f ceremonyRegFunc) Handle(p string, h http.Handler) { f(p, h) }"

// ceremonyAdaptedRegistrar — вызов регистрации через переменную с пустышкой и
// адаптером над jwksMux.Handle за n слоями; adapter=false — адаптер объявлен,
// но переменной не отдан (близнец: у вызова одна пустышка).
func ceremonyAdaptedRegistrar(f *ceremonyFixture, n int, adapter bool) {
	ceremonyRootFile(f, "ceremony_probe_layers_reg.go", "\t\"net/http\"", ceremonyRegAdapterDecls)
	code := "var ceremonyX ceremonyReg = ceremonyNop{}\n"
	if adapter {
		code += "ceremonyX = " + strings.Repeat("ceremonyLayer{", n) + "ceremonyRegFunc(jwksMux.Handle)" +
			strings.Repeat("}", n) + "\n"
	}
	code += "ceremonyX.Handle(authorizehttp.AuthorizePath, authorizehttp.New())"
	f.insertAfter(ceremonyRootDir, "serve.go", "", anchorIntrospect, code)
}

// ceremonyMounterIface и ceremonyMountBody — монтировщик за интерфейсом:
// метод получает мультиплексор и регистрирует на нём координату.
const (
	ceremonyMounterIface = "type ceremonyMounter interface{ Mount(*http.ServeMux) }\n\n"
	ceremonyMountBody    = "{\n\tm.Handle(authorizehttp.AuthorizePath, authorizehttp.New())\n}"
)

// ceremonyMounter — файл монтировщика с типом decl и его методом Mount.
func ceremonyMounter(f *ceremonyFixture, decl, recv string) {
	ceremonyRootFile(f, "ceremony_probe_mounter.go", "\t\"net/http\""+ceremonyImportLine,
		ceremonyMounterIface+decl+"\n\nfunc ("+recv+") Mount(m *http.ServeMux) "+ceremonyMountBody)
}

// ceremonyCycleVarsSource — цикл записей строковых переменных пакета
// P → Q → S → P; в Q записана координата, в P — путь пробы.
const ceremonyCycleVarsSource = `package main

import "github.com/PRO-Robotech/kaname/internal/handler/authorizehttp"

var ceremonyP, ceremonyQ, ceremonyS string

func init() {
	ceremonyP = ceremonyQ
	ceremonyQ = ceremonyS
	ceremonyS = ceremonyP
	ceremonyQ = authorizehttp.AuthorizePath
	ceremonyP = "/probe-p"
}
`

// ceremonyCycleTypesSource — типы с циклом через указатели: TA несёт
// мультиплексор и указатель на TB, TB — указатель на TA. first — переменная
// пакета, первой спрашивающая о TA.
func ceremonyCycleTypesSource(first bool) string {
	src := "package main\n\nimport \"net/http\"\n\n" +
		"type ceremonyTA struct {\n\tb *ceremonyTB\n\tm *http.ServeMux\n}\n\n" +
		"type ceremonyTB struct{ a *ceremonyTA }\n"
	if first {
		src += "\nvar ceremonyFirst ceremonyTA\n"
	}
	return src
}

// ceremonyThroughCycleTypes — мультиплексор внутреннего зеркала течёт в
// переменную сквозь значение TB; у той же переменной есть мультиплексор-
// пустышка, смонтированный на соседнем поддереве.
const ceremonyThroughCycleTypes = "ceremonyDummy := http.NewServeMux()\n" +
	"jwksMux.Handle(\"/probe-dummy/\", ceremonyDummy)\n" +
	"ceremonyB0 := ceremonyTB{a: &ceremonyTA{m: jwksMux}}\n" +
	"ceremonyR := ceremonyDummy\n" +
	"ceremonyR = ceremonyB0.a.m\n" +
	"ceremonyR.Handle(authorizehttp.AuthorizePath, authorizehttp.New())"

// ceremonyInjection — одна инъекция: ровно один факт F-cer.
type ceremonyInjection struct {
	id   string
	edit func(f *ceremonyFixture)
	want []string
}

func ceremonyInjections() []ceremonyInjection {
	serve := func(f *ceremonyFixture, anchor, text string) {
		f.insertAfter(ceremonyRootDir, "serve.go", "", anchor, text)
	}
	return []ceremonyInjection{
		{"I1_second_mount_on_internal_mux", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, "jwksMux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"I2_second_external_surface_rest_front", func(f *ceremonyFixture) {
			f.addImport("internal/restfront", "front.go", anchorCeremonyImp)
			f.insertAfter("internal/restfront", "front.go", "NewPublic", "mux := newMux()",
				"_ = mux.HandlePath(http.MethodGet, authorizehttp.AuthorizePath, "+
					"func(w http.ResponseWriter, _ *http.Request, _ map[string]string) { w.WriteHeader(http.StatusOK) })")
		}, []string{"эндпоинт авторизации", "2 поверхностях", "собственный публичный REST-фронт"}},

		{"I3_eighth_surface", ceremonyEighthSurface,
			[]string{"эндпоинт авторизации", "2 поверхностях", "лишняя поверхность пробы"}},

		{"I4_same_handler_two_surfaces", func(f *ceremonyFixture) {
			f.insertBefore(ceremonyRootDir, "serve.go", "", anchorSurfaces,
				ceremonySurfaceBlock("ceremonyExtraSurface", "registryTokenHandler"))
			f.appendRaised("{knobMetrics, ceremonyExtraSurface}")
		}, []string{"эндпоинт авторизации", "2 поверхностях", "лишняя поверхность пробы"}},

		{"I5_same_handler_through_wrapper", func(f *ceremonyFixture) {
			f.add(ceremonyRootDir, "ceremony_probe_wrap.go", ceremonyWrapSource)
			f.insertBefore(ceremonyRootDir, "serve.go", "", anchorSurfaces,
				ceremonySurfaceBlock("ceremonyExtraSurface", "ceremonyProbeWrap(registryTokenHandler)"))
			f.appendRaised("{knobMetrics, ceremonyExtraSurface}")
		}, []string{"эндпоинт авторизации", "2 поверхностях", "лишняя поверхность пробы"}},

		{"I6a_subtree_delegation", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, `jwksMux.Handle("/iam/v1/", registryTokenHandler)`)
		}, []string{"эндпоинт авторизации", "2 поверхностях", "/iam/v1/"}},

		{"I6b_root_delegation", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, `jwksMux.Handle("/", registryTokenHandler)`)
		}, []string{"эндпоинт авторизации", "2 поверхностях", "зеркало публичных ключей"}},

		{"I7_trailing_slash", func(f *ceremonyFixture) {
			serve(f, anchorMetrics, `metricsMux.Handle("/iam/v1/authorize/", authorizehttp.New())`)
		}, []string{"эндпоинт авторизации", "2 поверхностях", "диагностика (/metrics)"}},

		{"I8_method_in_pattern", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, `jwksMux.Handle("GET /iam/v1/authorize", authorizehttp.New())`)
		}, []string{"эндпоинт авторизации", "2 поверхностях", "GET /iam/v1/authorize"}},

		{"I9_literal_instead_of_constant", func(f *ceremonyFixture) {
			serve(f, anchorMetrics, `metricsMux.Handle("/iam/v1/authorize", authorizehttp.New())`)
		}, []string{"эндпоинт авторизации", "2 поверхностях", "диагностика (/metrics)"}},

		{"I10_import_alias", func(f *ceremonyFixture) {
			f.addImport(ceremonyRootDir, "serve.go", `az "github.com/PRO-Robotech/kaname/internal/handler/authorizehttp"`)
			serve(f, anchorIntrospect, "jwksMux.Handle(az.AuthorizePath, az.New())")
		}, []string{"эндпоинт авторизации", "2 поверхностях", "az.AuthorizePath"}},

		{"I11_local_const_concat_in_package_constructor", func(f *ceremonyFixture) {
			f.insertAfter("internal/handler/iamhooks", "http_server.go", "NewMux", `mux.Handle("GET /readyz", agg.ReadyHandler())`,
				"const ceremonyProbePath = \"/iam/v1\" + \"/authorize\"\nmux.Handle(ceremonyProbePath, agg.LiveHandler())")
		}, []string{"эндпоинт авторизации", "2 поверхностях", "вебхуки провайдера личности"}},

		{"I12_registration_inside_login_lane_constructor", func(f *ceremonyFixture) {
			f.insertAfter("internal/handler/loginlanehttp", "handler.go", "New",
				"h.mux.HandleFunc(PathStepUp, h.method(http.MethodPost, h.stepUp))",
				`h.mux.HandleFunc("/iam/v1/authorize", h.method(http.MethodGet, h.csrf))`)
		}, []string{"эндпоинт авторизации", "2 поверхностях", "полоса входа паролем"}},

		{"I13_registration_by_data_record", func(f *ceremonyFixture) {
			f.insertBefore(ceremonyRootDir, "serve.go", "", anchorBinding,
				"records = append(records, jwksproxyhttp.Record{Issuer: \"https://probe.invalid\", "+
					"Path: authorizehttp.AuthorizePath, Handler: authorizehttp.New()})")
		}, []string{"эндпоинт авторизации", "2 поверхностях", "зеркало публичных ключей"}},

		{"I14_gateway_http_rule", func(f *ceremonyFixture) {
			f.replaceExpr("pkg/api/kaname/cloud/iam/v1", "authorize_service.pb.gw.go", "",
				`runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 2, 2}, []string{"iam", "v1", "authorize"}, "check"))`,
				`runtime.MustPattern(runtime.NewPattern(1, []int{2, 0, 2, 1, 2, 2}, []string{"iam", "v1", "authorize"}, ""))`)
		}, []string{"эндпоинт авторизации", "3 поверхностях", "собственный внутренний REST-фронт"}},

		{"I15_discovery_alone", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, "jwksMux.Handle(authorizehttp.DiscoveryPath, authorizehttp.New())")
		}, []string{"метаданные обнаружения", "2 поверхностях", reachInternalMark}},

		{"I17_built_not_mounted", func(f *ceremonyFixture) {
			f.replaceExpr(ceremonyRootDir, "serve.go", "", "mux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())",
				"_ = authorizehttp.New()")
		}, []string{"эндпоинт авторизации", "не резолвится ни на одной поверхности", "authorizehttp.AuthorizePath"}},

		{"I23_host_in_pattern", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, `jwksMux.Handle("kaname.invalid/iam/v1/authorize", authorizehttp.New())`)
		}, []string{"эндпоинт авторизации", "2 поверхностях", "kaname.invalid/iam/v1/authorize"}},

		{"I24a_trailing_wildcard", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, `jwksMux.Handle("/iam/v1/{rest...}", authorizehttp.New())`)
		}, []string{"эндпоинт авторизации", "2 поверхностях", "/iam/v1/{rest...}"}},

		{"I24b_segment_wildcard", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, `jwksMux.Handle("/iam/{version}/authorize", authorizehttp.New())`)
		}, []string{"эндпоинт авторизации", "2 поверхностях", "/iam/{version}/authorize"}},

		{"I25_sprintf_of_constants", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, `jwksMux.Handle(fmt.Sprintf("%s/authorize", "/iam/v1"), authorizehttp.New())`)
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"I26_default_serve_mux", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, "http.Handle(authorizehttp.AuthorizePath, authorizehttp.New())")
		}, []string{"эндпоинт авторизации", "которого не поднимает ни одна поверхность"}},

		{"I27_unresolvable_path", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, `jwksMux.Handle(os.Getenv("KANAME_PROBE_PATH"), authorizehttp.New())`)
		}, []string{"не сводится к значению", "os.Getenv"}},

		{"I28_runtime_concatenation", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, "ceremonyBase := \"/iam/v1\"\njwksMux.Handle(ceremonyBase+\"/authorize\", authorizehttp.New())")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"I29_manual_routing_by_path", func(f *ceremonyFixture) {
			ceremonyManualOnMetrics(f, ceremonyManualSource("", "",
				`if r.URL.Path == "/iam/v1/authorize"`, "w.WriteHeader(http.StatusOK)"))
		}, []string{"по пути запроса в теле обработчика", "сравнение пути"}},

		{"I30_unknown_foreign_wrapper", func(f *ceremonyFixture) {
			f.addImport(ceremonyRootDir, "serve.go", `"github.com/prometheus/client_golang/prometheus/promhttp"`)
			f.addImport(ceremonyRootDir, "serve.go", `"github.com/prometheus/client_golang/prometheus"`)
			f.replaceExpr(ceremonyRootDir, "serve.go", "", "Handler: metricsMux",
				"Handler: promhttp.InstrumentMetricHandler(prometheus.NewRegistry(), metricsMux)")
		}, []string{"чужой код", "promhttp.InstrumentMetricHandler"}},

		{"I32_http_server_literal_outside_surfaces", func(f *ceremonyFixture) {
			f.insertBefore(ceremonyRootDir, "serve.go", "", anchorSurfaces,
				"ceremonyMux := http.NewServeMux()\n"+
					"ceremonyMux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())\n"+
					"_ = &http.Server{Addr: \"127.0.0.1:0\", Handler: ceremonyMux, ReadHeaderTimeout: time.Second}")
		}, []string{"HTTP-сервер", "в обход объявления поверхности", "не объявленный поверхностью"}},

		{"I34_second_listener_of_a_declared_handler", func(f *ceremonyFixture) {
			f.insertBefore(ceremonyRootDir, "serve.go", "", anchorSurfaces,
				"_ = &http.Server{Addr: \"127.0.0.1:0\", Handler: registryTokenHandler, ReadHeaderTimeout: time.Second}")
		}, []string{"HTTP-сервер", "в обход объявления поверхности", "вторым слушателем"}},

		{"I33_listen_and_serve_outside_surfaces", func(f *ceremonyFixture) {
			f.insertBefore(ceremonyRootDir, "serve.go", "", anchorSurfaces,
				"ceremonyMux := http.NewServeMux()\n"+
					"ceremonyMux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())\n"+
					"go func() { _ = http.ListenAndServe(\"127.0.0.1:0\", ceremonyMux) }() // #nosec G114 -- проба")
		}, []string{"HTTP-сервер", "в обход объявления поверхности", "не объявленный поверхностью"}},

		{"I31_conflicting_registration", func(f *ceremonyFixture) {
			serve(f, anchorTokenMount, "mux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())")
		}, []string{"мультиплексор отказал бы в регистрации"}},

		{"I35a_recursive_factory_through_self_call", func(f *ceremonyFixture) {
			f.add(ceremonyRootDir, "ceremony_probe_chain.go",
				ceremonyChainSelfSource(ceremonyImportLine, "authorizehttp.AuthorizePath", "authorizehttp.New()"))
			serve(f, anchorMetrics, `metricsMux.Handle("/iam/v1/", ceremonyChainSelf(3))`)
		}, []string{"эндпоинт авторизации", "2 поверхностях", "диагностика (/metrics)"}},

		{"I35b_recursive_factory_through_mutual_call", func(f *ceremonyFixture) {
			f.add(ceremonyRootDir, "ceremony_probe_chain.go",
				ceremonyChainMutualSource(ceremonyImportLine, `"/probe-chain/x"`, "authorizehttp.AuthorizePath",
					"authorizehttp.New()"))
			serve(f, anchorMetrics, `metricsMux.Handle("/iam/v1/", ceremonyChainEven(1))`)
		}, []string{"эндпоинт авторизации", "2 поверхностях", "диагностика (/metrics)"}},

		// X1–X10 — формы, на которых гейт круга 1 молчал (приёмка проверки,
		// круг 1). Регистрация опознаётся по ВЫЗЫВАЕМОМУ методу, а не по
		// синтаксису вызова.
		{"X1_method_value", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, "ceremonyReg := jwksMux.Handle\n"+
				"ceremonyReg(authorizehttp.AuthorizePath, authorizehttp.New())")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"X2_method_expression", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, "(*http.ServeMux).Handle(jwksMux, authorizehttp.AuthorizePath, authorizehttp.New())")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"X3_interface_registrar", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, "var ceremonyReg interface{ Handle(string, http.Handler) } = jwksMux\n"+
				"ceremonyReg.Handle(authorizehttp.AuthorizePath, authorizehttp.New())")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"X3b_interface_registrar_through_an_empty_interface", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, "var ceremonyAny any = jwksMux\n"+
				"ceremonyAny.(interface{ Handle(string, http.Handler) }).Handle(authorizehttp.AuthorizePath, authorizehttp.New())")
		}, []string{"мультиплексор не прослежен", "authorizehttp.AuthorizePath"}},

		{"X1b_bound_serve_http_of_the_issuing_handler", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, `jwksMux.Handle("/iam/v1/", http.HandlerFunc(registryTokenHandler.ServeHTTP))`)
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"X4_embedded_mux_promoted_method", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_router.go", `"net/http"`, "type ceremonyRouter struct{ *http.ServeMux }")
			serve(f, anchorIntrospect, "ceremonyR := ceremonyRouter{jwksMux}\n"+
				"ceremonyR.Handle(authorizehttp.AuthorizePath, authorizehttp.New())")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"X5_interface_dispatched_mounter", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_mounter.go", "\t\"net/http\""+ceremonyImportLine,
				"type ceremonyMounter interface{ Mount(*http.ServeMux) }\n\ntype ceremonyAuthorizeMount struct{}\n\n"+
					"func (ceremonyAuthorizeMount) Mount(m *http.ServeMux) {\n"+
					"\tm.Handle(authorizehttp.AuthorizePath, authorizehttp.New())\n}")
			serve(f, anchorIntrospect, "var ceremonyM ceremonyMounter = ceremonyAuthorizeMount{}\nceremonyM.Mount(jwksMux)")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"X6_generic_registrar", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_generic.go", "\t\"net/http\""+ceremonyImportLine,
				"func ceremonyMount[M interface{ Handle(string, http.Handler) }](m M) {\n"+
					"\tm.Handle(authorizehttp.AuthorizePath, authorizehttp.New())\n}")
			serve(f, anchorIntrospect, "ceremonyMount(jwksMux)")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"X7_manual_routing_through_local_var", func(f *ceremonyFixture) {
			ceremonyManualOnMetrics(f, ceremonyManualSource("", "",
				`if p := r.URL.Path; p == "/iam/v1/authorize"`, "w.WriteHeader(http.StatusOK)"))
		}, []string{"по пути запроса в теле обработчика", "сравнение пути"}},

		{"X8_manual_routing_map_lookup", func(f *ceremonyFixture) {
			ceremonyManualOnMetrics(f, ceremonyManualSource(ceremonyImportLine,
				"\troutes := map[string]http.Handler{authorizehttp.AuthorizePath: authorizehttp.New()}\n",
				"if h, ok := routes[r.URL.Path]; ok", "h.ServeHTTP(w, r)"))
		}, []string{"по пути запроса в теле обработчика", "выбор из карты по пути"}},

		{"X9_manual_routing_path_base", func(f *ceremonyFixture) {
			ceremonyManualOnMetrics(f, ceremonyManualSource("\n\t\"path\"", "",
				`if path.Base(r.URL.Path) == "authorize"`, "w.WriteHeader(http.StatusOK)"))
		}, []string{"по пути запроса в теле обработчика", "сравнение пути"}},

		{"X9b_manual_routing_to_lower", func(f *ceremonyFixture) {
			ceremonyManualOnMetrics(f, ceremonyManualSource("\n\t\"strings\"", "",
				`if strings.ToLower(r.URL.Path) == "/iam/v1/authorize"`, "w.WriteHeader(http.StatusOK)"))
		}, []string{"по пути запроса в теле обработчика", "сравнение пути"}},

		// Остальные формы решения о маршруте по пути: switch, функция
		// сопоставления и путь адреса запроса, взятого значением.
		{"X9c_manual_routing_switch_on_a_derived_path", func(f *ceremonyFixture) {
			ceremonyManualOnMetrics(f, "package main\n\nimport (\n\t\"net/http\"\n\t\"strings\"\n)\n\n"+
				"func ceremonyProbeManual(next http.Handler) http.Handler {\n"+
				"\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n"+
				"\t\tswitch p := strings.TrimSuffix(r.URL.Path, \"/\"); p {\n"+
				"\t\tcase \"/iam/v1/authorize\":\n\t\t\tw.WriteHeader(http.StatusOK)\n"+
				"\t\tdefault:\n\t\t\tnext.ServeHTTP(w, r)\n\t\t}\n\t})\n}\n")
		}, []string{"по пути запроса в теле обработчика", "switch по пути"}},

		{"X9d_manual_routing_prefix_match", func(f *ceremonyFixture) {
			ceremonyManualOnMetrics(f, ceremonyManualSource("\n\t\"strings\"", "",
				`if strings.HasPrefix(r.URL.Path, "/iam/v1/auth")`, "w.WriteHeader(http.StatusOK)"))
		}, []string{"по пути запроса в теле обработчика", "сопоставление пути функцией strings.HasPrefix"}},

		{"X9e_manual_routing_through_the_request_url_value", func(f *ceremonyFixture) {
			ceremonyManualOnMetrics(f, ceremonyManualSource("", "",
				`if u := r.URL; u.Path == "/iam/v1/authorize"`, "w.WriteHeader(http.StatusOK)"))
		}, []string{"по пути запроса в теле обработчика", "сравнение пути"}},

		{"X10_declared_leaf_on_a_second_place", func(f *ceremonyFixture) {
			serve(f, anchorMetrics, "metricsMux.Handle(cfg.AuthN.TokenSigning.ResolveKeySetPath(), authorizehttp.New())")
		}, []string{"не сводится к значению", "KeySetPath", "cmd/kaname/serve.go:"}},

		// X11–X20 — формы рождения мультиплексора, регистрации и пути из
		// опытов приёмки проверки, круг 1.
		{"X11_zero_value_mux_on_a_new_surface", func(f *ceremonyFixture) {
			f.insertBefore(ceremonyRootDir, "serve.go", "", anchorSurfaces,
				"var ceremonyMux http.ServeMux\nceremonyMux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())\n"+
					ceremonySurfaceBlock("ceremonyExtraSurface", "&ceremonyMux"))
			f.appendRaised("{knobMetrics, ceremonyExtraSurface}")
		}, []string{"эндпоинт авторизации", "2 поверхностях", "лишняя поверхность пробы"}},

		{"X12_new_builtin_mux_on_a_new_surface", func(f *ceremonyFixture) {
			f.insertBefore(ceremonyRootDir, "serve.go", "", anchorSurfaces,
				"ceremonyMux := new(http.ServeMux)\nceremonyMux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())\n"+
					ceremonySurfaceBlock("ceremonyExtraSurface", "ceremonyMux"))
			f.appendRaised("{knobMetrics, ceremonyExtraSurface}")
		}, []string{"эндпоинт авторизации", "2 поверхностях", "лишняя поверхность пробы"}},

		{"X12b_composite_literal_mux_on_a_new_surface", func(f *ceremonyFixture) {
			f.insertBefore(ceremonyRootDir, "serve.go", "", anchorSurfaces,
				"ceremonyMux := &http.ServeMux{}\nceremonyMux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())\n"+
					ceremonySurfaceBlock("ceremonyExtraSurface", "ceremonyMux"))
			f.appendRaised("{knobMetrics, ceremonyExtraSurface}")
		}, []string{"эндпоинт авторизации", "2 поверхностях", "лишняя поверхность пробы"}},

		{"X13_registration_in_a_goroutine", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, "go jwksMux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"X14_registration_in_a_closure", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, "func() { jwksMux.Handle(authorizehttp.AuthorizePath, authorizehttp.New()) }()")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"X15_path_from_a_function_return", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_path.go", ceremonyImportLine,
				"func ceremonyAuthorizePath() string { return authorizehttp.AuthorizePath }")
			serve(f, anchorIntrospect, "jwksMux.Handle(ceremonyAuthorizePath(), authorizehttp.New())")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"X16_path_from_a_package_var", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_path.go", ceremonyImportLine, "var ceremonyPath = authorizehttp.AuthorizePath")
			serve(f, anchorIntrospect, "jwksMux.Handle(ceremonyPath, authorizehttp.New())")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"X17_path_join", func(f *ceremonyFixture) {
			f.addImport(ceremonyRootDir, "serve.go", `"path"`)
			serve(f, anchorIntrospect, `jwksMux.Handle(path.Join("/iam/v1", "authorize"), authorizehttp.New())`)
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"X18_mount_helper_in_the_ceremony_package", func(f *ceremonyFixture) {
			f.add(fixtureCeremonyPkg, "mount.go", "package authorizehttp\n\nimport \"net/http\"\n\n"+
				"// Mount — помощник монтажа.\nfunc Mount(m *http.ServeMux) { m.Handle(AuthorizePath, New()) }\n")
			serve(f, anchorIntrospect, "authorizehttp.Mount(jwksMux)")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"X19_typed_string_const", func(f *ceremonyFixture) {
			f.add(ceremonyRootDir, "ceremony_probe_path.go",
				"package main\n\ntype ceremonyRoute string\n\nconst ceremonyRouteAuthorize ceremonyRoute = \"/iam/v1/authorize\"\n")
			serve(f, anchorIntrospect, "jwksMux.Handle(string(ceremonyRouteAuthorize), authorizehttp.New())")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"X20_registrar_struct_method", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_reg.go", "\t\"net/http\""+ceremonyImportLine,
				"type ceremonyRegistrar struct{ mux *http.ServeMux }\n\n"+
					"func (r ceremonyRegistrar) add() { r.mux.Handle(authorizehttp.AuthorizePath, authorizehttp.New()) }")
			serve(f, anchorIntrospect, "ceremonyRegistrar{mux: jwksMux}.add()")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"I36_delegation_deeper_than_the_limit", func(f *ceremonyFixture) {
			n := check.CeremonyResolveDepthLimit + 4
			f.add(ceremonyRootDir, "ceremony_probe_layers.go", ceremonyLayersSource(n))
			f.replaceExpr(ceremonyRootDir, "serve.go", "", "Handler: metricsMux",
				"Handler: "+ceremonyLayersCall(n, "metricsMux"))
		}, []string{"обрезано на глубине", fmt.Sprint(check.CeremonyResolveDepthLimit)}},

		// D — регистратор за встроенными интерфейсами (рецензия стиля, круг 2).
		// Цикл встраивания отличает множество пройденных пар (значение, метод),
		// а не глубина: пятый слой не отбрасывается молча, даже когда у той же
		// переменной нашлась пустышка.
		{"D4n_registrar_behind_four_layers_next_to_a_no_op", func(f *ceremonyFixture) {
			ceremonyLayeredRegistrar(f, 4, true, "jwksMux")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"D5n_registrar_behind_five_layers_next_to_a_no_op", func(f *ceremonyFixture) {
			ceremonyLayeredRegistrar(f, 5, true, "jwksMux")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		// Часть получателей не прослежена (регистратор пришёл сквозь пустой
		// интерфейс), часть — пустышка: вызов «не прослежен», а не молчание.
		{"D6_registrar_through_an_empty_interface_next_to_a_no_op", func(f *ceremonyFixture) {
			ceremonyLayeredRegistrar(f, 1, true, "ceremonyAny.(ceremonyReg)")
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorIntrospect, "var ceremonyAny any = jwksMux")
		}, []string{"не прослежен", "ceremonyX.Handle"}},

		// D9, D10 — остальные ветки отказа диспетчеризации под той же
		// пустышкой: получатель не своего типа (адаптер над методом
		// мультиплексора) — прямо и за слоем, где отказ приходит из вложенной
		// диспетчеризации. D6 держит лишь слой без значений.
		{"D9_registrar_adapter_over_a_mux_method_next_to_a_no_op", func(f *ceremonyFixture) {
			ceremonyAdaptedRegistrar(f, 0, true)
		}, []string{"не прослежен", "ceremonyX.Handle"}},

		{"D10_registrar_adapter_behind_a_layer_next_to_a_no_op", func(f *ceremonyFixture) {
			ceremonyAdaptedRegistrar(f, 1, true)
		}, []string{"не прослежен", "ceremonyX.Handle"}},

		// Z — монтировщик за интерфейсом, чей получатель рождён не литералом
		// структуры (приёмка проверки, круг 2).
		{"Z1_mounter_behind_an_interface_named_non_struct_receiver", func(f *ceremonyFixture) {
			ceremonyMounter(f, "type ceremonyIntMount int", "ceremonyIntMount")
			serve(f, anchorIntrospect, "var ceremonyM ceremonyMounter = ceremonyIntMount(0)\nceremonyM.Mount(jwksMux)")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"Z1c_same_receiver_called_directly", func(f *ceremonyFixture) {
			ceremonyMounter(f, "type ceremonyIntMount int", "ceremonyIntMount")
			serve(f, anchorIntrospect, "ceremonyIntMount(0).Mount(jwksMux)")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"Z2_mounter_behind_an_interface_zero_value_struct", func(f *ceremonyFixture) {
			ceremonyMounter(f, "type ceremonyStructMount struct{}", "ceremonyStructMount")
			serve(f, anchorIntrospect, "var ceremonyS ceremonyStructMount\nvar ceremonyM ceremonyMounter = ceremonyS\nceremonyM.Mount(jwksMux)")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"Z2b_mounter_behind_an_interface_new_struct", func(f *ceremonyFixture) {
			ceremonyMounter(f, "type ceremonyStructMount struct{}", "*ceremonyStructMount")
			serve(f, anchorIntrospect, "var ceremonyM ceremonyMounter = new(ceremonyStructMount)\nceremonyM.Mount(jwksMux)")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"Z2c_mounter_behind_an_interface_zero_field_of_a_holder", func(f *ceremonyFixture) {
			ceremonyMounter(f, "type ceremonyStructMount struct{}\n\ntype ceremonyDeps struct{ am ceremonyStructMount }", "ceremonyStructMount")
			serve(f, anchorIntrospect, "var ceremonyD ceremonyDeps\nvar ceremonyM ceremonyMounter = ceremonyD.am\nceremonyM.Mount(jwksMux)")
		}, []string{"передан методу интерфейса", "ceremonyMounter.Mount"}},

		// Z3–Z12 — формы опытов приёмки проверки, круг 2, на которых гейт
		// краснел и без правки: в перечне они затем, чтобы красное держала
		// проба, а не опыт одноразовой копии. Основание — у каждой.
		//
		// Z3: получатель монтировщика — функция своего типа, реализации у него
		// нет; мультиплексор, отданный такому вызову, уходит из наблюдения.
		{"Z3_mounter_behind_an_interface_func_adapter", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_mounter.go", "\t\"net/http\"", ceremonyMounterIface+
				"type ceremonyMountFunc func(*http.ServeMux)\n\nfunc (fn ceremonyMountFunc) Mount(m *http.ServeMux) { fn(m) }")
			serve(f, anchorIntrospect, "var ceremonyM ceremonyMounter = ceremonyMountFunc(func(m *http.ServeMux) "+
				ceremonyMountBody+")\nceremonyM.Mount(jwksMux)")
		}, []string{"передан методу интерфейса", "ceremonyMounter.Mount"}},

		// Z4, Z5: метод мультиплексора значением течёт в параметр функции и в
		// поле структуры — X1 держит лишь локальную переменную.
		{"Z4_mux_method_value_passed_as_an_argument", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_with.go", "\t\"net/http\""+ceremonyImportLine,
				"func ceremonyWith(reg func(string, http.Handler)) {\n\treg(authorizehttp.AuthorizePath, authorizehttp.New())\n}")
			serve(f, anchorIntrospect, "ceremonyWith(jwksMux.Handle)")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"Z5_mux_method_value_in_a_struct_field", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_holder.go", "\t\"net/http\"",
				"type ceremonyHolder struct{ reg func(string, http.Handler) }")
			serve(f, anchorIntrospect, "ceremonyH := ceremonyHolder{reg: jwksMux.Handle}\n"+
				"ceremonyH.reg(authorizehttp.AuthorizePath, authorizehttp.New())")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		// Z6: функция регистрации на общем мультиплексоре процесса, взятая
		// значением; общий мультиплексор отдан поддереву зеркала. Прямой вызов
		// держит I26, делегирование без регистрации — близнец Z6t.
		{"Z6_default_mux_function_value", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, "jwksMux.Handle(\"/iam/v1/\", http.DefaultServeMux)\n"+
				"ceremonyHandle := http.Handle\nceremonyHandle(authorizehttp.AuthorizePath, authorizehttp.New())")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		// Z7, Z8: регистрация в литерале функции, отданном чужому коду
		// (sync.Once), и отложенным вызовом — X13 и X14 держат go и вызов на
		// месте.
		{"Z7_registration_in_sync_once", func(f *ceremonyFixture) {
			f.addImport(ceremonyRootDir, "serve.go", `"sync"`)
			serve(f, anchorIntrospect, "var ceremonyOnce sync.Once\n"+
				"ceremonyOnce.Do(func() { jwksMux.Handle(authorizehttp.AuthorizePath, authorizehttp.New()) })")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"Z8_deferred_registration", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, "defer jwksMux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		// Z9: мультиплексор рождён переменной пакета, регистрация — в init.
		{"Z9_package_mux_registered_in_init", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_global.go", "\t\"net/http\""+ceremonyImportLine,
				"var ceremonyGlobalMux = http.NewServeMux()\n\n"+
					"func init() {\n\tceremonyGlobalMux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())\n}")
			serve(f, anchorIntrospect, `jwksMux.Handle("/iam/v1/", ceremonyGlobalMux)`)
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		// Z11: срезанный префикс приводит запрос координаты к регистрации
		// внутреннего мультиплексора — положительная пара близнеца W7. Обработчик
		// нейтральный, как у W7: пара различается только путём.
		{"Z11_strip_prefix_onto_the_coordinate", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, "ceremonyInner := http.NewServeMux()\n"+
				"ceremonyInner.Handle(\"/v1/authorize\", "+ceremonyNeutralHandler+")\n"+
				"jwksMux.Handle(\"/iam/\", http.StripPrefix(\"/iam\", ceremonyInner))")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		// Z12: HandlePath мультиплексора шлюза значением — I2 держит прямой
		// вызов.
		{"Z12_gateway_handle_path_method_value", func(f *ceremonyFixture) {
			f.addImport("internal/restfront", "front.go", anchorCeremonyImp)
			f.insertAfter("internal/restfront", "front.go", "NewPublic", "mux := newMux()",
				"ceremonyHandlePath := mux.HandlePath\n_ = ceremonyHandlePath(http.MethodGet, authorizehttp.AuthorizePath, "+
					"func(w http.ResponseWriter, _ *http.Request, _ map[string]string) { w.WriteHeader(http.StatusOK) })")
		}, []string{"эндпоинт авторизации", "2 поверхностях", "собственный публичный REST-фронт"}},

		// S1 — путь регистрации сквозь цикл записей P → Q → S → P. Первой
		// сводится регистрация по P (безвредная: координата в ней с хвостом),
		// второй — по S. Значение S не зависит от того, кого свели первым.
		// Обработчик нейтральный, как у близнеца S1t: предмет — путь.
		{"S1_path_through_a_write_cycle_resolved_second", func(f *ceremonyFixture) {
			f.add(ceremonyRootDir, "ceremony_probe_cycle.go", ceremonyCycleVarsSource)
			serve(f, anchorIntrospect, "jwksMux.Handle(ceremonyP+\"/probe-x\", "+ceremonyNeutralHandler+")\n"+
				"jwksMux.Handle(ceremonyS, "+ceremonyNeutralHandler+")")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		{"S1c_path_through_a_write_cycle_alone", func(f *ceremonyFixture) {
			f.add(ceremonyRootDir, "ceremony_probe_cycle.go", ceremonyCycleVarsSource)
			serve(f, anchorIntrospect, "jwksMux.Handle(ceremonyS, "+ceremonyNeutralHandler+")")
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		// TY1 — течёт ли значение типа, не зависит от того, о каком типе цикла
		// спросили первым.
		{"TY1_value_type_asked_second_in_a_type_cycle", func(f *ceremonyFixture) {
			f.add(ceremonyRootDir, "ceremony_probe_types.go", ceremonyCycleTypesSource(true))
			serve(f, anchorIntrospect, ceremonyThroughCycleTypes)
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		// I40 — путь, выведенный из самого себя склейкой в цикле: координата
		// рождается лишь на третьем проходе, и одна развёртка её не видит.
		// Множество значений не ограничено — это лист, а не усечение.
		{"I40_path_derived_from_itself_by_concatenation", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, "ceremonyPath := \"\"\n"+
				"for _, ceremonySeg := range []string{\"/iam\", \"/v1\", \"/authorize\"} {\n"+
				"\tceremonyPath = ceremonyPath + ceremonySeg\n}\n"+
				"jwksMux.Handle(ceremonyPath, authorizehttp.New())")
		}, []string{"не сводится к значению", "выводится из самого себя"}},

		{"TY1c_value_type_asked_first_in_a_type_cycle", func(f *ceremonyFixture) {
			f.add(ceremonyRootDir, "ceremony_probe_types.go", ceremonyCycleTypesSource(false))
			serve(f, anchorIntrospect, ceremonyThroughCycleTypes)
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},

		// H — ОБРАБОТЧИК координаты под ЧУЖИМ путём (приёмка проверки, круг 3,
		// опыт H1). Путь координаты на второй поверхности не резолвится, а
		// эндпоинт смонтирован — «НИГДЕ больше» нарушено не путём, а монтажом.
		// H1 — опыт дословно: живой обработчик выдачи на поверхности
		// диагностики.
		{"H1_issuing_handler_under_another_path_on_the_metrics_surface", func(f *ceremonyFixture) {
			serve(f, anchorTokenMount, `metricsMux.Handle("/internal/client-token", clientTokenHandler)`)
		}, []string{"токен-эндпоинт", "обработчик координаты", "диагностика (/metrics)", "/internal/client-token"}},

		// H2 — второй экземпляр эндпоинта (тот же конструктор, другой вызов)
		// под соседним путём на внутреннем зеркале.
		{"H2_ceremony_handler_under_a_neighbour_path_on_an_internal_mux", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, `jwksMux.Handle("/iam/v1/authorizex", authorizehttp.New())`)
		}, []string{"эндпоинт авторизации", "обработчик координаты", reachInternalMark, "/iam/v1/authorizex"}},

		// H4 — обработчик координаты прошёл через пустой интерфейс: координата
		// резолвится, а до какого значения — нет. Где ещё смонтирован тот же
		// эндпоинт, гейт сказать не может, и это находка, а не молчание.
		{"H4_coordinate_handler_through_an_empty_interface", func(f *ceremonyFixture) {
			f.insertBefore(ceremonyRootDir, "serve.go", "", anchorTokenMount,
				"var ceremonyAnyHandler any = clientTokenHandler")
			f.replaceExpr(ceremonyRootDir, "serve.go", "", anchorTokenMount,
				"mux.Handle(clienttokenhttp.TokenPath, ceremonyAnyHandler.(http.Handler))")
		}, []string{"токен-эндпоинт", "обработчик не прослежен"}},

		// Y4i — пара близнеца Y4 на один факт (путь): нейтральный обработчик
		// РЕЗОЛВИТ координату. Без неё молчание Y4 могло бы держаться
		// обработчиком, который запрос не обслуживает, а не точностью пути.
		{"Y4i_neutral_handler_on_the_coordinate_on_an_internal_mux", func(f *ceremonyFixture) {
			serve(f, anchorIntrospect, `jwksMux.Handle("/iam/v1/authorize", `+ceremonyNeutralHandler+`)`)
		}, []string{"эндпоинт авторизации", "2 поверхностях", reachInternalMark}},
	}
}

// ceremonyNeutralHandler — обработчик, который обслуживает запрос и НЕ
// является эндпоинтом церемонии: у близнецов, чей предмет — путь, обработчик
// не должен быть вторым фактом.
const ceremonyNeutralHandler = "http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})"

// TestCeremonySurfaceInjections — новая инъекция: каждая краснеет, и
// находка называет свою причину.
func TestCeremonySurfaceInjections(t *testing.T) {
	for _, inj := range ceremonyInjections() {
		t.Run(inj.id, func(t *testing.T) {
			f := newCeremonyFixture(t)
			inj.edit(f)
			report := f.mustJudge(fixtureCeremonyCoordinates())
			got := requireFinding(t, report, inj.want...)
			t.Logf("находок %d; своя: %s", len(report.Findings), got)
		})
	}
}

// TestCeremonySurfaceInjectionEighthSurfaceIsCensused — перепись I3: восьмая
// поверхность насчитана и объявлением, и элементом среза подъёма.
func TestCeremonySurfaceInjectionEighthSurfaceIsCensused(t *testing.T) {
	f := newCeremonyFixture(t)
	ceremonyEighthSurface(f)
	c := f.mustJudge(fixtureCeremonyCoordinates()).Census
	if c.SurfaceDecls != 8 || c.RaisedSurfaces != 8 {
		t.Errorf("перепись I3: объявлений %d, поднимается %d — ожидалось 8 и 8", c.SurfaceDecls, c.RaisedSurfaces)
	}
}

// TestCeremonySurfaceRecursiveFactoryIsJudgedToTheFixedPoint — законная
// рекурсивная фабрика мультиплексора (самовызов и взаимный вызов): разбор
// доходит до неподвижной точки раньше предела, близнец молчит, и молчит,
// ВИДЯ маршруты фабрики, а не по слепоте.
func TestCeremonySurfaceRecursiveFactoryIsJudgedToTheFixedPoint(t *testing.T) {
	for _, tc := range []struct {
		id     string
		source string
		mount  string
		routes []string
	}{
		{"self_call", ceremonyChainSelfSource("", `"/probe-chain/x"`, "http.NotFoundHandler()"),
			`metricsMux.Handle("/probe-chain/", ceremonyChainSelf(3))`, []string{"/probe-chain/x"}},
		{"mutual_call", ceremonyChainMutualSource("", `"/probe-chain/x"`, `"/probe-chain/y"`, "http.NotFoundHandler()"),
			`metricsMux.Handle("/probe-chain/", ceremonyChainEven(1))`, []string{"/probe-chain/x", "/probe-chain/y"}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			f := newCeremonyFixture(t)
			f.add(ceremonyRootDir, "ceremony_probe_chain.go", tc.source)
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorMetrics, tc.mount)
			report, err := f.judge(fixtureCeremonyCoordinates())
			if err != nil {
				t.Fatalf("законная рекурсивная фабрика: гейт не исполнился — разбор обязан сходиться на ней: %v", err)
			}
			t.Logf("%s", report.Census.Summary())
			requireSilent(t, report)
			for _, want := range tc.routes {
				if !surfaceHasRoute(report, "диагностика (/metrics)", want) {
					t.Errorf("маршрут фабрики %s не попал в таблицу поверхности диагностики — близнец молчит по слепоте", want)
				}
			}
		})
	}
}

// surfaceHasRoute — выведенная таблица поверхности несёт образец.
func surfaceHasRoute(report check.CeremonySurfaceReport, surface, pattern string) bool {
	for _, s := range report.Surfaces {
		if s.Name != surface {
			continue
		}
		for _, p := range s.Patterns {
			if p == pattern {
				return true
			}
		}
	}
	return false
}

// TestCeremonySurfaceUnconvergedFlowIsNotAVerdict — разбор, не дошедший до
// неподвижной точки за предел раундов, — «гейт не исполнился», а не вердикт.
//
// Вход — законная цепочка возвратов длиннее предела: разбор продвигает
// значение на одно звено за раунд и за предел не доходит до дна.
func TestCeremonySurfaceUnconvergedFlowIsNotAVerdict(t *testing.T) {
	f := newCeremonyFixture(t)
	f.add(ceremonyRootDir, "ceremony_probe_deep.go", ceremonyDeepChainSource(check.CeremonySolveRoundLimit+8))
	f.insertAfter(ceremonyRootDir, "serve.go", "", anchorMetrics, `metricsMux.Handle("/probe-deep/", ceremonyDeep0())`)
	report, err := f.judge(fixtureCeremonyCoordinates())
	if err == nil {
		if report.Census.SolveRounds < check.CeremonySolveRoundLimit {
			t.Fatalf("условие не создано: цепочка сошлась за %d раундов при пределе %d — удлини её",
				report.Census.SolveRounds, check.CeremonySolveRoundLimit)
		}
		t.Fatalf("ИНЪЕКЦИЯ НЕ ПОЙМАНА: разбор не дошёл до неподвижной точки (раундов %d при пределе %d), а гейт "+
			"выдал вердикт — находок %d; перепись: %s", report.Census.SolveRounds, check.CeremonySolveRoundLimit,
			len(report.Findings), report.Census.Summary())
	}
	for _, want := range []string{"неподвижн", fmt.Sprint(check.CeremonySolveRoundLimit)} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет причину («%s»): %v", want, err)
		}
	}
}

// TestCeremonySurfaceResolveBudgetIsNotAVerdict — обратный разбор пути,
// исчерпавший бюджет шагов, — «гейт не исполнился», а не вердикт.
//
// Вход — законный, но переборный: n строковых переменных, каждая записана из
// каждой другой. Цикл копирований обрезается на узле стека, и результаты под
// обрезкой не кэшируются как окончательные — число путей растёт как (n-1)!.
func TestCeremonySurfaceResolveBudgetIsNotAVerdict(t *testing.T) {
	const n = 11
	var b strings.Builder
	b.WriteString("package main\n\nvar (\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "\tceremonyV%d string\n", i)
	}
	b.WriteString(")\n\nfunc init() {\n")
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i != j {
				fmt.Fprintf(&b, "\tceremonyV%d = ceremonyV%d\n", i, j)
			}
		}
	}
	b.WriteString("\tceremonyV0 = \"/probe-budget\"\n}\n")
	f := newCeremonyFixture(t)
	f.add(ceremonyRootDir, "ceremony_probe_budget.go", b.String())
	f.insertAfter(ceremonyRootDir, "serve.go", "", anchorMetrics, "metricsMux.Handle(ceremonyV1, http.NotFoundHandler())")
	report, err := f.judge(fixtureCeremonyCoordinates())
	if err == nil {
		t.Fatalf("ИНЪЕКЦИЯ НЕ ПОЙМАНА: обратный разбор (шагов %d) выдал вердикт — находок %d; перепись: %s",
			report.Census.ResolveSteps, len(report.Findings), report.Census.Summary())
	}
	if !strings.Contains(err.Error(), "бюджет") {
		t.Fatalf("отказ не называет причину (бюджет шагов обратного разбора): %v", err)
	}
}

// TestCeremonySurfaceInjectionLiveCoordinate — старая инъекция (I16): вторая
// регистрация ЖИВОЙ координаты на копии живого корня.
func TestCeremonySurfaceInjectionLiveCoordinate(t *testing.T) {
	f := newRootCopyFixture(t)
	f.insertAfter(ceremonyRootDir, "serve.go", "", anchorIntrospect,
		"jwksMux.Handle(clienttokenhttp.TokenPath, introspect)")
	report := f.mustJudge(liveCeremonyCoordinates())
	requireFinding(t, report, "токен-эндпоинт", "2 поверхностях", "положительный контроль")
}

// TestCeremonySurfaceFindingNamesBothRegistrations — текст находки (I22):
// координата, ОБЕ поверхности словом и досягаемостью, и строка КАЖДОЙ
// регистрации. «count 2 != 1» находкой не считается.
func TestCeremonySurfaceFindingNamesBothRegistrations(t *testing.T) {
	f := newCeremonyFixture(t)
	f.insertAfter(ceremonyRootDir, "serve.go", "", anchorIntrospect,
		"jwksMux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())")
	mountLine := f.lineOf(ceremonyRootDir, "serve.go", "mux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())")
	injLine := f.lineOf(ceremonyRootDir, "serve.go", "jwksMux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())")
	report := f.mustJudge(fixtureCeremonyCoordinates())
	requireFinding(t, report,
		fixtureAuthorizePath,
		"«выдача токенов (/iam/token, /iam/v1/token)» "+reachExternalMark,
		"«зеркало публичных ключей проверки (/.well-known/jwks.json)» "+reachInternalMark,
		fmt.Sprintf("cmd/kaname/serve.go:%d", mountLine),
		fmt.Sprintf("cmd/kaname/serve.go:%d", injLine))
}

// TestCeremonySurfacePremiseRedsOnAnEmptyWalk — I18: корень, в котором нет
// ни одного прод-файла, — не «ноль находок», а отказ предпосылки.
func TestCeremonySurfacePremiseRedsOnAnEmptyWalk(t *testing.T) {
	f := newRootCopyFixture(t)
	f.pkgs[ceremonyRootDir].files = map[string][]byte{
		"only_probe_test.go": []byte("package main\n\nimport \"testing\"\n\nfunc TestNothing(t *testing.T) {}\n"),
	}
	report := f.mustJudge(liveCeremonyCoordinates())
	requireFinding(t, report, "файлов корня 0")
	if report.Census.SurfaceDecls != 0 {
		t.Errorf("на пустом корне насчитано объявлений поверхности %d", report.Census.SurfaceDecls)
	}
}

// TestCeremonySurfacePremiseRedsOnAForeignRoot — I18: неверный корень модуля
// — «не исполнилось», а не зелёное.
//
// Отказ держит ГЕЙТ, а не окружение go: при GOFLAGS=-mod=mod `go list` вне
// модуля способен назвать пакет из кэша модулей, и тогда судилась бы чужая
// ревизия. Поэтому корень пакета обязан быть главным модулем, лежащим ровно
// в названном корне; подкаталог модуля — тоже чужой корень.
func TestCeremonySurfacePremiseRedsOnAForeignRoot(t *testing.T) {
	judge := func(t *testing.T, root string) error {
		t.Helper()
		_, err := check.JudgeCeremonySurfaces(t.Context(), check.CeremonySurfaceSpec{
			ModuleRoot:  root,
			RootPackage: ceremonyModulePath(t, ceremonyModuleRoot(t)) + "/" + ceremonyRootDir,
		}, liveCeremonyCoordinates())
		return err
	}
	t.Run("directory_without_a_module", func(t *testing.T) {
		if err := judge(t, t.TempDir()); err == nil {
			t.Fatalf("гейт на каталоге без модуля вернул вердикт — обязан был отказаться исполняться")
		}
	})
	t.Run("directory_without_a_module_under_mod_mod", func(t *testing.T) {
		t.Setenv("GOFLAGS", "-mod=mod")
		t.Setenv("GOPROXY", "off")
		if err := judge(t, t.TempDir()); err == nil {
			t.Fatalf("гейт на каталоге без модуля под GOFLAGS=-mod=mod вернул вердикт — обязан был отказаться")
		}
	})
	t.Run("subdirectory_of_the_module", func(t *testing.T) {
		err := judge(t, filepath.Join(ceremonyModuleRoot(t), "internal"))
		if err == nil {
			t.Fatalf("гейт на подкаталоге модуля вернул вердикт — судился бы модуль, а не названный корень")
		}
		if !strings.Contains(err.Error(), "корень модуля") {
			t.Fatalf("отказ не называет расхождение корня модуля: %v", err)
		}
	})
}

// TestCeremonySurfaceCensusCountsEveryRegistration — регистрация, которую
// разбор видит, попадает в графу переписи, даже если её мультиплексор не
// прослежен и сама она недостижима: иначе «регистраций столько-то» лжёт о
// прочитанном.
func TestCeremonySurfaceCensusCountsEveryRegistration(t *testing.T) {
	control := newCeremonyFixture(t).mustJudge(fixtureCeremonyCoordinates()).Census
	f := newCeremonyFixture(t)
	ceremonyRootFile(f, "ceremony_probe_dead.go", "\t\"net/http\""+ceremonyImportLine,
		"func ceremonyUnusedMount(m *http.ServeMux) {\n\tm.Handle(authorizehttp.AuthorizePath, authorizehttp.New())\n}")
	report := f.mustJudge(fixtureCeremonyCoordinates())
	requireSilent(t, report)
	got := report.Census
	if got.UnreachableRegistrations != control.UnreachableRegistrations+1 {
		t.Errorf("регистрация в недостижимой функции на непрослеженном мультиплексоре не насчитана: "+
			"в недостижимом коде %d, в контроле %d", got.UnreachableRegistrations, control.UnreachableRegistrations)
	}
	t.Logf("контроль: %s", control.Summary())
}

// TestCeremonySurfacePremiseRedsOnABypassedBuilder — I19: поверхность,
// собранная в обход общего помощника.
func TestCeremonySurfacePremiseRedsOnABypassedBuilder(t *testing.T) {
	f := newCeremonyFixture(t)
	f.insertBefore(ceremonyRootDir, "serve.go", "", anchorSurfaces, `bypassSurface, err := servicecontract.NewSurface(servicecontract.Surface{
		Service: "kaname",
		Name:    "поверхность в обход помощника",
		Mode:    surfaceMode,
		Logger:  logger,
		Addr:    addrAxis("", "проба"),
		Handler: http.NotFoundHandler(),
		Reach:   servicecontract.ReachClusterInternal,
		Auth:    servicecontract.NotApplicable[servicecontract.SurfaceAuthMech]("проба"),
	})
	if err != nil {
		return err
	}`)
	f.appendRaised("{knobMetrics, bypassSurface}")
	report := f.mustJudge(fixtureCeremonyCoordinates())
	requireFinding(t, report, "в обход", "NewSurface")
}

// TestCeremonySurfacePremiseRedsOnARaisedCountMismatch — I20: элементов
// среза подъёма больше, чем объявлений поверхности.
func TestCeremonySurfacePremiseRedsOnARaisedCountMismatch(t *testing.T) {
	f := newCeremonyFixture(t)
	f.appendRaised("{knobMetrics, metricsSurface}")
	report := f.mustJudge(fixtureCeremonyCoordinates())
	requireFinding(t, report, "срез подъёма", "объявлений поверхности")
}

// TestCeremonySurfacePremiseRedsOnAParseError — I21: синтаксическая ошибка в
// файле корня — отказ с текстом разбора, файл не пропускается молча.
func TestCeremonySurfacePremiseRedsOnAParseError(t *testing.T) {
	f := newCeremonyFixture(t)
	f.insertAfter(ceremonyRootDir, "serve.go", "", anchorTokenMount, "mux.Handle(")
	_, err := f.judge(fixtureCeremonyCoordinates())
	if err == nil {
		t.Fatalf("синтаксическая ошибка в корне дала вердикт — файл пропущен молча")
	}
	if !strings.Contains(err.Error(), "serve.go:") {
		t.Fatalf("отказ разбора не называет файл и строку: %v", err)
	}
}

// TestCeremonySurfaceWrittenCoordinateExpiresWithItsProducer — граница
// выписанной координаты истекает сама: появился производитель — находка.
func TestCeremonySurfaceWrittenCoordinateExpiresWithItsProducer(t *testing.T) {
	f := newCeremonyFixture(t)
	coords := fixtureCeremonyCoordinates()
	coords[1].Written = true
	report := f.mustJudge(coords)
	requireFinding(t, report, "выписана литералом", "authorizehttp.AuthorizePath")
}

// ceremonyTwin — законный близнец: обязан молчать.
type ceremonyTwin struct {
	id   string
	edit func(f *ceremonyFixture)
}

func ceremonyTwins() []ceremonyTwin {
	return []ceremonyTwin{
		{"T8_coordinate_in_text", func(f *ceremonyFixture) {
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorIntrospect,
				"// jwksMux.Handle(authorizehttp.AuthorizePath, h) — так НЕ монтируется: /iam/v1/authorize\n"+
					`logger.Info("/iam/v1/authorize", "coordinate", authorizehttp.AuthorizePath)`)
		}},
		{"T9_coordinate_in_test_file", func(f *ceremonyFixture) {
			f.add(ceremonyRootDir, "ceremony_probe_test.go", "package main\n\nimport \"net/http\"\n\n"+
				"func init() { m := http.NewServeMux(); m.Handle(\"/iam/v1/authorize\", http.NotFoundHandler()) }\n")
		}},
		{"T10_two_level_mount", func(f *ceremonyFixture) {
			f.replaceExpr(ceremonyRootDir, "serve.go", "", "mux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())",
				"mux.Handle(authorizehttp.AuthorizePath, authorizehttp.NewRouted())")
			f.replaceExpr(ceremonyRootDir, "serve.go", "", "mux.Handle(authorizehttp.DiscoveryPath, authorizehttp.New())",
				"mux.Handle(authorizehttp.DiscoveryPath, authorizehttp.NewRouted())")
		}},
		{"T11_method_pattern_on_the_issuing_surface", func(f *ceremonyFixture) {
			f.replaceExpr(ceremonyRootDir, "serve.go", "", "mux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())",
				`mux.Handle("GET "+authorizehttp.AuthorizePath, authorizehttp.New())`)
		}},
		{"T12_alias_and_local_const_on_the_issuing_surface", func(f *ceremonyFixture) {
			f.addImport(ceremonyRootDir, "serve.go", `az "github.com/PRO-Robotech/kaname/internal/handler/authorizehttp"`)
			f.replaceExpr(ceremonyRootDir, "serve.go", "", "mux.Handle(authorizehttp.AuthorizePath, authorizehttp.New())",
				"mux.Handle(az.AuthorizePath, az.New())")
			f.replaceExpr(ceremonyRootDir, "serve.go", "", "mux.Handle(authorizehttp.DiscoveryPath, authorizehttp.New())",
				"mux.Handle(ceremonyDiscoveryLocal, authorizehttp.New())")
			f.insertBefore(ceremonyRootDir, "serve.go", "", anchorTokenMount,
				"const ceremonyDiscoveryLocal = \"/.well-known\" + \"/oauth-authorization-server\"")
		}},
		{"T13_issuing_surface_disabled_on_this_landing", func(f *ceremonyFixture) {
			f.replaceExpr(ceremonyRootDir, "serve.go", "", `registryTokenAddr != ""`, "false")
		}},
		// Y1–Y5 — законные близнецы приёмки проверки, круг 1.
		{"Y1_method_pattern_second_registration_on_the_issuing_mux", func(f *ceremonyFixture) {
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorTokenMount,
				`mux.Handle("POST "+authorizehttp.AuthorizePath, authorizehttp.New())`)
		}},
		{"Y2_client_side_use_of_the_coordinate", func(f *ceremonyFixture) {
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorIntrospect,
				`_, _ = http.NewRequest(http.MethodGet, "https://kaname.invalid"+authorizehttp.AuthorizePath, nil)`)
		}},
		{"Y3_registration_in_an_unreached_function", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_dead.go", "\t\"net/http\""+ceremonyImportLine,
				"func ceremonyUnused() {\n\tm := http.NewServeMux()\n\tm.Handle(authorizehttp.AuthorizePath, authorizehttp.New())\n}")
		}},
		// Предмет Y4 — точность ПУТИ, и обработчик у него нейтральный: эндпоинт
		// церемонии под соседним путём на внутренней поверхности — уже не
		// близнец, а находка (инъекция H2). Нейтральный обработчик координату
		// резолвит — пара на один факт, Y4i.
		{"Y4_neighbour_path_on_an_internal_mux", func(f *ceremonyFixture) {
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorIntrospect,
				`jwksMux.Handle("/iam/v1/authorizex", `+ceremonyNeutralHandler+`)`)
		}},
		{"Y5_compare_of_a_configured_url_path", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_urlcmp.go", "\t\"net/url\"",
				"func ceremonyIsAuthorize(raw string) bool {\n\tu, err := url.Parse(raw)\n"+
					"\treturn err == nil && u.Path == \"/iam/v1/authorize\"\n}")
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorIntrospect,
				`_ = ceremonyIsAuthorize("https://kaname.invalid/iam/v1/authorize")`)
		}},
		// Путь запроса, прочитанный для проверки ввода (длина) и для журнала,
		// маршрута не выбирает.
		{"T18_request_path_length_check_and_log", func(f *ceremonyFixture) {
			ceremonyManualOnMetrics(f, "package main\n\nimport (\n\t\"log/slog\"\n\t\"net/http\"\n)\n\n"+
				"func ceremonyProbeManual(next http.Handler) http.Handler {\n"+
				"\treturn http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n"+
				"\t\tif len(r.URL.Path) > 4096 {\n\t\t\tw.WriteHeader(http.StatusRequestURITooLong)\n\t\t\treturn\n\t\t}\n"+
				"\t\tslog.Info(\"запрос\", \"path\", r.URL.Path)\n\t\tnext.ServeHTTP(w, r)\n\t})\n}\n")
		}},
		// Метод ServeHTTP мультиплексора, взятый значением, делегирует ЭТОМУ
		// мультиплексору, а не становится конечной точкой: поддерево /iam/v1/
		// на внутреннем зеркале отдано мультиплексору без координат.
		{"T17_bound_serve_http_of_a_mux_without_the_coordinate", func(f *ceremonyFixture) {
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorIntrospect,
				"ceremonyOther := http.NewServeMux()\n"+
					`ceremonyOther.Handle("/iam/v1/other", http.NotFoundHandler())`+"\n"+
					`jwksMux.Handle("/iam/v1/", http.HandlerFunc(ceremonyOther.ServeHTTP))`)
		}},
		// Одна обёртка, вложенная в саму себя: значение обёртки течёт в её же
		// параметр, и прохождение запроса встречает цикл. Цикл нового маршрута
		// не даёт — и не обрезается как «слишком глубоко».
		{"T16_wrapper_nested_into_itself", func(f *ceremonyFixture) {
			f.add(ceremonyRootDir, "ceremony_probe_wrap.go", ceremonyWrapSource)
			f.replaceExpr(ceremonyRootDir, "serve.go", "", "Handler: metricsMux",
				"Handler: ceremonyProbeWrap(ceremonyProbeWrap(metricsMux))")
		}},
		// W1–W3, W7 — законные близнецы приёмки проверки, круг 2.
		{"W1_interface_registrar_with_an_own_recorder", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_rec.go", "\t\"net/http\"",
				"type ceremonyRec struct{}\n\nfunc (ceremonyRec) Handle(string, http.Handler) {}")
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorIntrospect,
				"var ceremonyRecV interface{ Handle(string, http.Handler) } = ceremonyRec{}\n"+
					"ceremonyRecV.Handle(authorizehttp.AuthorizePath, authorizehttp.New())")
		}},
		{"W2_mux_method_value_taken_not_called", func(f *ceremonyFixture) {
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorIntrospect, "_ = jwksMux.Handle")
		}},
		{"W3_method_value_on_the_issuing_mux", func(f *ceremonyFixture) {
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorTokenMount,
				"ceremonyReg := mux.Handle\nceremonyReg(\"POST \"+authorizehttp.AuthorizePath, authorizehttp.New())")
		}},
		// W7 и S1t — предмет путь, обработчик нейтральный (см. Y4).
		{"W7_strip_prefix_onto_a_neighbour_only", func(f *ceremonyFixture) {
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorIntrospect,
				"ceremonyInner := http.NewServeMux()\nceremonyInner.Handle(\"/v1/other\", "+ceremonyNeutralHandler+")\n"+
					"jwksMux.Handle(\"/iam/\", http.StripPrefix(\"/iam\", ceremonyInner))")
		}},
		// Близнец Z6 на один факт: общий мультиплексор отдан поддереву, а
		// координата на нём не зарегистрирована.
		{"Z6t_default_mux_delegated_without_a_registration", func(f *ceremonyFixture) {
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorIntrospect, `jwksMux.Handle("/iam/v1/", http.DefaultServeMux)`)
		}},
		// Регистратор за шестью слоями вокруг пустышки, а не мультиплексора:
		// глубина встраивания сама по себе не находка.
		{"D7_registrar_behind_six_layers_around_a_no_op", func(f *ceremonyFixture) {
			ceremonyLayeredRegistrar(f, 6, false, "ceremonyNop{}")
		}},
		// Слой, встроивший сам себя: цикл встраивания обходится один раз, и
		// разбор сходится.
		{"D8_layer_embedding_itself", func(f *ceremonyFixture) {
			ceremonyLayeredRegistrar(f, 1, true, "ceremonyX")
		}},
		// Близнец D9 и D10 на один факт: адаптер объявлен, переменной не отдан.
		{"D9t_registrar_adapter_declared_not_assigned", func(f *ceremonyFixture) {
			ceremonyAdaptedRegistrar(f, 0, false)
		}},
		// Монтировщик за интерфейсом с получателем-приведением монтирует
		// координату с методом на поверхности ВЫДАЧИ: получатель выведен, и
		// гейт молчит по существу, а не отказом «не прослежен».
		{"Z1t_mounter_behind_an_interface_on_the_issuing_mux", func(f *ceremonyFixture) {
			ceremonyRootFile(f, "ceremony_probe_mounter.go", "\t\"net/http\""+ceremonyImportLine,
				ceremonyMounterIface+"type ceremonyIntMount int\n\nfunc (ceremonyIntMount) Mount(m *http.ServeMux) "+
					"{\n\tm.Handle(\"POST \"+authorizehttp.AuthorizePath, authorizehttp.New())\n}")
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorTokenMount,
				"var ceremonyM ceremonyMounter = ceremonyIntMount(0)\nceremonyM.Mount(mux)")
		}},
		// Близнецы H1 на один факт. H1t_a — тот же обработчик выдачи под
		// другим путём, но на САМОЙ поверхности выдачи. H1t_b — тот же путь на
		// поверхности диагностики, но обработчик не церемонии.
		{"H1t_a_issuing_handler_under_another_path_on_the_issuing_surface", func(f *ceremonyFixture) {
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorTokenMount,
				`mux.Handle("/internal/client-token", clientTokenHandler)`)
		}},
		{"H1t_b_other_handler_under_the_same_path_on_the_metrics_surface", func(f *ceremonyFixture) {
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorTokenMount,
				`metricsMux.Handle("/internal/client-token", `+ceremonyNeutralHandler+`)`)
		}},
		// Регистрация по P из цикла записей в одиночку: координата в ней с
		// хвостом и координату не резолвит.
		{"S1t_path_through_a_write_cycle_with_a_tail", func(f *ceremonyFixture) {
			f.add(ceremonyRootDir, "ceremony_probe_cycle.go", ceremonyCycleVarsSource)
			f.insertAfter(ceremonyRootDir, "serve.go", "", anchorIntrospect,
				"jwksMux.Handle(ceremonyP+\"/probe-x\", "+ceremonyNeutralHandler+")")
		}},
	}
}

// TestCeremonySurfaceTwinsAreSilent — законные близнецы молчат, и каждая
// координата по-прежнему насчитана ровно на одной поверхности.
func TestCeremonySurfaceTwinsAreSilent(t *testing.T) {
	for _, twin := range ceremonyTwins() {
		t.Run(twin.id, func(t *testing.T) {
			f := newCeremonyFixture(t)
			twin.edit(f)
			report := f.mustJudge(fixtureCeremonyCoordinates())
			requireSilent(t, report)
			for _, name := range []string{"токен-эндпоинт", "эндпоинт авторизации", "метаданные обнаружения"} {
				if n := coordinateSurfaces(t, report, name); n != 1 {
					t.Errorf("«%s»: поверхностей %d, ожидалась одна", name, n)
				}
			}
		})
	}
}
