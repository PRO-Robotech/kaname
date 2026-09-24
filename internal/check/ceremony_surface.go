// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_surface.go — гейт ЕДИНСТВЕННОСТИ ПОВЕРХНОСТИ церемонии (kaname#320;
// приёмка LINE-A-1, сценарий LINE-A-1-23: «эндпоинты монтируются на внешней
// поверхности выдачи и НИГДЕ больше»).
//
// # Что судится
//
// Для каждой координаты — на скольких ПОВЕРХНОСТЯХ процесса она резолвится.
// Не сколько раз её упомянули и не сколько вызовов Handle её назвали:
// обработчик, отданный двум поверхностям, регистрируется один раз и
// резолвится дважды; делегирование поддерева («/iam/v1/» → чужой
// мультиплексор) не называет координату вовсе и резолвит её.
//
// # Как выводится, а не выписывается
//
//   - ПОВЕРХНОСТЬ — объявление servicecontract.Surface в модуле службы: имя,
//     досягаемость, обработчик. Перечня слушателей в гейте нет.
//   - ОБРАБОТЧИК поверхности прослеживается до мест рождения мультиплексоров
//     сквозь переприсваивания, возвраты фабрик, поля, обёртки
//     (ceremony_surface_flow.go).
//   - РЕГИСТРАЦИЯ — вызов Handle/HandleFunc на мультиплексоре net/http,
//     Handle/HandlePath на мультиплексоре шлюза и http.Handle на общем
//     мультиплексоре процесса, где бы в бинаре он ни стоял; путь сводится к
//     значению обратным разбором (ceremony_surface_resolve.go). Опознаётся
//     ВЫЗЫВАЕМЫЙ метод, а не синтаксис вызова: прямой выбор, значение метода,
//     выражение метода, метод интерфейса и параметра типа, метод, продвинутый
//     из встроенного поля, — один и тот же метод мультиплексора.
//   - «РЕЗОЛВИТСЯ» решает НАСТОЯЩИЙ мультиплексор: для каждого места рождения
//     собирается http.ServeMux (или ServeMux шлюза) из выведенных образцов, и
//     запрос координаты проходит его так же, как прошёл бы в процессе:
//     метод и хост в образце, подстановки, хвостовой слэш, перенаправление.
//     Своим разбором образца вердикт не выносится: образец расщепляется лишь
//     затем, чтобы перечислить хосты, на которые идёт запрос, и формы переписи.
//
// # Чем гейт не судит (границы, названные прямо)
//
//   - Правила HTTP контракта (.proto) читаются через порождённую привязку
//     шлюза; её сверку с контрактом держит задание конвейера generate-diff.
//   - Путь, который задаёт оператор (поле, заполняемое декодером настройки),
//     значения не имеет: он — лист ведомости с причиной, не пропуск.
//   - Маршрут, решаемый по пути запроса в теле обработчика (сравнение,
//     switch, выбор из карты, функция сопоставления над путём и над всем, что
//     из него выведено строкой; ceremony_surface_manual.go), и мультиплексор,
//     отданный чужому коду, гейт не моделирует — и потому краснеет на них, а
//     не молчит.
//   - Значения, прошедшие через пустой интерфейс, не прослеживаются; вызов
//     метода регистрации через интерфейс, который реализует мультиплексор, без
//     единой найденной реализации — находка «не прослежен», а не молчание.
//   - Маршруты, которые заводят варианты конструктора мультиплексора шлюза
//     (runtime.With…), не наблюдаются: вариант — чужой код без переданного
//     ему мультиплексора. Сегодня варианты корня маршрутов не заводят.
package check

import (
	"context"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"math"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"

	"github.com/PRO-Robotech/corelib/servicecontract"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

// CeremonyCoordinate — одна координата, которую судит гейт.
type CeremonyCoordinate struct {
	// Name — координата словом: её называет находка.
	Name string
	// Path — путь, который судится.
	Path string
	// Written — путь ВЫПИСАН литералом, потому что производителя в дереве нет.
	// Граница истекает сама: появится постоянная с этим значением — находка.
	Written bool
	// Anchor — координата-якорь: её поверхность и есть поверхность выдачи.
	Anchor bool
}

// UnresolvedPathEntry — объявленный лист пути, который разбор не сводит к
// значению.
type UnresolvedPathEntry struct {
	// Leaf — ключ листа в том виде, в каком его печатает перепись.
	Leaf string
	// Where — полное имя объявленной функции, в которой стоит регистрация с
	// этим листом. Ведомость точна по МЕСТУ: тот же лист на месте, которого
	// запись не называет, — находка.
	Where string
	// Why — причина и предикат снятия.
	Why string
}

// CeremonySurfaceSpec — что судить.
type CeremonySurfaceSpec struct {
	// ModuleRoot — корень модуля службы.
	ModuleRoot string
	// RootPackage — путь импорта композиционного корня.
	RootPackage string
	// Overlay — путь импорта → каталог, чьи не-тестовые .go заменяют пакет
	// (или заводят новый).
	Overlay map[string]string
	// Unresolved — ведомость листов пути, не сводимых к значению. Точная по
	// листу И месту: лист на неназванном месте — находка, запись без листа на
	// своём месте — находка.
	Unresolved []UnresolvedPathEntry
}

// CeremonySolveRoundLimit — предел раундов неподвижной точки разбора.
//
// Страж, а не условие сходимости: прослеживание монотонно на конечной решётке
// (места рождения, копии по местам вызова без повторов, поля, результаты), и
// неподвижная точка наступает всегда. Предел ловит рост сверх разумного, и его
// достижение — «гейт не исполнился» с числом раундов, а не вердикт по
// недособранному разбору. Замер: живое дерево и F-cer со всеми инъекциями и
// близнецами (рекурсивные фабрики — тоже) сходятся за 4–5 раундов.
const CeremonySolveRoundLimit = 200

// CeremonyResolveDepthLimit — предел глубины прохождения запроса.
const CeremonyResolveDepthLimit = 16

// CeremonySurfaceCensus — объём осмотренного.
type CeremonySurfaceCensus struct {
	SolveRounds              int
	ResolveSteps             int
	Packages                 int
	Files                    int
	RootFiles                int
	SurfaceDecls             int
	RaisedSurfaces           int
	SurfaceBuilders          int
	HTTPMuxes                int
	GatewayMuxes             int
	HTTPRegistrations        int
	GatewayRegistrations     int
	DefaultRegistrations     int
	UnreachableRegistrations int
	UntracedRegistrations    int
	PathForms                map[string]int
	Unresolved               []string
	Escapes                  []string
	ManualRouting            []string
	URLPathReads             int
	PathCarriers             int
	Sinks                    int
	UnmountedMuxes           int
	WithoutProducer          int
	PositiveControls         int
}

// Summary — перепись одной строкой.
func (c CeremonySurfaceCensus) Summary() string {
	forms := make([]string, 0, len(c.PathForms))
	for k, v := range c.PathForms {
		forms = append(forms, fmt.Sprintf("%s %d", k, v))
	}
	sort.Strings(forms)
	return fmt.Sprintf("раундов разбора %d из предела %d · шагов обратного разбора пути %d · "+
		"пакетов исходником %d · файлов %d · файлов корня %d · объявлений поверхности %d · "+
		"элементов среза подъёма %d · построителей %d · мультиплексоров net/http %d · шлюза %d · "+
		"регистраций net/http %d · шлюза %d · на общем мультиплексоре %d · в недостижимом коде %d · "+
		"непрослеженных %d · листов пути %d [%s] · мультиплексоров у чужого кода %d · "+
		"чтений пути запроса %d · носителей пути %d · решений маршрута по нему %d · стоков сервера %d · мультиплексоров без поверхности %d · "+
		"координат без производителя %d · положительных контролей %d · формы пути: %s",
		c.SolveRounds, CeremonySolveRoundLimit, c.ResolveSteps, c.Packages, c.Files, c.RootFiles, c.SurfaceDecls, c.RaisedSurfaces, c.SurfaceBuilders,
		c.HTTPMuxes, c.GatewayMuxes, c.HTTPRegistrations, c.GatewayRegistrations, c.DefaultRegistrations,
		c.UnreachableRegistrations, c.UntracedRegistrations, len(c.Unresolved), strings.Join(c.Unresolved, "; "),
		len(c.Escapes), c.URLPathReads, c.PathCarriers, len(c.ManualRouting), c.Sinks, c.UnmountedMuxes, c.WithoutProducer,
		c.PositiveControls, strings.Join(forms, ", "))
}

// SurfaceHit — поверхность, на которой резолвится координата, и путь до
// регистрации.
type SurfaceHit struct {
	Name  string
	Reach string
	Decl  string
	Via   []string
}

// CoordinateVerdict — исход по одной координате.
type CoordinateVerdict struct {
	Name      string
	Path      string
	Surfaces  []SurfaceHit
	Producers []string
}

// Summary — исход координаты одной строкой.
func (c CoordinateVerdict) Summary() string {
	names := make([]string, 0, len(c.Surfaces))
	for _, s := range c.Surfaces {
		names = append(names, fmt.Sprintf("«%s» [%s] ← %s", s.Name, s.Reach, strings.Join(s.Via, " · ")))
	}
	return fmt.Sprintf("«%s» (%s): поверхностей %d, производителей %d [%s]",
		c.Name, c.Path, len(c.Surfaces), len(c.Producers), strings.Join(names, "; "))
}

// SurfaceRoutes — выведенная таблица маршрутов одной поверхности.
type SurfaceRoutes struct {
	Name     string
	Reach    string
	Decl     string
	Roots    int
	Patterns []string
}

// CeremonySurfaceReport — исход гейта.
type CeremonySurfaceReport struct {
	Census      CeremonySurfaceCensus
	Coordinates []CoordinateVerdict
	Surfaces    []SurfaceRoutes
	Findings    []string
}

// JudgeCeremonySurfaces судит, на скольких поверхностях резолвится каждая
// координата. Ошибка — гейт НЕ ИСПОЛНИЛСЯ (радиус не собран, файл не
// разобрался, разбор не дошёл до неподвижной точки): это не зелёное и не
// находка. ctx ограничивает сбор радиуса (`go list`) вместе с его сроком.
func JudgeCeremonySurfaces(ctx context.Context, spec CeremonySurfaceSpec, coords []CeremonyCoordinate) (CeremonySurfaceReport, error) {
	l, err := listingFor(ctx, spec.ModuleRoot, spec.RootPackage)
	if err != nil {
		return CeremonySurfaceReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	prog, err := l.program(spec.Overlay)
	if err != nil {
		return CeremonySurfaceReport{}, err
	}
	a := newSurfaceFlow(prog)
	a.collect()
	rounds, converged := a.solve(CeremonySolveRoundLimit)
	if !converged {
		return CeremonySurfaceReport{}, fmt.Errorf("разбор не дошёл до неподвижной точки за %d раундов "+
			"(предел CeremonySolveRoundLimit): значения, не дотёкшие до регистраций, неотличимы от отсутствующих — "+
			"вердикт по недособранному разбору не выносится", rounds)
	}
	j := &surfaceJudge{a: a, spec: spec, res: newStrResolver(a), reach: a.reachable()}
	j.census.SolveRounds = rounds
	return j.run(coords), nil
}

// ─── судья ──────────────────────────────────────────────────────────────────

type surfaceDecl struct {
	node    flowNode
	name    string
	reach   string
	decl    string
	handler ast.Expr
	roots   avSet
}

type regInfo struct {
	reg      *surfaceReg
	site     string
	text     string
	patterns []string
	gw       []gwPattern
	methods  []string
	handlers avSet
	leaves   map[string]bool
}

type simRoute struct {
	info    *regInfo
	pattern string
}

type httpSim struct {
	mux    *http.ServeMux
	routes map[string]*simRoute
	order  []string
}

type gwSim struct {
	mux    *runtime.ServeMux
	routes []*simRoute
	hit    int
}

type probeMarker struct{ pattern string }

func (probeMarker) ServeHTTP(http.ResponseWriter, *http.Request) {}

type probeReq struct {
	method string
	host   string
	path   string
}

type surfaceJudge struct {
	a        *surfaceFlow
	spec     CeremonySurfaceSpec
	res      *strResolver
	reach    map[fkey]bool
	infos    map[*surfaceReg]*regInfo
	https    map[*absVal]*httpSim
	gws      map[*absVal]*gwSim
	problems map[string]bool
	onPath   map[resolveKey]bool
	hosts    []string
	census   CeremonySurfaceCensus
	findings []string
}

var probeMethods = []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
	http.MethodDelete, http.MethodHead, http.MethodOptions}

func (j *surfaceJudge) find(format string, args ...any) {
	j.findings = append(j.findings, fmt.Sprintf(format, args...))
}

func (j *surfaceJudge) pos(n ast.Node) string { return position(j.a.prog.fset, n.Pos()) }

// reachableFk — достижима ли функция узла.
func (j *surfaceJudge) reachableFk(fk fkey) bool { return j.reach[fk] }

func (j *surfaceJudge) run(coords []CeremonyCoordinate) CeremonySurfaceReport {
	j.infos = map[*surfaceReg]*regInfo{}
	j.https = map[*absVal]*httpSim{}
	j.gws = map[*absVal]*gwSim{}
	j.problems = map[string]bool{}
	j.onPath = map[resolveKey]bool{}
	j.census.PathForms = map[string]int{}
	prog := j.a.prog
	j.census.Packages = len(prog.pkgs)
	for _, sp := range prog.pkgs {
		j.census.Files += len(sp.files)
	}
	j.census.RootFiles = len(prog.root.files)

	surfaces := j.surfaces()
	j.premise(surfaces)
	j.registrations()
	j.collectHosts()

	report := CeremonySurfaceReport{}
	union := avSet{}
	for _, s := range surfaces {
		union.addAll(s.roots)
		report.Surfaces = append(report.Surfaces, SurfaceRoutes{
			Name: s.name, Reach: s.reach, Decl: s.decl, Roots: len(s.roots), Patterns: j.routeTable(s.roots),
		})
	}
	report.Coordinates = j.coordinates(surfaces, coords)
	j.unmounted(surfaces, coords)
	j.sinks(union)

	probs := make([]string, 0, len(j.problems))
	for p := range j.problems {
		probs = append(probs, p)
	}
	sort.Strings(probs)
	j.findings = append(j.findings, probs...)
	report.Census = j.census
	report.Findings = j.findings
	return report
}

// ─── поверхности ────────────────────────────────────────────────────────────

func (j *surfaceJudge) surfaces() []*surfaceDecl {
	var out []*surfaceDecl
	for _, n := range j.a.surfaceLits {
		lit := n.node.(*ast.CompositeLit)
		d := &surfaceDecl{node: n, decl: j.pos(lit), name: "<имя не выводится>", reach: "<досягаемость не объявлена>"}
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, _ := kv.Key.(*ast.Ident)
			if key == nil {
				continue
			}
			switch key.Name {
			case "Name":
				if r := j.res.str(n.pkg, n.fk, kv.Value); len(r.vals) > 0 {
					d.name = strings.Join(r.sortedVals(), " | ")
				}
			case "Reach":
				d.reach = reachWord(n.pkg, kv.Value)
			case "Handler":
				d.handler = kv.Value
			}
		}
		if d.handler != nil {
			d.roots = j.a.eval(n.pkg, n.fk, d.handler)
		}
		out = append(out, d)
	}
	j.census.SurfaceDecls = len(out)
	return out
}

// reachWord — досягаемость поверхности словом фундамента
// (servicecontract.SurfaceReach.String) — тем же, что несут журнал и
// tools/surfaceroster. Судится ЗНАЧЕНИЕ постоянной, а не её имя: своего
// написания досягаемости у гейта нет.
func reachWord(sp *surfaceSrcPkg, e ast.Expr) string {
	tv, ok := sp.info.Types[e]
	if !ok || tv.Value == nil || !isServiceContract(tv.Type, "SurfaceReach") {
		return "<досягаемость не постоянная>"
	}
	u, exact := constant.Uint64Val(tv.Value)
	if !exact || u > math.MaxUint8 {
		return "<досягаемость вне своего типа>"
	}
	return servicecontract.SurfaceReach(uint8(u)).String()
}

// premise — предпосылки: корень разобран, объявления сходятся с подъёмом,
// поверхность строит один помощник, обработчик каждой прослежен.
func (j *surfaceJudge) premise(surfaces []*surfaceDecl) {
	c := &j.census
	for _, n := range j.a.raisedLits {
		c.RaisedSurfaces += len(n.node.(*ast.CompositeLit).Elts)
	}
	builders := map[string]bool{}
	for _, n := range j.a.builders {
		builders[j.res.funcLabel(j.topOf(n.fk))] = true
	}
	c.SurfaceBuilders = len(builders)
	if c.RootFiles == 0 || c.SurfaceDecls == 0 {
		j.find("ОБХОД ПУСТ: файлов корня %d, разобрано файлов %d, объявлений поверхности %d — «находок ноль» "+
			"здесь неотличимо от «ничего не прочитано», а корень без поверхностей не поднимается", c.RootFiles, c.Files, c.SurfaceDecls)
	}
	if len(j.a.raisedLits) == 0 {
		j.find("срез подъёма поверхностей в корне не найден (составной литерал среза, чей элемент несёт "+
			"servicecontract.SurfaceDescriptor): объявлений поверхности %d сверять не с чем", c.SurfaceDecls)
	} else if c.RaisedSurfaces != c.SurfaceDecls {
		j.find("срез подъёма несёт %d элементов при %d объявлений поверхности — судится не то, что поднимается",
			c.RaisedSurfaces, c.SurfaceDecls)
	}
	if len(builders) > 1 {
		names := make([]string, 0, len(builders))
		for b := range builders {
			names = append(names, b)
		}
		sort.Strings(names)
		j.find("поверхность строится servicecontract.NewSurface в %d функциях (%s): часть поверхностей "+
			"собрана в обход общего помощника корня", len(builders), strings.Join(names, ", "))
	}
	for _, s := range surfaces {
		if len(s.roots) == 0 {
			j.find("поверхность «%s» (%s): обработчик не прослежен ни до одного значения — "+
				"её маршрутов гейт не видит", s.name, s.decl)
		}
	}
}

// topOf — объявленная функция, внутри которой литерал.
func (j *surfaceJudge) topOf(fk fkey) fkey {
	for fk.lit != nil {
		fk = j.a.litOwner[fk.lit]
	}
	return fk
}

// ─── регистрации ────────────────────────────────────────────────────────────

func (j *surfaceJudge) info(reg *surfaceReg) *regInfo {
	if in, ok := j.infos[reg]; ok {
		return in
	}
	in := &regInfo{reg: reg, site: j.pos(reg.call), text: printedCall(reg), leaves: map[string]bool{}}
	switch reg.kind {
	case regHTTP, regDefault:
		r := j.res.str(reg.pkg, reg.fk, reg.path)
		in.patterns = r.sortedVals()
		for l := range r.leaves {
			in.leaves[l] = true
		}
	case regGatewayPattern:
		pr := j.res.pattern(reg.pkg, reg.fk, reg.path)
		in.gw = pr.vals
		for l := range pr.leaves {
			in.leaves[l] = true
		}
	case regGatewayPath:
		r := j.res.str(reg.pkg, reg.fk, reg.path)
		in.patterns = r.sortedVals()
		for l := range r.leaves {
			in.leaves[l] = true
		}
	}
	if reg.method != nil {
		m := j.res.str(reg.pkg, reg.fk, reg.method)
		in.methods = m.sortedVals()
		for l := range m.leaves {
			in.leaves[l] = true
		}
	}
	in.handlers = j.a.eval(reg.pkg, reg.fk, reg.handler)
	j.infos[reg] = in
	return in
}

// printedCall — регистрация так, как её написали.
func printedCall(reg *surfaceReg) string {
	var b strings.Builder
	b.WriteString(surfaceExprText(reg.call.Fun))
	b.WriteString("(")
	for i, a := range reg.call.Args {
		if i > 0 {
			b.WriteString(", ")
		}
		if i == len(reg.call.Args)-1 && len(reg.call.Args) > 1 {
			b.WriteString("…")
			continue
		}
		b.WriteString(surfaceExprText(a))
	}
	b.WriteString(")")
	return b.String()
}

func surfaceExprText(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return surfaceExprText(x.X) + "." + x.Sel.Name
	case *ast.BasicLit:
		return x.Value
	case *ast.CallExpr:
		args := make([]string, 0, len(x.Args))
		for _, a := range x.Args {
			args = append(args, surfaceExprText(a))
		}
		return surfaceExprText(x.Fun) + "(" + strings.Join(args, ", ") + ")"
	case *ast.BinaryExpr:
		return surfaceExprText(x.X) + " " + x.Op.String() + " " + surfaceExprText(x.Y)
	case *ast.ParenExpr:
		return "(" + surfaceExprText(x.X) + ")"
	case *ast.StarExpr:
		return "*" + surfaceExprText(x.X)
	case *ast.UnaryExpr:
		return x.Op.String() + surfaceExprText(x.X)
	case *ast.IndexExpr:
		return surfaceExprText(x.X) + "[" + surfaceExprText(x.Index) + "]"
	}
	return fmt.Sprintf("%T", e)
}

// leafPlace — лист пути на месте регистрации (объявленная функция).
type leafPlace struct {
	leaf  string
	where string
}

// registrations — перепись регистраций, их форм и листов; отказ на
// непрослеженных и неразрешённых.
func (j *surfaceJudge) registrations() {
	c := &j.census
	leafSites := map[leafPlace][]string{}
	counted := map[*ast.CallExpr]bool{}
	var muxes []*absVal
	for m := range j.a.regs {
		muxes = append(muxes, m)
	}
	sort.Slice(muxes, func(x, y int) bool { return muxes[x].seq < muxes[y].seq })
	bases := map[string]bool{}
	for _, m := range muxes {
		for _, reg := range j.a.regs[m] {
			if counted[reg.call] {
				continue
			}
			counted[reg.call] = true
			if !j.reachableFk(reg.fk) {
				c.UnreachableRegistrations++
				continue
			}
			switch reg.kind {
			case regHTTP:
				c.HTTPRegistrations++
			case regDefault:
				c.DefaultRegistrations++
			case regGatewayPattern, regGatewayPath:
				c.GatewayRegistrations++
			}
			in := j.info(reg)
			j.form(in)
			where := j.res.funcLabel(j.topOf(reg.fk))
			for l := range in.leaves {
				k := leafPlace{leaf: l, where: where}
				leafSites[k] = append(leafSites[k], in.site+" "+in.text)
			}
		}
		key := fmt.Sprint(m.kind, m.site)
		if !bases[key] && m != j.a.defMux {
			bases[key] = true
			if m.kind == avHTTPMux {
				c.HTTPMuxes++
			} else {
				c.GatewayMuxes++
			}
		}
	}
	var untraced []*surfaceReg
	inUntraced := map[*ast.CallExpr]bool{}
	for call, reg := range j.a.untraced {
		if !counted[call] && j.reachableFk(reg.fk) {
			untraced = append(untraced, reg)
			inUntraced[call] = true
		}
	}
	// Метод регистрации через интерфейс, который реализует мультиплексор, у
	// которого хоть одно значение получателя без реализации: значения не
	// дотекли, и регистрацию не приписать поверхности — даже если другие
	// получатели разрешились (разрешившиеся уже насчитаны на своих
	// мультиплексорах).
	for call, reg := range j.a.ifaceRegs {
		st := j.a.ifaceCalls[call]
		partial := st != nil && st.unresolved
		if inUntraced[call] || (!partial && (counted[call] || j.a.dispatched[call])) || !j.reachableFk(reg.fk) {
			continue
		}
		untraced = append(untraced, reg)
		inUntraced[call] = true
	}
	sort.Slice(untraced, func(x, y int) bool { return untraced[x].call.Pos() < untraced[y].call.Pos() })
	for _, reg := range untraced {
		call := reg.call
		c.UntracedRegistrations++
		j.find("регистрация %s %s: мультиплексор не прослежен до места рождения — маршрут не приписать "+
			"ни одной поверхности", j.pos(call), printedCall(reg))
	}
	declared := map[leafPlace]bool{}
	for _, e := range j.spec.Unresolved {
		k := leafPlace{leaf: e.Leaf, where: e.Where}
		declared[k] = true
		if _, ok := leafSites[k]; !ok {
			j.find("запись ведомости листов пути «%s» в %s без предмета — на этом месте такого листа разбор "+
				"больше не встречает; снять запись вместе с причиной", e.Leaf, e.Where)
		}
	}
	var places []leafPlace
	for k := range leafSites {
		places = append(places, k)
	}
	sort.Slice(places, func(x, y int) bool {
		if places[x].leaf != places[y].leaf {
			return places[x].leaf < places[y].leaf
		}
		return places[x].where < places[y].where
	})
	for _, k := range places {
		c.Unresolved = append(c.Unresolved, k.leaf+" в "+k.where)
		if !declared[k] {
			j.find("путь регистрации не сводится к значению: лист «%s» в %s (%s) — гейт не может сказать, на "+
				"скольких поверхностях резолвится координата; сверни путь к постоянной либо объяви лист "+
				"на этом месте в ведомости с причиной и предикатом снятия", k.leaf, k.where, strings.Join(leafSites[k], "; "))
		}
	}
	var escapes []token.Pos
	for pos, e := range j.a.escapes {
		if j.reachableFk(e.fk) {
			escapes = append(escapes, pos)
		}
	}
	sort.Slice(escapes, func(x, y int) bool { return escapes[x] < escapes[y] })
	for _, pos := range escapes {
		e := j.a.escapes[pos]
		c.Escapes = append(c.Escapes, e.name)
		j.find("мультиплексор уходит в чужой код %s (%s): регистрации, сделанные там, гейт не наблюдает",
			e.name, position(j.a.prog.fset, pos))
	}
	for _, n := range j.a.pathReads {
		if j.reachableFk(n.fk) {
			c.URLPathReads++
		}
	}
	for _, m := range j.a.manual {
		if !j.reachableFk(m.node.fk) {
			continue
		}
		c.ManualRouting = append(c.ManualRouting, j.pos(m.node.node))
		j.find("маршрут решается по пути запроса в теле обработчика — %s (%s): регистрацию на мультиплексоре "+
			"гейт видит, решение в теле обработчика — нет; такая форма монтажа координаты осталась бы незамеченной",
			m.form, j.pos(m.node.node))
	}
}

// form — форма записи пути регистрации (перепись по формам, B1).
func (j *surfaceJudge) form(in *regInfo) {
	f := &j.census.PathForms
	switch in.reg.kind {
	case regGatewayPattern:
		(*f)["образец шлюза"]++
		return
	case regGatewayPath:
		(*f)["HandlePath шлюза"]++
	case regDefault:
		(*f)["общий мультиплексор процесса"]++
	}
	sp := in.reg.pkg
	switch x := ast.Unparen(in.reg.path).(type) {
	case *ast.BasicLit:
		(*f)["литерал"]++
	case *ast.Ident:
		switch sp.info.Uses[x].(type) {
		case *types.Const:
			(*f)["постоянная своего пакета"]++
		case *types.Var:
			(*f)["переменная или параметр"]++
		default:
			(*f)["иное имя"]++
		}
	case *ast.SelectorExpr:
		if s, ok := sp.info.Selections[x]; ok && s.Kind() == types.FieldVal {
			(*f)["поле значения"]++
			break
		}
		if c, ok := sp.info.Uses[x.Sel].(*types.Const); ok {
			if id, ok := x.X.(*ast.Ident); ok && c.Pkg() != nil && id.Name != c.Pkg().Name() {
				(*f)["постоянная чужого пакета под псевдонимом"]++
			} else {
				(*f)["постоянная чужого пакета"]++
			}
			break
		}
		(*f)["выбор иного вида"]++
	case *ast.BinaryExpr:
		(*f)["склейка"]++
	case *ast.CallExpr:
		(*f)["вызов"]++
	default:
		(*f)["иное выражение"]++
	}
	for _, p := range in.patterns {
		method, host, rest := splitPattern(p)
		if method != "" {
			(*f)["образец с методом"]++
		}
		if host != "" {
			(*f)["образец с хостом"]++
		}
		if strings.Contains(rest, "{") {
			(*f)["образец с подстановкой"]++
		}
		if len(rest) > 1 && strings.HasSuffix(rest, "/") {
			(*f)["образец-поддерево"]++
		}
	}
}

// splitPattern — [МЕТОД ][ХОСТ]/путь образца net/http.
func splitPattern(p string) (method, host, rest string) {
	rest = p
	if i := strings.IndexAny(rest, " \t"); i >= 0 {
		method = rest[:i]
		rest = strings.TrimLeft(rest[i:], " \t")
	}
	if i := strings.Index(rest, "/"); i > 0 {
		host = rest[:i]
		rest = rest[i:]
	}
	return method, host, rest
}

// collectHosts — хосты из образцов: запрос координаты идёт на каждый.
func (j *surfaceJudge) collectHosts() {
	seen := map[string]bool{"probe.invalid": true}
	j.hosts = []string{"probe.invalid"}
	var infos []*regInfo
	for _, in := range j.infos {
		infos = append(infos, in)
	}
	sort.Slice(infos, func(x, y int) bool { return infos[x].site < infos[y].site })
	for _, in := range infos {
		for _, p := range in.patterns {
			if _, host, _ := splitPattern(p); host != "" && !seen[host] {
				seen[host] = true
				j.hosts = append(j.hosts, host)
			}
		}
	}
}

// ─── настоящие мультиплексоры ───────────────────────────────────────────────

func (j *surfaceJudge) reachableRegs(m *absVal) []*regInfo {
	var out []*regInfo
	for _, reg := range j.a.effectiveRegs(m) {
		if j.reachableFk(reg.fk) {
			out = append(out, j.info(reg))
		}
	}
	return out
}

func (j *surfaceJudge) httpOf(m *absVal) *httpSim {
	if s, ok := j.https[m]; ok {
		return s
	}
	s := &httpSim{mux: http.NewServeMux(), routes: map[string]*simRoute{}}
	for _, in := range j.reachableRegs(m) {
		for _, p := range in.patterns {
			if prev, dup := s.routes[p]; dup {
				j.problems[fmt.Sprintf("мультиплексор отказал бы в регистрации «%s» (%s %s): образец уже "+
					"зарегистрирован (%s %s) — процесс не поднялся бы", p, in.site, in.text, prev.info.site, prev.info.text)] = true
				continue
			}
			if msg := registerHTTP(s.mux, p); msg != "" {
				j.problems[fmt.Sprintf("мультиплексор отказал бы в регистрации «%s» (%s %s): %s", p, in.site, in.text, msg)] = true
				continue
			}
			s.routes[p] = &simRoute{info: in, pattern: p}
			s.order = append(s.order, p)
		}
	}
	j.https[m] = s
	return s
}

func registerHTTP(mux *http.ServeMux, pattern string) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprint(r)
		}
	}()
	mux.Handle(pattern, probeMarker{pattern: pattern})
	return ""
}

func (j *surfaceJudge) gwOf(m *absVal) *gwSim {
	if s, ok := j.gws[m]; ok {
		return s
	}
	s := &gwSim{hit: -1}
	s.mux = runtime.NewServeMux(runtime.WithRoutingErrorHandler(
		func(context.Context, *runtime.ServeMux, runtime.Marshaler, http.ResponseWriter, *http.Request, int) {}))
	add := func(in *regInfo, method, display string, handle func(runtime.HandlerFunc) error) {
		id := len(s.routes)
		s.routes = append(s.routes, &simRoute{info: in, pattern: method + " " + display})
		if err := handle(func(http.ResponseWriter, *http.Request, map[string]string) { s.hit = id }); err != nil {
			j.problems[fmt.Sprintf("шлюз отказал бы в регистрации «%s %s» (%s %s): %v", method, display, in.site, in.text, err)] = true
		}
	}
	for _, in := range j.reachableRegs(m) {
		methods := in.methods
		if len(methods) == 0 {
			methods = probeMethods
		}
		for _, method := range methods {
			switch in.reg.kind {
			case regGatewayPattern:
				for _, gp := range in.gw {
					pat, err := runtime.NewPattern(gp.version, gp.ops, gp.pool, gp.verb)
					if err != nil {
						j.problems[fmt.Sprintf("образец шлюза не собирается (%s %s): %v", in.site, in.text, err)] = true
						continue
					}
					add(in, method, pat.String(), func(h runtime.HandlerFunc) error {
						s.mux.Handle(method, pat, h)
						return nil
					})
				}
			case regGatewayPath:
				for _, p := range in.patterns {
					add(in, method, p, func(h runtime.HandlerFunc) error { return s.mux.HandlePath(method, p, h) })
				}
			}
		}
	}
	j.gws[m] = s
	return s
}

// ─── прохождение запроса ────────────────────────────────────────────────────

// resolveKey — значение, которое запрос проходит на текущем пути.
type resolveKey struct {
	v  *absVal
	rq probeReq
}

// resolve — цепочки, по которым запрос доходит до конечной точки.
//
// Значение, которое ТОТ ЖЕ запрос уже проходит выше по пути, — цикл
// (обёртка, вложенная в саму себя; мультиплексор рекурсивной фабрики,
// смонтированный в себя): прохождение детерминировано, и цикл нового маршрута
// не даёт — второй раз он не обходится. Путь без цикла длиннее
// CeremonyResolveDepthLimit не обрезается молча: глубже гейт не смотрит, и
// это находка — сколько поверхностей резолвят координату, не установлено.
func (j *surfaceJudge) resolve(set avSet, rq probeReq, depth int) [][]string {
	var out [][]string
	for _, v := range set.sorted() {
		k := resolveKey{v: v, rq: rq}
		if j.onPath[k] {
			continue
		}
		if depth > CeremonyResolveDepthLimit {
			j.problems[fmt.Sprintf("прохождение запроса обрезано на глубине %d (предел CeremonyResolveDepthLimit) "+
				"у %s: глубже гейт не смотрит — на скольких поверхностях резолвится координата, не установлено",
				CeremonyResolveDepthLimit, j.valueLabel(v))] = true
			continue
		}
		j.onPath[k] = true
		out = append(out, j.resolveOne(v, rq, depth)...)
		delete(j.onPath, k)
	}
	return out
}

// valueLabel — значение словом для находки: вид и место рождения.
func (j *surfaceJudge) valueLabel(v *absVal) string {
	if v.site.IsValid() {
		return "значения, рождённого " + position(j.a.prog.fset, v.site)
	}
	if v.fn != nil {
		return "функции " + fnName(v.fn)
	}
	return "общего мультиплексора процесса"
}

// resolveOne — прохождение запроса через одно значение.
func (j *surfaceJudge) resolveOne(v *absVal, rq probeReq, depth int) [][]string {
	switch v.kind {
	case avHTTPMux:
		sim := j.httpOf(v)
		req := httptest.NewRequest(rq.method, "http://"+rq.host+rq.path, nil)
		h, pat := sim.mux.Handler(req)
		if pat == "" {
			return nil
		}
		var route *simRoute
		redirect := false
		if mk, ok := h.(probeMarker); ok {
			route = sim.routes[mk.pattern]
		} else {
			route, redirect = sim.routes[pat], true
		}
		if route == nil {
			return nil
		}
		step := fmt.Sprintf("регистрация %s %s образец «%s»", route.info.site, route.info.text, route.pattern)
		if redirect {
			return [][]string{{step + " (мультиплексор отвечает перенаправлением — путь резолвится)"}}
		}
		return j.through(step, route.info.handlers, rq, depth)
	case avGatewayMux:
		sim := j.gwOf(v)
		sim.hit = -1
		req := httptest.NewRequest(rq.method, "http://"+rq.host+rq.path, nil)
		sim.mux.ServeHTTP(httptest.NewRecorder(), req)
		if sim.hit < 0 {
			return nil
		}
		route := sim.routes[sim.hit]
		step := fmt.Sprintf("регистрация шлюза %s %s образец «%s»", route.info.site, route.info.text, route.pattern)
		return j.through(step, route.info.handlers, rq, depth)
	case avNotFound:
		return nil
	case avOpaque:
		return [][]string{{"конечная точка " + fnName(v.fn)}}
	case avExtWrap:
		return j.external(v, rq, depth)
	}
	kids, isHandler, desc := j.a.delegates(v)
	if !isHandler {
		return nil
	}
	if len(kids) == 0 {
		return [][]string{{}}
	}
	var out [][]string
	for _, c := range j.resolve(kids, rq, depth+1) {
		if desc != "" {
			c = append([]string{desc}, c...)
		}
		out = append(out, c)
	}
	return out
}

// through — маршрут найден; запрос идёт в его обработчик.
func (j *surfaceJudge) through(step string, handlers avSet, rq probeReq, depth int) [][]string {
	if len(handlers) == 0 {
		return [][]string{{step}}
	}
	var out [][]string
	for _, c := range j.resolve(handlers, rq, depth+1) {
		out = append(out, append([]string{step}, c...))
	}
	return out
}

// external — чужая обёртка: известные сохраняют путь либо снимают префикс,
// неизвестная — находка, и запрос идёт дальше как через прозрачную.
func (j *surfaceJudge) external(v *absVal, rq probeReq, depth int) [][]string {
	name := fnName(v.fn)
	kids := j.a.extKids[v]
	switch name {
	case "net/http.TimeoutHandler", "net/http.MaxBytesHandler", "net/http.AllowQuerySemicolons":
	case "net/http.StripPrefix":
		call := j.a.extCalls[v]
		ce, _ := call.node.(*ast.CallExpr)
		if ce == nil || len(ce.Args) == 0 {
			break
		}
		r := j.res.str(call.pkg, call.fk, ce.Args[0])
		if len(r.leaves) > 0 {
			j.problems[fmt.Sprintf("префикс http.StripPrefix (%s) не сводится к значению", j.pos(ce))] = true
		}
		var out [][]string
		for _, pre := range r.sortedVals() {
			if strings.HasPrefix(rq.path, pre) {
				rq2 := rq
				rq2.path = strings.TrimPrefix(rq.path, pre)
				for _, c := range j.resolve(kids, rq2, depth+1) {
					out = append(out, append([]string{"http.StripPrefix «" + pre + "»"}, c...))
				}
			}
		}
		return out
	default:
		call := j.a.extCalls[v]
		j.problems[fmt.Sprintf("обработчик поверхности уходит в чужой код %s (%s): что эта обёртка делает с "+
			"путём, гейт не наблюдает", name, position(j.a.prog.fset, call.node.Pos()))] = true
	}
	var out [][]string
	for _, c := range j.resolve(kids, rq, depth+1) {
		out = append(out, append([]string{"чужая обёртка " + name}, c...))
	}
	return out
}

// surfaceHits — резолвится ли путь на поверхности и через что.
func (j *surfaceJudge) surfaceHits(roots avSet, path string) []string {
	seen := map[string]bool{}
	var via []string
	for _, host := range j.hosts {
		for _, m := range probeMethods {
			for _, c := range j.resolve(roots, probeReq{method: m, host: host, path: path}, 0) {
				s := strings.Join(c, " → ")
				if s == "" {
					s = "обработчик поверхности — конечная точка"
				}
				if !seen[s] {
					seen[s] = true
					via = append(via, s)
				}
			}
		}
	}
	sort.Strings(via)
	return via
}

// muxesUnder — мультиплексоры, достижимые от значений (без учёта пути).
func (j *surfaceJudge) muxesUnder(set avSet, seen map[*absVal]bool) {
	for v := range set {
		if seen[v] {
			continue
		}
		seen[v] = true
		switch v.kind {
		case avHTTPMux, avGatewayMux:
			for _, in := range j.reachableRegs(v) {
				j.muxesUnder(in.handlers, seen)
			}
		default:
			kids, _, _ := j.a.delegates(v)
			j.muxesUnder(kids, seen)
		}
	}
}

// routeTable — выведенные образцы, до которых доходит поверхность.
func (j *surfaceJudge) routeTable(roots avSet) []string {
	seen := map[*absVal]bool{}
	j.muxesUnder(roots, seen)
	var out []string
	uniq := map[string]bool{}
	for v := range seen {
		switch v.kind {
		case avHTTPMux:
			for _, p := range j.httpOf(v).order {
				if !uniq[p] {
					uniq[p] = true
					out = append(out, p)
				}
			}
		case avGatewayMux:
			for _, r := range j.gwOf(v).routes {
				if !uniq[r.pattern] {
					uniq[r.pattern] = true
					out = append(out, r.pattern)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// ─── координаты ─────────────────────────────────────────────────────────────

// producers — постоянные радиуса с тем же значением, что у координаты.
func (j *surfaceJudge) producers(path string) []string {
	var out []string
	for _, sp := range j.a.prog.pkgs {
		scope := sp.types.Scope()
		for _, name := range scope.Names() {
			c, ok := scope.Lookup(name).(*types.Const)
			if !ok || c.Val().Kind() != constant.String || constant.StringVal(c.Val()) != path {
				continue
			}
			out = append(out, sp.path+"."+name)
		}
	}
	sort.Strings(out)
	return out
}

func (j *surfaceJudge) coordinates(surfaces []*surfaceDecl, coords []CeremonyCoordinate) []CoordinateVerdict {
	var verdicts []CoordinateVerdict
	for _, c := range coords {
		v := CoordinateVerdict{Name: c.Name, Path: c.Path, Producers: j.producers(c.Path)}
		for _, s := range surfaces {
			via := j.surfaceHits(s.roots, c.Path)
			if len(via) > 0 {
				v.Surfaces = append(v.Surfaces, SurfaceHit{Name: s.name, Reach: s.reach, Decl: s.decl, Via: via})
			}
		}
		verdicts = append(verdicts, v)
	}
	var issuing *SurfaceHit
	for i, c := range coords {
		v := verdicts[i]
		if !c.Anchor {
			continue
		}
		switch {
		case len(v.Surfaces) != 1:
			j.find("координата-якорь «%s» (%s) резолвится на %d поверхностях — положительный контроль не "+
				"выполнен: поверхность выдачи из дерева не выводится%s", c.Name, c.Path, len(v.Surfaces), hitsText(v.Surfaces))
		case v.Surfaces[0].Reach != servicecontract.ReachExternal.String():
			j.find("координата-якорь «%s» (%s) резолвится на «%s» [%s] — поверхность выдачи обязана быть внешней",
				c.Name, c.Path, v.Surfaces[0].Name, v.Surfaces[0].Reach)
		default:
			issuing = &v.Surfaces[0]
			j.census.PositiveControls++
		}
	}
	for i, c := range coords {
		v := verdicts[i]
		switch {
		case c.Written && len(v.Producers) > 0:
			j.find("координата «%s» выписана литералом (%s), а производитель в бинаре есть: %s — бери путь "+
				"оттуда; граница «производителя нет» истекла", c.Name, c.Path, strings.Join(v.Producers, ", "))
		case !c.Written && len(v.Producers) == 0:
			j.find("координата «%s» объявлена взятой у производителя, а постоянной со значением %s в бинаре нет",
				c.Name, c.Path)
		}
		if c.Anchor {
			continue
		}
		switch {
		case len(v.Surfaces) == 0 && len(v.Producers) > 0:
			j.find("координата «%s» (%s) имеет производителя (%s), но не резолвится ни на одной поверхности — "+
				"собрана и не смонтирована", c.Name, c.Path, strings.Join(v.Producers, ", "))
		case len(v.Surfaces) == 0:
			j.census.WithoutProducer++
		case len(v.Surfaces) > 1:
			want := "поверхность выдачи не выведена"
			if issuing != nil {
				want = fmt.Sprintf("поверхности выдачи «%s» [%s]", issuing.Name, issuing.Reach)
			}
			j.find("координата «%s» (%s) резолвится на %d поверхностях, а обязана ровно на одной — %s:%s",
				c.Name, c.Path, len(v.Surfaces), want, hitsText(v.Surfaces))
		case issuing == nil:
			j.find("координата «%s» (%s) резолвится на «%s» [%s], а поверхность выдачи не выведена — сверять не с чем",
				c.Name, c.Path, v.Surfaces[0].Name, v.Surfaces[0].Reach)
		case v.Surfaces[0].Decl != issuing.Decl:
			j.find("координата «%s» (%s) резолвится на одной поверхности, но не на поверхности выдачи «%s» [%s]:%s",
				c.Name, c.Path, issuing.Name, issuing.Reach, hitsText(v.Surfaces))
		default:
			j.census.PositiveControls++
		}
	}
	return verdicts
}

func hitsText(hits []SurfaceHit) string {
	var b strings.Builder
	for _, h := range hits {
		fmt.Fprintf(&b, "\n  · «%s» [%s] (объявлена %s): %s", h.Name, h.Reach, h.Decl, strings.Join(h.Via, "; "))
	}
	return b.String()
}

// unmounted — координата на мультиплексоре, которого не поднимает ни одна
// поверхность.
func (j *surfaceJudge) unmounted(surfaces []*surfaceDecl, coords []CeremonyCoordinate) {
	seen := map[*absVal]bool{}
	for _, s := range surfaces {
		j.muxesUnder(s.roots, seen)
	}
	covered := map[*absVal]bool{}
	for v := range seen {
		for p := v; p != nil; p = p.parent {
			covered[p] = true
		}
	}
	var muxes []*absVal
	for m := range j.a.regs {
		if !covered[m] && len(j.reachableRegs(m)) > 0 {
			muxes = append(muxes, m)
		}
	}
	sort.Slice(muxes, func(x, y int) bool { return muxes[x].seq < muxes[y].seq })
	j.census.UnmountedMuxes = len(muxes)
	for _, m := range muxes {
		where := "общий мультиплексор процесса http.DefaultServeMux"
		if m != j.a.defMux {
			where = "рождён " + position(j.a.prog.fset, m.site)
		}
		for _, c := range coords {
			if via := j.surfaceHits(avSet{m: {}}, c.Path); len(via) > 0 {
				j.find("координата «%s» (%s) зарегистрирована на мультиплексоре, которого не поднимает ни одна "+
					"поверхность (%s): %s", c.Name, c.Path, where, strings.Join(via, "; "))
			}
		}
	}
}

// sinks — HTTP-сервер процесса поднимает ТОЛЬКО объявленную поверхность.
//
// Санкционированный сток один по устройству: подъём фундамента отдаёт серверу
// поле Handler объявления servicecontract.Surface. Любой другой сток —
// литерал http.Server, http.ListenAndServe, http.Serve — слушатель вне
// объявлений, даже если обслуживает уже объявленный обработчик: второй
// слушатель того же обработчика и есть вторая поверхность.
func (j *surfaceJudge) sinks(union avSet) {
	for _, s := range j.a.sinks {
		if !j.reachableFk(s.node.fk) {
			continue
		}
		j.census.Sinks++
		if j.fromSurfaceDecl(s.node.pkg, s.expr) {
			continue
		}
		what := "обработчик, не прослеженный до места рождения"
		for _, v := range j.a.eval(s.node.pkg, s.node.fk, s.expr).sorted() {
			if _, ok := union[v]; ok {
				what = "обработчик объявленной поверхности вторым слушателем"
			} else {
				what = "обработчик, не объявленный поверхностью (" + position(j.a.prog.fset, v.site) + ")"
			}
			break
		}
		j.find("HTTP-сервер (%s) поднят в обход объявления поверхности и обслуживает %s — "+
			"слушатель вне перечня, который гейт судит", j.pos(s.node.node), what)
	}
}

// fromSurfaceDecl — выражение читает поле Handler объявления поверхности.
func (j *surfaceJudge) fromSurfaceDecl(sp *surfaceSrcPkg, e ast.Expr) bool {
	sel, ok := ast.Unparen(e).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Handler" {
		return false
	}
	s, ok := sp.info.Selections[sel]
	return ok && s.Kind() == types.FieldVal && isServiceContract(s.Recv(), "Surface")
}
