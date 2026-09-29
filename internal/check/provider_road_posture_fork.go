// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_road_posture_fork.go — У КАЖДОГО ПОТРЕБИТЕЛЯ АДМИНИСТРАТИВНОЙ ДОРОГИ
// СВОЁ РЕШЕНИЕ О ПОСАДКЕ (задача kaname#338; преемник гейта ответа kaname#313).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Дорога к внешнему поставщику строится только на посадке, у которой он есть.
// Потребителей у неё два рода: тот, кто зовёт строителя, и тот, кому клиента
// передают ДОВОДОМ. Прежний гейт судил первый род (связан ли ответ о посадке с
// именем) и не видел второго by construction: решение о посадке за принявшего
// доводом принимал сборщик, и принимал один раз на нескольких.
//
// Решение о форме записано до кода —
// `docs/engineering/architecture/provider-admin-road-posture-is-a-fork.md`: не
// разбор типов, а УСТРОЙСТВО. Посадка — развилка: вызывающий подаёт две ветви,
// ветвь построенной посадки получает клиента параметром, ветвь другой посадки не
// получает ничего. Потребитель, принимающий дорогу доводом, — ровно эта ветвь, и
// в паре с ней всегда стоит ветвь другой посадки.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ДЕРЖИТ КОМПИЛЯТОР, А ЧТО — ЭТОТ РАЗБОР
//
// Компилятор: вызов развилки без ветви другой посадки не собирается, а в той
// ветви дороги нет в области видимости. Разбор (синтаксис, без типов) — то,
// что собирается и всё равно отдаёт дорогу без решения:
//
//   - ветвь `nil`, либо ветвь, записанная не литералом функции: вторую разбор
//     не читает, и молчать о ней он не вправе;
//   - дорога уходит из ветви не доводом вызова и не операндом возврата, а
//     присваиванием, селектором или захватом во вложенное замыкание;
//   - одна ветвь отдаёт дорогу нескольким потребителям — исходная форма задачи;
//   - дорогу строит не развилка: функция корня, читающая резолвер адреса,
//     отличается от развилки. Её вызовы — потребители первого рода без
//     устройства, а приёмы значения из них — потребители второго рода без
//     своего решения;
//   - развилка взята значением, а не вызвана.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО РАЗБОР НЕ ВИДИТ — НАЗВАНО, А НЕ СПРЯТАНО
//
//  1. Строитель, вызванный селектором (метод, другой пакет): вызов судится по
//     имени функции пакета. Такой строитель резолвер читает ВНЕ владельца, и его
//     находит соседний гейт единственного читателя адреса.
//  2. Имя дороги, заново объявленное внутри ветви: следование идёт по имени, и
//     затенённая переменная считается той же дорогой. Ошибка здесь уходит в
//     лишнюю находку, а не в молчание.
//  3. Потребитель внутри другого пакета, хранящий полученную из ветви дорогу:
//     посадка у него построенная по устройству, производитель один.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
)

// Виды находки — закрытый словарь. Текст находки называет ПРИЧИНУ, а не
// только координату.
const (
	RoadFindingBuilderOutsideFork = "дорогу строит не развилка: функция читает резолвер адреса, " +
		"и потребители получают её значением на обеих посадках"
	RoadFindingUnforkedCall = "потребитель зовёт строителя мимо развилки: на посадке без " +
		"поставщика дорога существует значением, и что он её не тронет, держит ветвь, " +
		"которую компилятор не судит"
	RoadFindingUnforkedReception = "дорога принята доводом из строителя мимо развилки: решение " +
		"о посадке за потребителя принял тот, кто его собирал"
	RoadFindingArmMissing     = "у развилки нет ветви одной из посадок"
	RoadFindingArmNil         = "ветвь развилки — nil: вызов собирается и паникует на своей посадке"
	RoadFindingArmNotLiteral  = "ветвь развилки записана не литералом функции: её приёмов разбор не видит"
	RoadFindingNoRoadParam    = "ветвь построенной посадки не берёт дорогу параметром"
	RoadFindingNoReception    = "ветвь построенной посадки дорогу никому не отдаёт"
	RoadFindingSharedDecision = "одна ветвь отдаёт дорогу нескольким потребителям: решение о " +
		"посадке принято одно на всех, а не каждым"
	RoadFindingUntrackedForm = "дорога уходит формой, которой разбор не прослеживает"
	RoadFindingForkAsValue   = "развилка взята значением, а не вызвана: её ветвей разбор не видит"
)

// Индексы ветвей в вызове развилки: `fork(cfg, obs, built, absent)`.
const (
	roadForkBuiltArm  = 2
	roadForkAbsentArm = 3
)

// ProviderRoadFinding — потребитель дороги без своего решения о посадке.
type ProviderRoadFinding struct {
	File string
	Line int
	Func string
	// Kind — вид из закрытого словаря RoadFinding*.
	Kind string
	// Detail — кем и в какой форме: имя принявшего, вид узла.
	Detail string
}

// ProviderRoadConsumerCensus — объём осмотренного и оба рода потребителей.
type ProviderRoadConsumerCensus struct {
	// Funcs — функций с телом осмотрено.
	Funcs int

	// ForkCalls — вызовов развилки (первый род, с устройством).
	ForkCalls int
	// UnforkedCalls — вызовов строителя мимо развилки (первый род, без него).
	UnforkedCalls int

	// ArmReceptions — приёмов дороги доводом из ветви построенной посадки
	// (второй род, решение своё).
	ArmReceptions int
	// UnforkedReceptions — приёмов значения из строителя мимо развилки (второй
	// род, решение чужое).
	UnforkedReceptions int
}

// FirstKind — потребителей первого рода: зовущих строителя.
func (c ProviderRoadConsumerCensus) FirstKind() int { return c.ForkCalls + c.UnforkedCalls }

// SecondKind — потребителей второго рода: принимающих дорогу доводом.
func (c ProviderRoadConsumerCensus) SecondKind() int {
	return c.ArmReceptions + c.UnforkedReceptions
}

// Add — сложение переписей файлов.
func (c ProviderRoadConsumerCensus) Add(o ProviderRoadConsumerCensus) ProviderRoadConsumerCensus {
	return ProviderRoadConsumerCensus{
		Funcs:              c.Funcs + o.Funcs,
		ForkCalls:          c.ForkCalls + o.ForkCalls,
		UnforkedCalls:      c.UnforkedCalls + o.UnforkedCalls,
		ArmReceptions:      c.ArmReceptions + o.ArmReceptions,
		UnforkedReceptions: c.UnforkedReceptions + o.UnforkedReceptions,
	}
}

// ProviderRoadBuilders — имена функций, строящих дорогу: тех, что читают
// резолвер её адреса. Выводится из чтений соседнего гейта, а не выписывается:
// второй перечень строителей разошёлся бы с первым молча.
func ProviderRoadBuilders(reads []ProviderAddressRead) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range reads {
		if !seen[r.Func] {
			seen[r.Func] = true
			out = append(out, r.Func)
		}
	}
	sort.Strings(out)
	return out
}

// ProviderRoadBuildersOutsideTheFork — строители, которые развилкой не являются.
// Находка ставится на каждое чтение резолвера вне развилки: оно и есть место,
// где дорога строится мимо устройства.
func ProviderRoadBuildersOutsideTheFork(reads []ProviderAddressRead, fork string) []ProviderRoadFinding {
	var out []ProviderRoadFinding
	for _, r := range reads {
		if r.Func == fork {
			continue
		}
		out = append(out, ProviderRoadFinding{
			File: r.File, Line: r.Line, Func: r.Func,
			Kind: RoadFindingBuilderOutsideFork, Detail: "читает " + r.Callee,
		})
	}
	return out
}

// ScanProviderRoadConsumers разбирает ОДИН файл.
//
// fork — имя развилки; builders — имена функций, строящих дорогу (обычно
// выведены `ProviderRoadBuilders`). Предмет подаётся именем, а не выводится из
// этого файла: строитель живёт в одном файле, потребители — в других.
func ScanProviderRoadConsumers(path string, src []byte, fork string, builders []string) (
	[]ProviderRoadFinding, ProviderRoadConsumerCensus, error,
) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, ProviderRoadConsumerCensus{}, fmt.Errorf("parse %s: %w", path, err)
	}
	unforked := map[string]bool{}
	for _, b := range builders {
		if b != fork {
			unforked[b] = true
		}
	}

	s := &roadScan{fset: fset, path: path, fork: fork, unforked: unforked}
	for _, decl := range f.Decls {
		fn, isFunc := decl.(*ast.FuncDecl)
		if !isFunc {
			// Уровень пакета: вызова здесь нет, но значение развилки быть может.
			s.fn = "уровень пакета"
			walkWithParents(decl, func(n ast.Node, parents []ast.Node) bool {
				s.checkForkValue(n, parents)
				return true
			})
			continue
		}
		if fn.Body == nil {
			continue
		}
		s.census.Funcs++
		s.fn = claimFuncQualifiedName(fn)
		s.body = fn.Body
		walkWithParents(fn.Body, s.visit)
	}
	sort.SliceStable(s.out, func(i, j int) bool { return s.out[i].Line < s.out[j].Line })
	return s.out, s.census, nil
}

// roadScan — состояние разбора одного файла.
type roadScan struct {
	fset     *token.FileSet
	path     string
	fork     string
	unforked map[string]bool

	fn   string
	body *ast.BlockStmt

	out    []ProviderRoadFinding
	census ProviderRoadConsumerCensus
}

func (s *roadScan) find(at ast.Node, kind, detail string) {
	s.out = append(s.out, ProviderRoadFinding{
		File: s.path, Line: s.fset.Position(at.Pos()).Line, Func: s.fn,
		Kind: kind, Detail: detail,
	})
}

// visit — узел тела функции.
func (s *roadScan) visit(n ast.Node, parents []ast.Node) bool {
	s.checkForkValue(n, parents)
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return true
	}
	switch callee := calleeIdentName(call); {
	case callee == s.fork && callee != "":
		s.census.ForkCalls++
		s.judgeFork(call)
	case s.unforked[callee]:
		s.census.UnforkedCalls++
		s.find(call, RoadFindingUnforkedCall, callee+"()")
		s.followUnforked(call, callee, parents)
	}
	return true
}

// checkForkValue — имя развилки, стоящее НЕ на месте вызываемого.
func (s *roadScan) checkForkValue(n ast.Node, parents []ast.Node) {
	id, ok := n.(*ast.Ident)
	if !ok || s.fork == "" || id.Name != s.fork {
		return
	}
	if !isCalleePosition(id, parents) && !isDeclaringName(id, parents) {
		s.find(id, RoadFindingForkAsValue, id.Name)
	}
}

// judgeFork — ветви одного вызова развилки.
func (s *roadScan) judgeFork(call *ast.CallExpr) {
	if len(call.Args) <= roadForkAbsentArm {
		s.find(call, RoadFindingArmMissing,
			fmt.Sprintf("доводов %d, ветви стоят %d-м и %d-м", len(call.Args),
				roadForkBuiltArm+1, roadForkAbsentArm+1))
		return
	}
	absent := call.Args[roadForkAbsentArm]
	if _, isLit := absent.(*ast.FuncLit); !isLit {
		s.find(absent, armFormKind(absent), "ветвь посадки без поставщика: "+roadExprText(absent))
	}
	built := call.Args[roadForkBuiltArm]
	lit, isLit := built.(*ast.FuncLit)
	if !isLit {
		s.find(built, armFormKind(built), "ветвь построенной посадки: "+roadExprText(built))
		return
	}
	road := firstParamName(lit)
	if road == nil || road.Name == "_" {
		s.find(lit, RoadFindingNoRoadParam, "у ветви нет именованного параметра дороги")
		return
	}
	receptions := s.followRoad(lit, road.Name, lit, road)
	s.census.ArmReceptions += len(receptions)
	switch {
	case len(receptions) == 0:
		s.find(lit, RoadFindingNoReception, road.Name)
	case len(receptions) > 1:
		who := make([]string, 0, len(receptions))
		for _, r := range receptions {
			who = append(who, r.who)
		}
		s.find(lit, RoadFindingSharedDecision, strings.Join(who, ", "))
	}
}

// followUnforked — куда уходит значение строителя мимо развилки.
func (s *roadScan) followUnforked(call *ast.CallExpr, callee string, parents []ast.Node) {
	if len(parents) == 0 {
		return
	}
	var bound *ast.Ident
	switch p := parents[len(parents)-1].(type) {
	case *ast.AssignStmt:
		if len(p.Rhs) == 1 && len(p.Lhs) > 0 {
			bound, _ = p.Lhs[0].(*ast.Ident)
		}
	case *ast.ValueSpec:
		if len(p.Values) == 1 && len(p.Names) > 0 {
			bound = p.Names[0]
		}
	case *ast.CallExpr:
		s.census.UnforkedReceptions++
		s.find(call, RoadFindingUnforkedReception, "довод "+roadExprText(p.Fun)+" из "+callee+"()")
		return
	case *ast.ReturnStmt:
		s.census.UnforkedReceptions++
		s.find(call, RoadFindingUnforkedReception, "возврат из "+callee+"()")
		return
	}
	if bound == nil || bound.Name == "_" {
		return
	}
	for _, r := range s.followRoad(s.body, bound.Name, nil, bound) {
		s.census.UnforkedReceptions++
		s.find(r.at, RoadFindingUnforkedReception, r.who+" из "+callee+"()")
	}
}

// roadReception — одно место, где дорогу приняли доводом или возвратом.
type roadReception struct {
	at  ast.Node
	who string
}

// followRoad — приёмы дороги с именем road внутри scope.
//
// arm — литерал ветви, если дорога её параметр: захват во вложенное замыкание
// судится относительно него, и scope тогда — сам литерал. def — объявляющее
// вхождение имени, которое приёмом не является. Возвращает принявших дорогу
// доводом или возвратом; всякая иная форма уходит находкой сразу.
func (s *roadScan) followRoad(scope ast.Node, road string, arm *ast.FuncLit, def *ast.Ident) []roadReception {
	var out []roadReception
	walkWithParents(scope, func(n ast.Node, parents []ast.Node) bool {
		if arm != nil && n == arm.Type {
			// Параметры и результаты ветви — объявления, а не приёмы.
			return false
		}
		id, ok := n.(*ast.Ident)
		if !ok || id.Name != road || id == def || len(parents) == 0 {
			return true
		}
		if isFieldName(id, parents) {
			return true
		}
		if nearestFuncLit(parents) != arm {
			s.find(id, RoadFindingUntrackedForm, "захват во вложенное замыкание")
			return true
		}
		switch p := parents[len(parents)-1].(type) {
		case *ast.CallExpr:
			if isArgOf(id, p) {
				out = append(out, roadReception{at: id, who: "довод " + roadExprText(p.Fun)})
				return true
			}
			s.find(id, RoadFindingUntrackedForm, "дорога вызвана как функция")
		case *ast.ReturnStmt:
			out = append(out, roadReception{at: id, who: "возврат"})
		default:
			s.find(id, RoadFindingUntrackedForm, roadNodeForm(p))
		}
		return true
	})
	return out
}

// ProviderRoadConsumerPremise — предпосылка вердикта.
//
// Обход, не нашедший строителя дороги, вердикта не выносит: «находок ноль»
// означало бы «прочитано ноль». Строитель есть, а потребителей нет — тоже не
// вердикт: разбор потерял потребителей, а не дерево стало чистым.
func ProviderRoadConsumerPremise(parsed, floor int, builders []string, census ProviderRoadConsumerCensus, fork string) error {
	if parsed < floor {
		return fmt.Errorf("прод-файлов Go разобрано %d при пороге %d — обход не добрался до дерева",
			parsed, floor)
	}
	if census.Funcs == 0 {
		return fmt.Errorf("функций с телом осмотрено 0 — разбор ничего не читал")
	}
	if len(builders) == 0 {
		return fmt.Errorf("строителя административной дороги в дереве нет: резолвер адреса не "+
			"читает ни одна функция. Дорога снята — развилка %s и этот гейт уходят тем же "+
			"изменением, а не остаются стеречь пустоту", fork)
	}
	if census.FirstKind() == 0 {
		return fmt.Errorf("строитель есть (%s), а потребителей первого рода не найдено ни одного: "+
			"разбор потерял вызовы, и «находок ноль» здесь означает «прочитано ноль»",
			strings.Join(builders, ", "))
	}
	return nil
}

// ── разбор узлов ────────────────────────────────────────────────────────────

// walkWithParents обходит поддерево, подавая каждому узлу цепочку его предков
// (ближайший — последним). visit, вернувший false, в поддерево не спускается.
func walkWithParents(root ast.Node, visit func(n ast.Node, parents []ast.Node) bool) {
	var stack []ast.Node
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		if !visit(n, stack) {
			return false
		}
		stack = append(stack, n)
		return true
	})
}

// calleeIdentName — имя вызываемой функции пакета, в том числе с явной
// подстановкой типов (`f[A, B](…)`); для селектора и прочего — пусто.
func calleeIdentName(call *ast.CallExpr) string {
	fun := call.Fun
	switch x := fun.(type) {
	case *ast.IndexExpr:
		fun = x.X
	case *ast.IndexListExpr:
		fun = x.X
	}
	if id, ok := fun.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// isCalleePosition — стоит ли имя на месте вызываемого: `f(…)` либо `f[T](…)`.
func isCalleePosition(id *ast.Ident, parents []ast.Node) bool {
	if len(parents) == 0 {
		return false
	}
	var node ast.Node = id
	i := len(parents) - 1
	switch x := parents[i].(type) {
	case *ast.IndexExpr:
		if x.X != id {
			return false
		}
		node, i = x, i-1
	case *ast.IndexListExpr:
		if x.X != id {
			return false
		}
		node, i = x, i-1
	}
	if i < 0 {
		return false
	}
	call, ok := parents[i].(*ast.CallExpr)
	return ok && call.Fun == node
}

// isDeclaringName — имя в собственном объявлении функции.
func isDeclaringName(id *ast.Ident, parents []ast.Node) bool {
	if len(parents) == 0 {
		return false
	}
	fn, ok := parents[len(parents)-1].(*ast.FuncDecl)
	return ok && fn.Name == id
}

// isFieldName — имя, которое переменной не является: поле за селектором и ключ
// литерала структуры.
func isFieldName(id *ast.Ident, parents []ast.Node) bool {
	switch p := parents[len(parents)-1].(type) {
	case *ast.SelectorExpr:
		return p.Sel == id
	case *ast.KeyValueExpr:
		return p.Key == id
	}
	return false
}

func isArgOf(id *ast.Ident, call *ast.CallExpr) bool {
	for _, a := range call.Args {
		if a == id {
			return true
		}
	}
	return false
}

func nearestFuncLit(parents []ast.Node) *ast.FuncLit {
	for i := len(parents) - 1; i >= 0; i-- {
		if lit, ok := parents[i].(*ast.FuncLit); ok {
			return lit
		}
	}
	return nil
}

func firstParamName(lit *ast.FuncLit) *ast.Ident {
	if lit.Type.Params == nil || len(lit.Type.Params.List) == 0 {
		return nil
	}
	names := lit.Type.Params.List[0].Names
	if len(names) == 0 {
		return nil
	}
	return names[0]
}

func armFormKind(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok && id.Name == "nil" {
		return RoadFindingArmNil
	}
	return RoadFindingArmNotLiteral
}

// roadExprText — короткое имя выражения для текста находки.
func roadExprText(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return roadExprText(x.X) + "." + x.Sel.Name
	case *ast.IndexExpr:
		return roadExprText(x.X)
	case *ast.IndexListExpr:
		return roadExprText(x.X)
	case *ast.FuncLit:
		return "литерал функции"
	case *ast.CallExpr:
		return roadExprText(x.Fun) + "(…)"
	}
	return fmt.Sprintf("%T", e)
}

// roadNodeForm — как назван узел, в котором дорога ушла не доводом и не возвратом.
func roadNodeForm(n ast.Node) string {
	switch n.(type) {
	case *ast.AssignStmt, *ast.ValueSpec:
		return "присваивание"
	case *ast.SelectorExpr:
		return "селектор"
	case *ast.CompositeLit, *ast.KeyValueExpr:
		return "составной литерал"
	case *ast.UnaryExpr:
		return "взятие адреса либо унарная операция"
	case *ast.SendStmt:
		return "отправка в канал"
	}
	return fmt.Sprintf("узел %T", n)
}
