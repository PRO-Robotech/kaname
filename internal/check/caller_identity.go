// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"fmt"
	"go/ast"
	"go/constant"
	"go/types"
	"sort"
	"strings"
	"time"
)

// CallerReadKind различает последствия чтения; объявление не меняет допуск.
type CallerReadKind string

const (
	CallerAuthority   CallerReadKind = "authority"
	CallerOwnership   CallerReadKind = "ownership"
	CallerAudit       CallerReadKind = "audit"
	CallerObservation CallerReadKind = "observation"
)

// CallerReadDeclaration относится к конкретному RPC и месту чтения.
// Site — функция-потребитель, а не путь или перечень разрешённых помощников.
type CallerReadDeclaration struct {
	RPC      string
	Producer string
	Site     string
	Kind     CallerReadKind
	Reason   string
}

type CallerIdentityRead struct{ RPC, Producer, Site, Coordinate string }

// CallerIdentityReport содержит перепись отдельно от находок.
type CallerIdentityReport struct {
	Files, RPCs           int
	Roots                 []string
	Reads                 []CallerIdentityRead
	Findings              []string
	ExcludedExternalCalls int
	ExternalLeaves        []string
	IdentityFreeBindings  []string
	Invalid               string
	Work                  CallerIdentityWork
	declarationEvidence   *callerDeclarationEvidence
}

type callerBody struct {
	sp   *surfaceSrcPkg
	node ast.Node
	name string
}
type callerNode struct {
	fn  *types.Func
	lit *ast.FuncLit
}
type callerGraph struct {
	p                     *surfaceProgram
	closureOwners         map[*ast.FuncLit][]callerNode // Неизменяемый индекс синтаксиса; called остаётся отдельным для каждого решения.
	bodies                map[callerNode]callerBody
	methods               map[string][]*types.Func
	safeExternal          map[string]bool
	index                 *resolveIndex
	live                  map[*types.Var][]valueSrc
	emptyVariadic         map[*types.Var]bool
	may                   map[callerNode]bool
	identityFree          map[string]bool
	assignments           map[*types.Var][]valueSrc
	parameters            map[*types.Var]paramOf
	sourceMemo            map[*types.Var][]valueSrc // Полные синтаксические списки текущей эпохи; только чтение.
	sourceMemoEpoch       int
	sourceMemoWeight      int
	bindingEpoch          int
	zeroVars              map[*types.Var]fkey
	lifetimeCalls         []callSrc
	scalarStoreParams     map[*types.Var]bool                       // Только неизменяемые факты исходного кода.
	projectedStoreCells   map[*ast.SelectorExpr]map[*types.Var]bool // Только неизменяемые источники адреса записи.
	localAppendBuilders   map[*types.Var]bool                       // Полные лексические доказательства; не ответы resolver.
	closedMapHandles      map[*types.Var]callerObjectKey            // Точный initializer либо отсутствие полного source proof.
	lifetimeWrites        []callerLifetimeWrite
	lifetimeWriteIndex    *callerLifetimeWriteIndex
	containerInactive     *callerContainerInactiveMemo
	lifetimeScanning      bool
	effectScanning        bool
	effectEpoch           int
	effectIncomplete      bool
	startup               []callerNode
	containerTypePairs    map[callerSignaturePair]bool
	containerCosts        map[callerResolveKey]*CallerContainerCost
	containerScanning     map[callerResolveKey]bool
	fieldQueries          []callerFieldQuery
	objectCuts            uint64
	objectSourceIDs       map[callerResolveKey]callerObjectSourceID
	objectMemo            map[callerObjectSourceID]callerObjectAnswer
	initialObjectMemo     map[callerObjectSourceID]callerObjectAnswer
	objectMemoEpoch       int
	objectMemoWeight      int // Общий вес полных и начальных ответов.
	objectMemoGeneration  uint64
	resolveMemoGeneration uint64
	objectExecutions      *callerObjectExecutions
	mutations             map[*types.Var][]callerFieldMutation
	mutationScanning      map[callerFieldKey]bool
	resolveMemo           map[callerResolveKey]callerResolveAnswer
	initialResolveMemo    map[callerResolveKey]callerResolveAnswer
	initialResolveWeight  int
	initialSkips          uint64
	completedInitialSkips uint64 // Начальные границы, покрытые завершённым внешним lifetime-барьером.
	resolveMemoEpoch      int
	resolveCuts           uint64
	semanticOverflow      bool // Необратимый отказ всего запуска, включая последующие RPC.
	called                map[callerNode]bool
	resolveWeight         int
	resolveEntryCap       int
	resolveValueCap       int
	work                  CallerIdentityWork
	observer              CallerIdentityObserver
	ctx                   context.Context
	analysisErr           error
	pure                  *callerPureMemo
	mayMemo               *callerMayMemo
	signatureBodies       map[callerSignatureShape][]callerNode

	fieldQueryHeads        map[callerResolveKey]int   // Индексы с единицы; только активные кадры.
	fieldQueryIndexedDepth int                        // -1 сохраняет линейный поиск до полного снятия синтетического стека.
	embeddedLiterals       callerEmbeddedLiteralIndex // Неизменяемый синтаксис; общий для копий графа.
}

func callerFunction(sp *surfaceSrcPkg, expr ast.Expr) *types.Func {
	switch e := ast.Unparen(expr).(type) {
	case *ast.IndexExpr:
		return callerFunction(sp, e.X)
	case *ast.IndexListExpr:
		return callerFunction(sp, e.X)
	case *ast.Ident:
		f, _ := sp.info.Uses[e].(*types.Func)
		return f
	case *ast.SelectorExpr:
		if s := sp.info.Selections[e]; s != nil {
			f, _ := s.Obj().(*types.Func)
			return f
		}
		f, _ := sp.info.Uses[e.Sel].(*types.Func)
		return f
	}
	return nil
}

func callerVariable(sp *surfaceSrcPkg, e ast.Expr) *types.Var {
	switch x := ast.Unparen(e).(type) {
	case *ast.Ident:
		if v, ok := sp.info.Defs[x].(*types.Var); ok {
			return v
		}
		v, _ := sp.info.Uses[x].(*types.Var)
		return v
	case *ast.SelectorExpr:
		if s := sp.info.Selections[x]; s != nil {
			v, _ := s.Obj().(*types.Var)
			return v
		}
		v, _ := sp.info.Uses[x.Sel].(*types.Var)
		return v
	}
	return nil
}

func newCallerGraph(p *surfaceProgram) *callerGraph {
	g := &callerGraph{p: p, bodies: map[callerNode]callerBody{}, methods: map[string][]*types.Func{}, live: map[*types.Var][]valueSrc{}, identityFree: map[string]bool{}}
	flow := newSurfaceFlow(p)
	flow.collect()
	g.index = flow.idx
	g.zeroVars = flow.zeroVars
	g.assignments = map[*types.Var][]valueSrc{}
	g.parameters = map[*types.Var]paramOf{}
	for v, refs := range g.index.varWrites {
		g.assignments[v.Origin()] = append(g.assignments[v.Origin()], refs...)
	}
	for v, refs := range g.index.fieldWrites {
		g.assignments[v.Origin()] = append(g.assignments[v.Origin()], refs...)
	}
	for v, p := range g.index.params {
		g.parameters[v.Origin()] = p
	}
	for fn, decl := range flow.decls {
		if decl.decl.Body == nil {
			continue
		}
		fn = fn.Origin()
		g.bodies[callerNode{fn: fn}] = callerBody{decl.pkg, decl.decl.Body, fn.FullName()}
		if decl.decl.Recv != nil {
			g.methods[fn.Name()] = append(g.methods[fn.Name()], fn)
		}
	}
	for lit, sp := range flow.litPkg {
		g.bodies[callerNode{lit: lit}] = callerBody{sp, lit.Body, "closure@" + p.fset.Position(lit.Pos()).String()}
	}
	g.indexCallerClosureOwners()
	// go/types даёт отдельный объект каждой ветви type switch. Индекс
	// общих присваиваний его не содержит; источник у него — operand switch.
	for _, sp := range p.pkgs {
		for _, file := range sp.files {
			ast.Inspect(file, func(n ast.Node) bool {
				if literal, ok := n.(*ast.CompositeLit); ok {
					g.embeddedLiterals.add(sp, literal)
				}
				sw, ok := n.(*ast.TypeSwitchStmt)
				if !ok {
					return true
				}
				var operand ast.Expr
				switch a := sw.Assign.(type) {
				case *ast.AssignStmt:
					if assertion, ok := a.Rhs[0].(*ast.TypeAssertExpr); ok {
						operand = assertion.X
					}
				case *ast.ExprStmt:
					if assertion, ok := a.X.(*ast.TypeAssertExpr); ok {
						operand = assertion.X
					}
				}
				if operand != nil {
					for _, branch := range sw.Body.List {
						if v, ok := sp.info.Implicits[branch].(*types.Var); ok {
							g.assignments[v.Origin()] = append(g.assignments[v.Origin()], valueSrc{pkg: sp, expr: operand, tuple: -1})
						}
					}
				}
				return true
			})
		}
	}
	g.collectCallerMutations()
	g.collectCallerLifetime()
	g.indexCallerLifetimeWrites()
	g.prepareCallerSignatures()
	return g
}

func (g *callerGraph) targets(sp *surfaceSrcPkg, e ast.Expr, _ map[*types.Var]bool) (out []callerNode, unresolved bool) {
	values, u := g.resolve(valueSrc{pkg: sp, expr: e, tuple: -1}, false, map[callerResolveKey]bool{})
	unresolved = u || len(values) == 0
	seen := map[callerNode]bool{}
	for _, v := range values {
		if v.foreign || v.nilValue {
			continue
		}
		if !seen[v.node] {
			out = append(out, v.node)
			seen[v.node] = true
		}
	}
	if unresolved && g.may != nil && !g.unresolvedCallerRelevant(sp, e) {
		g.identityFree[pPosition(g.p, e)] = true
		unresolved = false
	}
	return out, unresolved
}

func pPosition(p *surfaceProgram, e ast.Expr) string { return p.fset.Position(e.Pos()).String() }

func callerProducer(fn *types.Func) string {
	if fn == nil || fn.Pkg() == nil {
		return ""
	}
	path := fn.Pkg().Path()
	if path == "github.com/PRO-Robotech/corelib/operations" && (fn.Name() == "PrincipalFromContext" || fn.Name() == "PrincipalFromContextOK") {
		return path + "." + fn.Name()
	}
	if path == "github.com/PRO-Robotech/corelib/grpcsrv" && (fn.Name() == "CertIdentityFromContext" || fn.Name() == "CertIdentityDomainFromContext") {
		return path + "." + fn.Name()
	}
	if path == "github.com/PRO-Robotech/kaname/internal/moduleidentity" && fn.Name() == "FromContext" {
		sig := fn.Type().(*types.Signature)
		if sig.Recv() != nil && isNamed(sig.Recv().Type(), path, "Roster") {
			return path + ".Roster.FromContext"
		}
	}
	return ""
}

// CallerIdentityFindings проверяет реальные корни и объявления, включая
// устаревшие записи. Наложение использует тот же загрузчик, что живое дерево.
func CallerIdentityFindings(ctx context.Context, root string, declared []CallerReadDeclaration, overlay map[string]string, observers ...CallerIdentityObserver) (CallerIdentityReport, error) {
	var observer CallerIdentityObserver
	if len(observers) > 0 {
		observer = observers[0]
	}
	loadStart := time.Now()
	if observer != nil {
		observer("load:start", CallerIdentityWork{})
	}
	l, err := bindingPairListingFor(ctx, root, []string{"cmd/kaname"})
	if err != nil {
		return CallerIdentityReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	p, err := l.program(overlay)
	if err != nil {
		return CallerIdentityReport{}, err
	}
	loadElapsed := time.Since(loadStart)
	if observer != nil {
		observer("load:end", CallerIdentityWork{Load: loadElapsed})
	}
	r := judgeCallerIdentityObserved(ctx, p, declared, callerExternalLeafProof(l), observer)
	r.Work.Load = loadElapsed
	if r.Invalid != "" {
		return r, fmt.Errorf("гейт НЕ ИСПОЛНЯЛСЯ: %s", r.Invalid)
	}
	return r, nil
}

// callerExternalLeafProof выводит отсечение из всего графа импортов:
// пакет и все его зависимости не имеют доступа к API ключей личности наших
// модулей. Доводы-функции рассматриваются отдельно, а не исключаются пакетом.
func callerExternalLeafProof(l *surfaceListing) map[string]bool {
	proof := map[string]bool{}
	seen := map[string]bool{}
	var safe func(string) bool
	safe = func(path string) bool {
		if seen[path] {
			return proof[path]
		}
		seen[path] = true
		if strings.HasPrefix(path, "github.com/PRO-Robotech/") {
			return false
		}
		p, ok := l.byPath[path]
		if !ok {
			return false
		}
		for _, dep := range p.Imports {
			if !safe(dep) {
				return false
			}
		}
		proof[path] = true
		return true
	}
	for path := range l.byPath {
		safe(path)
	}
	return proof
}

func judgeCallerIdentity(p *surfaceProgram, declared []CallerReadDeclaration, external ...map[string]bool) CallerIdentityReport {
	var proof map[string]bool
	if len(external) > 0 {
		proof = external[0]
	}
	return judgeCallerIdentityObserved(context.Background(), p, declared, proof, nil)
}

func judgeCallerIdentityObserved(ctx context.Context, p *surfaceProgram, declared []CallerReadDeclaration, proof map[string]bool, observer CallerIdentityObserver) CallerIdentityReport {
	return judgeCallerIdentityDiagnostic(ctx, p, declared, proof, observer, "")
}

// Непустой diagnosticRPC используется только явно включаемым профилировщиком. Он всегда
// возвращает INVALID, даже если выбранный корень завершён; это не доказательство покрытия.
func judgeCallerIdentityDiagnostic(ctx context.Context, p *surfaceProgram, declared []CallerReadDeclaration, proof map[string]bool, observer CallerIdentityObserver, diagnosticRPC string) (report CallerIdentityReport) {
	if diagnosticRPC != "" {
		defer func() {
			// Любой выход, включая отсутствие программы и ошибки до выбора
			// корня, явно непригоден как свидетельство покрытия.
			reason := report.Invalid
			if reason == "" {
				reason = strings.Join(report.Findings, "; ")
			}
			report.Invalid = "DIAGNOSTIC ONLY / NOT_ACCEPTANCE: " + diagnosticRPC
			if reason != "" {
				report.Invalid += ": " + reason
			}
		}()
	}
	scope := callerRegisteredWalk{rpc: diagnosticRPC}
	r := scope.collect(ctx, p, proof, observer)
	if r.Invalid != "" || scope.readSet == nil {
		return r
	}
	if diagnosticRPC != "" {
		return CallerIdentityReport{Invalid: "selected root traversal completed", Roots: r.Roots, RPCs: r.RPCs, Work: r.Work}
	}
	narrow, err := callerRuntimeNarrowing(p)
	if err != nil {
		r.Findings = append(r.Findings, err.Error())
	}
	evidence := &callerDeclarationEvidence{readSet: scope.readSet, narrow: narrow, appliedNarrow: scope.appliedNarrow}
	r.Findings = append(r.Findings, evidence.findings(r.Reads, declared)...)
	sort.Strings(r.Findings)
	if err := ctx.Err(); err != nil {
		return CallerIdentityReport{Invalid: err.Error(), Work: r.Work}
	}
	r.declarationEvidence = evidence
	return r
}

// Факты вызовов появляются только после завершения каждого выбранного корня.
// Пустой rpc требует обхода всей регистрации. Один rpc годится для проверки
// конкретного обработчика и не подтверждает декларации остальных методов.
type callerRegisteredWalk struct {
	rpc           string
	readSet       map[string]bool
	appliedNarrow map[string]bool
}

func (scope *callerRegisteredWalk) collect(ctx context.Context, p *surfaceProgram, proof map[string]bool, observer CallerIdentityObserver) (report CallerIdentityReport) {
	if p == nil || p.root == nil {
		return CallerIdentityReport{Findings: []string{"обход личности пуст: нет композиционного корня"}}
	}
	g := callerGraphFor(p, observer)
	defer g.refuseCallerSemanticOverflow(&report)
	g.ctx = ctx
	g.safeExternal = proof
	g.callerMayRead()
	if g.analysisErr != nil {
		return CallerIdentityReport{Invalid: g.analysisErr.Error(), Work: g.work}
	}
	solveStart := time.Now()
	if observer != nil {
		observer("rpc-solve:start", g.work)
	}
	r := CallerIdentityReport{}
	roots := map[string][]callerNode{}
	rootBindings := map[string]map[*types.Var][]valueSrc{}
	for _, sp := range p.pkgs {
		r.Files += len(sp.files)
	}
	for _, registrationPkg := range p.pkgs {
		for _, file := range registrationPkg.files {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				fn := callerFunction(registrationPkg, call.Fun)
				if fn == nil || fn.Pkg() == nil || !strings.HasPrefix(fn.Name(), "Register") || !strings.HasSuffix(fn.Name(), "ServiceServer") {
					return true
				}
				registration, exists := g.bodies[callerNode{fn: fn.Origin()}]
				if !exists {
					r.Findings = append(r.Findings, "источник регистрации не разрешён: "+fn.FullName())
					return true
				}
				registers := false
				ast.Inspect(registration.node, func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok {
						if target := callerFunction(registration.sp, c.Fun); target != nil && target.Pkg() != nil && target.Pkg().Path() == "google.golang.org/grpc" && target.Name() == "RegisterService" {
							registers = true
						}
					}
					return true
				})
				if !registers {
					return true
				}
				sig := fn.Type().(*types.Signature)
				if sig.Params().Len() != 2 || len(call.Args) != 2 {
					return true
				}
				iface, ok := sig.Params().At(1).Type().Underlying().(*types.Interface)
				if !ok {
					return true
				}
				actual := registrationPkg.info.TypeOf(call.Args[1])
				service := strings.TrimSuffix(strings.TrimPrefix(fn.Name(), "Register"), "Server")
				for i := 0; i < iface.NumMethods(); i++ {
					method := iface.Method(i)
					if !method.Exported() {
						continue
					}
					key := fn.Pkg().Path() + "/" + service + "/" + method.Name()
					if actual == nil {
						r.Findings = append(r.Findings, key+": тип обработчика не разрешён")
						continue
					}
					obj, lookupPath, _ := types.LookupFieldOrMethod(actual, true, method.Pkg(), method.Name())
					target, ok := obj.(*types.Func)
					if !ok {
						r.Findings = append(r.Findings, key+": метод обработчика не разрешён")
						continue
					}
					var ns []callerNode
					var u bool
					if isIfaceMethod(target) || len(lookupPath) > 1 {
						ns, u = g.boundMethod(registrationPkg, call.Args[1], target, map[callerResolveKey]bool{})
					} else {
						ns = []callerNode{{fn: target.Origin()}}
					}
					if u {
						r.Findings = append(r.Findings, key+": реализация обработчика не разрешена")
					}
					roots[key] = append(roots[key], ns...)
					if rootBindings[key] == nil {
						rootBindings[key] = map[*types.Var][]valueSrc{}
					}
					for _, node := range ns {
						if node.fn == nil {
							continue
						}
						recv := node.fn.Type().(*types.Signature).Recv()
						if recv == nil {
							continue
						}
						refs := g.live[recv.Origin()]
						if !isIfaceMethod(target) && len(lookupPath) <= 1 {
							refs = []valueSrc{{pkg: registrationPkg, expr: call.Args[1], tuple: -1}}
						}
						rootBindings[key][recv.Origin()] = append(rootBindings[key][recv.Origin()], refs...)
					}
				}
				return true
			})
		}
	}
	r.RPCs = len(roots)
	for rpc := range roots {
		r.Roots = append(r.Roots, rpc)
	}
	sort.Strings(r.Roots)
	cut := map[string]bool{}
	readSet := map[string]bool{}
	readCoordinates := map[string]bool{}
	appliedNarrow := map[string]bool{}
	visitedRoots := 0
	for _, rpc := range r.Roots {
		if g.semanticOverflow {
			return r
		}
		starts, exists := roots[rpc]
		if !exists {
			return CallerIdentityReport{Invalid: "sorted RPC root missing: " + rpc, Work: g.work}
		}
		if scope.rpc != "" && rpc != scope.rpc {
			continue
		}
		visitedRoots++
		g.containerTypePairs = nil
		g.containerCosts = nil
		g.work.ContainerUniqueTypePairs = 0
		g.work.ContainerSlowest = [5]CallerContainerCost{}
		if err := ctx.Err(); err != nil {
			return CallerIdentityReport{Invalid: err.Error(), Work: g.work}
		}
		g.live = map[*types.Var][]valueSrc{}
		g.emptyVariadic = map[*types.Var]bool{}
		g.called = map[callerNode]bool{}
		g.containerInactive = nil
		g.bindingEpoch = 0
		g.sourceMemo = nil
		g.sourceMemoEpoch, g.sourceMemoWeight = 0, 0
		g.effectEpoch = -1
		g.objectMemo = nil
		g.initialObjectMemo = nil
		g.objectMemoEpoch, g.objectMemoWeight = 0, 0
		g.resolveMemo = nil
		g.resolveWeight = 0
		g.resetCallerObjectExecutions()
		g.work.ResolveMemoEntries, g.work.ResolveMemoValues = 0, 0
		for v, refs := range rootBindings[rpc] {
			for _, ref := range refs {
				g.addCallerLive(v, ref)
			}
		}
		if observer != nil {
			g.work.Solve = time.Since(solveStart)
			observer("rpc-solve:root:start "+rpc, g.work)
		}
		findStart, readStart, externalStart := len(r.Findings), len(r.Reads), r.ExcludedExternalCalls
		seen := map[callerNode]bool{}
		var walk func(callerNode)
		walk = func(node callerNode) {
			if ctx.Err() != nil {
				return
			}
			if seen[node] {
				return
			}
			seen[node] = true
			g.markCallerCalled(node)
			b, ok := g.bodies[node]
			if !ok {
				return
			}
			ast.Inspect(b.node, func(n ast.Node) bool {
				if ctx.Err() != nil {
					return false
				}
				if _, nested := n.(*ast.FuncLit); nested {
					return false
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				fn := callerFunction(b.sp, call.Fun)
				if fn != nil && fn.Pkg() != nil && fn.Pkg().Path() == "github.com/PRO-Robotech/kaname/internal/authzguard" && fn.Name() == "NarrowsCallerArgument" && len(call.Args) == 2 {
					if value := b.sp.info.Types[call.Args[0]].Value; value != nil && value.Kind() == constant.String {
						if callerRPCName(constant.StringVal(value)) == rpc {
							appliedNarrow[rpc] = true
						}
					}
				}
				if producer := callerProducer(fn); producer != "" {
					row := CallerIdentityRead{rpc, producer, b.name, p.fset.Position(call.Pos()).String()}
					key := rpc + "\x00" + producer + "\x00" + b.name
					if !readCoordinates[key+row.Coordinate] {
						r.Reads = append(r.Reads, row)
						readCoordinates[key+row.Coordinate] = true
					}
					readSet[key] = true
					return true
				}
				// Преобразование типа и встроенная операция не зовут помощника.
				if tv, ok := b.sp.info.Types[call.Fun]; ok && tv.IsType() {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok {
					if _, ok := b.sp.info.Uses[id].(*types.Builtin); ok {
						return true
					}
				}
				ns, u := g.targets(b.sp, call.Fun, map[*types.Var]bool{})
				if ctx.Err() != nil {
					return false
				}
				if u {
					r.Findings = append(r.Findings, rpc+": неразрешённый вызов "+p.fset.Position(call.Pos()).String())
				}
				if len(ns) == 0 && !u {
					if fn != nil && fn.Pkg() != nil && g.safeExternal[fn.Pkg().Path()] {
						r.ExcludedExternalCalls++
						cut[fn.Pkg().Path()] = true
					}
				}
				for _, next := range ns {
					g.bindCaller(b.sp, node, call, next)
					if ctx.Err() != nil {
						return false
					}
					if producer := callerProducer(next.fn); producer != "" {
						row := CallerIdentityRead{rpc, producer, b.name, p.fset.Position(call.Pos()).String()}
						key := rpc + "\x00" + producer + "\x00" + b.name
						if !readCoordinates[key+row.Coordinate] {
							r.Reads = append(r.Reads, row)
							readCoordinates[key+row.Coordinate] = true
						}
						readSet[key] = true
					} else {
						walk(next)
					}
					if ctx.Err() != nil {
						return false
					}
				}
				for index, arg := range call.Args {
					if len(ns) != 0 || u || g.callerArgumentStoredWithoutCall(b.sp, call, index) {
						continue
					}
					typ := b.sp.info.TypeOf(arg)
					if typ == nil {
						continue
					}
					if _, ok := typ.Underlying().(*types.Signature); !ok {
						continue
					}
					ns, u := g.targets(b.sp, arg, map[*types.Var]bool{})
					if ctx.Err() != nil {
						return false
					}
					if u {
						r.Findings = append(r.Findings, rpc+": неразрешённый callback "+p.fset.Position(arg.Pos()).String())
					}
					for _, next := range ns {
						walk(next)
						if ctx.Err() != nil {
							return false
						}
					}
				}
				return true
			})
		}
		converged := false
		for round := 0; round < CeremonySolveRoundLimit; round++ {
			if g.semanticOverflow {
				return r
			}
			g.work.SolveRounds++
			if err := ctx.Err(); err != nil {
				r.Invalid = err.Error()
				r.Work = g.work
				return r
			}
			epoch := g.bindingEpoch
			seen = map[callerNode]bool{}
			r.Findings = r.Findings[:findStart]
			r.Reads = r.Reads[:readStart]
			r.ExcludedExternalCalls = externalStart
			appliedNarrow[rpc] = false
			for key := range readSet {
				if strings.HasPrefix(key, rpc+"\x00") {
					delete(readSet, key)
				}
			}
			for key := range readCoordinates {
				if strings.HasPrefix(key, rpc+"\x00") {
					delete(readCoordinates, key)
				}
			}
			for _, start := range starts {
				walk(start)
				if ctx.Err() != nil {
					break
				}
			}
			if err := ctx.Err(); err != nil {
				g.work.Solve = time.Since(solveStart)
				if observer != nil {
					observer("rpc-solve:root:interrupted "+rpc, g.work)
				}
				return CallerIdentityReport{Invalid: err.Error(), Work: g.work}
			}
			if epoch == g.bindingEpoch {
				converged = true
				break
			}
		}
		g.work.Solve = time.Since(solveStart)
		if !converged {
			r.Invalid = "привязки вызовов не достигли неподвижной точки: " + rpc
			r.Work = g.work
			if observer != nil {
				observer("rpc-solve:root:invalid "+rpc, g.work)
			}
			return r
		}
		if observer != nil {
			observer("rpc-solve:root:end "+rpc, g.work)
		}
	}
	if err := ctx.Err(); err != nil {
		return CallerIdentityReport{Invalid: err.Error(), Work: g.work}
	}
	if scope.rpc == "" {
		if visitedRoots != len(roots) || visitedRoots != len(r.Roots) {
			return CallerIdentityReport{Invalid: "sorted RPC traversal lost roots", Work: g.work}
		}
	} else if visitedRoots != 1 || len(roots[scope.rpc]) == 0 {
		return CallerIdentityReport{Invalid: "selected RPC has no registered implementation: " + scope.rpc, Work: g.work}
	}
	if r.Files == 0 || r.RPCs == 0 || len(r.Reads) == 0 {
		r.Findings = append(r.Findings, "обход личности пуст: файлов, RPC или чтений нет")
	}
	g.work.Solve = time.Since(solveStart)
	if observer != nil && scope.rpc == "" {
		observer("rpc-solve:end", g.work)
	}
	scope.readSet = readSet
	scope.appliedNarrow = appliedNarrow
	if scope.rpc != "" {
		r.Work = g.work
		return r
	}
	sort.Slice(r.Reads, func(i, j int) bool { return fmt.Sprint(r.Reads[i]) < fmt.Sprint(r.Reads[j]) })
	for pkg := range cut {
		r.ExternalLeaves = append(r.ExternalLeaves, pkg)
	}
	sort.Strings(r.ExternalLeaves)
	for position := range g.identityFree {
		r.IdentityFreeBindings = append(r.IdentityFreeBindings, position)
	}
	sort.Strings(r.IdentityFreeBindings)
	if err := ctx.Err(); err != nil {
		return CallerIdentityReport{Invalid: err.Error(), Work: g.work}
	}
	r.Work = g.work
	return r
}

// Эти множества получены из того же типизированного обхода, что и Reads.
type callerDeclarationEvidence struct {
	readSet, narrow, appliedNarrow map[string]bool
}

func (e *callerDeclarationEvidence) findings(reads []CallerIdentityRead, declared []CallerReadDeclaration) []string {
	var findings []string
	entries := map[string][]CallerReadDeclaration{}
	for _, d := range declared {
		key := d.RPC + "\x00" + d.Producer + "\x00" + d.Site
		entries[key] = append(entries[key], d)
		if d.Reason == "" || (d.Kind != CallerAuthority && d.Kind != CallerOwnership && d.Kind != CallerAudit && d.Kind != CallerObservation) {
			findings = append(findings, "неполное описание чтения: "+key)
		}
		if !e.readSet[key] {
			findings = append(findings, "устаревшее описание чтения: "+key)
		}
	}
	for _, row := range reads {
		key := row.RPC + "\x00" + row.Producer + "\x00" + row.Site
		ds := entries[key]
		isNarrow := e.narrow[row.RPC] && e.appliedNarrow[row.RPC] && strings.HasSuffix(row.Producer, "moduleidentity.Roster.FromContext")
		if len(ds) > 1 || (isNarrow && len(ds) > 0) {
			findings = append(findings, row.Coordinate+": пересечение описаний "+row.RPC)
		}
		if !isNarrow && len(ds) == 0 {
			findings = append(findings, row.Coordinate+": чтение личности без объявления "+row.RPC+" -> "+row.Producer+" @ "+row.Site)
		}
	}
	for rpc := range e.narrow {
		if !e.appliedNarrow[rpc] {
			findings = append(findings, "объявление сужения не применяется обработчиком: "+rpc)
		}
		found := false
		for _, row := range reads {
			if row.RPC == rpc && strings.HasSuffix(row.Producer, "moduleidentity.Roster.FromContext") {
				found = true
			}
		}
		if !found {
			findings = append(findings, "объявление сужения без reader: "+rpc)
		}
	}
	return findings
}

func callerRuntimeNarrowing(p *surfaceProgram) (map[string]bool, error) {
	out := map[string]bool{}
	sp := p.byPath["github.com/PRO-Robotech/kaname/internal/authzguard"]
	if sp == nil {
		return out, fmt.Errorf("источник runtime-сужений не прочитан")
	}
	for _, file := range sp.files {
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if name.Name != "callerNarrowedArguments" {
						continue
					}
					if i >= len(vs.Values) {
						return out, fmt.Errorf("объявление runtime-сужений не разрешено")
					}
					lit, ok := vs.Values[i].(*ast.CompositeLit)
					if !ok {
						return out, fmt.Errorf("объявление runtime-сужений не literal")
					}
					for _, e := range lit.Elts {
						kv, ok := e.(*ast.KeyValueExpr)
						if !ok {
							return out, fmt.Errorf("строка runtime-сужений не разрешена")
						}
						profiles, ok := kv.Value.(*ast.CompositeLit)
						if !ok || len(profiles.Elts) == 0 {
							return out, fmt.Errorf("профили runtime-сужения пусты или не разрешены")
						}
						value := sp.info.Types[kv.Key].Value
						if value == nil || value.Kind() != constant.String {
							return out, fmt.Errorf("имя runtime-сужения не разрешено")
						}
						method := constant.StringVal(value)
						key := callerRPCName(method)
						if key == "" {
							return out, fmt.Errorf("имя runtime-сужения не полное: %s", method)
						}
						out[key] = true
					}
					return out, nil
				}
			}
		}
	}
	return out, fmt.Errorf("единственное объявление runtime-сужений не найдено")
}

func callerRPCName(method string) string {
	parts := strings.Split(method, "/")
	if len(parts) != 3 || parts[0] != "" {
		return ""
	}
	service := strings.Split(parts[1], ".")
	return "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1/" + service[len(service)-1] + "/" + parts[2]
}
