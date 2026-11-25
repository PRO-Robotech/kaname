// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"go/ast"
	"go/types"
	"sync"
	"time"
)

// CallerIdentityWork считает работу прибора, а не предполагает её по времени.
type CallerIdentityWork struct {
	OriginTransferHits, OriginTransferStores, OriginTransferRejected, OriginTransferReads int
	OriginTransferCapacityFallbacks, OriginTransferEvictions, OriginTransferCandidates    int
	OriginTransferOwners, OriginTransferFieldRestores                                     int
	OriginTransferRepeatReplays                                                           int // Полные повторные переводы, уже обеспеченные тем же live frame.
	FieldQueryCandidates                                                                  int // Число реально посещённых активных кадров запроса поля.
	EmbeddedLiteralHits                                                                   int // Раскрытия через неизменяемый индекс полей литерала.
	Load, Collect, MayEdges, MayPropagation, Solve                                        time.Duration
	GraphBuilds, GraphHits, MayBuilds, MayHits                                            int
	PotentialQueries, PotentialEvaluations, PotentialHits                                 int
	SignatureQueries, SignatureEvaluations, SignatureHits                                 int
	TypeQueries, TypeVisits, TypeHits, SolveRounds                                        int
	ResolveQueries, ResolveEvaluations, ResolveHits, ResolveCycleCuts                     int
	ResolveRawValues, ResolveDistinctValues, ResolveMaxRaw, ResolveMaxDistinct            int
	ResolveMemoEntries, ResolveMemoValues, ResolvePeakEntries, ResolvePeakValues          int
	ResolveRejected, ResolveInvalidations                                                 int
	ResolveInitialQueries, ResolveInitialHits, LifetimeProofs, LifetimeInitialSkips       int
	// Original = Scanned + Excluded + InactiveSkipped, включая полные обходы.
	// Счётчики активности и пар типов описывают посещённые записи.
	ContainerCalls, ContainerScannedWrites, ContainerActiveWrites                 int
	ContainerOriginalWrites, ContainerExcludedWrites, ContainerIndexFallbacks     int
	ContainerInactiveSkippedWrites, ContainerInactiveCandidateChecks              int
	ContainerInactiveCacheHits, ContainerInactiveCacheBuilds                      int
	ContainerInactiveEpochFallbacks                                               int
	ContainerCandidateHits, ContainerCandidateBuilds                              int
	ContainerTypeCompatibleWrites, ContainerMatchedWrites                         int
	ContainerTypePairQueries, ContainerUniqueTypePairs, ContainerTypePairOverflow int
	ContainerCoordinateDrops                                                      int
	ContainerInputAdmissionBypasses                                               int // Начальные обходы контейнера без внешнего execution-снимка.
	ContainerOwnerAdmissionBypasses                                               int // Обходы владельца без попытки получить общий execution-снимок.
	ObjectTraceQueries, ObjectTraceHits, ObjectTraceStores                        int
	ObjectTraceSeenReads, ObjectTraceDependencySteps, ObjectTraceValidationSteps  int
	ObjectTraceEvictions, ObjectTraceEvictedValues                                int // Удалённые сертификаты и единицы их собственного хранения.
	ObjectTraceCapacityFallbacks                                                  int
	ObjectTraceCycleBypasses                                                      int // Уже активные source, переданные raw без trace admission при нехватке места.
	ObjectSourceIDs                                                               int
	ObjectQueries, ObjectHits, ObjectEpochResets, ObjectRetained                  int
	ObjectSemanticOverflows                                                       int // Необратимые отказы семантической арифметики.
	ObjectRawEvaluations                                                          int // Реальные входы в сырой обход, включая дочерние.
	ObjectExecutionQueries, ObjectExecutionHits, ObjectExecutionStores            int
	ObjectExecutionFallbacks                                                      int // Вызовы слоя, переданные исходному обходу, включая обычный memo.
	ObjectExecutionInvalidations, ObjectExecutionCapacityFallbacks                int
	ObjectExecutionPeakEntries, ObjectExecutionPeakValues                         int
	ObjectExecutionEvictions, ObjectExecutionEvictedValues                        int // Удалённые при допуске fresh answers и их собственные единицы, без scopes.
	ObjectExecutionRetiredAnswers, ObjectExecutionReleasedScopes                  int // Реально освобождённые obsolete answers и scopes без ссылок.
	ObjectScopeHandoffs                                                           int // Первые interior tickets без повторного полного scopeHash, после exact matches.
	ObjectScopeTrackedFrameVisits                                                 int // Реально прочитанные кадры полного structural tracked-доказательства.
	ObjectRejectEpoch, ObjectRejectCut, ObjectRejectInitial, ObjectRejectCapacity int
	// Только записи объединения through: baseline — прежний размер копируемого дочернего множества;
	// actual считает меньшее множество при передаче владения неопубликованным дочерним результатом.
	ObjectUnionBaselineWrites, ObjectUnionWrites, ObjectUnionTransfers                    int
	EffectClosureCalls, EffectClosureRounds, EffectClosureSites, EffectClosureActiveSites int
	ClosureOwnershipQueries, ClosureOwnershipCandidates, ClosureOwnershipFallbacks        int
	LifetimeProbeSteps                                                                    int
	ContainerSlowest                                                                      [5]CallerContainerCost
	ResolveSlowest                                                                        [5]CallerResolveCost
	UnboundCallbackQueries                                                                int
	RecentUnboundCallbacks                                                                [8]string
}

func (g *callerGraph) observeUnboundCallback(v *types.Var) {
	g.taintCallerOrigins()
	param, ok := g.parameters[v.Origin()]
	if !ok || param.fk.lit == nil || g.p == nil {
		return
	}
	g.work.UnboundCallbackQueries++
	position := g.p.fset.Position(v.Pos()).String()
	for _, old := range g.work.RecentUnboundCallbacks {
		if old == position {
			return
		}
	}
	copy(g.work.RecentUnboundCallbacks[1:], g.work.RecentUnboundCallbacks[:])
	g.work.RecentUnboundCallbacks[0] = position
}

// Самые долгие отдельные вычисления, не сумма вложенных длительностей.
type CallerResolveCost struct {
	Coordinate    string
	Elapsed       time.Duration
	Raw, Distinct int
}

// Верхние координаты считают включительную работу обхода первых 256 ключей запросов на
// RPC, а не процессорное время. ContainerCoordinateDrops явно показывает усечение. Ключи пар хранят
// неизменяемые идентичности go/types; при переполнении число уникальных пар — нижняя граница.
// При overflow > 0 эта нижняя граница никогда не доказывает порог отношения <= 1%.
type CallerContainerCost struct {
	key                                         callerResolveKey // Та же идентичность, что в ограниченной карте; намеренно отсутствует в JSON.
	Coordinate                                  string
	Calls, Scanned, Active, Compatible, Matched int
}

const callerDiagnosticPairLimit = 4096

func (g *callerGraph) observeContainerPair(a, b types.Type) {
	g.work.ContainerTypePairQueries++
	key := callerSignaturePair{a, b}
	if g.containerTypePairs[key] {
		return
	}
	if len(g.containerTypePairs) >= callerDiagnosticPairLimit {
		g.work.ContainerTypePairOverflow++
		return
	}
	if g.containerTypePairs == nil {
		g.containerTypePairs = map[callerSignaturePair]bool{}
	}
	g.containerTypePairs[key] = true
	g.work.ContainerUniqueTypePairs = len(g.containerTypePairs)
}

func (g *callerGraph) observeContainerCost(src valueSrc, before CallerContainerCost) {
	key := callerResolveKeyFor(src, true)
	cost := g.containerCosts[key]
	if cost == nil {
		// Храним ограниченные координаты вместо печати неограниченной карты.
		if len(g.containerCosts) >= 256 {
			g.work.ContainerCoordinateDrops++
			return
		}
		if g.containerCosts == nil {
			g.containerCosts = map[callerResolveKey]*CallerContainerCost{}
		}
		cost = &CallerContainerCost{key: key, Coordinate: pPosition(g.p, src.expr)}
		g.containerCosts[key] = cost
	}
	cost.Calls++
	cost.Scanned += g.work.ContainerScannedWrites - before.Scanned
	cost.Active += g.work.ContainerActiveWrites - before.Active
	cost.Compatible += g.work.ContainerTypeCompatibleWrites - before.Compatible
	cost.Matched += g.work.ContainerMatchedWrites - before.Matched
	top := g.work.ContainerSlowest
	for i, old := range top {
		if old.key == cost.key {
			copy(top[i:], top[i+1:])
			top[len(top)-1] = CallerContainerCost{}
			break
		}
	}
	for i, old := range top {
		if cost.Scanned > old.Scanned || cost.Scanned == old.Scanned && cost.Coordinate < old.Coordinate {
			copy(top[i+1:], top[i:])
			top[i] = *cost
			break
		}
	}
	g.work.ContainerSlowest = top
}

type CallerIdentityObserver func(string, CallerIdentityWork)
type callerSignaturePair struct{ a, b types.Type }
type callerPotentialKey struct {
	fn        *types.Func
	lit       *ast.FuncLit
	signature types.Type
}
type callerSignatureShape struct {
	params, results int
	variadic        bool
}
type callerPureMemo struct {
	mu         sync.Mutex
	potential  map[callerPotentialKey][]callerNode
	signatures map[callerSignaturePair]bool
}
type callerMayMemo struct {
	once   sync.Once
	values map[callerNode]bool
	err    error
}
type callerGraphMemo struct {
	once    sync.Once
	graph   *callerGraph
	elapsed time.Duration
}

var callerGraphs sync.Map // ключ — неизменяемый разобранный program
var callerTypeParams = struct {
	sync.Mutex
	values map[types.Type]bool
}{values: map[types.Type]bool{}}

func callerShape(t types.Type) (callerSignatureShape, bool) {
	s, ok := t.Underlying().(*types.Signature)
	if !ok {
		return callerSignatureShape{}, false
	}
	return callerSignatureShape{s.Params().Len(), s.Results().Len(), s.Variadic()}, true
}

func callerGraphFor(p *surfaceProgram, observe CallerIdentityObserver) *callerGraph {
	value, _ := callerGraphs.LoadOrStore(p, &callerGraphMemo{})
	entry := value.(*callerGraphMemo)
	built := false
	if observe != nil {
		observe("collect:start", CallerIdentityWork{})
	}
	entry.once.Do(func() {
		built = true
		start := time.Now()
		entry.graph = newCallerGraph(p)
		entry.elapsed = time.Since(start)
	})
	g := *entry.graph
	g.objectSourceIDs = nil
	g.fieldQueryHeads = nil
	g.fieldQueryIndexOwner = nil
	g.fieldQueryIndexedDepth = 0
	g.live = map[*types.Var][]valueSrc{}
	g.emptyVariadic = map[*types.Var]bool{}
	g.called = map[callerNode]bool{}
	g.containerInactive = nil
	g.identityFree = map[string]bool{}
	g.bindingEpoch = 0
	g.sourceMemo = nil
	g.sourceMemoEpoch, g.sourceMemoWeight = 0, 0
	g.objectMemo = nil
	g.initialObjectMemo = nil
	g.objectMemoEpoch, g.objectMemoWeight = 0, 0
	g.mutationScanning = map[callerFieldKey]bool{}
	g.resolveMemo = nil
	g.initialResolveMemo = nil
	g.initialResolveWeight = 0
	g.semanticOverflow = false
	g.initialSkips = 0
	g.completedInitialSkips = 0
	g.resolveMemoEpoch = 0
	g.resolveCuts = 0
	g.resolveWeight = 0
	g.observer = observe
	g.work = CallerIdentityWork{}
	g.containerTypePairs = nil
	g.containerCosts = nil
	if built {
		g.work.GraphBuilds = 1
		g.work.Collect = entry.elapsed
	} else {
		g.work.GraphHits = 1
	}
	if observe != nil {
		observe("collect:end", g.work)
	}
	g.resetCallerObjectExecutions()
	return &g
}

func callerDistinctOrigins(values []callerOrigin) []callerOrigin {
	if len(values) < 2 {
		return values
	}
	seen := make(map[callerOrigin]bool, len(values))
	out := make([]callerOrigin, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func (g *callerGraph) observeCallerResolve(src valueSrc, elapsed time.Duration, raw, distinct int) {
	g.work.ResolveRawValues += raw
	g.work.ResolveDistinctValues += distinct
	g.work.ResolveMaxRaw = max(g.work.ResolveMaxRaw, raw)
	g.work.ResolveMaxDistinct = max(g.work.ResolveMaxDistinct, distinct)
	for i, old := range g.work.ResolveSlowest {
		if elapsed > old.Elapsed {
			copy(g.work.ResolveSlowest[i+1:], g.work.ResolveSlowest[i:])
			coordinate := ""
			if g.p != nil {
				coordinate = pPosition(g.p, src.expr)
			}
			g.work.ResolveSlowest[i] = CallerResolveCost{coordinate, elapsed, raw, distinct}
			break
		}
	}
}

// Бюджет ограничивает только удержание завершённых ответов: отказ кэша
// оставляет полный результат вычисления и обычный пересчёт при следующем запросе.
// Это ограничение памяти, не измеренный оптимум производительности.
func (g *callerGraph) retainCallerAnswer(key callerResolveKey, answer callerResolveAnswer, initial bool) {
	if g.semanticOverflow {
		return
	}
	entries, values := g.resolveEntryCap, g.resolveValueCap
	if entries <= 0 {
		entries = 32768
	}
	if values <= 0 {
		values = 262144
	}
	if len(g.resolveMemo)+len(g.initialResolveMemo) >= entries || len(answer.values) > values-g.resolveWeight-g.initialResolveWeight {
		g.work.ResolveRejected++
		return
	}
	// Копия размером ровно с ответ не удерживает ёмкость сырого объединения.
	answer.values = append([]callerOrigin(nil), answer.values...)
	g.resolveMemoGeneration++
	if initial {
		g.initialResolveMemo[key] = answer
		g.initialResolveWeight += len(answer.values)
	} else {
		g.resolveMemo[key] = answer
		g.resolveWeight += len(answer.values)
	}
	g.work.ResolveMemoEntries = len(g.resolveMemo) + len(g.initialResolveMemo)
	g.work.ResolveMemoValues = g.resolveWeight + g.initialResolveWeight
	g.work.ResolvePeakEntries = max(g.work.ResolvePeakEntries, g.work.ResolveMemoEntries)
	g.work.ResolvePeakValues = max(g.work.ResolvePeakValues, g.work.ResolveMemoValues)
}

func (g *callerGraph) prepareCallerSignatures() {
	g.signatureBodies = map[callerSignatureShape][]callerNode{}
	for node, b := range g.bodies {
		var typ types.Type
		if node.fn != nil {
			typ = node.fn.Type()
		} else {
			typ = b.sp.info.TypeOf(node.lit)
		}
		if typ == nil {
			continue
		}
		if shape, ok := callerShape(typ); ok {
			g.signatureBodies[shape] = append(g.signatureBodies[shape], node)
		}
	}
	g.pure = &callerPureMemo{potential: map[callerPotentialKey][]callerNode{}, signatures: map[callerSignaturePair]bool{}}
	g.mayMemo = &callerMayMemo{}
}

func (g *callerGraph) potentialCallerTargets(sp *surfaceSrcPkg, expr ast.Expr) []callerNode {
	g.work.PotentialQueries++
	key := callerPotentialKey{}
	if fn := callerFunction(sp, expr); fn != nil {
		key.fn = fn.Origin()
	} else if lit, ok := ast.Unparen(expr).(*ast.FuncLit); ok {
		key.lit = lit
	} else {
		typ := sp.info.TypeOf(expr)
		if typ == nil {
			return nil
		}
		if _, ok := callerShape(typ); !ok {
			return nil
		}
		key.signature = typ
	}
	g.pure.mu.Lock()
	cached, ok := g.pure.potential[key]
	g.pure.mu.Unlock()
	if ok {
		g.work.PotentialHits++
		return cached
	}
	g.work.PotentialEvaluations++
	out := g.potentialCallerTargetsRaw(sp, expr)
	g.pure.mu.Lock()
	g.pure.potential[key] = out
	g.pure.mu.Unlock()
	return out
}

func (g *callerGraph) signatureCompatible(a, b types.Type) bool {
	g.work.SignatureQueries++
	key := callerSignaturePair{a, b}
	g.pure.mu.Lock()
	value, ok := g.pure.signatures[key]
	g.pure.mu.Unlock()
	if ok {
		g.work.SignatureHits++
		return value
	}
	g.work.SignatureEvaluations++
	value = g.signatureCompatibleRaw(a, b)
	g.pure.mu.Lock()
	g.pure.signatures[key] = value
	g.pure.mu.Unlock()
	return value
}

// hasCallerTypeParam публикует ответ только после замыкания всего компонента.
// Обратное распространение от параметров сохраняет истинность на циклах.
// Ключ — объект завершённого go/types, а не имя типа или путь исходника.
func (g *callerGraph) hasCallerTypeParam(t types.Type) bool {
	g.work.TypeQueries++
	t = types.Unalias(t)
	callerTypeParams.Lock()
	defer callerTypeParams.Unlock()
	if value, ok := callerTypeParams.values[t]; ok {
		g.work.TypeHits++
		return value
	}
	parents := map[types.Type][]types.Type{}
	fresh := map[types.Type]bool{}
	positive := map[types.Type]bool{}
	stack := []types.Type{t}
	var queue []types.Type
	for len(stack) > 0 {
		node := types.Unalias(stack[len(stack)-1])
		stack = stack[:len(stack)-1]
		if _, ok := fresh[node]; ok {
			continue
		}
		if value, ok := callerTypeParams.values[node]; ok {
			if value && !positive[node] {
				positive[node] = true
				queue = append(queue, node)
			}
			continue
		}
		fresh[node] = true
		g.work.TypeVisits++
		children, seed := callerParamChildren(node)
		if seed {
			positive[node] = true
			queue = append(queue, node)
		}
		for _, child := range children {
			child = types.Unalias(child)
			parents[child] = append(parents[child], node)
			stack = append(stack, child)
		}
	}
	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		for _, parent := range parents[node] {
			if !positive[parent] {
				positive[parent] = true
				queue = append(queue, parent)
			}
		}
	}
	for node := range fresh {
		callerTypeParams.values[node] = positive[node]
	}
	return callerTypeParams.values[t]
}

func callerParamChildren(t types.Type) ([]types.Type, bool) {
	if _, ok := t.(*types.TypeParam); ok {
		return nil, true
	}
	if named, ok := t.(*types.Named); ok {
		var out []types.Type
		for i := 0; i < named.TypeArgs().Len(); i++ {
			out = append(out, named.TypeArgs().At(i))
		}
		if named.TypeArgs().Len() == 0 && named.TypeParams().Len() > 0 {
			return out, true
		}
		obj := named.Obj()
		if obj.Pkg() == nil || obj.Parent() != obj.Pkg().Scope() {
			out = append(out, named.Underlying())
		}
		return out, false
	}
	out := interestingKids(t)
	if iface, ok := t.(*types.Interface); ok {
		for i := 0; i < iface.NumEmbeddeds(); i++ {
			out = append(out, iface.EmbeddedType(i))
		}
	}
	if union, ok := t.(*types.Union); ok {
		for i := 0; i < union.Len(); i++ {
			out = append(out, union.Term(i).Type())
		}
	}
	return out, false
}
