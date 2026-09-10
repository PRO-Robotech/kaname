// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_coordinate_tree_touch_gate_test.go — ОСЬ ЯКОРЯ по ВСЕМУ МОДУЛЮ, а не
// по одному пакету (задача #2420).
//
// # Предмет
//
// Соседний гейт (`platform_coordinate_resolve_gate_test.go`) судит ось якоря
// РОВНО В ОДНОМ пакете — `internal/domain`, — и это записано там прямо: на модуле
// та ось упёрлась бы в синтетические корни. Остальное дерево модуля оказывается
// не «чистым», а НЕВИДИМЫМ: координата, записанная в непросматриваемом файле, не
// даёт ни красного, ни зелёного.
//
// Цена невидимости измерена, а не предположена: настоящий отказ нашёлся разбором
// красного ствола, а не этим гейтом. Второй нашёлся этой правкой — в пробе,
// читавшей каталог прав подъёмом к САМОМУ ВНЕШНЕМУ маркеру модуля.
//
// # ПОЧЕМУ ОХВАТ НЕЛЬЗЯ РАСШИРИТЬ ПРЯМО — ЗАМЕР, А НЕ МНЕНИЕ
//
// Прогон той же оси по всему модулю ДО этой правки (2098 прочитанных исходников)
// даёт 322 координаты и **270** находок, из которых настоящая — одна. Остальные
// распадаются на три класса, и каждый законен:
//
//	сообщение     — строка называет координату в ТЕКСТЕ отказа, заголовке отчёта
//	                или таблице ожиданий. Путём она не становится никогда;
//	синтетика     — фикстура строит дерево в `t.TempDir()` и законно пишет
//	                `services/…` литералом;
//	свой каталог  — `deploy` есть и сегмент дерева платформы, и СОБСТВЕННЫЙ
//	                каталог модуля; `Join(корень модуля, "deploy")` за модуль не
//	                выходит.
//
// Гейт, у которого 269 находок из 270 ложные, перестают читать; перестав читать,
// возвращаются к тому, что он заменял.
//
// # ЧТО СУДИТСЯ ЗДЕСЬ: КАСАНИЕ ДЕРЕВА, А НЕ УПОМИНАНИЕ
//
// Координата попадает под вердикт РОВНО ТОГДА, когда она доезжает до файловой
// операции: `os.ReadFile`, `os.Stat`, `filepath.WalkDir` и прочие из закрытого
// перечня. Тогда вопрос «чем приведена посадка» имеет предмет: путь открывают, и
// открывают его в КАКОМ-ТО дереве.
//
// Утверждение при этом строго сильнее прежнего охвата, а не слабее: под
// наблюдение попадают все 2098 файлов модуля, тогда как прежде — файлы одного
// пакета.
//
// # РАЗЛИЧИТЕЛЬ ЗАКОННОГО БЛИЗНЕЦА — ПО ПРИЗНАКУ, А НЕ ПО ПЕРЕЧНЮ ИМЁН
//
// У каждого касания спрашивается ВИД БАЗЫ, к которой приставлена координата.
// Перечень имён здесь не годится: он стареет молча, и первое же переименование
// вернуло бы слепоту. Виды выводятся разбором:
//
//	детектор       — база пришла от `platformtree`/`treeposture`/`treeroot`
//	                 либо от обхода, который САМ ими приведён;
//	синтетика      — база пришла от `t.TempDir()`/`os.MkdirTemp` либо от
//	                 помощника своего пакета, который их зовёт. ЭТО И ЕСТЬ
//	                 законный близнец из предиката задачи;
//	корень модуля  — база пришла от подъёма к СВОЕМУ маркеру (`go.mod`),
//	                 останавливающегося на ПЕРВОМ найденном. Такой подъём за
//	                 корень модуля не выходит — так устроен и сам детектор;
//	вызывающий     — база есть ПАРАМЕТР функции: посадку назначает не этот файл;
//	побег          — подъём к маркеру, который НЕ останавливается на первом, а
//	                 записывает и идёт выше (САМЫЙ ВНЕШНИЙ `go.mod`). В
//	                 самостоятельном клоне он даёт сам модуль, под чужим деревом —
//	                 чужой корень;
//	локальная      — база вычислена здесь и ничем не приведена;
//	нет базы       — координата открывается КАК ЕСТЬ, то есть от рабочего каталога.
//
// Первые четыре — молчание, последние три — находка. Вид «не выведена» — тоже
// находка: недоступность не есть «да», и распознаватель, не понявший выражение,
// обязан звать к себе, а не молчать.
//
// # ПЕРВЫЙ И САМЫЙ ВНЕШНИЙ МАРКЕР РАЗЛИЧАЮТСЯ СТРОЕНИЕМ, А НЕ ИМЕНЕМ
//
// Оба подъёма щупают один и тот же `go.mod`, и по образцу они неразличимы.
// Различает их ФОРМА ветви: первый ВОЗВРАЩАЕТ каталог прямо на попадании,
// второй ЗАПИСЫВАЕТ его и продолжает идти вверх. Именно из-за этой пары шагов
// один остаётся внутри модуля, а другой выходит за него.
//
// # ЧЕГО ГЕЙТ НЕ СУДИТ — названо, а не подразумевается
//
//	упоминание без касания   — строка в сообщении, отчёте, таблице ожиданий;
//	база от вызывающего      — посадку назначает вызывающий, и судится она у него;
//	правильность координаты  — это предмет самой пробы, а не гейта;
//	подъём по дереву         — предмет СОСЕДНЕЙ оси, и она уже сплошная по модулю
//	                           (`TestNoSelfAscentToAPlatformCoordinateInTheModule`).
//	                           Литерал вида `"../../../../proto/…"` координатой
//	                           платформы здесь не считается вовсе — его судит она;
//	межпакетный помощник     — виды выводятся в пределах ПАКЕТА (каталога).
//	                           Помощник, живущий в соседнем пакете, даёт вид
//	                           «не выведена», то есть находку, а не молчание.
//
// Разделение осей доказано инъекцией по дереву: дефект оси касания роняет ТОЛЬКО
// эту пробу, дефект оси подъёма — ТОЛЬКО соседнюю, а целое дерево молчит у обеих.
//
// Способность падать и молчать доказывает не этот прогон, а инъекция
// (`platform_coordinate_tree_touch_gate_injection_test.go`).
package domain_test

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
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// moduleMarkerFile — маркер корня модуля Go.
//
// Тот же файл, по которому корень ищет сам детектор: гейт, судящий подъёмы к
// маркеру, обязан щупать ровно тот маркер, вокруг которого спор.
const moduleMarkerFile = "go.mod"

// treeTouchCalls — ЗАКРЫТЫЙ перечень вызовов, которые ТРОГАЮТ дерево.
//
// Закрытый намеренно: открытый («всё, что похоже на чтение») превратил бы
// вердикт в догадку о чужом пакете. Индекс аргумента здесь всегда нулевой —
// иных форм в дереве нет, и появление такой формы обязано прийти сюда правкой,
// а не остаться невидимым.
var treeTouchCalls = map[string]map[string]bool{
	"os": {
		"ReadFile": true, "Open": true, "OpenFile": true, "Stat": true, "Lstat": true,
		"ReadDir": true, "WriteFile": true, "MkdirAll": true, "Mkdir": true, "Create": true,
		"Remove": true, "RemoveAll": true, "DirFS": true, "Rename": true,
	},
	"filepath": {"Walk": true, "WalkDir": true, "Glob": true},
	"path":     {"Glob": true},
}

// pathPassthroughFuncs — преобразования пути, не меняющие ЕГО ДЕРЕВА.
//
// `Dir`, `Clean`, `Abs` возвращают путь того же дерева, поэтому вид базы у них
// наследуется. `Join` разбирается отдельно: у него база — первый аргумент.
var pathPassthroughFuncs = map[string]bool{
	"Dir": true, "Clean": true, "Abs": true, "FromSlash": true, "ToSlash": true, "EvalSymlinks": true,
}

// baseKind — вид базы, к которой приставлена координата.
type baseKind int

const (
	baseUnknown baseKind = iota
	baseDetector
	baseSynthetic
	baseModuleRoot
	baseCallerGiven
	baseEscaping
	baseLocal
	baseNone
)

// baseKindName — как вид называется в переписи и в находке.
var baseKindName = map[baseKind]string{
	baseUnknown:     "не выведена",
	baseDetector:    "детектор посадки",
	baseSynthetic:   "синтетический корень",
	baseModuleRoot:  "корень своего модуля",
	baseCallerGiven: "параметр вызывающего",
	baseEscaping:    "побег за корень модуля",
	baseLocal:       "вычислена здесь",
	baseNone:        "нет базы (рабочий каталог)",
}

// baseKindRank — старшинство вида при наследовании через обход.
//
// Порядок не произволен: приведённые виды старше выводимых, потому что один
// приведённый вход приводит весь обход; среди неприведённых старше тот, что
// называет ПРИЧИНУ точнее, а «не выведена» — младше всех, она означает «не
// прочитано».
func baseKindRank(k baseKind) int {
	switch k {
	case baseDetector:
		return 0
	case baseSynthetic:
		return 1
	case baseCallerGiven:
		return 2
	case baseModuleRoot:
		return 3
	case baseEscaping:
		return 4
	case baseLocal:
		return 5
	case baseNone:
		return 6
	default:
		return 7
	}
}

// baseKindIsAnchored — вид базы, при котором посадку назначает НЕ этот файл
// произвольным вычислением.
func baseKindIsAnchored(k baseKind) bool {
	switch k {
	case baseDetector, baseSynthetic, baseModuleRoot, baseCallerGiven:
		return true
	default:
		return false
	}
}

// touchCensus — объём осмотренного. Печатается ВСЕГДА и по видам порознь:
// «ноль находок» обязано быть отличимо от «ноль прочитанного», а молчание
// различителя — от его слепоты.
type touchCensus struct {
	Files   int
	Touches int
	ByBase  map[baseKind]int
}

func (c touchCensus) String() string {
	kinds := make([]int, 0, len(c.ByBase))
	for k := range c.ByBase {
		kinds = append(kinds, int(k))
	}
	sort.Ints(kinds)
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%s %d", baseKindName[baseKind(k)], c.ByBase[baseKind(k)]))
	}
	base := "—"
	if len(parts) > 0 {
		base = strings.Join(parts, " · ")
	}
	return fmt.Sprintf("файлов Go прочитано %d · касаний дерева координатой %d · по видам базы: %s",
		c.Files, c.Touches, base)
}

// auditTreeTouch — разбор исходников на касания дерева координатой платформы.
//
// Вход — исходники, а не каталог: тот же разбор прогоняется инъекцией на
// синтетике, и способность падать доказывается без правки настоящего дерева.
func auditTreeTouch(sources []sourceFile) (findings []string, census touchCensus, err error) {
	census.ByBase = map[baseKind]int{}

	files := append([]sourceFile(nil), sources...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	// Виды помощников выводятся В ПРЕДЕЛАХ ПАКЕТА: имя функции без пакета
	// неоднозначно, и склеивание всего модуля в один словарь дало бы вердикт о
	// чужом `serviceRoot`.
	type parsed struct {
		src  sourceFile
		file *ast.File
		fset *token.FileSet
	}
	byDir := map[string][]parsed{}
	dirs := []string{}
	for _, src := range files {
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, src.Name, src.Text, parser.SkipObjectResolution)
		if perr != nil {
			// Неразбираемый исходник — НЕ вердикт: гейт не вправе называть
			// находкой то, чего он не прочитал.
			return nil, census, fmt.Errorf("разбор %s не отработал: %w", src.Name, perr)
		}
		d := filepath.ToSlash(filepath.Dir(src.Name))
		if _, seen := byDir[d]; !seen {
			dirs = append(dirs, d)
		}
		byDir[d] = append(byDir[d], parsed{src, f, fset})
	}
	sort.Strings(dirs)

	for _, d := range dirs {
		pkg := byDir[d]
		asts := make([]*ast.File, 0, len(pkg))
		for _, p := range pkg {
			asts = append(asts, p.file)
		}
		helpers := classifyPackageHelpers(asts)

		for _, p := range pkg {
			census.Files++
			fileBind := fileLevelBindings(p.file)

			for _, decl := range p.file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				sc := &touchScope{
					bind:    map[string][]ast.Expr{},
					params:  map[string]bool{},
					file:    fileBind,
					helpers: helpers,
					busy:    map[string]bool{},
				}
				if fd.Type.Params != nil {
					for _, prm := range fd.Type.Params.List {
						for _, nm := range prm.Names {
							sc.params[nm.Name] = true
						}
					}
				}
				bindFuncBody(fd.Body, sc.params, sc.bind)

				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, isCall := n.(*ast.CallExpr)
					if !isCall || len(call.Args) == 0 || !isTreeTouchCall(call) {
						return true
					}
					arg := call.Args[0]
					coords := sc.coordsOf(arg, 0)
					if len(coords) == 0 {
						return true
					}
					census.Touches++
					kind := sc.baseOf(arg, 0)
					census.ByBase[kind]++
					if baseKindIsAnchored(kind) {
						return true
					}
					findings = append(findings, fmt.Sprintf(
						"%s:%d: координата %q доезжает до дерева, а базу назначает %s — "+
							"в самостоятельном клоне и под чужим деревом путь укажет на чужой файл, "+
							"и вердикт будет о нём",
						p.src.Name, p.fset.Position(call.Pos()).Line, coords[0], baseKindName[kind]))
					return true
				})
			}
		}
	}
	return findings, census, nil
}

// isTreeTouchCall — вызов из закрытого перечня файловых операций.
func isTreeTouchCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && treeTouchCalls[pkg.Name][sel.Sel.Name]
}

// isDetectorCall — вызов детектора посадки.
//
// Пакетов ТРИ, а не два: `treeroot` называет корень индексом git и проверяет,
// что дерево отслеживает спрашивающий каталог, — это тот же вопрос о посадке.
// Не знать его значило бы читать законный прод-резолв как отсутствие якоря.
func isDetectorCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && detectorPackages[id.Name] && detectorResolvers[sel.Sel.Name]
}

// isTempRootCall — вызов, заводящий СИНТЕТИЧЕСКИЙ корень.
func isTempRootCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && (sel.Sel.Name == "TempDir" || sel.Sel.Name == "MkdirTemp")
}

// classifyPackageHelpers — вид базы, который возвращает каждый помощник пакета.
//
// Считается до фиксированной точки: помощник, зовущий классифицированного
// соседа, наследует его вид. Без этого шага цепочка «резолв корня вынесен в
// отдельную функцию» читалась бы как вычисление на месте.
func classifyPackageHelpers(files []*ast.File) map[string]baseKind {
	out := map[string]baseKind{}
	var decls []*ast.FuncDecl
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Recv != nil {
				continue
			}
			decls = append(decls, fd)
			if k := helperBaseKind(fd); k != baseUnknown {
				out[fd.Name.Name] = k
			}
		}
	}
	for round := 0; round < 8; round++ {
		changed := false
		for _, fd := range decls {
			if _, done := out[fd.Name.Name]; done {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, ok := c.Fun.(*ast.Ident)
				if !ok || id.Name == fd.Name.Name {
					return true
				}
				if k, known := out[id.Name]; known {
					out[fd.Name.Name] = k
					changed = true
					return false
				}
				return true
			})
		}
		if !changed {
			break
		}
	}
	return out
}

// helperBaseKind — вид базы, которую возвращает ОДНА функция.
func helperBaseKind(fd *ast.FuncDecl) baseKind {
	var detector, synthetic bool
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isDetectorCall(c) {
			detector = true
		}
		if isTempRootCall(c) {
			synthetic = true
		}
		return true
	})
	switch {
	case detector:
		return baseDetector
	case synthetic:
		return baseSynthetic
	}
	return markerAscentKind(fd.Body)
}

// markerAscentKind — ПЕРВЫЙ маркер или САМЫЙ ВНЕШНИЙ, и различает их СТРОЕНИЕ.
//
// Оба подъёма щупают один и тот же `go.mod` и по образцу неразличимы. Различает
// их ветвь попадания: подъём к ПЕРВОМУ маркеру ВОЗВРАЩАЕТ каталог прямо на нём и
// за корень модуля не выходит; подъём к САМОМУ ВНЕШНЕМУ ЗАПИСЫВАЕТ каталог и
// идёт выше — то есть выходит.
//
// Форма, которой распознаватель не знает, даёт «не выведена», а не молчание:
// подъём к маркеру есть ровно тот предмет, вокруг которого гейт заведён.
func markerAscentKind(body ast.Node) baseKind {
	kind := baseUnknown
	ast.Inspect(body, func(n ast.Node) bool {
		// Первая же ветвь маркера и решает: у функции с двумя такими ветвями
		// вид иначе зависел бы от порядка обхода, а не от строения.
		if kind != baseUnknown {
			return false
		}
		ifs, ok := n.(*ast.IfStmt)
		if !ok || !mentionsModuleMarker(ifs.Init) && !mentionsModuleMarker(ifs.Cond) {
			return true
		}
		if containsReturn(ifs.Body) {
			kind = baseModuleRoot
			return false
		}
		kind = baseEscaping
		return false
	})
	return kind
}

// mentionsModuleMarker — выражение щупает маркер корня модуля.
func mentionsModuleMarker(e ast.Node) bool {
	if e == nil {
		return false
	}
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		if s, uerr := strconv.Unquote(lit.Value); uerr == nil && s == moduleMarkerFile {
			found = true
			return false
		}
		return true
	})
	return found
}

func containsReturn(body ast.Node) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.ReturnStmt); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

// touchScope — связывание имён в пределах ОДНОЙ функции плюс файловые
// объявления. Пределы функции существенны: имя `root` в одном файле бывает и
// синтетическим корнем, и настоящим, и словарь на весь файл выбрал бы последнее
// присваивание, а не то, что действует в этом месте.
type touchScope struct {
	bind    map[string][]ast.Expr
	params  map[string]bool
	file    map[string][]ast.Expr
	helpers map[string]baseKind
	busy    map[string]bool
}

func (sc *touchScope) lookup(name string) ([]ast.Expr, bool) {
	if e, ok := sc.bind[name]; ok {
		return e, true
	}
	e, ok := sc.file[name]
	return e, ok
}

// baseOf — вид базы выражения-пути.
func (sc *touchScope) baseOf(e ast.Expr, depth int) baseKind {
	if e == nil || depth > 12 {
		return baseUnknown
	}
	switch x := e.(type) {
	case *ast.BasicLit:
		return baseNone
	case *ast.Ident:
		if sc.params[x.Name] {
			return baseCallerGiven
		}
		if sc.busy[x.Name] {
			return baseUnknown
		}
		values, ok := sc.lookup(x.Name)
		if !ok {
			return baseUnknown
		}
		sc.busy[x.Name] = true
		defer delete(sc.busy, x.Name)
		// Имя, переприсвоенное в цикле, несёт НЕСКОЛЬКО связываний, и первое из
		// них обычно и есть база. Берётся ПЕРВОЕ выведенное: «не выведена»
		// означает «не прочитано», а не «нет базы», и потому не годится в ответ,
		// пока остались непрочитанные связывания.
		for _, v := range values {
			if k := sc.baseOf(v, depth+1); k != baseUnknown {
				return k
			}
		}
		return baseUnknown
	case *ast.CallExpr:
		if isDetectorCall(x) {
			return baseDetector
		}
		if isTempRootCall(x) {
			return baseSynthetic
		}
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok2 := sel.X.(*ast.Ident); ok2 && (pkg.Name == "filepath" || pkg.Name == "path") && len(x.Args) > 0 {
				if sel.Sel.Name == "Join" || pathPassthroughFuncs[sel.Sel.Name] {
					return sc.baseOf(x.Args[0], depth+1)
				}
			}
			// Обход отдаёт пути ТОЙ ЖЕ посадки, что и его вход:
			// `treecorpus.Glob(platformtree.RequirePath(t, rel))`. Вид входа и
			// наследуется — не только приведённый, но и любой выведенный: находка,
			// назвавшая «не выведена» там, где база вычислена на месте, послала бы
			// читателя искать не там.
			best := baseUnknown
			for _, a := range x.Args {
				if k := sc.baseOf(a, depth+1); baseKindRank(k) < baseKindRank(best) {
					best = k
				}
			}
			return best
		}
		if id, ok := x.Fun.(*ast.Ident); ok {
			if k, known := sc.helpers[id.Name]; known {
				return k
			}
			return baseLocal
		}
	}
	return baseUnknown
}

// coordsOf — координаты платформы внутри выражения-пути, через связывание имён.
//
// Через связывание, а не только по литералам: обычная и законная запись —
// константа файла, приставляемая к корню в другом месте.
func (sc *touchScope) coordsOf(e ast.Expr, depth int) []string {
	if e == nil || depth > 12 {
		return nil
	}
	var out []string
	ast.Inspect(e, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BasicLit:
			if x.Kind != token.STRING {
				return true
			}
			s, uerr := strconv.Unquote(x.Value)
			if uerr != nil {
				return true
			}
			if isPlatformCoordinate(s) {
				out = append(out, s)
			}
		case *ast.Ident:
			key := "coord:" + x.Name
			if sc.params[x.Name] || sc.busy[key] {
				return true
			}
			values, ok := sc.lookup(x.Name)
			if !ok {
				return true
			}
			sc.busy[key] = true
			for _, v := range values {
				out = append(out, sc.coordsOf(v, depth+1)...)
			}
			delete(sc.busy, key)
		}
		return true
	})
	return out
}

// fileLevelBindings — файловые `const`/`var`.
func fileLevelBindings(f *ast.File) map[string][]ast.Expr {
	out := map[string][]ast.Expr{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, nm := range vs.Names {
				if i < len(vs.Values) {
					out[nm.Name] = append(out[nm.Name], vs.Values[i])
				}
			}
		}
	}
	return out
}

// bindFuncBody — связывание имён в теле функции, включая литералы функций.
func bindFuncBody(body ast.Node, params map[string]bool, bind map[string][]ast.Expr) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			switch {
			case len(s.Lhs) == len(s.Rhs):
				for i, l := range s.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						bind[id.Name] = append(bind[id.Name], s.Rhs[i])
					}
				}
			case len(s.Rhs) == 1:
				for _, l := range s.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						bind[id.Name] = append(bind[id.Name], s.Rhs[0])
					}
				}
			}
		case *ast.ValueSpec:
			for i, nm := range s.Names {
				if i < len(s.Values) {
					bind[nm.Name] = append(bind[nm.Name], s.Values[i])
				}
			}
		case *ast.RangeStmt:
			// Элемент обхода наследует посадку самого обхода.
			if id, ok := s.Value.(*ast.Ident); ok {
				bind[id.Name] = append(bind[id.Name], s.X)
			}
			if id, ok := s.Key.(*ast.Ident); ok {
				bind[id.Name] = append(bind[id.Name], s.X)
			}
		case *ast.FuncLit:
			if s.Type.Params != nil {
				for _, p := range s.Type.Params.List {
					for _, nm := range p.Names {
						params[nm.Name] = true
					}
				}
			}
		}
		return true
	})
}

// TestPlatformCoordinatesTouchingTheTreeAreAnchoredInTheModule — сплошная
// перепись по ВСЕМУ модулю по оси якоря, суженной до КАСАНИЙ дерева.
func TestPlatformCoordinatesTouchingTheTreeAreAnchoredInTheModule(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	moduleRoot, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не установлен: %v", err)
	}

	sources, skipped := moduleGoSources(t, moduleRoot)

	findings, census, err := auditTreeTouch(sources)
	if err != nil {
		t.Fatalf("разбор не отработал: %v", err)
	}
	t.Logf("осмотрено по модулю (%s): %s", moduleRoot, census)
	t.Logf("найдено: касаний без приведённой базы %d", len(findings))

	// Премисы. Каждая отвечает на своё «ноль», и все три печатают ноль одинаково,
	// поэтому различает их только эта проверка.
	if census.Files == 0 {
		t.Fatal("обход пуст: ни одного файла Go не прочитано — вердикт беспредметен")
	}
	if skipped != 0 {
		t.Fatalf("файлов не прочитано: %d — «ноль находок» стало бы «ноль прочитанного»", skipped)
	}
	if census.Touches == 0 {
		t.Fatal("касаний дерева координатой ноль: распознаватель не увидел ни одного " +
			"места, о котором гейт судит, — его «находок ноль» ничего не означает")
	}
	if census.ByBase[baseDetector] == 0 {
		t.Fatal("касаний с базой от детектора посадки ноль: законный якорь не распознан " +
			"ни разу — молчание гейта неотличимо от его слепоты")
	}
	// Премиса РАЗЛИЧИТЕЛЯ, и она отдельная: молчание на фикстуре доказывает
	// работу различителя только если фикстуры есть. Ноль здесь означает одно из
	// двух — предмет исчез (тогда различитель снимают вместе с ним) либо
	// различитель ослеп, — и разбирать надо оба, а не считать это чистотой.
	if census.ByBase[baseSynthetic] == 0 {
		t.Fatal("касаний с синтетическим корнем ноль: у различителя законного близнеца " +
			"не осталось предмета — либо фикстур больше нет (снимите различитель), " +
			"либо он перестал их узнавать")
	}

	for _, f := range findings {
		t.Errorf("НАХОДКА: %s", f)
	}
}
