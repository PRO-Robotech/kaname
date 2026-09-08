// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// platform_coordinate_resolve_gate_test.go — координату от корня платформы
// резолвит ДЕТЕКТОР ПОСАДКИ, а не собственный подъём по дереву (задачи #2160,
// #2282, #2289).
//
// # Предмет
//
// Пробы судят контракт и страницу арендатора. Контракт лежит НАД модулем
// (`proto/…` корня платформы) и в поставку модуля не входит; страница лежит
// ВНУТРИ него. Значит у прогона две посадки, и в одной из них предмет части проб
// отсутствует BY CONSTRUCTION — это «условие не создано», третий исход, и он не
// вычитается из вердикта и не зачитывается в успех.
//
// Назначить этот исход можно двумя способами, и они РАЗНЫЕ:
//
//	детектор посадки  — `internal/treeposture` спрашивает, лежит ли модуль в
//	                    каталоге модулей ЭТОГО дерева, и только потом приводит
//	                    координату. Чужое дерево над клоном ему не годится;
//	свой подъём       — путь, чей якорь выводит ВЫШЕ корня модуля. Он судит по
//	                    НАЛИЧИЮ ФАЙЛА, поэтому в клоне, стоящем под чужим деревом
//	                    с той же координатой, находит ЧУЖОЙ файл и выносит
//	                    вердикт о нём.
//
// # Цена измерена, а не предположена
//
// Клон модуля положен под дерево, несущее `proto/kaname/cloud/iam/v1/role.proto`
// с другим содержимым. Проба, резолвящая ту же координату через `platformtree`,
// назвала «УСЛОВИЕ НЕ СОЗДАНО» и вышла кодом 0. Пробы, резолвившие своим
// подъёмом, прочитали ЧУЖОЙ контракт, напечатали НАХОДКУ о нём и вышли кодом 1.
// Один и тот же исход, два ответа, и машинный неверен.
//
// # ТРИ ФОРМЫ ПОДЪЁМА, и распознаватель обязан знать каждую (#2289)
//
// Форма, о которой распознаватель не знает, не даёт ни красного, ни зелёного —
// она МОЛЧИТ, и всё записанное в ней оказывается вне наблюдения. Прежняя
// редакция знала одну форму из трёх:
//
//	цикл           — тело цикла зовёт `Dir(x)` и присваивает `x`, а щупает
//	                 КООРДИНАТУ платформы. Подъём к маркеру модуля (`go.mod`)
//	                 сюда НЕ относится: он останавливается на своём корне и за
//	                 него не выходит — так устроен сам детектор;
//	фиксированный  — `Join` с литеральными `..`, число которых БОЛЬШЕ глубины
//	                 файла под корнем модуля. Ровно этой формой был записан
//	                 живой экземпляр в `internal/migrations`;
//	литерал        — одна строка вида `"../../../../proto/…"`. Та же арифметика.
//
// # ГЛУБИНА — несущий различитель, а не украшение
//
// `../../deploy` из `cmd/kaname` поднимается на 2 при глубине 2 и попадает в
// СОБСТВЕННЫЙ каталог поставки модуля. Тот же по виду путь на шаг длиннее выходит
// за корень модуля и попадает к соседу. Различает их только арифметика, поэтому
// распознаватель считает подъём и сверяет его с глубиной файла, а не ловит `..`
// по образцу: ловля по образцу назвала бы находкой верный код.
//
// # ОСЬ ЯКОРЯ — ПОКООРДИНАТНАЯ, а не пофайловая (#2289)
//
// Прежняя редакция спрашивала «есть ли в ФАЙЛЕ хоть один резолв через детектор».
// Тогда ОДИН законный `platformtree.Require*` маскировал любое число координат,
// резолвнутых иначе, — а смешанный файл и есть вероятная будущая регрессия.
// Теперь якорь спрашивается у КАЖДОЙ координаты: она либо стоит аргументом
// детектора, либо связана с именем, которое детектору передают, либо приставлена
// к базе, полученной от детектора.
//
// # Что гейт судит и чего не судит
//
// Судит УПОТРЕБЛЕНИЕ: несёт ли файл координату от корня платформы и чем он её
// резолвит. Не судит, ПРАВИЛЬНАЯ ли координата — это предмет самой пробы.
//
// Читается ИСПОЛНЯЕМАЯ ЧАСТЬ (разбор в синтаксическое дерево), а не текст:
// координата встречается и в объяснениях, и в фикстурах соседних гейтов, и
// проверка по подстроке краснела бы на собственном комментарии.
//
// # ДВЕ ПРОБЫ, ДВА ОХВАТА — и граница названа, а не подразумевается
//
//	пакет `internal/domain`  — ОБЕ оси. Здесь популяция координат адъюдицирована
//	                           поимённо, поэтому ось якоря даёт вердикт;
//	весь модуль              — ТОЛЬКО ось подъёма. Она точна by construction
//	                           (арифметика глубины и предмет щупания), тогда как
//	                           ось якоря на модуле упёрлась бы в 54 синтетических
//	                           корня (`t.TempDir()`), которые якоря не имеют и
//	                           иметь не должны. Объявлять по ним вердикт значило
//	                           бы краснеть на верном коде.
//
// Способность падать и молчать доказывает не этот прогон, а инъекция
// (`platform_coordinate_resolve_gate_injection_test.go`).
package domain_test

import (
	"fmt"
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

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// domainPackageDir — координата ЭТОГО пакета от корня платформы.
//
// Записана так же, как всё, что гейт судит, и резолвится тем же детектором:
// гейт, требующий свойства от других, обязан быть его первым носителем. Пакет
// лежит ВНУТРИ модуля, поэтому координата резолвится в ОБЕИХ посадках и пропуска
// здесь не бывает.
const domainPackageDir = "services/iam/internal/domain"

// domainPackageDepth — глубина этого пакета под корнем модуля
// (`internal/domain` — два шага).
const domainPackageDepth = 2

// platformRootSegments — первые сегменты координат, записанных ОТ КОРНЯ ПЛАТФОРМЫ.
//
// Перечень закрытый и короткий намеренно: он называет каталоги, которые в дереве
// платформы лежат РЯДОМ с каталогом модулей, — то есть ровно те, чьё присутствие
// у арендатора не гарантировано.
var platformRootSegments = map[string]bool{
	"proto":    true,
	"services": true,
	"deploy":   true,
	".github":  true,
}

// detectorPackages — имена пакетов, чей вызов и есть детектор посадки.
//
// Два, а не один: `platformtree` даёт пробе третий исход, `treeposture` — тот же
// резолв без `testing`, и его зовёт прод-код модуля. Знать надо оба, иначе
// законный прод-резолв читался бы как отсутствие якоря.
var detectorPackages = map[string]bool{"platformtree": true, "treeposture": true}

// detectorResolvers — методы детектора, возвращающие ПУТЬ либо КОРЕНЬ.
//
// Перечень закрытый: `ErrNoPlatformTree` и прочие имена того же пакета путей не
// возвращают, и засчитывать их значило бы считать якорем упоминание.
var detectorResolvers = map[string]bool{
	"Require": true, "RequirePath": true, "RequireCorpus": true,
	"RootFrom": true, "PathOf": true, "PathUnder": true,
	"CorpusRoot": true, "ModuleRootFrom": true, "Under": true,
}

// resolveCensus — объём осмотренного. Печатается всегда: «ноль находок» обязано
// быть отличимо от «ноль прочитанного».
type resolveCensus struct {
	Files    int
	Coords   int
	Resolves int
	Ascents  int
}

func (c resolveCensus) String() string {
	return fmt.Sprintf(
		"файлов Go прочитано %d · координат от корня платформы %d · "+
			"резолвов через детектор посадки %d · собственных подъёмов по дереву %d",
		c.Files, c.Coords, c.Resolves, c.Ascents)
}

// resolveFindings — находки ДВУХ осей порознь.
//
// Порознь, а не одним списком: охваты у осей разные (см. шапку), и слитый список
// заставил бы модульную пробу судить то, чего она судить не вправе.
type resolveFindings struct {
	Unanchored []string // координата без якоря-детектора
	Ascents    []string // побег: якорь выводит выше корня модуля
}

// sourceFile — исходник и его ГЛУБИНА под корнем модуля.
//
// Глубина — вход распознавателя, а не свойство разбора: без неё `..` не отличить
// от побега (см. шапку, «ГЛУБИНА — несущий различитель»).
type sourceFile struct {
	Name  string
	Depth int
	Text  string
}

// isPlatformCoordinate — строка записана координатой ОТ КОРНЯ ПЛАТФОРМЫ.
//
// Требуется разделитель: голое `deploy` — имя каталога, а не координата, и
// засчитывать его значило бы краснеть на слове.
func isPlatformCoordinate(s string) bool {
	head, _, ok := strings.Cut(s, "/")
	return ok && platformRootSegments[head]
}

// climbOf — сколько шагов вверх делает путь и достаёт ли он до корневого сегмента.
func climbOf(s string) (climb int, reachesRoot bool) {
	for _, seg := range strings.Split(filepath.ToSlash(s), "/") {
		switch {
		case seg == "..":
			climb++
		case platformRootSegments[seg]:
			reachesRoot = true
		}
	}
	return climb, reachesRoot
}

// auditPlatformCoordinateResolve — разбор ИСХОДНИКОВ на находки двух осей.
//
// Вход — исходники со своей глубиной, а не каталог: тогда тот же разбор
// прогоняется инъекцией на синтетике, и способность падать доказывается без
// правки настоящего дерева.
func auditPlatformCoordinateResolve(sources []sourceFile) (resolveFindings, resolveCensus, error) {
	var (
		out    resolveFindings
		census resolveCensus
	)

	files := append([]sourceFile(nil), sources...)
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	for _, src := range files {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, src.Name, src.Text, parser.SkipObjectResolution)
		if err != nil {
			// Неразбираемый исходник — НЕ вердикт: гейт не вправе называть
			// находкой то, чего он не прочитал.
			return resolveFindings{}, census, fmt.Errorf("разбор %s не отработал: %w", src.Name, err)
		}
		census.Files++

		one := auditOneSource(file, fset, src.Depth)
		census.Coords += one.coords
		census.Resolves += one.resolves
		census.Ascents += len(one.escapes)

		for _, c := range one.unanchored {
			out.Unanchored = append(out.Unanchored, fmt.Sprintf(
				"%s:%d: координата %q не имеет якоря-детектора — предпосылку назначает не "+
					"посадка модуля, и в клоне под чужим деревом вердикт будет о чужом дереве",
				src.Name, c.line, c.what))
		}
		for _, e := range one.escapes {
			out.Ascents = append(out.Ascents, fmt.Sprintf(
				"%s:%d: собственный подъём по дереву (%s) к координате %q — исход назначает "+
					"НАЛИЧИЕ ФАЙЛА, а не посадка модуля",
				src.Name, e.line, e.form, e.what))
		}
	}

	return out, census, nil
}

// site — одно место с координатой либо подъёмом.
type site struct {
	line int
	what string
	form string
}

// sourceVerdict — три величины и две находки одного файла.
type sourceVerdict struct {
	coords     int
	resolves   int
	unanchored []site
	escapes    []site
}

// auditOneSource — разбор одного файла.
func auditOneSource(file *ast.File, fset *token.FileSet, depth int) sourceVerdict {
	var v sourceVerdict
	line := func(p token.Pos) int { return fset.Position(p).Line }

	litArgs, joinBases := anchorMap(file)

	ast.Inspect(file, func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.BasicLit:
			if e.Kind != token.STRING {
				return true
			}
			s, uerr := strconv.Unquote(e.Value)
			if uerr != nil {
				return true
			}
			switch {
			case isPlatformCoordinate(s):
				v.coords++
				if !litArgs[e] {
					v.unanchored = append(v.unanchored, site{line(e.Pos()), s, ""})
				}
			case strings.HasPrefix(s, "../"):
				// ТРЕТЬЯ ФОРМА ПОДЪЁМА: координата и подъём одной строкой.
				climb, reaches := climbOf(s)
				if reaches && climb > depth {
					v.coords++
					v.escapes = append(v.escapes, site{line(e.Pos()), s, "литерал"})
				}
			}
		case *ast.CallExpr:
			sel, ok := e.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch {
			case detectorPackages[pkg.Name] && detectorResolvers[sel.Sel.Name]:
				v.resolves++
			case (pkg.Name == "filepath" || pkg.Name == "path") && sel.Sel.Name == "Join":
				// ВТОРАЯ ЗАКОННАЯ ФОРМА записи координаты — по сегментам. Знать её
				// обязательно: именно ею записан живой экземпляр. Сегмент ищется
				// среди ВСЕХ аргументов, а не только первого: приставка к базе,
				// полученной от детектора, — обычная и законная форма.
				sh := joinShape(e)
				switch {
				case sh.climb > 0 && sh.reachesRoot && sh.climb > depth:
					// ВТОРАЯ ФОРМА ПОДЪЁМА: фиксированная глубина.
					if !sh.hasFullCoord {
						v.coords++
					}
					v.escapes = append(v.escapes, site{line(e.Pos()), sh.rootSeg, "фиксированная глубина"})
				case sh.climb == 0 && sh.bareRoot != "" && !sh.hasFullCoord:
					// Целая координата среди аргументов уже сосчитана разбором
					// литералов: два счёта одного места завысили бы перепись и
					// удвоили бы находку.
					v.coords++
					if !joinBases[e] {
						v.unanchored = append(v.unanchored, site{line(e.Pos()), sh.bareRoot, ""})
					}
				}
			}
		}
		return true
	})

	// ПЕРВАЯ ФОРМА ПОДЪЁМА: цикл.
	for _, body := range loopBodies(file) {
		if !climbsInLoop(body) {
			continue
		}
		if probe := loopProbesCoordinate(body); probe != "" {
			v.escapes = append(v.escapes, site{line(body.Pos()), probe, "цикл"})
		}
	}
	return v
}

// joinShape — форма пути, собранного `Join`.
//
// Считаются ТОЛЬКО литеральные аргументы: выражение может быть чем угодно, и
// приписывать ему подъём значило бы утверждать о том, что не прочитано.
type joinForm struct {
	climb        int    // сколько шагов вверх дают литеральные `..`
	reachesRoot  bool   // достаёт ли путь до корневого сегмента платформы
	rootSeg      string // чем именно достаёт — для текста находки
	bareRoot     string // ГОЛЫЙ корневой сегмент (`"proto"`), если он есть
	hasFullCoord bool   // среди аргументов есть ЦЕЛАЯ координата (`"proto/…"`)
}

func joinShape(call *ast.CallExpr) joinForm {
	var f joinForm
	for _, a := range call.Args {
		lit, ok := a.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			continue
		}
		c, r := climbOf(s)
		f.climb += c
		if isPlatformCoordinate(s) {
			f.hasFullCoord = true
			r = true
		}
		if platformRootSegments[s] && f.bareRoot == "" {
			f.bareRoot = s
		}
		if r {
			f.reachesRoot = true
			if f.rootSeg == "" {
				f.rootSeg = s
			}
		}
	}
	return f
}

// anchorMap — что в этом файле УЖЕ приведено детектором.
//
// Три вида якоря, и все три законны:
//
//	литерал стоит аргументом детектора    → platformtree.RequirePath(t, "proto/…")
//	литерал связан с именем, которое ему  → const rel = "proto/…"; …Require(t, rel)
//	   передают
//	`Join` приставлен к базе от детектора → filepath.Join(root, "services", …)
func anchorMap(file *ast.File) (litArgs map[*ast.BasicLit]bool, joinBases map[*ast.CallExpr]bool) {
	anchoredIdents := map[string]bool{}
	litArgs = map[*ast.BasicLit]bool{}
	joinBases = map[*ast.CallExpr]bool{}

	detectorCall := func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && detectorPackages[id.Name] && detectorResolvers[sel.Sel.Name]
	}

	// Имена, полученные ОТ детектора, и имена, ПЕРЕДАННЫЕ детектору.
	derived := map[string]bool{}
	bind := func(lhs, rhs []ast.Expr) {
		for i, r := range rhs {
			if !detectorCall(r) {
				continue
			}
			for j, l := range lhs {
				id, ok := l.(*ast.Ident)
				if !ok {
					continue
				}
				if len(rhs) == 1 || i == j {
					derived[id.Name] = true
				}
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			bind(s.Lhs, s.Rhs)
		case *ast.ValueSpec:
			lhs := make([]ast.Expr, 0, len(s.Names))
			for _, nm := range s.Names {
				lhs = append(lhs, nm)
			}
			bind(lhs, s.Values)
		}
		if detectorCall(n) {
			for _, a := range n.(*ast.CallExpr).Args {
				switch x := a.(type) {
				case *ast.BasicLit:
					litArgs[x] = true
				case *ast.Ident:
					anchoredIdents[x.Name] = true
				}
			}
		}
		return true
	})

	// Литерал, связанный с якорным именем, якорен вместе с ним.
	markBound := func(lhs, rhs []ast.Expr) {
		for i, l := range lhs {
			id, ok := l.(*ast.Ident)
			if !ok || !anchoredIdents[id.Name] || i >= len(rhs) {
				continue
			}
			if lit, ok := rhs[i].(*ast.BasicLit); ok {
				litArgs[lit] = true
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			markBound(s.Lhs, s.Rhs)
		case *ast.ValueSpec:
			lhs := make([]ast.Expr, 0, len(s.Names))
			for _, nm := range s.Names {
				lhs = append(lhs, nm)
			}
			markBound(lhs, s.Values)
		case *ast.CallExpr:
			sel, ok := s.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pk, ok := sel.X.(*ast.Ident)
			if !ok || (pk.Name != "filepath" && pk.Name != "path") || sel.Sel.Name != "Join" || len(s.Args) == 0 {
				return true
			}
			switch base := s.Args[0].(type) {
			case *ast.Ident:
				if derived[base.Name] {
					joinBases[s] = true
				}
			case *ast.CallExpr:
				if detectorCall(base) {
					joinBases[s] = true
				}
			}
			// База от детектора приводит к посадке ВСЕ сегменты, приставленные к
			// ней, — включая записанные целой координатой.
			if joinBases[s] {
				for _, a := range s.Args {
					if lit, ok := a.(*ast.BasicLit); ok {
						litArgs[lit] = true
					}
				}
			}
		}
		return true
	})
	return litArgs, joinBases
}

func loopBodies(file *ast.File) []*ast.BlockStmt {
	var out []*ast.BlockStmt
	ast.Inspect(file, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.ForStmt:
			out = append(out, s.Body)
		case *ast.RangeStmt:
			out = append(out, s.Body)
		}
		return true
	})
	return out
}

// climbsInLoop — тело цикла ПОДНИМАЕТСЯ, а не просто берёт каталог.
//
// Подъём — это `Dir(x)`, где `x` в том же теле ПЕРЕПРИСВАИВАЕТСЯ. Обе живые формы
// записи покрыты одним признаком: и прямая (`dir = filepath.Dir(dir)`), и
// двухшаговая (`parent := filepath.Dir(dir); …; dir = parent`), которой записан
// сам детектор. Одиночное взятие каталога у элемента обхода
// (`d := filepath.Dir(vp)`) подъёмом НЕ является, и требовать по нему вердикта
// значило бы краснеть на верном коде — такой код в дереве есть.
func climbsInLoop(body *ast.BlockStmt) bool {
	dirArgs := map[string]bool{}
	assigned := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.CallExpr:
			sel, ok := s.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pk, ok := sel.X.(*ast.Ident)
			if !ok || (pk.Name != "filepath" && pk.Name != "path") || sel.Sel.Name != "Dir" || len(s.Args) != 1 {
				return true
			}
			if id, ok := s.Args[0].(*ast.Ident); ok {
				dirArgs[id.Name] = true
			}
		case *ast.AssignStmt:
			for _, l := range s.Lhs {
				if id, ok := l.(*ast.Ident); ok {
					assigned[id.Name] = true
				}
			}
		}
		return true
	})
	for name := range dirArgs {
		if assigned[name] {
			return true
		}
	}
	return false
}

// loopProbesCoordinate — что цикл ЩУПАЕТ.
//
// Различитель между побегом и законным подъёмом к маркеру модуля: цикл, ищущий
// `go.mod`, останавливается на СВОЁМ корне и за него не выходит — так устроен сам
// детектор, и краснеть на нём значило бы запретить единственный правильный
// способ. Цикл, ищущий координату ПЛАТФОРМЫ, за корень модуля выходит всегда.
func loopProbesCoordinate(body *ast.BlockStmt) string {
	found := ""
	ast.Inspect(body, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || found != "" {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		if isPlatformCoordinate(s) || platformRootSegments[s] {
			found = s
		}
		return true
	})
	return found
}

// readGoSources — исходники Go названного каталога (без подкаталогов).
func readGoSources(t *testing.T, dir string, depth int) []sourceFile {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: каталог пакета не прочитан (%s): %v", dir, err)
	}
	var out []sourceFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(dir, e.Name()))
		if rerr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: исходник не прочитан (%s): %v", e.Name(), rerr)
		}
		out = append(out, sourceFile{Name: e.Name(), Depth: depth, Text: string(b)})
	}
	return out
}

// TestPlatformCoordinatesInThisPackageResolveThroughTheDetector — вердикт о
// НАСТОЯЩЕМ пакете по ОБЕИМ осям.
func TestPlatformCoordinatesInThisPackageResolveThroughTheDetector(t *testing.T) {
	sources := readGoSources(t, platformtree.RequirePath(t, domainPackageDir), domainPackageDepth)

	findings, census, err := auditPlatformCoordinateResolve(sources)
	if err != nil {
		t.Fatalf("разбор не отработал: %v", err)
	}
	t.Logf("осмотрено: %s", census)
	t.Logf("найдено: координат без якоря %d · подъёмов %d",
		len(findings.Unanchored), len(findings.Ascents))

	// Премиса: «ноль находок» обязано быть отличимо от «ноль прочитанного».
	// Числа координат здесь НЕ требуется: ноль координат — законная цель (пробы
	// пакета могут перестать судить дерево), а не поломка. Способность
	// распознавателя ИХ ВИДЕТЬ доказывает инъекция, а не это число.
	if census.Files == 0 {
		t.Fatal("обход пуст: ни одного файла Go не прочитано — вердикт беспредметен")
	}

	for _, f := range findings.Unanchored {
		t.Errorf("НАХОДКА: %s", f)
	}
	for _, f := range findings.Ascents {
		t.Errorf("НАХОДКА: %s", f)
	}
}

// TestNoSelfAscentToAPlatformCoordinateInTheModule — сплошная перепись по ВСЕМУ
// модулю по ОСИ ПОДЪЁМА (задача #2282).
//
// Ось якоря здесь НЕ судится, и это решение, а не пропуск: на модуле она упёрлась
// бы в синтетические корни (`t.TempDir()` и его потомки), у которых якоря нет и
// быть не должно. Ось подъёма точна by construction — её различители
// арифметические (подъём против глубины) и предметные (что щупает цикл).
func TestNoSelfAscentToAPlatformCoordinateInTheModule(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	moduleRoot, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не установлен: %v", err)
	}

	sources, skipped := moduleGoSources(t, moduleRoot)

	findings, census, err := auditPlatformCoordinateResolve(sources)
	if err != nil {
		t.Fatalf("разбор не отработал: %v", err)
	}
	t.Logf("осмотрено по модулю (%s): %s", moduleRoot, census)
	t.Logf("найдено: подъёмов %d (ось якоря на модуле не судится — см. шапку)",
		len(findings.Ascents))

	// Обе премисы разом: пустой обход и обход БЕЗ единого резолва одинаково
	// означают, что распознаватель ничего не прочитал, — и оба обязаны ронять
	// прогон, а не печатать зелёное (предикат #2282).
	if census.Files == 0 {
		t.Fatal("обход пуст: ни одного файла Go не прочитано — вердикт беспредметен")
	}
	if census.Resolves == 0 {
		t.Fatal("резолвов через детектор посадки ноль: распознаватель не увидел ни одного " +
			"законного якоря — вердикт о подъёмах беспредметен")
	}
	if skipped != 0 {
		t.Fatalf("файлов не прочитано: %d — «ноль находок» стало бы «ноль прочитанного»", skipped)
	}

	for _, f := range findings.Ascents {
		t.Errorf("НАХОДКА: %s", f)
	}
}

// moduleGoSources — все исходники Go модуля со своей глубиной.
func moduleGoSources(t *testing.T, root string) (out []sourceFile, skipped int) {
	t.Helper()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			// Чужие деревья внутри модуля вердикту не подлежат.
			if n := d.Name(); n == "vendor" || n == "node_modules" || n == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			skipped++
			return nil
		}
		b, ferr := os.ReadFile(p)
		if ferr != nil {
			skipped++
			return nil
		}
		depth := 0
		if dir := filepath.ToSlash(filepath.Dir(rel)); dir != "." {
			depth = len(strings.Split(dir, "/"))
		}
		out = append(out, sourceFile{Name: filepath.ToSlash(rel), Depth: depth, Text: string(b)})
		return nil
	})
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обход модуля не отработал: %v", err)
	}
	return out, skipped
}
