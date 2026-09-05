// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

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

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
	"github.com/stretchr/testify/require"
)

// Потолок ТЕМПА заведения аккаунтов (задача #618) — три на личность в час. Значит
// ЛЮБАЯ проба, заводящая больше трёх аккаунтов ОДНОЙ личностью, краснеет по полосе,
// о которой ничего не утверждает, — и красное это приходит только с конвейера.
//
// # ПОЧЕМУ ГЕЙТ ПО СВОЙСТВУ, А НЕ ПО ИМЕНИ
//
// Радиус в своё время искали по имени файла (`*quota*`), а свойство — «сколько
// аккаунтов на личность заводит проба». Имя и свойство не совпадают: проба страницы
// списка под имя не подпала и упала на конвейере. Здесь считается СВОЙСТВО.
//
// # ПРАВИЛА СЧЁТА ОБЪЯВЛЕНЫ, А НЕ ПОДРАЗУМЕВАЮТСЯ
//
// Гейт судит узлы синтаксического дерева, а не подстроки: заведения бывают в цикле,
// в хелпере фикстуры и в теле подпробы, и текстовый поиск их не сложит.
//
//  1. ЛИЧНОСТЬ — переменная, которой присвоен результат `mustSeedUser`.
//  2. `mustSeedUser` сам заводит аккаунт (его фикстура вставляет строку `accounts`)
//     — это +1 своей личности. Именно эта единица и делала четвёртым заведением то,
//     что на глаз выглядело третьим.
//  3. `seedAccount(…, ЛИЧНОСТЬ)` — +1 названной последним аргументом личности.
//  4. Вклад внутри `for` умножается на произведение разрешимых границ ЭТИХ циклов —
//     КРОМЕ случая, когда личность (пере)связывается `mustSeedUser` внутри того же
//     цикла: тогда у каждой итерации личность СВОЯ, и множитель не применяется.
//     Это и есть законная форма `migrate_backfill_p8` — пять аккаунтов на пять
//     разных личностей потолка темпа не касаются.
//  5. Граница цикла разрешается из целого литерала либо из имени, которому в той же
//     функции присвоен целый литерал (`:=`, `=`, `const`); у `range` — длина литерала
//     набора либо имени, которому такой литерал присвоен. Неразрешимая граница даёт
//     множитель 1 и печатается в переписи отдельным числом — слепая зона названа, а
//     не спрятана.
//  6. Личность опознаётся ОБЛАСТЬЮ ВИДИМОСТИ, а не именем. Две подпробы `t.Run`,
//     каждая со своим `uid := mustSeedUser(…)`, — это ДВЕ личности, а не одна на
//     четыре аккаунта. Счёт по имени давал здесь ложную находку, и это не гипотеза:
//     первая редакция гейта её выдала, и снял её именно переход к областям.
//
// # ГРАНИЦА
//
// Гейт видит два названных хелпера фикстуры. Проба, заводящая аккаунт голым
// `INSERT`, ему невидима — и это сказано вслух, а не оставлено умолчанием: перепись
// печатает объём осмотренного, поэтому «ноль находок» отличимо от «ноль
// прочитанного».
//
// # СОСТАВ ДЕРЕВА БЕРЁТСЯ ИЗ ИНДЕКСА, А НЕ ОБХОДОМ ДИСКА
//
// Обход диска прочитал бы и то, чего в репозитории нет — рабочие копии агентов,
// отчёты прогонов, локальные распаковки, — и вердикт стал бы свойством ЧУЖОГО
// рабочего каталога, а не коммита. Ошибается такой обход в обе стороны: красным на
// файле, которого в репозитории нет, и молчанием в свежем checkout там, где обязан
// говорить.
const (
	// accountProbeDirRel — дом интеграционных проб, заводящих аккаунты.
	accountProbeDirRel = "services/iam/internal/repo/kacho/pg"

	// seedUserCall — фикстура личности; заводит и личность, и её аккаунт.
	seedUserCall = "mustSeedUser"
	// seedAccountCall — заведение аккаунта названной личности.
	seedAccountCall = "seedAccount"
	// rateCeilingLift — поднятие потолка темпа из-под ног.
	rateCeilingLift = "liftRateCeilingOutOfTheWay"

	// rateCeilingDefault — умолчание потолка темпа: три заведения в час на
	// личность (задача #618). Четвёртое отвергается.
	rateCeilingDefault = 3
)

// rateCensus — объём осмотренного.
type rateCensus struct {
	filesRead      int // файлов проб прочитано
	probes         int // функций-проб осмотрено
	identities     int // личностей опознано
	seedCalls      int // заведений аккаунта прочитано
	liftingProbes  int // проб, поднимающих потолок
	unresolvedLoop int // циклов с неразрешимой границей (слепая зона)
}

// intLiterals собирает имена, которым в функции присвоен целый литерал.
func intLiterals(fn *ast.FuncDecl) map[string]int {
	out := map[string]int{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch d := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range d.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || i >= len(d.Rhs) {
					continue
				}
				if v, ok := literalInt(d.Rhs[i]); ok {
					out[id.Name] = v
				}
			}
		case *ast.ValueSpec:
			for i, name := range d.Names {
				if i < len(d.Values) {
					if v, ok := literalInt(d.Values[i]); ok {
						out[name.Name] = v
					}
				}
			}
		}
		return true
	})
	return out
}

// compositeLens собирает имена, которым в функции присвоен литерал набора:
// `range` по такому имени имеет разрешимую границу — его длину.
func compositeLens(fn *ast.FuncDecl) map[string]int {
	out := map[string]int{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || i >= len(as.Rhs) {
				continue
			}
			if cl, ok := as.Rhs[i].(*ast.CompositeLit); ok {
				out[id.Name] = len(cl.Elts)
			}
		}
		return true
	})
	return out
}

// rangeBound — длина обхода `range`: литерал набора либо имя, которому такой
// литерал присвоен. Прочее неразрешимо, и это печатается переписью.
func rangeBound(r *ast.RangeStmt, lens map[string]int) (int, bool) {
	switch x := r.X.(type) {
	case *ast.CompositeLit:
		return len(x.Elts), true
	case *ast.Ident:
		if n, ok := lens[x.Name]; ok {
			return n, true
		}
	}
	return 0, false
}

func literalInt(e ast.Expr) (int, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0, false
	}
	v, err := strconv.Atoi(lit.Value)
	if err != nil {
		return 0, false
	}
	return v, true
}

// loopBound — граница цикла `for i := 0; i < N; i++`; second value false, когда
// граница неразрешима.
func loopBound(f *ast.ForStmt, consts map[string]int) (int, bool) {
	bin, ok := f.Cond.(*ast.BinaryExpr)
	if !ok || (bin.Op != token.LSS && bin.Op != token.LEQ) {
		return 0, false
	}
	n, ok := literalInt(bin.Y)
	if !ok {
		id, isIdent := bin.Y.(*ast.Ident)
		if !isIdent {
			return 0, false
		}
		if n, ok = consts[id.Name]; !ok {
			return 0, false
		}
	}
	if bin.Op == token.LEQ {
		n++
	}
	return n, true
}

// identityArg — имя личности из последнего аргумента вызова.
func identityArg(call *ast.CallExpr) string {
	if len(call.Args) == 0 {
		return ""
	}
	id, ok := call.Args[len(call.Args)-1].(*ast.Ident)
	if !ok {
		return ""
	}
	return id.Name
}

// callName — имя вызываемой функции, если это простой идентификатор.
func callName(call *ast.CallExpr) string {
	id, ok := call.Fun.(*ast.Ident)
	if !ok {
		return ""
	}
	return id.Name
}

// identityRef — личность как ОБЪЕКТ, а не как имя: две подпробы со своим
// `uid` дают две разные личности.
type identityRef struct {
	name     string       // как названа в исходнике — для текста находки
	declLoop *ast.ForStmt // цикл, внутри которого она рождается (nil — верхний уровень)
	count    int          // сколько аккаунтов ей заведено
}

// scopeStack — стек областей видимости: имя → личность.
type scopeStack []map[string]*identityRef

func (s scopeStack) lookup(name string) *identityRef {
	for i := len(s) - 1; i >= 0; i-- {
		if ref, ok := s[i][name]; ok {
			return ref
		}
	}
	return nil
}

// auditProbeFile — чистое ядро: находки и перепись по одному файлу проб.
func auditProbeFile(name, src string) ([]string, rateCensus, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		return nil, rateCensus{}, fmt.Errorf("разбор %s: %w", name, err)
	}

	var findings []string
	c := rateCensus{filesRead: 1}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "Test") {
			continue
		}
		c.probes++
		consts := intLiterals(fn)
		lens := compositeLens(fn)

		var all []*identityRef
		lifts := false
		var loops []*ast.ForStmt
		boundOf := map[*ast.ForStmt]int{}

		// multiplier — правило 4: умножают только циклы, лежащие СТРОГО ВНУТРИ
		// того, в котором личность рождается. Личность, рождённая внутри цикла,
		// у каждой итерации своя, поэтому сам цикл и всё, что снаружи, не множат.
		multiplier := func(ref *identityRef) int {
			m, inside := 1, ref.declLoop == nil
			for _, f := range loops {
				if inside {
					if b, ok := boundOf[f]; ok {
						m *= b
					}
				}
				if f == ref.declLoop {
					inside = true
				}
			}
			return m
		}

		innermostLoop := func() *ast.ForStmt {
			if len(loops) == 0 {
				return nil
			}
			return loops[len(loops)-1]
		}

		var walkNode func(n ast.Node, scopes scopeStack)
		var walkList func(list []ast.Stmt, scopes scopeStack)

		walkExpr := func(e ast.Expr, scopes scopeStack) {
			ast.Inspect(e, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch callName(call) {
				case rateCeilingLift:
					lifts = true
				case seedAccountCall:
					if who := identityArg(call); who != "" {
						c.seedCalls++
						if ref := scopes.lookup(who); ref != nil {
							ref.count += multiplier(ref)
						}
					}
				}
				return true
			})
		}

		walkList = func(list []ast.Stmt, scopes scopeStack) {
			inner := append(scopes, map[string]*identityRef{})
			for _, st := range list {
				walkNode(st, inner)
			}
		}

		walkNode = func(n ast.Node, scopes scopeStack) {
			switch node := n.(type) {
			case *ast.BlockStmt:
				walkList(node.List, scopes)
			case *ast.ForStmt:
				if b, ok := loopBound(node, consts); ok {
					boundOf[node] = b
				} else {
					c.unresolvedLoop++
				}
				loops = append(loops, node)
				walkList(node.Body.List, scopes)
				loops = loops[:len(loops)-1]
			case *ast.RangeStmt:
				// `range` по литералу набора имеет разрешимую границу — его длину;
				// синтетический цикл нужен, чтобы множитель её увидел.
				synthetic := &ast.ForStmt{}
				if b, ok := rangeBound(node, lens); ok {
					boundOf[synthetic] = b
				} else {
					c.unresolvedLoop++
				}
				loops = append(loops, synthetic)
				walkList(node.Body.List, scopes)
				loops = loops[:len(loops)-1]
			case *ast.IfStmt:
				if node.Init != nil {
					walkNode(node.Init, scopes)
				}
				walkExpr(node.Cond, scopes)
				walkList(node.Body.List, scopes)
				if node.Else != nil {
					walkNode(node.Else, scopes)
				}
			case *ast.AssignStmt:
				for i, rhs := range node.Rhs {
					call, isCall := rhs.(*ast.CallExpr)
					if isCall && callName(call) == seedUserCall && i < len(node.Lhs) {
						if id, ok := node.Lhs[i].(*ast.Ident); ok && id.Name != "_" {
							ref := &identityRef{name: id.Name, declLoop: innermostLoop()}
							ref.count = multiplier(ref) // правило 2: фикстура заводит аккаунт
							scopes[len(scopes)-1][id.Name] = ref
							all = append(all, ref)
							c.identities++
							continue
						}
					}
					walkExpr(rhs, scopes)
				}
			default:
				// прочие узлы: интересуют только вызовы внутри них, плюс тела
				// функциональных литералов — там живут подпробы `t.Run`.
				ast.Inspect(n, func(m ast.Node) bool {
					if lit, ok := m.(*ast.FuncLit); ok {
						walkList(lit.Body.List, scopes)
						return false
					}
					if call, ok := m.(*ast.CallExpr); ok {
						switch callName(call) {
						case rateCeilingLift:
							lifts = true
						case seedAccountCall:
							if who := identityArg(call); who != "" {
								c.seedCalls++
								if ref := scopes.lookup(who); ref != nil {
									ref.count += multiplier(ref)
								}
							}
						}
					}
					return true
				})
			}
		}

		walkList(fn.Body.List, scopeStack{})

		if lifts {
			c.liftingProbes++
			continue
		}
		sort.SliceStable(all, func(i, j int) bool { return all[i].name < all[j].name })
		for _, ref := range all {
			if ref.count > rateCeilingDefault {
				findings = append(findings, fmt.Sprintf(
					"%s: проба %s заводит %d аккаунтов личностью %q при потолке темпа %d — "+
						"она обязана звать %s, иначе краснеет по полосе, о которой ничего не утверждает",
					name, fn.Name.Name, ref.count, ref.name, rateCeilingDefault, rateCeilingLift))
			}
		}
	}
	return findings, c, nil
}

// TestProbesOutgrowingTheRateCeilingLiftIt — несущее утверждение.
func TestProbesOutgrowingTheRateCeilingLiftIt(t *testing.T) {
	root := monorepoRoot(t)
	dir := filepath.Join(root, accountProbeDirRel)

	paths, err := treecorpus.UnderWithSuffix(dir, "_test.go")
	require.NoError(t, err)

	var findings []string
	var total rateCensus
	for _, p := range paths {
		raw, err := os.ReadFile(p) // #nosec G304 -- путь пришёл из индекса собственного репозитория
		require.NoError(t, err)
		f, c, err := auditProbeFile(filepath.Base(p), string(raw))
		require.NoError(t, err)
		findings = append(findings, f...)
		total.filesRead += c.filesRead
		total.probes += c.probes
		total.identities += c.identities
		total.seedCalls += c.seedCalls
		total.liftingProbes += c.liftingProbes
		total.unresolvedLoop += c.unresolvedLoop
	}

	t.Logf("перепись: файлов проб прочитано %d · функций-проб осмотрено %d · "+
		"личностей опознано %d · заведений аккаунта прочитано %d · проб поднимают потолок %d · "+
		"циклов с неразрешимой границей %d · находок %d",
		total.filesRead, total.probes, total.identities, total.seedCalls,
		total.liftingProbes, total.unresolvedLoop, len(findings))

	require.NotZerof(t, total.filesRead, "обход пуст — вердикт беспредметен (%s)", accountProbeDirRel)
	require.NotZerof(t, total.seedCalls, "заведений аккаунта не прочитано ни одного — вердикт беспредметен")
	require.NotZerof(t, total.liftingProbes, "ни одна проба не поднимает потолок — предпосылка гейта исчезла")

	require.Emptyf(t, findings,
		"пробы упираются в потолок темпа заведения аккаунтов, о котором ничего не утверждают:\n%s",
		strings.Join(findings, "\n"))
}
