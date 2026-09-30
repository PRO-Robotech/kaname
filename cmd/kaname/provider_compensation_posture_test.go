// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_compensation_posture_test.go — ветвь `own` сборщика дренажа
// компенсаций судится пробой (задача kaname#368).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Сборщик `buildProviderCompensationDrainer` на посадке `own` возвращает
// НУЛЕВУЮ ЗАДАЧУ ПРИ НУЛЕВОЙ ОШИБКЕ — законный третий исход, разобранный в его
// шапке. До этой пробы сборщик звала одна проба (`drainer_shutdown_test.go`), и
// та — с нулевой настройкой, которая читается как внешняя посадка
// (`AuthNConfig.HasExternalIdentityProvider`). Ветвь `own` не брал никто:
// возвращённая в ней ошибка либо собранная там задача проходили весь пакет
// зелёными.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВЕ ПОЛОВИНЫ СВОЙСТВА, И КАЖДАЯ СУДИТСЯ СВОИМ СПОСОБОМ
//
//  1. СБОРЩИК. Под `own` — (nil, nil); под `external` — живая задача дренажа.
//     Это поведение, и оно спрашивается вызовом. Близнец отличается от
//     отрицания РОВНО ОДНИМ фактом — значением посадки: без него «задачи нет»
//     зеленело бы на сборщике, который не собирает её НИКОГДА.
//
//  2. КОРЕНЬ. Нулевая задача, поставленная в группу, роняет корень
//     разыменованием, а отказ в ветви «задачи нет» не пускает посадку `own` в
//     старт вовсе. `runServe` пробой не поднимается: это весь путь подъёма —
//     база, ключи, слушатели, — и его исход здесь был бы исходом всего этого, а
//     не предмета. Поэтому его ТЕЛО разбирается, и судится то, как оно
//     обращается с результатом сборщика: каждое употребление задачи стоит под
//     проверкой «задача есть», а ветвь «задачи нет» только называет отсутствие.
//     Способность этого судьи упасть доказана на синтетике рядом
//     (`provider_compensation_posture_injection_test.go`).
//
// ─────────────────────────────────────────────────────────────────────────────
// СРОК ГОДНОСТИ
//
// Обе половины живут, пока у службы есть ДВЕ посадки. Снятие переключателя
// (#363) снимает близнец вместе с его значением, а сборщик — вместе с
// единственной ветвью, где он что-то собирает; эти пробы уходят ТЕМ ЖЕ
// изменением. Оставленные, они стали бы судьёй без предмета: близнец не
// соберётся, а разбор корня откажет словом «не выполнилось», а не зелёным.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// compensationBuilderName — сборщик, чей результат судится в теле корня.
const compensationBuilderName = "buildProviderCompensationDrainer"

// compensationRootFunc — тело корня, в котором сборщик зовётся и его задача
// ставится в группу.
const compensationRootFunc = "runServe"

// TestCompensationDrainerPosture_OwnBuildsNoTaskAndNoError — ПОЛОВИНА 1,
// отрицание: под `own` дренировать нечего и некуда.
func TestCompensationDrainerPosture_OwnBuildsNoTaskAndNoError(t *testing.T) {
	reg := metrics.NewRegistry()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	task, err := buildProviderCompensationDrainer(deadPool(t),
		roadCfg(config.IdentityProviderOwn, "9097"),
		reg.CompensationRecorder(), reg.ProviderRoadRecorder(), logger)

	asserted := 0
	asserted++
	if err != nil {
		t.Errorf("под own сборщик дренажа компенсаций ОТКАЗАЛ: %v. Корень читает эту "+
			"ошибку как фатальную для старта, то есть посадка без внешнего поставщика "+
			"не поднимается вовсе — а у очереди на ней нет ни одного производителя", err)
	}
	asserted++
	if task != nil {
		t.Errorf("под own сборщик СОБРАЛ задачу дренажа компенсаций: она била бы в " +
			"отставленную дорогу на каждой строке и добивала бы её до порога отравления — " +
			"«звонить некуда» превратилось бы в «строка отравлена»")
	}
	t.Logf("исполнено утверждений: %d", asserted)
}

// TestCompensationDrainerPosture_ExternalTwinBuildsALiveTask — ПОЛОВИНА 1,
// законный близнец: та же проба, другое значение посадки — и задача есть.
//
// Задача спрашивается не только на «не nil»: она обязана быть ЖИВЫМ дренажом —
// не возвращаться при живом контексте и возвращаться по отмене. Иначе близнец
// зеленел бы и на сборщике, отдающем под `external` пустышку, и отрицание выше
// снова оказалось бы неотличимо от сборщика, не дренирующего никогда.
func TestCompensationDrainerPosture_ExternalTwinBuildsALiveTask(t *testing.T) {
	reg := metrics.NewRegistry()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	task, err := buildProviderCompensationDrainer(deadPool(t),
		roadCfg(config.IdentityProviderExternal, "9097"),
		reg.CompensationRecorder(), reg.ProviderRoadRecorder(), logger)

	asserted := 0
	asserted++
	if err != nil {
		t.Fatalf("под external сборщик дренажа компенсаций отказал: %v — близнец не "+
			"собран, и отрицание под own ничего не различает", err)
	}
	asserted++
	if task == nil {
		t.Fatal("под external сборщик НЕ собрал задачу дренажа компенсаций — отрицание " +
			"под own зеленело бы на сборщике, который не собирает её никогда, а " +
			"намерения снять клиента у поставщика копились бы без исполнителя")
	}
	asserted++
	assertTaskStopsOnCancel(t, "дренаж компенсаций под external", task)
	t.Logf("исполнено утверждений: %d", asserted)
}

// TestCompensationDrainerPosture_RootSchedulesTheTaskOnlyWhenItExists —
// ПОЛОВИНА 2: тело корня ставит задачу в группу только там, где она есть, и в
// ветви «задачи нет» не отказывает в старте.
func TestCompensationDrainerPosture_RootSchedulesTheTaskOnlyWhenItExists(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("serve.go не разобран: %v — непрочитанный корень есть НАХОДКА, а не зелёное", err)
	}

	census, findings, err := judgeCompensationScheduling(fset, file)
	t.Logf("%s", census.Summary())
	if err != nil {
		t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ: %v", err)
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// TestCompensationDrainerPosture_NoCallerOutsideTheRootBody — судья тела корня
// видит ровно одно тело. Сборщик, позванный ещё где-то в пакете корня, собрал
// бы задачу, постановку которой не судит никто, поэтому обходится весь пакет.
func TestCompensationDrainerPosture_NoCallerOutsideTheRootBody(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("чтение каталога корня: %v", err)
	}
	fset := token.NewFileSet()
	var (
		parsed, refs int
		declSeen     bool
		findings     []string
	)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("разбор %s: %v — непрочитанный файл есть НАХОДКА, а не зелёное", name, perr)
		}
		parsed++
		seen, n, f := judgeBuilderReferencesOutsideRoot(fset, file)
		declSeen = declSeen || seen
		refs += n
		findings = append(findings, f...)
	}
	t.Logf("прод-файлов корня разобрано %d · объявление %s найдено: %t · упоминаний вне "+
		"тела %s %d · находок %d", parsed, compensationBuilderName, declSeen,
		compensationRootFunc, refs, len(findings))

	if parsed == 0 {
		t.Fatal("НЕ-ВЫПОЛНИЛОСЬ: обход не разобрал ни одного прод-файла корня — «ноль " +
			"находок» неотличим от «ноль прочитанного»")
	}
	if !declSeen {
		t.Fatalf("НЕ-ВЫПОЛНИЛОСЬ: обход не нашёл объявления %s (разобрано %d файлов) — "+
			"перепись слепа к предмету, либо сборщик снят и проба обязана уйти с ним",
			compensationBuilderName, parsed)
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// compensationScheduleCensus — объём осмотренного; печатается ВСЕГДА.
type compensationScheduleCensus struct {
	Calls       int // вызовов сборщика в теле корня
	Uses        int // употреблений задачи, кроме связывания и сравнений с nil
	Guarded     int // из них — под проверкой «задача есть»
	Guards      int // условий ветви, сравнивающих задачу с nil
	NilBranches int // ветвей «задачи нет»
	NilStmts    int // операторов в них
	Findings    int
}

// Summary — перепись одной строкой.
func (c compensationScheduleCensus) Summary() string {
	return fmt.Sprintf("тело %s · вызовов %s %d · употреблений задачи %d · из них под "+
		"проверкой «задача есть» %d · условий ветви по задаче %d · ветвей «задачи нет» %d · "+
		"операторов в них %d · находок %d",
		compensationRootFunc, compensationBuilderName, c.Calls, c.Uses, c.Guarded,
		c.Guards, c.NilBranches, c.NilStmts, c.Findings)
}

// compensationGuard — условие ветви, сравнивающее задачу с nil, и две его ветви.
// Нулевая ветвь означает «такой ветви у условия нет».
type compensationGuard struct {
	ifs        *ast.IfStmt
	taskBranch ast.Node
	nilBranch  ast.Node
}

// slogMethods — единственное законное содержимое ветви «задачи нет»: она
// НАЗЫВАЕТ отсутствие и ничего не делает. Словарь закрыт намеренно: возврат,
// гашение процесса, отмена корня и постановка работы суть разные слова для
// одного дефекта, и перечень запретов разошёлся бы с ними на первом новом.
var slogMethods = map[string]bool{
	"Debug": true, "Info": true, "Warn": true, "Error": true,
	"DebugContext": true, "InfoContext": true, "WarnContext": true, "ErrorContext": true,
	"Log": true, "LogAttrs": true,
}

// judgeCompensationScheduling судит, как тело корня обращается с результатом
// сборщика дренажа компенсаций.
//
// Ошибка — отказ ПРЕДПОСЫЛКИ: тело не найдено либо сборщик в нём не зовётся.
// Это «не выполнилось», а не «чисто»: судить нечего, и молчание было бы
// неотличимо от исправного корня.
//
// Законные формы записи — закрытый словарь, и всё вне его есть находка, а не
// молчание:
//
//   - связывание `T, E := сборщик(…)` либо `T, E = сборщик(…)`, T не `_`;
//   - условие ветви `T == nil` / `T != nil` в любом порядке операндов и в
//     скобках; ветвь «задача есть» — где сравнение истинно для непустой задачи;
//   - каждое иное упоминание T лексически внутри ветви «задача есть»;
//   - ветвь «задачи нет» — только вызовы журнала.
func judgeCompensationScheduling(fset *token.FileSet, file *ast.File) (
	c compensationScheduleCensus, findings []string, err error,
) {
	at := func(p token.Pos) string { return fset.Position(p).String() }
	defer func() {
		sort.Strings(findings)
		c.Findings = len(findings)
	}()

	var body *ast.BlockStmt
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Recv == nil && fn.Name.Name == compensationRootFunc && fn.Body != nil {
			body = fn.Body
		}
	}
	if body == nil {
		return c, nil, fmt.Errorf("в %s нет тела %s — судить обращение с задачей "+
			"дренажа компенсаций негде", fset.File(file.Pos()).Name(), compensationRootFunc)
	}

	// Проход 1: вызовы сборщика и его упоминания не вызовом.
	var binding *ast.AssignStmt
	var bindingCall *ast.CallExpr
	var callSites []string
	walkWithStack(body, func(n ast.Node, stack []ast.Node) {
		id, ok := n.(*ast.Ident)
		if !ok || id.Name != compensationBuilderName {
			return
		}
		call, ok := stack[len(stack)-2].(*ast.CallExpr)
		if !ok || call.Fun != id {
			findings = append(findings, fmt.Sprintf("%s — сборщик упомянут не вызовом: "+
				"результат, взятый обходным путём, этот судья не видит, и форма вне его "+
				"словаря — находка, а не молчание", at(id.Pos())))
			return
		}
		c.Calls++
		callSites = append(callSites, at(call.Pos()))
		bindingCall = call
		binding = nil
		if len(stack) >= 3 {
			if as, ok := stack[len(stack)-3].(*ast.AssignStmt); ok &&
				len(as.Rhs) == 1 && as.Rhs[0] == call {
				binding = as
			}
		}
	})
	switch {
	case c.Calls == 0 && len(findings) > 0:
		// Сборщик в теле ЕСТЬ, но взят не вызовом: это находка, а не пропажа
		// предмета.
		return c, findings, nil
	case c.Calls == 0:
		return c, findings, fmt.Errorf("тело %s не зовёт %s — предмет исчез, и судить "+
			"нечего: снимите эту пробу тем же изменением, что сняло сборщик",
			compensationRootFunc, compensationBuilderName)
	case c.Calls > 1:
		findings = append(findings, fmt.Sprintf("тело %s зовёт %s %d раз(а) (%s) — "+
			"судится ровно одна задача дренажа, и две сборки одной очереди этот судья не "+
			"разводит", compensationRootFunc, compensationBuilderName, c.Calls,
			strings.Join(callSites, ", ")))
		return c, findings, nil
	}

	task := bindingTaskIdent(binding)
	if task == nil {
		findings = append(findings, fmt.Sprintf("%s — связывание результата сборщика вне "+
			"словаря: ожидается `задача, ошибка := %s(…)` с именованной задачей. Задача, "+
			"не названная именем, либо выброшена — и тогда под external дренажа нет, — "+
			"либо взята формой, которой этот судья не читает",
			at(bindingCall.Pos()), compensationBuilderName))
		return c, findings, nil
	}

	// Проход 2: всякое упоминание задачи.
	var guards []compensationGuard
	walkWithStack(body, func(n ast.Node, stack []ast.Node) {
		id, ok := n.(*ast.Ident)
		if !ok || id.Name != task.Name || id == task {
			return
		}
		parent := stack[len(stack)-2]
		if rebindsName(parent, id) {
			findings = append(findings, fmt.Sprintf("%s — имя задачи `%s` связано второй "+
				"раз: проверенное на nil и употреблённое могут оказаться разными значениями, "+
				"и судить их по имени нельзя", at(id.Pos()), task.Name))
			return
		}
		if bin, ok := parent.(*ast.BinaryExpr); ok {
			if op := nilComparison(bin, id); op != token.ILLEGAL {
				ifs := ifWhoseCondIs(stack[:len(stack)-1])
				if ifs == nil {
					findings = append(findings, fmt.Sprintf("%s — сравнение задачи с nil вне "+
						"условия ветви (составное условие либо значение): ветвь, в которой оно "+
						"решает, этот судья не выводит, и под own она может отказать в старте",
						at(id.Pos())))
					return
				}
				g := compensationGuard{ifs: ifs}
				if op == token.EQL {
					g.nilBranch, g.taskBranch = ifs.Body, ifs.Else
				} else {
					g.taskBranch, g.nilBranch = ifs.Body, ifs.Else
				}
				guards = append(guards, g)
				c.Guards++
				return
			}
		}
		c.Uses++
		if underTaskBranch(stack, guards) {
			c.Guarded++
			return
		}
		findings = append(findings, fmt.Sprintf("%s — задача употреблена без проверки "+
			"«задача есть»: под own сборщик отдаёт nil, и поставленная в группу нулевая "+
			"задача роняет корень разыменованием — отсутствие дороги пришло бы паникой",
			at(id.Pos())))
	})
	if c.Uses == 0 {
		findings = append(findings, fmt.Sprintf("%s — задача собрана и не поставлена: "+
			"под external очередь компенсаций остаётся без исполнителя, намерения копятся, "+
			"а занятое у поставщика не освобождается", at(bindingCall.Pos())))
	}

	// Проход 3: ветви «задачи нет» только называют отсутствие.
	for _, g := range guards {
		if g.nilBranch == nil {
			continue
		}
		c.NilBranches++
		block, ok := g.nilBranch.(*ast.BlockStmt)
		if !ok {
			findings = append(findings, fmt.Sprintf("%s — ветвь «задачи нет» продолжена "+
				"условием: её исход зависит от другого предмета, и судить его здесь нечем",
				at(g.nilBranch.Pos())))
			continue
		}
		for _, stmt := range block.List {
			c.NilStmts++
			switch s := stmt.(type) {
			case *ast.ReturnStmt:
				findings = append(findings, fmt.Sprintf("%s — в ветви «задачи нет» корень "+
					"возвращается: посадка own, у очереди которой нет ни одного "+
					"производителя, не поднимается вовсе", at(s.Pos())))
			case *ast.ExprStmt:
				if isJournalCall(s.X) {
					continue
				}
				findings = append(findings, nilBranchActionFinding(at(s.Pos())))
			case *ast.EmptyStmt:
			default:
				findings = append(findings, nilBranchActionFinding(at(s.Pos())))
			}
		}
	}
	return c, findings, nil
}

// judgeBuilderReferencesOutsideRoot — упоминания сборщика в одном разобранном
// файле вне тела корня и вне его собственного объявления. Каждое — находка:
// задача, собранная там, лежит вне судьи тела корня, и её постановку в группу
// не судит никто. Первым значением возвращается, встречено ли объявление, —
// без него «ноль упоминаний» неотличим от обхода, не видящего предмета.
func judgeBuilderReferencesOutsideRoot(fset *token.FileSet, file *ast.File) (
	declSeen bool, refs int, findings []string,
) {
	for _, d := range file.Decls {
		fn, isFunc := d.(*ast.FuncDecl)
		if isFunc && fn.Recv == nil && fn.Name.Name == compensationRootFunc {
			continue
		}
		var own *ast.Ident
		if isFunc && fn.Recv == nil && fn.Name.Name == compensationBuilderName {
			declSeen = true
			own = fn.Name
		}
		ast.Inspect(d, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || id == own || id.Name != compensationBuilderName {
				return true
			}
			refs++
			findings = append(findings, fmt.Sprintf("%s — %s упомянут вне тела %s: "+
				"задачу, собранную здесь, судья тела корня не видит, и её постановку в "+
				"группу не судит никто", fset.Position(id.Pos()), compensationBuilderName,
				compensationRootFunc))
			return true
		})
	}
	return declSeen, refs, findings
}

func nilBranchActionFinding(where string) string {
	return fmt.Sprintf("%s — в ветви «задачи нет» стоит действие вне словаря: ветвь "+
		"обязана только назвать отсутствие. Поставленная там работа — задача, которой на "+
		"этой посадке быть не должно, а гашение или отмена корня — отказ в старте", where)
}

// walkWithStack обходит поддерево, передавая узел вместе с цепочкой предков;
// последний элемент цепочки — сам узел.
func walkWithStack(root ast.Node, visit func(n ast.Node, stack []ast.Node)) {
	var stack []ast.Node
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		stack = append(stack, n)
		visit(n, stack)
		return true
	})
}

// bindingTaskIdent — имя задачи в законном связывании, либо nil.
func bindingTaskIdent(as *ast.AssignStmt) *ast.Ident {
	if as == nil || len(as.Lhs) != 2 || (as.Tok != token.DEFINE && as.Tok != token.ASSIGN) {
		return nil
	}
	id, ok := as.Lhs[0].(*ast.Ident)
	if !ok || id.Name == "_" {
		return nil
	}
	return id
}

// rebindsName — связывает ли родитель имя заново: присваивание, объявление,
// параметр, переменная цикла.
func rebindsName(parent ast.Node, id *ast.Ident) bool {
	switch p := parent.(type) {
	case *ast.AssignStmt:
		for _, l := range p.Lhs {
			if l == id {
				return true
			}
		}
	case *ast.ValueSpec:
		for _, name := range p.Names {
			if name == id {
				return true
			}
		}
	case *ast.Field:
		for _, name := range p.Names {
			if name == id {
				return true
			}
		}
	case *ast.RangeStmt:
		return p.Key == id || p.Value == id
	}
	return false
}

// nilComparison — оператор сравнения задачи с nil, либо ILLEGAL.
func nilComparison(bin *ast.BinaryExpr, id *ast.Ident) token.Token {
	if bin.Op != token.EQL && bin.Op != token.NEQ {
		return token.ILLEGAL
	}
	isNil := func(e ast.Expr) bool {
		n, ok := ast.Unparen(e).(*ast.Ident)
		return ok && n.Name == "nil"
	}
	if (bin.X == id && isNil(bin.Y)) || (bin.Y == id && isNil(bin.X)) {
		return bin.Op
	}
	return token.ILLEGAL
}

// ifWhoseCondIs — условие ветви, чьё условие и есть последний узел цепочки
// (с точностью до скобок), либо nil.
func ifWhoseCondIs(stack []ast.Node) *ast.IfStmt {
	i := len(stack) - 1
	expr := stack[i]
	for i--; i >= 0; i-- {
		if _, ok := stack[i].(*ast.ParenExpr); ok {
			expr = stack[i]
			continue
		}
		ifs, ok := stack[i].(*ast.IfStmt)
		if ok && ifs.Cond == expr {
			return ifs
		}
		return nil
	}
	return nil
}

// underTaskBranch — лежит ли узел лексически в ветви «задача есть» одного из
// уже встреченных условий.
func underTaskBranch(stack []ast.Node, guards []compensationGuard) bool {
	for k := len(stack) - 2; k >= 0; k-- {
		ifs, ok := stack[k].(*ast.IfStmt)
		if !ok {
			continue
		}
		for _, g := range guards {
			if g.ifs == ifs && g.taskBranch != nil && stack[k+1] == g.taskBranch {
				return true
			}
		}
	}
	return false
}

// isJournalCall — вызов метода журнала: единственное законное действие ветви
// «задачи нет».
func isJournalCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && slogMethods[sel.Sel.Name]
}
