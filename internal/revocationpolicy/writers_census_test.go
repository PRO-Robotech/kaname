// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package revocationpolicy_test

// writers_census_test.go — перепись писателей моментов, сравниваемых с
// отсечкой отзыва-всех, ВЫВОДИТСЯ ИЗ ДЕРЕВА (задача kaname#589, предикат 1):
// ни один из них не берёт часы процесса реплики.
//
// # Что считается писателем
//
// Узел разбора, а не слово. Пять форм записи момента:
//
//   - поле `RevokeBefore` литерала `UserTokenRevocation` — отсечка «сейчас»;
//   - третий довод вызова `RevokeAllUserTokensTx` / `RevokeAllUserTokens` —
//     отсечка через дверь отзыва-всех;
//   - поле `At` литерала `IssueInput` — момент аутентификации сессии;
//   - поле `CreatedAt` литерала `UserOAuthClient` — момент выдачи
//     долговременного удостоверения;
//   - присваивание `claims["iat"]` — `iat` подписанта.
//
// Адаптеры хранилища (`internal/repo/`) в перепись не входят: они переносят
// момент, поданный вызывающим, и их вход — довод, чей источник судится у
// вызывающего, то есть здесь.
//
// # Что считается законным источником
//
// Корень выражения (сквозь `.Add`, `.Truncate`, `.UTC`, `.Round`, скобки)
// прослеживается до определения в той же функции, а если это параметр — до
// довода во всех вызовах этой функции в том же пакете. Законны:
//
//   - вызов метода `Now` с ОДНИМ доводом (порт `revocationpolicy.Clock` /
//     `tokensigner.Clock`) и его обёртки `revocationpolicy.Moment`,
//     `sharedMoment`;
//   - `revocationMoment` — момент, выведенный из СОХРАНЁННОГО момента первой
//     аутентификации (он поставлен общим источником при выдаче);
//   - чтение памяти первой аутентификации (`….FirstAuthentication(…)`) — тот
//     же сохранённый момент; правило `domain.CutoffBelowFirstAuthentication`
//     производное своего довода, как `.Add`, и судится по нему (kaname#669).
//
// Всё прочее — находка с координатой: `time.Now()`, поле часов процесса без
// доводов (`uc.now()`, `d.Now()`), непрослеживаемое выражение.
//
// Перепись печатается всегда; пустой обход и форма без единого писателя —
// отказ: распознаватель, переставший узнавать форму, иначе молчал бы как
// чистое дерево.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// sinkForms — пять форм записи момента. Порядок — порядок печати.
var sinkForms = []string{"cutoff-literal", "cutoff-door", "session-at", "issued-at", "iat"}

type sink struct {
	form    string
	pos     string
	verdict string // shared | stored | finding
	why     string
}

type censusResult struct {
	files int
	sinks []sink
}

func (c censusResult) String() string {
	byForm := map[string]int{}
	byVerdict := map[string]int{}
	for _, s := range c.sinks {
		byForm[s.form]++
		byVerdict[s.verdict]++
	}
	var forms []string
	for _, f := range sinkForms {
		forms = append(forms, fmt.Sprintf("%s=%d", f, byForm[f]))
	}
	return fmt.Sprintf("перепись: файлов разобрано %d · писателей %d (%s) · от общего источника %d · от сохранённого момента %d · находок %d",
		c.files, len(c.sinks), strings.Join(forms, " "), byVerdict["shared"], byVerdict["stored"], byVerdict["finding"])
}

// pkgFiles — разобранные файлы одного каталога (пакета).
type pkgFiles struct {
	fset  *token.FileSet
	files map[string]*ast.File
}

// scanTree — перепись писателей по корню модуля root, в каталогах tops.
func scanTree(t *testing.T, root string, tops []string) censusResult {
	t.Helper()
	var res censusResult
	pkgs := map[string]*pkgFiles{}
	for _, top := range tops {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if strings.HasPrefix(rel, "internal/repo/") || strings.HasPrefix(rel, "internal/testsupport/") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			dir := filepath.Dir(rel)
			pf := pkgs[dir]
			if pf == nil {
				pf = &pkgFiles{fset: token.NewFileSet(), files: map[string]*ast.File{}}
				pkgs[dir] = pf
			}
			f, perr := parser.ParseFile(pf.fset, rel, mustRead(t, p), parser.SkipObjectResolution)
			if perr != nil {
				return perr
			}
			pf.files[rel] = f
			res.files++
			return nil
		})
		require.NoError(t, err)
	}
	var dirs []string
	for d := range pkgs {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		res.sinks = append(res.sinks, scanPackage(pkgs[d])...)
	}
	return res
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	return b
}

// scanPackage — писатели одного пакета и их вердикты.
func scanPackage(pf *pkgFiles) []sink {
	var out []sink
	var names []string
	for n := range pf.files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		f := pf.files[name]
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				for _, s := range sinksOf(n) {
					verdict, why := judge(pf, fn, s.expr, 0)
					out = append(out, sink{form: s.form, pos: pf.fset.Position(s.expr.Pos()).String(), verdict: verdict, why: why})
				}
				return true
			})
		}
	}
	return out
}

type rawSink struct {
	form string
	expr ast.Expr
}

// sinksOf — писатели момента в узле n.
func sinksOf(n ast.Node) []rawSink {
	switch x := n.(type) {
	case *ast.CompositeLit:
		typeName := ""
		switch tt := x.Type.(type) {
		case *ast.Ident:
			typeName = tt.Name
		case *ast.SelectorExpr:
			typeName = tt.Sel.Name
			// Строка удостоверения — доменный тип; одноимённое сообщение
			// контракта (`iamv1.UserOAuthClient`) — проекция для ответа, не запись.
			if typeName == "UserOAuthClient" && !isIdent(tt.X, "domain") {
				return nil
			}
		}
		field := map[string]string{"UserTokenRevocation": "RevokeBefore", "IssueInput": "At", "UserOAuthClient": "CreatedAt"}[typeName]
		form := map[string]string{"UserTokenRevocation": "cutoff-literal", "IssueInput": "session-at", "UserOAuthClient": "issued-at"}[typeName]
		if field == "" {
			return nil
		}
		for _, e := range x.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); ok && k.Name == field {
				return []rawSink{{form: form, expr: kv.Value}}
			}
		}
	case *ast.CallExpr:
		sel, ok := x.Fun.(*ast.SelectorExpr)
		if ok && (sel.Sel.Name == "RevokeAllUserTokensTx" || sel.Sel.Name == "RevokeAllUserTokens") && len(x.Args) >= 3 {
			return []rawSink{{form: "cutoff-door", expr: x.Args[2]}}
		}
	case *ast.AssignStmt:
		for i, l := range x.Lhs {
			idx, ok := l.(*ast.IndexExpr)
			if !ok || i >= len(x.Rhs) {
				continue
			}
			if lit, ok := idx.Index.(*ast.BasicLit); ok && lit.Value == `"iat"` {
				return []rawSink{{form: "iat", expr: x.Rhs[i]}}
			}
		}
	}
	return nil
}

// rootOf — корень выражения сквозь производные момента.
func rootOf(e ast.Expr) ast.Expr {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.UnaryExpr:
			e = x.X
		case *ast.CallExpr:
			sel, ok := x.Fun.(*ast.SelectorExpr)
			if !ok {
				return e
			}
			switch sel.Sel.Name {
			case "Add", "Truncate", "UTC", "Round", "Unix":
				e = sel.X
			default:
				return e
			}
		default:
			return e
		}
	}
}

// lawfulCall — вердикт по вызову-источнику.
func lawfulCall(call *ast.CallExpr) (string, string, bool) {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		switch {
		case fun.Sel.Name == "Now" && len(call.Args) == 1:
			return "shared", "порт источника моментов", true
		case fun.Sel.Name == "Moment" && isIdent(fun.X, "revocationpolicy"):
			return "shared", "revocationpolicy.Moment", true
		case fun.Sel.Name == "Now" && len(call.Args) == 0:
			return "finding", "часы процесса: вызов Now без довода", true
		case fun.Sel.Name == "FirstAuthentication":
			return "stored", "сохранённый момент первой аутентификации (чтение памяти)", true
		}
	case *ast.Ident:
		switch fun.Name {
		case "sharedMoment":
			return "shared", "sharedMoment", true
		case "revocationMoment":
			return "stored", "сохранённый момент первой аутентификации", true
		}
	}
	return "", "", false
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// judge — откуда корень выражения e в функции fn. depth ограничивает переход
// через параметры.
func judge(pf *pkgFiles, fn *ast.FuncDecl, e ast.Expr, depth int) (string, string) {
	r := rootOf(e)
	switch x := r.(type) {
	case *ast.CallExpr:
		// Правило момента отсечки ниже первой аутентификации — производное
		// своего довода: судится довод, а не вызов.
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "CutoffBelowFirstAuthentication" &&
			isIdent(sel.X, "domain") && len(x.Args) == 1 {
			return judge(pf, fn, x.Args[0], depth)
		}
		if v, why, ok := lawfulCall(x); ok {
			return v, why
		}
		if depth < 2 {
			if callee := declOf(pf, calleeName(x)); callee != nil {
				return judgeReturns(pf, callee, depth+1)
			}
		}
		return "finding", "вызов вне словаря источников: " + exprString(pf, x)
	case *ast.Ident:
		return judgeIdent(pf, fn, x.Name, depth)
	case *ast.SelectorExpr:
		// Поле значения, построенного в этой же функции литералом записи:
		// `marker.RevokeBefore`, где `marker` — `&m`, а `m` — литерал с
		// судимым полем. Судится значение поля в литерале.
		if base, ok := rootOf(x.X).(*ast.Ident); ok {
			if v, why, ok := judgeFieldOfLiteral(pf, fn, base.Name, x.Sel.Name, depth, 0); ok {
				return v, why
			}
		}
	}
	return "finding", "непрослеживаемое выражение: " + exprString(pf, r)
}

// judgeIdent — все определения имени в функции законны; параметр — по доводам
// вызывающих в том же пакете.
func judgeIdent(pf *pkgFiles, fn *ast.FuncDecl, name string, depth int) (string, string) {
	var verdicts []string
	var whys []string
	add := func(v, why string) { verdicts = append(verdicts, v); whys = append(whys, why) }
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, l := range as.Lhs {
			id, ok := l.(*ast.Ident)
			if !ok || id.Name != name {
				continue
			}
			var rhs ast.Expr
			if len(as.Rhs) == len(as.Lhs) {
				rhs = as.Rhs[i]
			} else if len(as.Rhs) == 1 {
				rhs = as.Rhs[0]
			}
			if rhs == nil {
				add("finding", "присваивание без правой части")
				continue
			}
			if rr, ok := rootOf(rhs).(*ast.Ident); ok && rr.Name == name {
				continue // производная того же имени: at = at.Truncate(...)
			}
			v, why := judge(pf, fn, rhs, depth)
			add(v, why)
		}
		return true
	})
	if idx, ok := paramIndex(fn, name); ok {
		if depth >= 2 {
			add("finding", "параметр без прослеживаемого вызывающего: "+name)
		} else {
			callers := 0
			for _, f := range pf.files {
				for _, d := range f.Decls {
					cfn, ok := d.(*ast.FuncDecl)
					if !ok || cfn.Body == nil {
						continue
					}
					// Метод судится вызовами из методов ТОГО ЖЕ получателя через
					// его имя: одноимённые методы разных типов пакета (`issue` у
					// входа паролем и у входа ключом) иначе смешались бы.
					recvName, sameRecv := sameReceiver(fn, cfn)
					if fn.Recv != nil && !sameRecv {
						continue
					}
					ast.Inspect(cfn.Body, func(n ast.Node) bool {
						call, ok := n.(*ast.CallExpr)
						if !ok || calleeName(call) != fn.Name.Name || idx >= len(call.Args) {
							return true
						}
						if fn.Recv != nil {
							sel, ok := call.Fun.(*ast.SelectorExpr)
							if !ok || !isIdent(sel.X, recvName) {
								return true
							}
						}
						callers++
						v, why := judge(pf, cfn, call.Args[idx], depth+1)
						add(v, why)
						return true
					})
				}
			}
			if callers == 0 {
				add("finding", "параметр без вызывающего в пакете: "+name)
			}
		}
	}
	if len(verdicts) == 0 {
		return "finding", "имя без определения: " + name
	}
	result := verdicts[0]
	for i, v := range verdicts {
		if v == "finding" {
			return "finding", whys[i]
		}
		if v != result {
			result = "shared"
		}
	}
	return result, whys[0]
}

// declOf — функция или метод пакета с этим именем (единственная).
func declOf(pf *pkgFiles, name string) *ast.FuncDecl {
	var found *ast.FuncDecl
	n := 0
	for _, f := range pf.files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if ok && fn.Body != nil && fn.Name.Name == name {
				found = fn
				n++
			}
		}
	}
	if n != 1 {
		return nil
	}
	return found
}

// judgeReturns — первый результат каждого возврата функции законен.
func judgeReturns(pf *pkgFiles, fn *ast.FuncDecl, depth int) (string, string) {
	verdict, why := "", ""
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || len(ret.Results) == 0 || verdict == "finding" {
			return true
		}
		// Возврат отказа (нулевой момент вместе с ошибкой) момента не пишет.
		if cl, ok := ret.Results[0].(*ast.CompositeLit); ok && len(cl.Elts) == 0 {
			return true
		}
		v, w := judge(pf, fn, ret.Results[0], depth)
		if verdict == "" || v == "finding" {
			verdict, why = v, w
		}
		return true
	})
	if verdict == "" {
		return "finding", "функция без возврата момента: " + fn.Name.Name
	}
	return verdict, why
}

// judgeFieldOfLiteral — значение поля field литерала, которым определено имя
// base в функции fn (сквозь `&` и переприсваивание имени).
func judgeFieldOfLiteral(pf *pkgFiles, fn *ast.FuncDecl, base, field string, depth, hops int) (string, string, bool) {
	if hops > 3 {
		return "", "", false
	}
	var verdict, why string
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || found || len(as.Lhs) != len(as.Rhs) {
			return true
		}
		for i, l := range as.Lhs {
			id, ok := l.(*ast.Ident)
			if !ok || id.Name != base {
				continue
			}
			switch r := rootOf(as.Rhs[i]).(type) {
			case *ast.CompositeLit:
				for _, e := range r.Elts {
					kv, ok := e.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					if k, ok := kv.Key.(*ast.Ident); ok && k.Name == field {
						verdict, why = judge(pf, fn, kv.Value, depth)
						found = true
					}
				}
			case *ast.Ident:
				if r.Name != base {
					verdict, why, found = judgeFieldOfLiteral(pf, fn, r.Name, field, depth, hops+1)
				}
			}
		}
		return true
	})
	return verdict, why, found
}

// sameReceiver — у fn и cfn один тип получателя; возвращает имя получателя
// cfn, через которое он зовёт свои методы.
func sameReceiver(fn, cfn *ast.FuncDecl) (string, bool) {
	if fn.Recv == nil || cfn.Recv == nil || len(fn.Recv.List) != 1 || len(cfn.Recv.List) != 1 {
		return "", false
	}
	if recvType(fn.Recv.List[0].Type) != recvType(cfn.Recv.List[0].Type) || len(cfn.Recv.List[0].Names) != 1 {
		return "", false
	}
	return cfn.Recv.List[0].Names[0].Name, true
}

func recvType(e ast.Expr) string {
	if st, ok := e.(*ast.StarExpr); ok {
		e = st.X
	}
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

func calleeName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

func paramIndex(fn *ast.FuncDecl, name string) (int, bool) {
	i := 0
	for _, field := range fn.Type.Params.List {
		if len(field.Names) == 0 {
			i++
			continue
		}
		for _, n := range field.Names {
			if n.Name == name {
				return i, true
			}
			i++
		}
	}
	return 0, false
}

func exprString(pf *pkgFiles, e ast.Expr) string {
	return fmt.Sprintf("%T@%s", e, pf.fset.Position(e.Pos()))
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(root, "go.mod"))
	require.NoError(t, err, "предпосылка переписи: корень модуля не найден (%s)", root)
	return root
}

// TestEveryMomentComparedWithTheCutoffComesFromTheSharedClock — kaname#589,
// предикат 1, по дереву.
func TestEveryMomentComparedWithTheCutoffComesFromTheSharedClock(t *testing.T) {
	res := scanTree(t, moduleRoot(t), []string{"internal", "cmd"})
	t.Log(res.String())
	require.Positive(t, res.files, "обход не разобрал ни одного файла — вердикт беспредметен")
	seen := map[string]int{}
	var findings []string
	for _, s := range res.sinks {
		seen[s.form]++
		t.Logf("  %s · %s · %s (%s)", s.form, s.pos, s.verdict, s.why)
		if s.verdict == "finding" {
			findings = append(findings, fmt.Sprintf("%s [%s]: %s", s.pos, s.form, s.why))
		}
	}
	for _, f := range sinkForms {
		require.Positivef(t, seen[f], "форма %q не нашла ни одного писателя — распознаватель перестал её узнавать", f)
	}
	require.Emptyf(t, findings, "писатель момента, сравниваемого с отсечкой, берёт не общий источник (%d):\n%s",
		len(findings), strings.Join(findings, "\n"))
}

// TestWritersCensusInjection — способность упасть: дефект (часы процесса)
// краснеет с координатой, законный близнец той же формы молчит.
func TestWritersCensusInjection(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\n"), 0o600))
		dir := filepath.Join(root, "internal", "apps", "probe")
		require.NoError(t, os.MkdirAll(dir, 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "w.go"), []byte(body), 0o600))
		return root
	}
	const header = "package probe\n\nimport (\n\t\"context\"\n\t\"time\"\n)\n\ntype UserTokenRevocation struct{ RevokeBefore time.Time }\n" +
		"type clock interface{ Now(context.Context) (time.Time, error) }\n" +
		"type uc struct {\n\tnow   func() time.Time\n\tclock clock\n}\n\nvar _ = time.Now\n"
	for name, c := range map[string]struct {
		body    string
		verdict string
	}{
		"дефект: time.Now()":                        {header + "func (u uc) w(ctx context.Context) UserTokenRevocation {\n\tat := time.Now().UTC()\n\treturn UserTokenRevocation{RevokeBefore: at}\n}\n", "finding"},
		"дефект: поле часов процесса":               {header + "func (u uc) w(ctx context.Context) UserTokenRevocation {\n\treturn UserTokenRevocation{RevokeBefore: u.now().UTC()}\n}\n", "finding"},
		"дефект: параметр от часов процесса":        {header + "func (u uc) w(ctx context.Context, at time.Time) UserTokenRevocation {\n\treturn UserTokenRevocation{RevokeBefore: at}\n}\nfunc (u uc) c(ctx context.Context) { _ = u.w(ctx, time.Now()) }\n", "finding"},
		"дефект: правило отсечки от часов процесса": {header + "func (u uc) w(ctx context.Context) UserTokenRevocation {\n\treturn UserTokenRevocation{RevokeBefore: domain.CutoffBelowFirstAuthentication(time.Now())}\n}\n", "finding"},
		"законный близнец: правило отсечки от памяти": {header + "type mem interface {\n\tFirstAuthentication(context.Context, string) (time.Time, bool, error)\n}\n" +
			"func (u uc) w(ctx context.Context, m mem) UserTokenRevocation {\n\tfirst, _, _ := m.FirstAuthentication(ctx, \"u\")\n\treturn UserTokenRevocation{RevokeBefore: domain.CutoffBelowFirstAuthentication(first)}\n}\n", "stored"},
		"законный близнец: порт источника":    {header + "func (u uc) w(ctx context.Context) UserTokenRevocation {\n\tat, _ := u.clock.Now(ctx)\n\tat = at.Truncate(time.Microsecond)\n\treturn UserTokenRevocation{RevokeBefore: at}\n}\n", "shared"},
		"законный близнец: параметр от порта": {header + "func (u uc) w(ctx context.Context, at time.Time) UserTokenRevocation {\n\treturn UserTokenRevocation{RevokeBefore: at.Add(time.Microsecond)}\n}\nfunc (u uc) c(ctx context.Context) {\n\tm, _ := u.clock.Now(ctx)\n\t_ = u.w(ctx, m)\n}\n", "shared"},
	} {
		t.Run(name, func(t *testing.T) {
			res := scanTree(t, write(t, c.body), []string{"internal"})
			t.Log(res.String())
			require.Len(t, res.sinks, 1, "писатель в синтетике узнан ровно один")
			require.Equalf(t, c.verdict, res.sinks[0].verdict, "вердикт %s (%s)", res.sinks[0].verdict, res.sinks[0].why)
			if c.verdict == "finding" {
				require.Contains(t, res.sinks[0].pos, "internal/apps/probe/w.go:", "находка называет координату")
			}
		})
	}
}
