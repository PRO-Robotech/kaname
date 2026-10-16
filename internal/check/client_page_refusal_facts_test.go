// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"html"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// Факты об отказах на клиентских страницах службы, которые выводятся из
// производителей, а не выписываются (задачи kaname#719, kaname#757).
//
//   - строка `403` таблицы статусов `rest-surface.mdx` называла одну причину
//     («доступ к объекту не выдан»), а служба отдаёт `403` ещё на несвежую
//     сессию, неподтверждённый адрес и признак формы (kaname#719). Таблица
//     причин сверяется с признаками, которые производители `403` дерева
//     приписывают отказу, — в обе стороны;
//   - отказ свежести на двух страницах службы обязан быть одним: тот же
//     `message`, тот же признак (kaname#719, FSR-07);
//   - утверждение ключа доступа принимают две поверхности с разной формой, кодом
//     и судьбой испытания, и различие не было объявлено (kaname#757, AKS-10).
//     Таблица различия сверяется с константами отказа и с полями сообщения
//     `AssertionCredential`.
//
// # ГРАНИЦА
//
// Судятся СОСТАВ и ДОСЛОВНОСТЬ таблиц, а не верность прозы вокруг них. Перечень
// производителей `403` выводится разбором Go двумя формами записи, которые есть
// в дереве: вызов, в аргументах которого стоят и код `403`, и признак; функция
// одного кода `403`, собирающая `ErrorInfo{Reason: …}`. Признак, который
// производитель берёт ПАРАМЕТРОМ из третьего места, этот разбор не видит —
// перепись печатает, сколько вызовов и функций прочитано.
const (
	refusalFactsRestSurfaceRel = "docs/content/api/rest-surface.mdx"
	refusalFactsAuthLaneRel    = "docs/content/api/auth-lane.mdx"

	// forbiddenReasonsAnchor — якорь таблицы причин `403`; на него ссылаются
	// строка `403` таблицы статусов и страница полосы входа.
	forbiddenReasonsAnchor = "{#forbidden-reasons}"
	// assertionSurfacesAnchor — якорь таблицы различия поверхностей утверждения.
	assertionSurfacesAnchor = "{#assertion-surfaces}"

	refusalFactsModule = "github.com/PRO-Robotech/kaname"
)

// refusalFactsRow — строка таблицы страницы: ячейки в порядке появления.
var refusalFactsRow = regexp.MustCompile(`(?s)<tr>(.*?)</tr>`)

// refusalFactsCell — ячейка строки (`td` либо `th`).
var refusalFactsCell = regexp.MustCompile(`(?s)<t[dh]>(.*?)</t[dh]>`)

// refusalFactsCode — код-форматирование внутри ячейки.
var refusalFactsCode = regexp.MustCompile(`<code>([^<]*)</code>`)

// reasonToken — форма признака `ErrorInfo.reason`: заглавные слова через `_`.
var reasonToken = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`)

// sectionAfter — текст страницы от якоря до следующего заголовка того же или
// более высокого уровня; ok=false — якоря нет.
func sectionAfter(page, anchor string) (string, int, bool) {
	n := strings.Count(page, anchor)
	at := strings.Index(page, anchor)
	if at < 0 {
		return "", 0, false
	}
	head := page[strings.LastIndex(page[:at], "\n")+1 : at]
	level := len(head) - len(strings.TrimLeft(head, "#"))
	rest := page[at+len(anchor):]
	for _, line := range regexp.MustCompile(`\n#{1,`+strconv.Itoa(level)+`} `).FindAllStringIndex(rest, 1) {
		rest = rest[:line[0]]
	}
	return rest, n, true
}

// tableRows — строки таблиц текста; каждая — ячейки с разметкой.
func tableRows(text string) [][]string {
	var out [][]string
	for _, r := range refusalFactsRow.FindAllStringSubmatch(text, -1) {
		var cells []string
		for _, c := range refusalFactsCell.FindAllStringSubmatch(r[1], -1) {
			cells = append(cells, strings.TrimSpace(c[1]))
		}
		out = append(out, cells)
	}
	return out
}

// codesIn — содержимое код-форматирования ячейки, сущности раскрыты.
func codesIn(cell string) []string {
	var out []string
	for _, m := range refusalFactsCode.FindAllStringSubmatch(cell, -1) {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

func hasCode(cell, want string) bool {
	for _, c := range codesIn(cell) {
		if c == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Производители `403`: признаки, выведенные разбором Go.

// forbiddenCensus — объём осмотренного обходом. Печатается всегда.
type forbiddenCensus struct {
	files     int // файлов Go прочитано
	consts    int // строковых констант формы признака
	calls     int // вызовов с кодом 403 и признаком в аргументах
	functions int // функций одного кода 403 с ErrorInfo{Reason: …}
}

type goConst struct {
	value string // значение, если литерал
	ref   string // ключ константы, на которую ссылается, если не литерал
}

// forbiddenReasonProducers — признаки, которые производители `403` дерева
// приписывают отказу, с координатой первого производителя каждого.
func forbiddenReasonProducers(root string, dirs []string) (map[string]string, forbiddenCensus, error) {
	type parsed struct {
		file    *ast.File
		pkgPath string
		path    string
	}
	var files []parsed
	pkgName := map[string]string{} // путь импорта → имя пакета
	fset := token.NewFileSet()
	for _, d := range dirs {
		base := filepath.Join(root, d)
		if _, err := os.Stat(base); err != nil {
			continue
		}
		err := filepath.WalkDir(base, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.IsDir() {
				if n := e.Name(); n == "testdata" || n == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, p, nil, 0)
			if perr != nil {
				return perr
			}
			rel, _ := filepath.Rel(root, filepath.Dir(p))
			pp := refusalFactsModule + "/" + filepath.ToSlash(rel)
			pkgName[pp] = f.Name.Name
			files = append(files, parsed{file: f, pkgPath: pp, path: p})
			return nil
		})
		if err != nil {
			return nil, forbiddenCensus{}, err
		}
	}
	census := forbiddenCensus{files: len(files)}

	// Имена импортов файла: псевдоним либо имя пакета → путь.
	importsOf := func(f *ast.File) map[string]string {
		m := map[string]string{}
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			name := pkgName[p]
			if name == "" {
				name = p[strings.LastIndex(p, "/")+1:]
			}
			if im.Name != nil {
				name = im.Name.Name
			}
			m[name] = p
		}
		return m
	}
	// keyOf — ключ константы, названной выражением, в контексте файла.
	keyOf := func(e ast.Expr, pkgPath string, imports map[string]string) string {
		switch x := e.(type) {
		case *ast.Ident:
			return pkgPath + "." + x.Name
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok {
				if p, ok := imports[id.Name]; ok {
					return p + "." + x.Sel.Name
				}
			}
		}
		return ""
	}

	consts := map[string]goConst{}
	for _, pf := range files {
		imports := importsOf(pf.file)
		for _, decl := range pf.file.Decls {
			g, ok := decl.(*ast.GenDecl)
			if !ok || g.Tok != token.CONST {
				continue
			}
			for _, spec := range g.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					key := pf.pkgPath + "." + name.Name
					switch v := vs.Values[i].(type) {
					case *ast.BasicLit:
						if v.Kind == token.STRING {
							s, _ := strconv.Unquote(v.Value)
							consts[key] = goConst{value: s}
						}
					default:
						if k := keyOf(v, pf.pkgPath, imports); k != "" {
							consts[key] = goConst{ref: k}
						}
					}
				}
			}
		}
	}
	resolve := func(key string) (string, bool) {
		for i := 0; i < 8 && key != ""; i++ {
			c, ok := consts[key]
			if !ok {
				return "", false
			}
			if c.ref == "" {
				return c.value, true
			}
			key = c.ref
		}
		return "", false
	}
	for k := range consts {
		if v, ok := resolve(k); ok && reasonToken.MatchString(v) {
			census.consts++
		}
	}

	// is403 / isCode — маркеры кода: `codes.<имя>` и `http.Status<имя>`.
	codeOf := func(e ast.Node, imports map[string]string) (string, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		switch imports[id.Name] {
		case "google.golang.org/grpc/codes":
			return sel.Sel.Name, true
		case "net/http":
			if strings.HasPrefix(sel.Sel.Name, "Status") {
				return sel.Sel.Name, true
			}
		}
		return "", false
	}
	is403 := func(name string) bool { return name == "PermissionDenied" || name == "StatusForbidden" }

	found := map[string]string{}
	note := func(reason, where string) {
		if _, ok := found[reason]; !ok {
			found[reason] = where
		}
	}
	reasonRef := func(e ast.Node, pkgPath string, imports map[string]string) (string, bool) {
		ex, ok := e.(ast.Expr)
		if !ok {
			return "", false
		}
		k := keyOf(ex, pkgPath, imports)
		if k == "" {
			return "", false
		}
		v, ok := resolve(k)
		return v, ok && reasonToken.MatchString(v)
	}

	for _, pf := range files {
		imports := importsOf(pf.file)
		rel, _ := filepath.Rel(root, pf.path)
		where := func(n ast.Node) string {
			return fmt.Sprintf("%s:%d", filepath.ToSlash(rel), fset.Position(n.Pos()).Line)
		}
		// Форма 1: вызов, в аргументах которого стоят код 403 и признак.
		ast.Inspect(pf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			has403 := false
			var reasons []string
			for _, a := range call.Args {
				ast.Inspect(a, func(m ast.Node) bool {
					if _, nested := m.(*ast.CallExpr); nested && m != a {
						return false // вложенный вызов судится сам
					}
					if name, ok := codeOf(m, imports); ok && is403(name) {
						has403 = true
					}
					if r, ok := reasonRef(m, pf.pkgPath, imports); ok {
						reasons = append(reasons, r)
					}
					return true
				})
			}
			if has403 && len(reasons) > 0 {
				census.calls++
				for _, r := range reasons {
					note(r, where(call))
				}
			}
			return true
		})
		// Форма 2: функция ОДНОГО кода 403, собирающая ErrorInfo{Reason: …}.
		for _, decl := range pf.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			only403, any403 := true, false
			var reasons []string
			ast.Inspect(fn.Body, func(m ast.Node) bool {
				if name, ok := codeOf(m, imports); ok {
					if is403(name) {
						any403 = true
					} else {
						only403 = false
					}
				}
				if kv, ok := m.(*ast.KeyValueExpr); ok {
					if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Reason" {
						if r, ok := reasonRef(kv.Value, pf.pkgPath, imports); ok {
							reasons = append(reasons, r)
						}
					}
				}
				return true
			})
			if any403 && only403 && len(reasons) > 0 {
				census.functions++
				for _, r := range reasons {
					note(r, where(fn))
				}
			}
		}
	}
	return found, census, nil
}

// forbiddenReasonsOnPage — признаки первой ячейки таблицы причин и строки без
// признака (по тексту первой ячейки).
func forbiddenReasonsOnPage(page string) (reasons map[string][]string, findings []string) {
	section, n, ok := sectionAfter(page, forbiddenReasonsAnchor)
	if !ok {
		return nil, []string{fmt.Sprintf("на странице %s нет таблицы причин `403` (якорь %s) — "+
			"строка 403 таблицы статусов не может на неё сослаться", refusalFactsRestSurfaceRel, forbiddenReasonsAnchor)}
	}
	if n != 1 {
		findings = append(findings, fmt.Sprintf("якорь %s стоит на странице %d раз — таблица причин обязана быть одна",
			forbiddenReasonsAnchor, n))
	}
	reasons = map[string][]string{}
	for _, cells := range tableRows(section) {
		if len(cells) == 0 || strings.Contains(cells[0], "reason") {
			continue // шапка
		}
		for _, c := range codesIn(cells[0]) {
			if reasonToken.MatchString(c) {
				reasons[c] = cells
			}
		}
	}
	return reasons, findings
}

// auditForbiddenReasons — таблица причин против производителей, в обе стороны.
func auditForbiddenReasons(page string, produced map[string]string) []string {
	reasons, findings := forbiddenReasonsOnPage(page)
	if reasons == nil {
		return findings
	}
	for _, r := range sortedKeys(func() map[string]bool {
		m := map[string]bool{}
		for k := range produced {
			m[k] = true
		}
		return m
	}()) {
		if _, ok := reasons[r]; !ok {
			findings = append(findings, fmt.Sprintf("признак %s служба приписывает отказу 403 (%s), а таблица "+
				"причин на странице %s его не называет — клиент прочтёт этот 403 как «права не выданы»",
				r, produced[r], refusalFactsRestSurfaceRel))
		}
	}
	for r := range reasons {
		if _, ok := produced[r]; !ok {
			findings = append(findings, fmt.Sprintf("строка таблицы причин называет признак %s, а ни один "+
				"производитель 403 службы его не приписывает — строка пережила предмет либо выдумана", r))
		}
	}
	if !strings.Contains(page, "#forbidden-reasons") {
		findings = append(findings, "строка 403 таблицы статусов не ссылается на таблицу причин (#forbidden-reasons)")
	}
	sort.Strings(findings)
	return findings
}

// TestForbiddenReasonsTableMatchesTheProducers — FSR-06: таблица причин `403`
// полна и не шире производителей.
func TestForbiddenReasonsTableMatchesTheProducers(t *testing.T) {
	root := platformtree.Require(t)
	produced, census, err := forbiddenReasonProducers(root, []string{"internal", "cmd"})
	require.NoError(t, err)
	t.Logf("перепись: файлов Go %d · констант формы признака %d · вызовов 403 с признаком %d · "+
		"функций одного кода 403 с признаком %d · признаков %d %v",
		census.files, census.consts, census.calls, census.functions, len(produced), sortedKeys(func() map[string]bool {
			m := map[string]bool{}
			for k := range produced {
				m[k] = true
			}
			return m
		}()))
	require.Positive(t, census.files, "обход не прочёл ни одного файла Go — судить не о чем")
	require.NotEmpty(t, produced, "предпосылка разбора: в дереве есть производители 403 с признаком "+
		"(проверка свежести ключей доступа) — ноль значит, что разбор ослеп, а не что их нет")

	page, err := os.ReadFile(platformtree.RequirePath(t, refusalFactsRestSurfaceRel)) // #nosec G304 -- путь собран из корня собственного модуля
	require.NoError(t, err)
	require.Empty(t, auditForbiddenReasons(string(page), produced))
}

// TestForbiddenReasonsInjection — FSR-06 близнецы: производитель с новым
// признаком без строки — красное с признаком; строка без производителя —
// красное с признаком; производитель того же вида с кодом не 403 — молчание.
func TestForbiddenReasonsInjection(t *testing.T) {
	dir := t.TempDir()
	src := func(code string) string {
		return `package x

import (
	"net/http"

	"google.golang.org/grpc/codes"
)

const ReasonInjected = "INJECTED_REASON"

func withReason(c codes.Code, reason, text string) error { return nil }

func writeRefusal(w any, status int, info any) {}

type errorInfo struct{ Reason string }

func a() error { return withReason(codes.` + code + `, ReasonInjected, "t") }

func b() { writeRefusal(nil, http.StatusForbidden, &errorInfo{Reason: "x"}) }
`
	}
	write := func(code string) {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "internal", "x"), 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "internal", "x", "x.go"), []byte(src(code)), 0o600))
	}
	page := "## Причины\n\n### Причины `403` " + forbiddenReasonsAnchor + "\n\n<table>\n" +
		"<tr><th><code>reason</code></th><th>когда</th></tr>\n" +
		"<tr><td><code>KNOWN_REASON</code></td><td>…</td></tr>\n</table>\n\n## Дальше\n" +
		"<tr><td><code>403</code></td><td><a href=\"#forbidden-reasons\">причины</a></td></tr>\n"

	write("PermissionDenied")
	produced, census, err := forbiddenReasonProducers(dir, []string{"internal"})
	require.NoError(t, err)
	require.Equal(t, 1, census.calls, "вызов с кодом 403 и признаком прочитан")
	require.Contains(t, produced, "INJECTED_REASON")
	produced["KNOWN_REASON"] = "известный производитель"
	got := strings.Join(auditForbiddenReasons(page, produced), "\n")
	require.Contains(t, got, "признак INJECTED_REASON служба приписывает отказу 403")

	delete(produced, "INJECTED_REASON")
	delete(produced, "KNOWN_REASON")
	got = strings.Join(auditForbiddenReasons(page, produced), "\n")
	require.Contains(t, got, "называет признак KNOWN_REASON, а ни один производитель")

	write("InvalidArgument")
	produced, _, err = forbiddenReasonProducers(dir, []string{"internal"})
	require.NoError(t, err)
	require.NotContains(t, produced, "INJECTED_REASON", "код не 403 — не производитель причины 403")

	produced = map[string]string{"KNOWN_REASON": "известный"}
	require.Empty(t, auditForbiddenReasons(page, produced), "законный близнец: таблица равна производителям")
	require.Contains(t, strings.Join(auditForbiddenReasons(strings.ReplaceAll(page, forbiddenReasonsAnchor, ""), produced), "\n"),
		"нет таблицы причин")
}

// ---------------------------------------------------------------------------
// FSR-07: отказ свежести на двух страницах — один.

// freshnessRowOf — строка таблицы отказов полосы входа с признаком reason.
func refusalRowWithReason(page, reason string) []string {
	for _, cells := range tableRows(page) {
		for _, c := range cells {
			if hasCode(c, reason) {
				return cells
			}
		}
	}
	return nil
}

func auditFreshnessAgreement(restSurface, authLane string) []string {
	var findings []string
	reasons, f := forbiddenReasonsOnPage(restSurface)
	findings = append(findings, f...)
	row := reasons[humansession.ReasonSessionNotFresh]
	if row == nil {
		return append(findings, "таблица причин 403 не называет SESSION_NOT_FRESH")
	}
	if !strings.Contains(strings.Join(row, " "), "<code>"+humansession.TextSessionNotFresh+"</code>") {
		findings = append(findings, fmt.Sprintf("строка SESSION_NOT_FRESH таблицы причин не несёт текст %q дословно",
			humansession.TextSessionNotFresh))
	}
	lane := refusalRowWithReason(authLane, humansession.ReasonSessionNotFresh)
	switch {
	case lane == nil:
		findings = append(findings, "таблица отказов полосы входа не называет SESSION_NOT_FRESH")
	case len(lane) < 3 || lane[0] != "403" || lane[1] != "7" || !hasCode(lane[2], humansession.TextSessionNotFresh):
		findings = append(findings, fmt.Sprintf("строка SESSION_NOT_FRESH таблицы отказов полосы входа — %q, "+
			"а не 403 · 7 · %q, как в таблице причин", lane, humansession.TextSessionNotFresh))
	}
	for _, want := range []string{"](/api/rest-surface#forbidden-reasons)", "<a href=\"/api/rest-surface#forbidden-reasons\">"} {
		if strings.Contains(authLane, want) {
			return findings
		}
	}
	return append(findings, "страница полосы входа не ссылается на таблицу причин 403 (/api/rest-surface#forbidden-reasons)")
}

// TestFreshnessRefusalAgreesOnBothPages — FSR-07.
func TestFreshnessRefusalAgreesOnBothPages(t *testing.T) {
	// Предпосылка: у отказа свежести два производителя с одним текстом и признаком.
	require.Equal(t, humansession.TextSessionNotFresh, access_keys.TextSessionNotFresh)
	require.Equal(t, humansession.ReasonSessionNotFresh, access_keys.ReasonSessionNotFresh)

	rs, err := os.ReadFile(platformtree.RequirePath(t, refusalFactsRestSurfaceRel)) // #nosec G304 -- путь собран из корня собственного модуля
	require.NoError(t, err)
	al, err := os.ReadFile(platformtree.RequirePath(t, refusalFactsAuthLaneRel)) // #nosec G304 -- путь собран из корня собственного модуля
	require.NoError(t, err)
	require.Empty(t, auditFreshnessAgreement(string(rs), string(al)))
}
