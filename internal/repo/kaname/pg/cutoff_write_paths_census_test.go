// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// cutoff_write_paths_census_test.go — каждый путь записи строки отсечки
// отзыва-всех подан пробам выдачи по отсечке (задача kaname#379).
//
// # Почему перепись, а не выписанный перечень
//
// Пробы выдачи по отсечке (`client_token_revoke_all_integration_test.go`,
// `basic_credential_revoke_all_integration_test.go`) подают отсечку каждым
// путём записи отдельно: читатель, понимающий форму строки одного пути, был бы
// зелен на пробе, подающей только его. Перечень путей, выписанный в пробе
// рукой, этого не держит — путь, заведённый позже и в перечень не внесённый,
// остаётся без пробы молча, а длина выписанного перечня совпадает сама с собой
// при любом дереве.
//
// # Опознаётся СТРОКА, а не имя оператора
//
// Строка — `user_token_revocations`: её читают обе полосы, о которых пробы
// (наш токен-эндпоинт — через `SessionRevocationsAdapter.UserRevokedBefore`,
// полоса базового секрета — соединением в своём операторе). Операция записи —
// оператор, который эту строку ПИШЕТ (`INSERT INTO` либо `UPDATE`), в какой бы
// константе, переменной или литерале он ни стоял и как бы ни назывался.
//
// Прежняя редакция искала операцию по имени. Переименование (kaname#313 свёл
// запись в одну дверь и назвал оператор иначе) сделало перепись пустой: на
// дереве, где пути есть, она не нашла ни одного и упала «не выполнилось».
// Имя — свойство правки, строка — свойство предмета.
//
// Отсечка по ключу семейства (kaname#396) пишет ДРУГУЮ строку —
// `minted_token_revocations`, ключом семейства, а не человека, — и путём этой
// строки не является: полосы, о которых пробы, её не читают.
//
// # Путь — внешний конец цепочки
//
// Оператор исполняет одна функция, её зовёт дверь, дверь зовут методы — по
// одному на исполнителя и вызывающую транзакцию. Путь записи — ВНЕШНИЙ конец
// такой цепочки: метод, либо функция без получателя, которую в пакете никто не
// зовёт. Цепочка прослеживается по имени функции без получателя (в пакете оно
// однозначно). Вызов метода через селектор не прослеживается, и метод, зовущий
// путь так, отдельным путём не считается: его подача — подача того пути.
//
// # Чего перепись не видит — названо
//
//  1. пакеты, кроме этого;
//  2. оператор, собранный во время исполнения (`fmt.Sprintf`, `strings.Join`),
//     и функцию, объявленную литералом в переменной пакета;
//  3. имя функции без получателя, затенённое локальной переменной, считается
//     вызовом функции;
//  4. запись в схеме (триггер) — не Go и здесь не судится.
//
// # Перепись печатает обе величины
//
// «Путей записи по дереву N · подано пробой M». Ноль путей по дереву — не
// «покрыто всё», а «не выполнилось»: обход, не нашедший ни одного пути,
// падает с названной причиной.
package pg_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// cutoffRowTable — строка отсечки, о которой пробы.
const cutoffRowTable = "user_token_revocations"

// cutoffRowWrite — оператор, ПИШУЩИЙ строку: вставка либо изменение, с именем
// схемы и кавычками или без. Таблица с тем же началом имени (`…_archive`) не
// подходит: за именем стоит граница слова либо закрывающая кавычка. Чтение
// (`FROM`, `JOIN`) записью не является.
var cutoffRowWrite = regexp.MustCompile(`(?is)\b(?:INSERT\s+INTO|UPDATE)\s+` +
	`(?:"?kaname"?\s*\.\s*)?(?:"` + cutoffRowTable + `"|` + cutoffRowTable + `\b)`)

// cutoffWriteCensus — объём осмотренного и найденное.
type cutoffWriteCensus struct {
	// parsed — разобрано прод-файлов пакета.
	parsed int
	// ops — объявления пакета (константы, переменные), несущие оператор записи.
	ops []string
	// reach — функций, достигающих записи строки своим оператором или цепочкой.
	reach int
	// paths — пути записи: внешние концы цепочек.
	paths []string
}

// cutoffWritePathsInTree — пути записи строки отсечки в этом пакете и число
// разобранных файлов.
func cutoffWritePathsInTree(t *testing.T) ([]string, int) {
	t.Helper()
	return cutoffWritePathsIn(t, ".")
}

// cutoffWritePathsIn — та же перепись по каталогу dir.
func cutoffWritePathsIn(t *testing.T, dir string) ([]string, int) {
	t.Helper()
	c := cutoffCensusIn(t, dir)
	return c.paths, c.parsed
}

// cutoffFunc — функция пакета и то, что о записи строки видно в её теле.
type cutoffFunc struct {
	path   string
	name   string
	recv   bool
	direct bool
	refs   map[string]struct{}
}

// cutoffCensusIn — перепись путей записи строки отсечки по каталогу пакета dir.
func cutoffCensusIn(t *testing.T, dir string) cutoffWriteCensus {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err, "чтение каталога пакета")
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		require.NoErrorf(t, perr, "разбор %s", name)
		files = append(files, file)
	}

	// Проход 1: строковые объявления пакета. Значение вычисляется склейкой
	// литералов и соседних объявлений — оператор, собранный из частей, пишет
	// строку так же, как написанный целиком.
	declared := map[string]ast.Expr{}
	for _, file := range files {
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, id := range vs.Names {
					if i < len(vs.Values) {
						declared[id.Name] = vs.Values[i]
					}
				}
			}
		}
	}
	values := map[string]string{}
	for changed := true; changed; {
		changed = false
		for name, expr := range declared {
			if _, done := values[name]; done {
				continue
			}
			if s, ok := cutoffStringValue(expr, values); ok {
				values[name] = s
				changed = true
			}
		}
	}
	ops := map[string]struct{}{}
	for name, s := range values {
		if cutoffRowWrite.MatchString(s) {
			ops[name] = struct{}{}
		}
	}

	// Проход 2: функции — пишет ли тело строку своим оператором и какие имена
	// оно называет. Имя за селектором (`x.Name`) именем функции пакета не является.
	var funcs []cutoffFunc
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			f := cutoffFunc{
				path: funcPathName(fn), name: fn.Name.Name,
				recv: fn.Recv != nil && len(fn.Recv.List) > 0,
				refs: map[string]struct{}{},
			}
			selected := map[*ast.Ident]struct{}{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.SelectorExpr:
					selected[x.Sel] = struct{}{}
				case *ast.Ident:
					if _, sel := selected[x]; sel {
						return true
					}
					f.refs[x.Name] = struct{}{}
					if _, op := ops[x.Name]; op {
						f.direct = true
					}
				case *ast.BasicLit:
					f.direct = f.direct || cutoffWritesRow(x, values)
				case *ast.BinaryExpr:
					f.direct = f.direct || cutoffWritesRow(x, values)
				}
				return true
			})
			funcs = append(funcs, f)
		}
	}

	// Цепочка: функция достигает записи, если пишет сама либо называет функцию
	// без получателя, которая её достигает.
	reached := map[string]struct{}{}
	chain := map[string]struct{}{}
	for changed := true; changed; {
		changed = false
		for _, f := range funcs {
			if _, done := reached[f.path]; done {
				continue
			}
			hit := f.direct
			for r := range f.refs {
				if _, ok := chain[r]; ok {
					hit = true
					break
				}
			}
			if !hit {
				continue
			}
			reached[f.path] = struct{}{}
			if !f.recv {
				chain[f.name] = struct{}{}
			}
			changed = true
		}
	}

	// Внешние концы: метод — всегда; функция без получателя — если её не
	// называет никто из достигших.
	outer := map[string]struct{}{}
	for _, f := range funcs {
		if _, ok := reached[f.path]; !ok {
			continue
		}
		called := false
		if !f.recv {
			for _, g := range funcs {
				if _, ok := reached[g.path]; !ok || g.path == f.path {
					continue
				}
				if _, ok := g.refs[f.name]; ok {
					called = true
					break
				}
			}
		}
		if !called {
			outer[f.path] = struct{}{}
		}
	}

	c := cutoffWriteCensus{parsed: len(files), reach: len(reached)}
	for name := range ops {
		c.ops = append(c.ops, name)
	}
	sort.Strings(c.ops)
	c.paths = make([]string, 0, len(outer))
	for p := range outer {
		c.paths = append(c.paths, p)
	}
	sort.Strings(c.paths)
	return c
}

// cutoffWritesRow — выражение есть оператор, пишущий строку отсечки.
func cutoffWritesRow(e ast.Expr, values map[string]string) bool {
	s, ok := cutoffStringValue(e, values)
	return ok && cutoffRowWrite.MatchString(s)
}

// cutoffStringValue — значение строкового выражения, известное до исполнения:
// литерал, склейка, скобки, имя уже вычисленного объявления.
func cutoffStringValue(e ast.Expr, values map[string]string) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		return s, err == nil
	case *ast.ParenExpr:
		return cutoffStringValue(x.X, values)
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, lok := cutoffStringValue(x.X, values)
		r, rok := cutoffStringValue(x.Y, values)
		return l + r, lok && rok
	case *ast.Ident:
		s, ok := values[x.Name]
		return s, ok
	}
	return "", false
}

// funcPathName — «Получатель.Метод» либо имя функции без получателя.
func funcPathName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	typ := fn.Recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	switch g := typ.(type) {
	case *ast.IndexExpr:
		typ = g.X
	case *ast.IndexListExpr:
		typ = g.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// fedCutoffWritePaths — пути записи, которые подаёт проба выдачи по отсечке.
func fedCutoffWritePaths() []string {
	seen := map[string]struct{}{}
	for _, w := range revokeAllWritersUnderTest() {
		seen[w.path] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// TestRevokeAllProbeFeedsEveryWritePathOfTheCutoffRow — перепись путей записи
// по дереву против путей, которые подаёт проба. Расхождение в любую сторону —
// находка: путь без пробы молчит о своей форме строки, а запись пробы о пути,
// которого нет, — исключение, пережившее свой предмет.
func TestRevokeAllProbeFeedsEveryWritePathOfTheCutoffRow(t *testing.T) {
	c := cutoffCensusIn(t, ".")
	require.NotZerof(t, c.parsed, "не разобран ни один файл пакета — перепись не выполнилась")
	require.NotEmptyf(t, c.paths,
		"по дереву не найдено ни одного пути записи строки %s (объявлений оператора записи %d, "+
			"функций, достигающих записи, %d) среди %d файлов — перепись не выполнилась, это не «покрыто всё»",
		cutoffRowTable, len(c.ops), c.reach, c.parsed)

	fed := fedCutoffWritePaths()
	fedSet := map[string]struct{}{}
	for _, p := range fed {
		fedSet[p] = struct{}{}
	}
	treeSet := map[string]struct{}{}
	for _, p := range c.paths {
		treeSet[p] = struct{}{}
	}
	var unfed, stale []string
	for _, p := range c.paths {
		if _, ok := fedSet[p]; !ok {
			unfed = append(unfed, p)
		}
	}
	for _, p := range fed {
		if _, ok := treeSet[p]; !ok {
			stale = append(stale, p)
		}
	}
	t.Logf("перепись: файлов разобрано %d · объявлений оператора записи строки %s %d %v · "+
		"функций, достигающих записи, %d · путей записи по дереву %d · подано пробой %d",
		c.parsed, cutoffRowTable, len(c.ops), c.ops, c.reach, len(c.paths), len(fed))
	if len(unfed) > 0 {
		t.Errorf("пути записи строки отсечки без пробы выдачи по отсечке: %v", unfed)
	}
	if len(stale) > 0 {
		t.Errorf("проба подаёт пути записи, которых в дереве нет: %v", stale)
	}
}
