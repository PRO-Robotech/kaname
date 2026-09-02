// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// ids_fixture_form_test.go — ГЕЙТ по дереву: фикстура пробы не снисходительнее
// продукта в том, что касается формы СОБСТВЕННОГО идентификатора.
//
// # ЧТО ОН ДЕРЖИТ
//
// `e2e-flow.md` §5 требует, чтобы подстановка выполняла контракт настоящего:
// фикстура, принимающая вход, на котором продукт отвечает отказом, делает
// невидимым ровно тот дефект, ради которого её подставляют. Здесь предмет —
// ФОРМА идентификатора: строгая проверка `ValidateResourceID` (ids.go) судит
// префикс И длину, а фикстуры годами пользовались идентификаторами, которые
// продукт не может ни отчеканить, ни принять (`sva_test`, `usr_alice`,
// `prj-1`). Пока ни одна проверка длины не стояла на пути, согласие пробы с
// продуктом было СЛЕДСТВИЕМ ОБЩЕГО ДЕФЕКТА, а не свидетельством правоты:
// ужесточение проверки в ОДНОМ месте (задача #1791) уронило 39 проб, ни одна из
// которых про формат не была.
//
// # ГЕЙТ ЗОВЁТ ПРОВЕРКУ ПРОДУКТА, А НЕ СВОЮ КОПИЮ
//
// Вердикт выносит `shared.ValidateResourceID` — та самая функция, которую зовёт
// прод-код. Копия предиката разошлась бы с продуктом молча, и это был бы ровно
// тот класс, который гейт ловит. Поэтому гейт и живёт в дереве сервиса: из
// `internal/repohygiene` пакет `services/iam/internal/...` недостижим by
// construction (правило Go про `internal`), и вердикт пришлось бы выписывать
// копией.
//
// # ОХВАТ ВЫВЕДЕН ИЗ ПРОДУКТА, А НЕ ОБЪЯВЛЕН СПИСКОМ
//
// Судятся пробы тех пакетов, чей ПРОД-КОД сам зовёт строгую проверку. Там
// расхождение фикстуры с продуктом доказуемо: одна и та же форма в одном пакете
// объявлена обязательной кодом и нарушена пробой. Список пакетов не
// выписывается — он собирается обходом (второе место об одном предмете
// разошлось бы с деревом молча) и растёт САМ: пакет, начавший судить форму,
// немедленно приводит с собой и требование к своим фикстурам. Именно это и
// снимает класс #1791 — ужесточение проверки перестаёт ронять чужие пробы.
//
// Литералы в пакетах ВНЕ охвата считаются и печатаются переписью отдельной
// строкой: «ноль находок» обязано быть отличимо от «ноль осмотренного», а
// величина, которую никто не назвал, не перестаёт существовать оттого, что её
// не судят. Предмет этого остатка заведён задачей продукта #1809.
//
// # ЧТО СЧИТАЕТСЯ ПОЗИЦИЕЙ СОБСТВЕННОГО ИДЕНТИФИКАТОРА
//
// Четыре формы записи, и распознаватель обязан знать ВСЕ (testing.md §«Гейт на
// класс», п. 7): поле составного литерала · объявление const/var · присваивание
// · приведение к типу-идентификатору. Форма, о которой распознаватель не знает,
// не редкость, а СЛЕПАЯ ЗОНА — в ней не бывает ни красного, ни зелёного.
//
// Позицию отличает ИМЯ (поля, переменной, типа), а значение обязано ЗАЯВЛЯТЬ
// собственный идентификатор — то есть начинаться с префикса, объявленного в
// собственном пакете domain, и нести за ним хоть что-то. Обе половины нужны:
// поиск по одному имени префикса уже пробовали, и он провалил контроль в обе
// стороны — из 3611 «попаданий» 524 были обычным словом (`account`,
// `access_token`), а 47 — самой константой префикса.
//
// # НАМЕРЕННО НЕГОДНЫЙ ЛИТЕРАЛ ПОМЕЧАЕТСЯ, И ПОМЕТКА ИСТЕКАЕТ САМА
//
// Проба, утверждающая, что негодная форма ОТВЕРГАЕТСЯ, обязана негодную форму
// предъявить. Такой литерал помечается комментарием `негодная форма id
// намеренно: <причина>` на своей строке или строкой выше. Пометка на литерале,
// который проверку ПРОХОДИТ, — находка: исключению нечего исключать.
//
// # ОСТАТОК ЗАПИСАН ТОЧНЫМ ЧИСЛОМ, А НЕ ПОТОЛКОМ
//
// Пакет, чьи фикстуры ещё не приведены к форме, стоит в ведомости с ТОЧНЫМ
// числом. Расхождение в любую сторону — находка: потолок не покраснел бы
// никогда и потому не истёк бы сам.
//
// Печатает объём осмотренного и падает на пустом обходе. Способность падать и
// молчать доказана инъекцией в обе стороны (ids_fixture_form_injection_test.go).
package shared_test

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

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
)

// deliberateBadFormMark — пометка намеренно негодного литерала. Текст
// объявлен ОДИН раз: инъекция берёт его отсюда же, поэтому «пометка распознана»
// доказывается на том же анкере, что исполняется на дереве.
const deliberateBadFormMark = "негодная форма id намеренно"

// fixtureFormLedger — ОСТАТОК: пакет (путь от корня сервиса) → ТОЧНОЕ число
// литералов, ещё не приведённых к форме. Не потолок: расхождение в любую
// сторону — находка, поэтому запись истекает сама, как только остаток убран.
//
// Каждая запись обязана нести причину и предмет, которым она снимается.
var fixtureFormLedger = map[string]int{
	// Пакет несёт 77 файлов проб и около 180 РАЗЛИЧНЫХ негодных значений,
	// вплетённых в ожидаемые строки, кортежи прав и посевы репозитория. Замена
	// их одним заходом — механическая правка 282 мест с риском того же класса,
	// что уже наблюдался при закрытии #1791: старое значение сидит ВНУТРИ
	// ожидаемой строки, и подстановка ломает утверждение, ничего не сказав.
	//
	// Снимается своим изменением (задача продукта #1809): привести значения к
	// форме и удалить эту строку. Пока она стоит, класс в пакете не РАСТЁТ —
	// новая негодная фикстура сдвигает число и краснит гейт.
	"internal/apps/kacho/api/access_binding": 282,
}

// idPositionForm — форма записи позиции собственного идентификатора. Перечень
// закрыт и назван: перепись печатает его поимённо, поэтому расширение
// распознавателя ВИДНО числом, а не только на словах.
type idPositionForm string

const (
	formField  idPositionForm = "поле"
	formDecl   idPositionForm = "объявление"
	formAssign idPositionForm = "присваивание"
	formConv   idPositionForm = "приведение"
)

// idPositionForms — порядок печати переписи.
var idPositionForms = []idPositionForm{formField, formDecl, formAssign, formConv}

// fixtureLiteral — литерал в позиции собственного идентификатора вместе со
// всем, что нужно и вердикту, и переписи.
type fixtureLiteral struct {
	Path   string
	Line   int
	Form   idPositionForm
	Name   string
	Value  string
	Prefix string
	Marked bool
}

// fixtureFormCensus — перепись обхода. Печатается ВСЕГДА и до вердикта.
type fixtureFormCensus struct {
	TestFiles    int
	StringLits   int
	IDPositions  int
	Claims       int
	ByForm       map[idPositionForm]int
	ScopePkgs    []string
	Prefixes     []string
	InScopeBad   int
	OutOfBad     int
	Marked       int
	ByPackage    map[string]int
	Findings     []string
	StaleMarks   []string
	LedgerErrors []string
}

// collectPrefixValues собирает ЗНАЧЕНИЯ констант-префиксов собственного пакета
// domain. Владение выводится из дерева — перечня литералов здесь нет, иначе он
// стал бы вторым местом об одном предмете.
func collectPrefixValues(files []sourceFile) map[string]string {
	out := map[string]string{}
	for _, sf := range files {
		if sf.AST.Name == nil || sf.AST.Name.Name != "domain" {
			continue
		}
		for _, decl := range sf.AST.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, n := range vs.Names {
					if !strings.HasPrefix(n.Name, prefixConstPrefix) || n.Name == prefixConstPrefix {
						continue
					}
					if i >= len(vs.Values) {
						continue
					}
					bl, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || bl.Kind != token.STRING {
						continue
					}
					v, err := strconv.Unquote(bl.Value)
					if err != nil || v == "" {
						continue
					}
					out[n.Name] = v
				}
			}
		}
	}
	return out
}

// collectStrictScope собирает каталоги, чей ПРОД-код зовёт строгую проверку.
// Именно они и есть охват: там форма объявлена обязательной самим продуктом.
func collectStrictScope(files []sourceFile) map[string]struct{} {
	scope := map[string]struct{}{}
	for _, sf := range files {
		ast.Inspect(sf.AST, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isStrictValidatorCall(sf.AST, call) {
				return true
			}
			scope[filepath.ToSlash(filepath.Dir(sf.Path))] = struct{}{}
			return true
		})
	}
	return scope
}

// isIDName сообщает, что имя обозначает идентификатор ресурса. Три законных
// написания в этом дереве: Go-конвенция `…ID`, сгенерированное proto-поле `…Id`
// и колонка/ключ `…_id`; плюс само слово в любом регистре.
func isIDName(name string) bool {
	switch name {
	case "", "_":
		return false
	case "id", "ID", "Id":
		return true
	}
	return strings.HasSuffix(name, "ID") ||
		strings.HasSuffix(name, "Id") ||
		strings.HasSuffix(name, "_id")
}

// claimedPrefix возвращает префикс, который литерал ЗАЯВЛЯЕТ, и признак заявки.
// Заявкой считается префикс ПЛЮС хоть один символ за ним: голая константа
// префикса идентификатором не притворяется, и считать её находкой значило бы
// повторить предикат, уже проваливший контроль.
func claimedPrefix(value string, prefixes []string) (string, bool) {
	for _, p := range prefixes {
		if len(value) > len(p) && strings.HasPrefix(value, p) {
			return p, true
		}
	}
	return "", false
}

// markedLines собирает номера строк, накрытых пометкой намеренно негодной формы:
// сама строка комментария и строка сразу под ним (комментарий-объяснение стоит
// либо в хвосте строки, либо над ней).
func markedLines(fset *token.FileSet, f *ast.File) map[int]struct{} {
	out := map[int]struct{}{}
	for _, grp := range f.Comments {
		if !strings.Contains(grp.Text(), deliberateBadFormMark) {
			continue
		}
		start := fset.Position(grp.Pos()).Line
		end := fset.Position(grp.End()).Line
		for l := start; l <= end+1; l++ {
			out[l] = struct{}{}
		}
	}
	return out
}

// collectIDPositions — распознаватель позиций. Четыре формы записи; каждая
// доказана инъекцией отдельно.
func collectIDPositions(fset *token.FileSet, path string, f *ast.File, c *fixtureFormCensus) []fixtureLiteral {
	var out []fixtureLiteral
	marks := markedLines(fset, f)

	strLit := func(e ast.Expr) *ast.BasicLit {
		bl, ok := e.(*ast.BasicLit)
		if ok && bl.Kind == token.STRING {
			return bl
		}
		return nil
	}
	add := func(form idPositionForm, name string, bl *ast.BasicLit) {
		if !isIDName(name) {
			return
		}
		v, err := strconv.Unquote(bl.Value)
		if err != nil {
			return
		}
		line := fset.Position(bl.Pos()).Line
		_, marked := marks[line]
		c.IDPositions++
		c.ByForm[form]++
		out = append(out, fixtureLiteral{
			Path: path, Line: line, Form: form, Name: name, Value: v, Marked: marked,
		})
	}

	ast.Inspect(f, func(n ast.Node) bool {
		if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			c.StringLits++
		}
		switch t := n.(type) {
		case *ast.KeyValueExpr: // поле составного литерала: `Input{UserID: "…"}`
			if bl := strLit(t.Value); bl != nil {
				if key, ok := t.Key.(*ast.Ident); ok {
					add(formField, key.Name, bl)
				}
			}
		case *ast.ValueSpec: // объявление: `const userID = "…"`
			for i, v := range t.Values {
				if bl := strLit(v); bl != nil && i < len(t.Names) {
					add(formDecl, t.Names[i].Name, bl)
				}
			}
		case *ast.AssignStmt: // присваивание: `in.UserID = "…"` / `userID := "…"`
			for i, r := range t.Rhs {
				bl := strLit(r)
				if bl == nil || i >= len(t.Lhs) {
					continue
				}
				switch lhs := t.Lhs[i].(type) {
				case *ast.Ident:
					add(formAssign, lhs.Name, bl)
				case *ast.SelectorExpr:
					add(formAssign, lhs.Sel.Name, bl)
				}
			}
		case *ast.CallExpr: // приведение к типу-идентификатору: `domain.UserID("…")`
			if len(t.Args) != 1 {
				return true
			}
			bl := strLit(t.Args[0])
			if bl == nil {
				return true
			}
			switch fn := t.Fun.(type) {
			case *ast.SelectorExpr:
				add(formConv, fn.Sel.Name, bl)
			case *ast.Ident:
				add(formConv, fn.Name, bl)
			}
		}
		return true
	})
	return out
}

// inspectFixtureForm — ТЕЛО гейта. Чистая функция над разобранными деревьями:
// инъекция зовёт ровно её, поэтому доказательство относится к тому, что
// исполняется на дереве.
func inspectFixtureForm(prod []sourceFile, tests []testFile, serviceDir string, ledger map[string]int) fixtureFormCensus {
	c := fixtureFormCensus{
		TestFiles: len(tests),
		ByForm:    map[idPositionForm]int{},
		ByPackage: map[string]int{},
	}

	prefixByName := collectPrefixValues(prod)
	for _, v := range prefixByName {
		c.Prefixes = append(c.Prefixes, v)
	}
	// Длинный префикс — первым: `cond` не должен разбираться как `con`+`d`.
	sort.Slice(c.Prefixes, func(i, j int) bool {
		if len(c.Prefixes[i]) != len(c.Prefixes[j]) {
			return len(c.Prefixes[i]) > len(c.Prefixes[j])
		}
		return c.Prefixes[i] < c.Prefixes[j]
	})

	scope := collectStrictScope(prod)
	for d := range scope {
		c.ScopePkgs = append(c.ScopePkgs, rel(serviceDir, d))
	}
	sort.Strings(c.ScopePkgs)

	for _, tf := range tests {
		for _, lit := range collectIDPositions(tf.FSet, tf.Path, tf.AST, &c) {
			prefix, claims := claimedPrefix(lit.Value, c.Prefixes)
			if !claims {
				continue
			}
			c.Claims++
			lit.Prefix = prefix
			// Вердикт выносит ПРОДУКТ, а не копия предиката.
			ok := shared.ValidateResourceID(lit.Value, prefix, "id") == nil
			dir := filepath.ToSlash(filepath.Dir(lit.Path))
			_, inScope := scope[dir]
			if !inScope {
				if !ok {
					c.OutOfBad++
				}
				continue
			}
			if !ok {
				c.InScopeBad++
			}
			where := fmt.Sprintf("%s:%d: %s %s = %q", rel(serviceDir, lit.Path), lit.Line, lit.Form, lit.Name, lit.Value)
			if lit.Marked {
				c.Marked++
				if ok {
					c.StaleMarks = append(c.StaleMarks, where)
				}
				continue
			}
			if ok {
				continue
			}
			pkg := rel(serviceDir, dir)
			c.ByPackage[pkg]++
			if _, listed := ledger[pkg]; !listed {
				c.Findings = append(c.Findings, where)
			}
		}
	}

	for pkg, want := range ledger {
		got := c.ByPackage[pkg]
		switch {
		case got == 0:
			c.LedgerErrors = append(c.LedgerErrors,
				pkg+": ведомости нечего исключать — остаток убран, снимите запись")
		case got != want:
			c.LedgerErrors = append(c.LedgerErrors,
				fmt.Sprintf("%s: ведомость называет %d, найдено %d — приведите число к факту "+
					"(рост означает НОВУЮ негодную фикстуру и требует решения, а не правки числа)", pkg, want, got))
		}
	}

	sort.Strings(c.Findings)
	sort.Strings(c.StaleMarks)
	sort.Strings(c.LedgerErrors)
	return c
}

// rel приводит путь к виду «от корня сервиса»: находка и ведомость обязаны
// называть одну и ту же координату независимо от того, откуда запущен прогон.
func rel(base, path string) string {
	r, err := filepath.Rel(base, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(r)
}

// testFile — разобранный файл проб. Свой FileSet у каждого — номера строк нужны
// и находке, и пометке.
type testFile struct {
	Path string
	AST  *ast.File
	FSet *token.FileSet
}

// parseTestTree разбирает файлы проб поддерева ВМЕСТЕ С КОММЕНТАРИЯМИ: пометка
// намеренно негодной формы живёт в комментарии, и без них она была бы невидима.
func parseTestTree(t *testing.T, root string) []testFile {
	t.Helper()
	var out []testFile
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "testdata", "node_modules", "docs":
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		out = append(out, testFile{Path: path, AST: f, FSet: fset})
		return nil
	})
	if err != nil {
		t.Fatalf("обход файлов проб не состоялся: %v", err)
	}
	return out
}

// TestFixtureIdentifiersPassTheProductFormCheck — гейт: литерал в позиции
// собственного идентификатора обязан проходить проверку формы ПРОДУКТА.
func TestFixtureIdentifiersPassTheProductFormCheck(t *testing.T) {
	if _, err := os.Stat(serviceRoot); err != nil {
		t.Fatalf("корень сервиса не найден (%s): гейт судил бы о непрочитанном: %v", serviceRoot, err)
	}
	prod := parseProdTree(t, serviceRoot)
	tests := parseTestTree(t, serviceRoot)
	c := inspectFixtureForm(prod, tests, serviceRoot, fixtureFormLedger)

	forms := make([]string, 0, len(idPositionForms))
	for _, f := range idPositionForms {
		forms = append(forms, string(f)+"="+strconv.Itoa(c.ByForm[f]))
	}
	t.Logf("перепись: файлов проб прочитано %d · строковых литералов %d · "+
		"в позиции идентификатора %d (%s) · заявляют собственный префикс %d · "+
		"префиксов объявлено %d · пакетов в охвате %d · негодных В ОХВАТЕ %d "+
		"(из них помечено намеренно %d) · негодных ВНЕ охвата %d",
		c.TestFiles, c.StringLits, c.IDPositions, strings.Join(forms, " "), c.Claims,
		len(c.Prefixes), len(c.ScopePkgs), c.InScopeBad, c.Marked, c.OutOfBad)
	t.Logf("охват (пакеты, чей прод судит форму своего идентификатора): %s",
		strings.Join(c.ScopePkgs, " "))
	t.Logf("префиксы, выведенные из собственного пакета domain: %s", strings.Join(c.Prefixes, " "))
	{
		byPkg := make([]string, 0, len(c.ByPackage))
		for k, v := range c.ByPackage {
			byPkg = append(byPkg, k+"="+strconv.Itoa(v))
		}
		sort.Strings(byPkg)
		t.Logf("остаток по пакетам охвата: %s", strings.Join(byPkg, " "))
	}

	if c.TestFiles == 0 {
		t.Fatal("обход пуст: файлов проб не прочитано — вердикт беспредметен")
	}
	if len(c.Prefixes) == 0 {
		t.Fatal("в собственном пакете domain не найдено ни одной константы префикса — " +
			"предпосылка гейта не выполняется, и молчание означало бы «не с чем сверять»")
	}
	if len(c.ScopePkgs) == 0 {
		t.Fatal("ни один пакет не зовёт строгую проверку формы: либо она снята — тогда " +
			"снимите и этот гейт, — либо распознаватель перестал знать форму записи вызова")
	}
	if c.Claims == 0 {
		t.Fatal("ни один литерал в позиции идентификатора не заявляет собственный префикс: " +
			"распознаватель позиций ослеп — «ноль находок» здесь означало бы «ноль прочитанного»")
	}
	if len(c.StaleMarks) > 0 {
		t.Errorf("пометка «%s» стоит на литерале, который проверку ПРОХОДИТ — исключению нечего "+
			"исключать, снимите пометку:\n%s", deliberateBadFormMark, strings.Join(c.StaleMarks, "\n"))
	}
	if len(c.LedgerErrors) > 0 {
		t.Errorf("ведомость остатка разошлась с деревом:\n%s", strings.Join(c.LedgerErrors, "\n"))
	}
	if len(c.Findings) > 0 {
		t.Errorf("фикстура пользуется идентификатором, который продукт ОТВЕРГ БЫ "+
			"(shared.ValidateResourceID судит префикс И длину) — подстановка снисходительнее "+
			"продукта, e2e-flow.md §5. Либо приведите значение к форме, либо, если негодность "+
			"НАМЕРЕННА, пометьте её комментарием «%s: <причина>»:\n%s",
			deliberateBadFormMark, strings.Join(c.Findings, "\n"))
	}
}
