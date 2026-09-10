// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// bootbody_refusal_has_a_name_test.go — ГЕЙТ КЛАССА: отказ старта, построенный
// В ТЕЛЕ ПОДЪЁМА, обязан иметь ИМЯ либо стоять в самоистекающей ведомости
// (#2514).
//
// ─────────────────────────────────────────────────────────────────────────────
// ВТОРАЯ ПОЛОВИНА ПАРЫ, КОТОРУЮ СОСЕД НЕ ДЕРЖАЛ И ПРЯМО ОБ ЭТОМ ГОВОРИЛ
//
// `TestEveryNamedStartupGuardIsJudgedByTheProductionProfile` держит первую:
// каждый ИМЕНОВАННЫЙ страж судится пробой боевого профиля. Вторую — что условие
// отказа вообще ИМЕЕТ имя — не держало ничто, и его шапка это называла.
//
// Цена измерена, а не предположена: одно условие жило встроенной ветвью, боевой
// профиль его не удовлетворял, и проба профиля оставалась зелёной, потому что
// позвать безымянное условие нельзя by construction — она повторяла его СВОИМИ
// утверждениями, то есть была вторым местом об одном предмете.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЕДИНИЦА СЧЁТА НАЗВАНА, И ОНА НЕ ТА, ЧТО В ЗАДАЧЕ
//
// Задача мерила «вызов fmt.Errorf без %w, возвращаемый из тела подъёма» и
// назвала ВОСЕМЬ. По этой ревизии тем же выражением выходит ТРИ, и расхождение
// объяснимо: замер снят до посадки #2513, которая часть условий уже вынесла.
// Здесь единица шире на одну законную форму — `errors.New` со строковым
// литералом строит такой же отказ, и распознаватель, её не знающий, МОЛЧАЛ БЫ о
// написанном ею.
//
// Отказ, ОБОРАЧИВАЮЩИЙ чужую ошибку (`%w`), предметом НЕ является намеренно: он
// не решает о посадке, а передаёт дальше чужой вердикт вместе с его причиной.
// Требовать имени от него значило бы требовать свойства, о котором никто не
// решал, — ровно тот исход, из-за которого два прежних предиката этой задачи
// были отвергнуты замером.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ГЕЙТ НЕ УТВЕРЖДАЕТ
//
// Он судит ТЕЛО ПОДЪЁМА, а не всякую функцию пакета: отказы построения внутри
// помощников — их собственный предмет, и у них свои вызывающие. Область названа,
// чтобы её не читали шире.
//
// Способность упасть доказана инъекцией — bootbody_refusal_has_a_name_injection_test.go.

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
)

// bootBodyFunc — функция, чьё тело и есть подъём службы.
const bootBodyFunc = "runServe"

// bootRefusal — отказ, построенный в теле подъёма НА МЕСТЕ.
type bootRefusal struct {
	Text string
	File string
	Line int
}

func (r bootRefusal) String() string { return fmt.Sprintf("%s:%d", r.File, r.Line) }

// bootBodyVerdicts читает тело подъёма из ОДНОГО исходника и возвращает
// встроенные отказы плюс имена позванных стражей.
//
// Источник принимается доводом: тем же вызовом инъекция подаёт синтетический
// вход, меняя ровно один факт.
func bootBodyVerdicts(name string, src []byte) (inline []bootRefusal, guards []string, err error) {
	fset := token.NewFileSet()
	file, perr := parser.ParseFile(fset, name, src, parser.ParseComments)
	if perr != nil {
		return nil, nil, perr
	}

	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Name.Name != bootBodyFunc || fd.Body == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.ReturnStmt:
				for _, res := range node.Results {
					if text, ok := builtInPlaceRefusal(res); ok {
						pos := fset.Position(res.Pos())
						inline = append(inline, bootRefusal{
							Text: text, File: filepath.Base(pos.Filename), Line: pos.Line,
						})
					}
				}
			case *ast.CallExpr:
				if id, ok := node.Fun.(*ast.Ident); ok && isNamedStartupGuard(id.Name) {
					guards = append(guards, id.Name)
				}
			}
			return true
		})
	}
	sort.Strings(guards)
	return inline, uniqueStrings(guards), nil
}

// builtInPlaceRefusal — отказ, ПОСТРОЕННЫЙ на месте: `fmt.Errorf` со строковым
// литералом без `%w` либо `errors.New` со строковым литералом.
//
// Обе формы законны и обе встречаются; распознаватель, знающий одну, молчал бы о
// написанном другой — не красное и не зелёное, а отсутствие вопроса.
func builtInPlaceRefusal(expr ast.Expr) (string, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || len(call.Args) == 0 {
		return "", false
	}
	text, ok := bootEdgeConstantString(call.Args[0])
	if !ok {
		return "", false
	}
	switch {
	case pkg.Name == "errors" && sel.Sel.Name == "New":
		return text, true
	case pkg.Name == "fmt" && sel.Sel.Name == "Errorf":
		// Оборачивающий отказ передаёт чужой вердикт вместе с причиной и
		// решением о посадке не является.
		if strings.Contains(text, "%w") {
			return "", false
		}
		return text, true
	}
	return "", false
}

// isNamedStartupGuard — то же опознание, что у соседнего гейта: имя начинается
// с `require` и следом заглавная. Судится ИМЯ ВЫЗЫВАЕМОГО, а не строка.
func isNamedStartupGuard(name string) bool {
	const prefix = "require"
	if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
		return false
	}
	r := rune(name[len(prefix)])
	return r >= 'A' && r <= 'Z'
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// ВЕДОМОСТЬ — САМОИСТЕКАЮЩАЯ, И ЭТО НЕ ПОСЛАБЛЕНИЕ.
//
// Отказ ПРОВЯЗКИ — тот, что не решает о посадке, а отказывается СОБРАТЬ узел,
// когда его часть отсутствует. Выносить такой под имя нечего: профиль его не
// удовлетворяет и не может — он про целость сборки, а не про величины.
//
// Ключ — начальный фрагмент текста отказа. Запись, которой больше нечего
// прощать, — НАХОДКА: так снятый отказ не оставляет за собой прощение, под
// которое уедет следующий.

var bootBodyRefusalsNotGuards = map[string]string{
	"приём предъявленного удостоверения включён": "отказ ПОСТРОЕНИЯ, а не посадки: " +
		"условие уже отвергнуто стражем настройки (приём связан с чеканкой), и здесь " +
		"отказывается СОБРАТЬСЯ читатель — наполовину собранный отвергал бы всё, и " +
		"узналось бы это на первом запросе арендатора. Профилю удовлетворять здесь нечего: " +
		"речь о целости сборки, а не о величинах",
}

// ─────────────────────────────────────────────────────────────────────────────
// РАЗБОР.

type bootBodyCensus struct {
	Files    int
	Guards   int
	Inline   int
	InLedger int
}

func (c bootBodyCensus) String() string {
	return fmt.Sprintf(
		"файлов корня прочитано %d · отказов старта в теле подъёма всего %d · "+
			"вынесено в именованного стража %d · встроенной ветвью %d · названо в ведомости %d",
		c.Files, c.Guards+c.Inline, c.Guards, c.Inline, c.InLedger)
}

// auditBootBodyRefusals — находки и перепись. `*testing.T` не трогает.
func auditBootBodyRefusals(files int, inline []bootRefusal, guards []string,
	ledger map[string]string) ([]string, bootBodyCensus) {

	census := bootBodyCensus{Files: files, Guards: len(guards), Inline: len(inline)}
	var findings []string

	if files == 0 {
		return []string{"обход пуст: исходников композиционного корня прочитано 0"}, census
	}
	if len(guards)+len(inline) == 0 {
		return []string{"обход пуст: в теле подъёма не найдено НИ ОДНОГО отказа старта — " +
			"либо тело перестало называться так, как ищет разбор, либо распознаватель не " +
			"знает формы отказа; и то и другое читается этой строкой одинаково"}, census
	}

	excused := map[string]bool{}
	for _, r := range inline {
		key, ok := ledgerKeyFor(r.Text, ledger)
		if !ok {
			findings = append(findings, fmt.Sprintf(
				"отказ старта живёт ВСТРОЕННОЙ ВЕТВЬЮ и не имеет имени (%s): %q. "+
					"Позвать безымянное условие нельзя by construction, поэтому проба боевого "+
					"профиля о нём не высказывается, а повторить его СВОИМИ утверждениями значит "+
					"завести второе место об одном предмете. Вынесите в именованного стража либо "+
					"назовите в ведомости с причиной", r, shorten(r.Text)))
			continue
		}
		excused[key] = true
		census.InLedger++
	}

	for key := range ledger {
		if !excused[key] {
			findings = append(findings, fmt.Sprintf(
				"ведомость прощает %q, а такого отказа в теле подъёма больше нет — "+
					"запись пережила свой предмет и прощает то, что регрессирует в неё следующим", key))
		}
	}

	sort.Strings(findings)
	return findings, census
}

// ledgerKeyFor — запись ведомости, чей ключ есть начальный фрагмент отказа.
func ledgerKeyFor(text string, ledger map[string]string) (string, bool) {
	for key := range ledger {
		if strings.Contains(text, key) {
			return key, true
		}
	}
	return "", false
}

func shorten(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= 90 {
		return s
	}
	return s[:90] + "…"
}

// ─────────────────────────────────────────────────────────────────────────────
// ГЕЙТ.

func TestEveryStartupRefusalInTheBootBodyHasAName(t *testing.T) {
	files := postureRootFiles(t)
	var (
		inline []bootRefusal
		guards []string
	)
	for _, name := range files {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s не прочитан: %v", name, err)
		}
		gotInline, gotGuards, err := bootBodyVerdicts(name, src)
		if err != nil {
			t.Fatalf("%s не разобран: %v", name, err)
		}
		inline = append(inline, gotInline...)
		guards = append(guards, gotGuards...)
	}
	guards = uniqueStrings(guards)
	sort.Strings(guards)

	findings, census := auditBootBodyRefusals(len(files), inline, guards, bootBodyRefusalsNotGuards)

	t.Logf("объём осмотренного: %s", census)
	t.Logf("стражи, позванные телом подъёма: %s", strings.Join(guards, ", "))

	if len(findings) > 0 {
		t.Fatalf("находок %d:\n  • %s", len(findings), strings.Join(findings, "\n  • "))
	}
	if census.InLedger != census.Inline {
		t.Fatalf("перепись не сходится: встроенных отказов %d, названо в ведомости %d — "+
			"равенство и есть предмет этого гейта", census.Inline, census.InLedger)
	}
}
