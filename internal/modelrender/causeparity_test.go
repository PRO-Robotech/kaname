// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// causeparity_test.go — перечень поводов кода `1` в норме и поводы, которые
// обход РЕАЛЬНО производит, сверяются машинно, а не вниманием.
//
// # Предмет
//
// Норма §2 п. 7 приёмки `model-generated-from-manifest.md` перечисляет поводы
// кода `1` поимённо и сама объявляет: «повод без строки перечня и строка
// перечня без повода — обе находки». Держателя у этого требования не было: врезка
// той же нормы говорит прямо «чем держится — вниманием». Правило без механизма
// уже не выполнилось дважды — #1848 («норма называет два повода, обход
// производит четыре») и #2044 («норма называет тринадцать, обход производит
// пятнадцать»).
//
// Расхождение идёт в БЕЗОПАСНУЮ сторону — код строже нормы, — и потому тихое:
// покраснеть ему не на чем. Цена не в вердикте, а в читателе: сверяя поведение
// с нормой, он встречает находку, о которой норма молчит, и заключает, что
// неисправен гейт.
//
// # Единица счёта — ЗНАЧЕНИЕ Finding, собранное кодом
//
// Не строка и не вхождение подстроки. `grep -c 'Finding{'` считает СТРОКИ,
// поэтому два литерала в одной строке дали бы один повод, а слово `Finding{`
// в комментарии — лишний. Здесь считается узел разбора: композитный литерал
// типа `Finding` либо элемент литерала `[]Finding{…}`. Тогда проза о поводах
// (а её в этом пакете много) под счёт не подпадает by construction.
//
// # Чего гейт НЕ судит
//
// Не судит, ВЕРНО ли строка перечня описывает свой повод: сопоставление
// «строка ↔ литерал» по смыслу есть суждение, а не предикат. Судится
// ЧИСЛО и НУМЕРАЦИЯ — то, что расходится молча и ловится машиной.
package modelrender_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	// causeNormAnchor — первая строка раздела нормы, где живёт перечень поводов.
	causeNormAnchor = "7. **Исходов у обхода ТРИ"
	// causeNormNext — первая строка следующего пункта: граница раздела.
	causeNormNext = "8. **"
)

// cause — один повод кода `1`, произведённый кодом.
type cause struct {
	File  string
	Line  int
	Label string
}

func (c cause) String() string {
	if c.Label == "" {
		return fmt.Sprintf("%s:%d", c.File, c.Line)
	}
	return fmt.Sprintf("%s:%d (%s)", c.File, c.Line, c.Label)
}

// causeLabelRe — первые слова текста повода: они и есть его имя для читателя.
var causeLabelRe = regexp.MustCompile(`^[^"]*`)

// causesInSource — поводы, собранные ЭТИМ исходником.
//
// Возвращает находки списком, а не через *testing.T: разбор, обращающийся к
// тесту, инъекции не поддаётся.
func causesInSource(name string, src []byte) ([]cause, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	seen := map[token.Pos]bool{}
	var out []cause
	add := func(expr ast.Expr) {
		if seen[expr.Pos()] {
			return
		}
		seen[expr.Pos()] = true
		out = append(out, cause{
			File:  name,
			Line:  fset.Position(expr.Pos()).Line,
			Label: causeLabel(expr),
		})
	}

	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		switch typ := lit.Type.(type) {
		case *ast.Ident:
			if typ.Name == "Finding" {
				add(lit)
			}
		case *ast.ArrayType:
			ident, ok := typ.Elt.(*ast.Ident)
			if !ok || ident.Name != "Finding" {
				return true
			}
			// Элементы литерала `[]Finding{…}` тип не повторяют, поэтому
			// ветвь выше их не видит: каждый элемент — самостоятельный повод.
			for _, el := range lit.Elts {
				add(el)
			}
		}
		return true
	})
	return out, nil
}

// causeLabel — короткое имя повода для текста находки: начало его текста.
//
// Читатель, получивший «литералов 15, строк 13», обязан узнать, КАКИЕ два
// лишние, — иначе он ищет их глазами.
func causeLabel(expr ast.Expr) string {
	lit, ok := expr.(*ast.CompositeLit)
	if !ok {
		return ""
	}
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "Detail" {
			continue
		}
		return strings.TrimSpace(causeLabelRe.FindString(firstStringLiteral(kv.Value)))
	}
	return ""
}

// firstStringLiteral — первая строковая константа выражения: у текста повода
// она стоит впереди и при конкатенации, и внутри форматирования.
func firstStringLiteral(expr ast.Expr) string {
	var out string
	ast.Inspect(expr, func(n ast.Node) bool {
		if out != "" {
			return false
		}
		bl, ok := n.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return true
		}
		if unquoted, err := strconv.Unquote(bl.Value); err == nil {
			out = unquoted
		}
		return false
	})
	return out
}

// causeRowRe — строка нумерованной таблицы поводов. Строки первой таблицы
// раздела («0 · 1 · 2 VOID») под неё не подпадают: там номер выделен звёздочками.
var causeRowRe = regexp.MustCompile(`^\s*\|\s*(\d+)\s*\|`)

// normCauseRows — номера строк перечня поводов из раздела нормы.
func normCauseRows(doc string) []int {
	var rows []int
	inside := false
	for _, line := range strings.Split(doc, "\n") {
		switch {
		case strings.HasPrefix(line, causeNormAnchor):
			inside = true
			continue
		case inside && strings.HasPrefix(line, causeNormNext):
			inside = false
		}
		if !inside {
			continue
		}
		if m := causeRowRe.FindStringSubmatch(line); m != nil {
			n, err := strconv.Atoi(m[1])
			if err != nil {
				continue
			}
			rows = append(rows, n)
		}
	}
	return rows
}

// listCauses — перечень поводов с координатами, по одному в строке.
func listCauses(causes []cause) string {
	var sb strings.Builder
	for i, c := range causes {
		fmt.Fprintf(&sb, "      %2d) %s\n", i+1, c)
	}
	return strings.TrimRight(sb.String(), "\n")
}

// auditCauseParity — сверка в ОБЕ стороны. Возвращает находки списком.
func auditCauseParity(causes []cause, rows []int) []string {
	var findings []string
	if len(causes) == 0 {
		findings = append(findings, "обход пуст: поводов в прод-коде пакета прочитано 0 — "+
			"«находок 0» неотличимо от «прочитано 0»")
	}
	if len(rows) == 0 {
		findings = append(findings, "обход пуст: строк перечня "+causeNormAnchor+
			"… прочитано 0 — раздел нормы не найден либо переименован")
	}
	if len(causes) == 0 || len(rows) == 0 {
		return findings
	}

	for i, n := range rows {
		if n != i+1 {
			findings = append(findings, fmt.Sprintf(
				"нумерация перечня не сплошная: строка %d несёт номер %d — "+
					"повторённый номер держит счёт верным при потерянном поводе", i+1, n))
			break
		}
	}

	switch {
	case len(causes) > len(rows):
		// Называется ВЕСЬ перечень поводов, а не «хвост»: порядок чтения
		// исходника перечню нормы не соответствует, и «лишними» по позиции
		// оказались бы невиновные. Читатель сверяет два перечня сам —
		// диагностика обязана дать ему для этого координаты, а не догадку.
		findings = append(findings, fmt.Sprintf(
			"поводов в коде %d, строк перечня нормы %d: обход производит находку, о которой норма молчит.\n"+
				"    поводы кода по порядку чтения исходника:\n%s\n"+
				"    исходов два: назвать повод строкой перечня либо снять повод из кода",
			len(causes), len(rows), listCauses(causes)))
	case len(rows) > len(causes):
		findings = append(findings, fmt.Sprintf(
			"строк перечня нормы %d, поводов в коде %d: норма обещает находку, которой обход не производит.\n"+
				"    исходов два: завести повод в коде либо снять строку перечня",
			len(rows), len(causes)))
	}
	return findings
}

// TestSweepCauseCountMatchesTheNormList — несущее утверждение: перечень нормы и
// поводы обхода сходятся числом.
func TestSweepCauseCountMatchesTheNormList(t *testing.T) {
	src, err := os.ReadFile(sweepFile)
	if err != nil {
		t.Fatalf("исходник обхода не прочитан: %v", err)
	}
	causes, err := causesInSource(filepath.Base(sweepFile), src)
	if err != nil {
		t.Fatalf("исходник обхода не разобран: %v", err)
	}
	doc, err := os.ReadFile(normDoc)
	if err != nil {
		t.Fatalf("приёмка не прочитана: %v", err)
	}
	rows := normCauseRows(string(doc))

	for _, f := range auditCauseParity(causes, rows) {
		t.Error(f)
	}
	if len(causes) == 0 || len(rows) == 0 {
		t.Fatal("обход пуст — гейт судил бы о непрочитанном")
	}
	t.Logf("перепись: поводов кода 1 в %s прочитано %d · строк перечня нормы %d · файл нормы %s",
		sweepFile, len(causes), len(rows), normDoc)
}

// TestSweepCauseParity_CanFailAndStaysSilent — способность упасть и смолчать,
// по каждой оси отдельно и с законным близнецом.
func TestSweepCauseParity_CanFailAndStaysSilent(t *testing.T) {
	const head = "package modelrender\n\ntype Finding struct{ Detail string }\n\n"
	twoCauses := head + `
func a() []Finding { return []Finding{{Detail: "канон не резолвится: тут"}} }
func b() []Finding { return append([]Finding(nil), Finding{Detail: "обход дерева отказал: тут"}) }
`
	threeCauses := twoCauses + `
func c() []Finding { return []Finding{{Detail: "корень обхода не открыт: тут"}} }
`
	// Законный близнец распознавателя: слово `Finding{` в КОММЕНТАРИИ и в
	// строке — не повод. Гейт по подстроке засчитал бы обе.
	prose := twoCauses + `
// Повод собирается литералом Finding{…}: так его считает гейт.
func d() string { return "Finding{" }
`
	docWith := func(n int) string {
		var sb strings.Builder
		sb.WriteString("## §2\n\n" + causeNormAnchor + ", и «частично» не является четвёртым.**\n\n")
		sb.WriteString("   | код | состояние | когда наступает |\n   |---:|---|---|\n")
		sb.WriteString("   | **1** | **находка** | любой повод перечня ниже |\n\n")
		sb.WriteString("   | # | повод | где производится |\n   |---:|---|---|\n")
		for i := 1; i <= n; i++ {
			fmt.Fprintf(&sb, "   | %d | повод номер %d | `Sweep` |\n", i, i)
		}
		sb.WriteString("\n" + causeNormNext + "Блок канона.**\n\n   | 9 | вне раздела | `Sweep` |\n")
		return sb.String()
	}

	cases := []struct {
		name string
		src  string
		doc  string
		want string
		why  string
	}{
		{
			name: "законный близнец: числа сошлись", src: twoCauses, doc: docWith(2),
			why: "положительный контроль: без него всякое красное ниже могло бы приходить от самого разбора",
		},
		{
			name: "лишний повод в коде", src: threeCauses, doc: docWith(2),
			want: "поводов в коде 3, строк перечня нормы 2",
			why:  "ровно предмет #2044: обход производит находку, о которой норма молчит",
		},
		{
			name: "лишняя строка перечня", src: twoCauses, doc: docWith(4),
			want: "строк перечня нормы 4, поводов в коде 2",
			why:  "обратная сторона: норма обещает находку, которой обход не производит",
		},
		{
			name: "повод в прозе и в строке — не повод", src: prose, doc: docWith(2),
			why: "распознаватель судит УЗЕЛ разбора, а не подстроку: иначе комментарий о поводах " +
				"и литерал пробы считались бы поводами",
		},
		{
			name: "раздел нормы переименован", src: twoCauses, doc: "## §2\n\n9. Другой пункт\n",
			want: "строк перечня",
			why:  "«ноль строк» обязано быть отличимо от «строк ноль, потому что раздел не найден»",
		},
		{
			name: "поводов в коде нет вовсе", src: head, doc: docWith(2),
			want: "поводов в прод-коде пакета прочитано 0",
			why:  "пустой обход есть третий исход, а не зелёный вердикт",
		},
		{
			name: "нумерация перечня не сплошная",
			src:  twoCauses,
			doc: "## §2\n\n" + causeNormAnchor + "**\n\n   | # | повод |\n   |---:|---|\n" +
				"   | 1 | первый |\n   | 1 | он же снова |\n\n" + causeNormNext + "Блок.**\n",
			want: "нумерация перечня не сплошная",
			why:  "повторённый номер держит счёт верным при потерянном поводе — счёт один это не ловит",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			causes, err := causesInSource("injected.go", []byte(tc.src))
			if err != nil {
				t.Fatalf("инъекция не разобрана: %v", err)
			}
			findings := auditCauseParity(causes, normCauseRows(tc.doc))
			if tc.want == "" {
				if len(findings) != 0 {
					t.Fatalf("разбор нашёл на законном близнеце то, чего в нём нет — первое же ложное "+
						"срабатывание снимает гейт.\nнаходки:\n  %s", strings.Join(findings, "\n  "))
				}
				return
			}
			if len(findings) == 0 {
				t.Fatalf("разбор смолчал на инъекции — он НЕ способен упасть по этой оси.\n"+
					"что должно было ловиться: %s", tc.why)
			}
			if !strings.Contains(strings.Join(findings, "\n"), tc.want) {
				t.Fatalf("разбор покраснел не на том: ждали %q\nнаходки:\n  %s",
					tc.want, strings.Join(findings, "\n  "))
			}
		})
	}
}
