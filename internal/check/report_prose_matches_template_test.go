// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// report_prose_matches_template_test.go — ПРОЗА ОТЧЁТА СВЕРЯЕТСЯ С
// ЛИТЕРАЛОМ, КОТОРЫЙ ЕЁ ПЕЧАТАЕТ (задача продукта #877).
//
// Порт с монорепо (`internal/repohygiene/reportprosematchestemplate_test.go`,
// снят вынесением службы — `kacho#2597`). Дословно: разбор, предикат.
// Изменилось: пакет (`repohygiene` → `check_test`), обход
// (`repoRoot(t)` → `platformtree.RequireCorpus(t)`, СВОЙ модуль — предмет
// целиком внутри него), перечень `reportGlobs`: путь `services/iam/` снят
// (код лежит от корня), а запись `services/vpc/tests/k6/results/*.md`
// СНЯТА — предмет замера этой записи (в самом монорепо, дословно):
// «у четвёртого (замеры k6 у vpc) производителя заголовка вне службы не
// было НИКОГДА» — то есть даже в монорепо эта запись не находила своего
// шаблона внутри iam; сегодня она стала недостижимой координатой (каталога
// `services/vpc/` в дереве kaname нет), и оставлять её значило бы завести
// гейт, падающий на предпосылке «отчётов найдено 0» по пути, у которого
// никогда не было предмета для ЭТОЙ службы.
//
// # ПРЕДМЕТ (дословно из монорепо)
//
// Числа отчёта замера защищены отпечатком: гейт свежести сверяет их с
// деревом и краснеет, когда дерево ушло вперёд. Утверждения отчёта не
// защищены НИЧЕМ. Устаревшее утверждение опаснее устаревшего числа: число
// читают с оглядкой на провенанс, а прозу принимают на веру.
//
// # ЧТО ПРОВЕРЯЕТСЯ — ТОЖДЕСТВО, А НЕ ЛЕКСИКОН
//
// Заголовок отчёта печатается из строкового литерала в исходнике прибора.
// Литерал обязан присутствовать в каком-нибудь отчёте дерева ДОСЛОВНО.
// Детектор по словарю здесь уже проваливал контроль в обе стороны — записано
// в корпусе правил, повторять не нужно. Тождество строки такого недостатка
// не имеет: оно не судит смысл, оно сверяет байты.
package check_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// tmpl — заголовок, напечатанный из литерала: где объявлен и что печатает.
type tmpl struct {
	where   string
	literal string
}

// minProseChunk — короче этого куски не сверяются: случайное совпадение.
const minProseChunk = 24

// reportGlobs — где лежат отчёты приборов kaname. Перечень ЗДЕСЬ, потому что
// имя каталога — свойство прибора, а не дерева, и вывести его неоткуда.
var reportGlobs = []string{
	"internal/repo/kaname/pg/scalegrid/REPORT-*.txt",
	"tools/authzformbench/REPORT-*.txt",
	"tests/k6/results/*.md",
}

func TestReportProseMatchesTheTemplateThatPrintsIt(t *testing.T) {
	root, _ := platformtree.RequireCorpus(t)

	var reports []string
	corpus := map[string]string{}
	for _, g := range reportGlobs {
		matches, err := treecorpus.Glob(filepath.Join(root, g))
		if err != nil {
			t.Fatalf("перебор %s: %v", g, err)
		}
		for _, m := range matches {
			b, rerr := os.ReadFile(m)
			if rerr != nil {
				t.Fatalf("чтение отчёта %s: %v", m, rerr)
			}
			rel, _ := filepath.Rel(root, m)
			reports = append(reports, rel)
			corpus[rel] = string(b)
		}
	}

	files, err := treecorpus.UnderWithSuffix(root, ".go")
	if err != nil {
		t.Fatalf("состав дерева: %v", err)
	}

	var templates []tmpl
	withoutLiteral := 0
	scanned := 0

	fset := token.NewFileSet()
	for _, abs := range files {
		src, rerr := os.ReadFile(abs)
		if rerr != nil || !strings.Contains(string(src), ".Header(") {
			continue
		}
		f, relErr := filepath.Rel(root, abs)
		if relErr != nil {
			f = abs
		}
		file, perr := parser.ParseFile(fset, abs, src, 0)
		if perr != nil {
			continue
		}
		scanned++
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Header" || len(call.Args) == 0 {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || !strings.Contains(strings.ToLower(ident.Name), "prov") {
				return true
			}
			lits := stringLiteralsOf(call.Args[0])
			if len(lits) == 0 {
				withoutLiteral++
				return true
			}
			pos := fset.Position(call.Pos())
			for _, l := range lits {
				if len([]rune(l)) < minProseChunk {
					continue
				}
				templates = append(templates, tmpl{
					where:   f + ":" + strconv.Itoa(pos.Line),
					literal: l,
				})
			}
			return true
		})
	}

	t.Logf("осмотрено: файлов с вызовом заголовка %d · шаблонов с литералом %d · "+
		"вызовов без литерала %d (вне предмета) · отчётов прочитано %d",
		scanned, len(templates), withoutLiteral, len(reports))

	if len(reports) == 0 {
		t.Fatalf("отчётов не найдено ни по одному образцу — проверять нечего; "+
			"либо каталоги переехали, либо образцы устарели: %v", reportGlobs)
	}
	if len(templates) == 0 {
		t.Fatalf("шаблонов с литералом не найдено при %d осмотренных файлах — "+
			"разбор перестал узнавать вызов заголовка", scanned)
	}

	missing := proseMissingFromReports(templates, corpus)

	if len(missing) > 0 {
		t.Fatalf("заголовок шаблона не найден ни в одном отчёте (%d из %d):\n  %s\n\n"+
			"Это значит, что шаблон правили, а отчёт не пересняли: проза отчёта "+
			"утверждает не то, что печатает прибор. Пересними отчёт прогоном прибора "+
			"либо, если заголовок изменён осознанно, — тем же изменением.",
			len(missing), len(templates), strings.Join(missing, "\n  "))
	}
}

// stringLiteralsOf собирает строковые литералы выражения, включая конкатенацию.
func stringLiteralsOf(e ast.Expr) []string {
	var out []string
	ast.Inspect(e, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		s, uerr := strconv.Unquote(lit.Value)
		if uerr != nil {
			return true
		}
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
		return true
	})
	return out
}

func shortenProse(s string) string {
	r := []rune(s)
	if len(r) <= 60 {
		return s
	}
	return string(r[:57]) + "…"
}

// proseMissingFromReports — РЕШАЮЩАЯ ЧАСТЬ, вынесенная отдельно ради инъекции.
func proseMissingFromReports(templates []tmpl, corpus map[string]string) []string {
	var missing []string
	for _, tm := range templates {
		found := false
		for _, body := range corpus {
			if strings.Contains(body, tm.literal) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, tm.where+" — заголовок «"+shortenProse(tm.literal)+"»")
		}
	}
	return missing
}
