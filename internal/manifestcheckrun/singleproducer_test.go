// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifestcheckrun_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// singleproducer_test.go — у проверки манифестов ОДНА композиция и тонкие
// вызывающие (задача #1036).
//
// # Предмет
//
// Проверку зовут двое: сборочная цель `module-manifest-check` (её зовёт
// конвейер) и действие `iamctl validate` (его зовёт человек и pre-commit).
// Вторая композиция тех же стадий разошлась бы с первой МОЛЧА — и разошлась бы
// там, где расхождение не видно: обе дают «годно» на честном дереве, а
// разъезжаются на негодном, то есть ровно тогда, когда на них полагаются.
//
// Держится это ДВУМЯ утверждениями, и второе без первого бесполезно:
//
//  1. у чистой функции обхода ровно один прод-вызывающий на каждую точку входа —
//     иначе композиция завелась бы второй раз в обход этого пакета;
//  2. у самой композиции вызывающих ровно двое, и оба — команды: третий
//     вызывающий законен, но обязан быть замечен, потому что он и есть место,
//     где стадии начинают выбирать по-своему.
//
// # Распознаватель знает ОБЕ законные формы обращения
//
// Функция бывает не только ПОЗВАНА, но и ПЕРЕДАНА значением: композиционный
// корень инструмента вносит её портом (`Validate: manifestcheckrun.Run`), и это
// такое же обращение, как вызов, — просто исполняется оно позже. Распознаватель,
// знающий только узел вызова, второго вызывающего не увидел бы ВОВСЕ: не
// нарушением, а невидимостью. Замерено при заведении гейта: по узлу вызова
// находился один из двух.
//
// Поэтому судится узел СЕЛЕКТОРА — он один и тот же у обеих форм, и двойного
// счёта у вызова не даёт.
//
// # Почему разбор, а не поиск по образцу
//
// Имена этих функций встречаются в комментариях этого дерева десятками — в том
// числе в объяснении самого правила. Проверка по подстроке краснела бы на
// собственной шапке; поэтому судится УЗЕЛ вызова, а не строка.
//
// # Состав берётся у ИНДЕКСА, а не у диска
//
// Под корнем лежат каталоги, которых в репозитории нет: рабочие копии агентов,
// отчёты прогонов, сборочные и сгенерированные каталоги. Прочитав их, гейт
// сделал бы свой вердикт свойством ЧУЖОГО рабочего каталога, а не коммита — и
// ошибался бы в обе стороны: краснел на файле, которого в репозитории нет, и
// молчал в свежем checkout там, где обязан говорить. Первая редакция этого
// гейта шла по диску, и поймал её гейт обходов дерева, а не обзор.
//
// Синтетическое дерево инъекции репозиторием не является, поэтому его состав
// берётся отдельным конструктором — осознанно и по имени, а не молчаливым
// откатом внутри общего.
//
// # Объём осмотренного печатается всегда
//
// «Ноль лишних вызывающих» обязано быть отличимо от «ноль прочитанных файлов»:
// пустой обход — находка, а не успех.

// entryPointsUnder — точки входа, у каждой из которых прод-вызывающий ровно один.
//
// Координаты СКЛАДЫВАЮТСЯ от приставки, а не выписываются: в монорепо файлы
// модуля лежат под `services/iam`, в самостоятельном клоне — от его собственного
// корня. Выписанная координата верна ровно для одной посадки и в другой не
// совпадает ни с одной записью состава — молча, то есть «ноль находок» стало бы
// неотличимо от «ноль прочитанного».
func entryPointsUnder(prefix string) map[string]string {
	return map[string]string{
		"CheckTree":              platformtree.Under(prefix, "internal/manifestcheckrun"),
		"CheckTreeForGeneration": platformtree.Under(prefix, "internal/authzmapgen"),
	}
}

// composition — сама композиция и те, кому позволено её звать.
const compositionCall = "Run"

func compositionCallersUnder(prefix string) []string {
	return []string{
		platformtree.Under(prefix, "tools/modulemanifestcheck"),
		platformtree.Under(prefix, "cmd/iamctl"),
	}
}

type callSite struct {
	pkgDir string
	file   string
	line   int
}

// walkCalls обходит прод-дерево и собирает места вызова названных селекторов.
//
// Возвращает вдобавок ЧИСЛО прочитанных файлов: без него вердикт обхода
// неотличим от вердикта обхода, не прочитавшего ничего.
func walkCalls(t *testing.T, tree *treecorpus.Tree, want map[string]string) (map[string][]callSite, int) {
	t.Helper()
	found := make(map[string][]callSite)
	filesRead := 0
	root := tree.Root()
	for _, rel := range tree.SortedFiles() {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		// Сгенерённые стабы пишет генератор — судить его нечего.
		if strings.HasPrefix(rel, "pkg/api/") || strings.Contains(rel, "/testdata/") {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(rel))
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// Неразобранный файл — «не прочитано», а не «находок нет».
			t.Fatalf("обход НЕ ИСПОЛНЕН: файл %s не разобран: %v", rel, perr)
		}
		filesRead++
		pkgDir := filepath.ToSlash(filepath.Dir(rel))
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			name := sel.Sel.Name
			if _, wanted := want[name]; !wanted {
				return true
			}
			// Селектор судится вместе с квалификатором: одноимённый метод
			// чужого типа вызовом этой функции не является.
			ident, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch name {
			case compositionCall:
				if ident.Name != "manifestcheckrun" {
					return true
				}
			default:
				if ident.Name != "manifest" {
					return true
				}
			}
			found[name] = append(found[name], callSite{
				pkgDir: pkgDir,
				file:   rel,
				line:   fset.Position(sel.Pos()).Line,
			})
			return true
		})
	}
	return found, filesRead
}

// auditCallers — сами утверждения, отдающие НАХОДКИ, а не роняющие пробу.
//
// Вынесены из пробы именно затем, чтобы гейт можно было подать синтетическому
// дереву: проверка, которую нельзя позвать на подготовленном входе, свою
// способность упасть не доказывает ничем.
func auditCallers(t *testing.T, tree *treecorpus.Tree, prefix string) (findings []string, filesRead int) {
	t.Helper()
	entryPoints := entryPointsUnder(prefix)
	want := map[string]string{compositionCall: ""}
	for name, dir := range entryPoints {
		want[name] = dir
	}
	found, filesRead := walkCalls(t, tree, want)

	for _, name := range sortedKeys(entryPoints) {
		wantDir := entryPoints[name]
		sites := found[name]
		if len(sites) != 1 {
			findings = append(findings, fmt.Sprintf(
				"у точки входа %s прод-вызывающих %d, а обязан быть ОДИН: %v — "+
					"второй вызывающий заводит ВТОРУЮ композицию стадий, и разойдётся она молча",
				name, len(sites), describe(sites)))
			continue
		}
		if sites[0].pkgDir != wantDir {
			findings = append(findings, fmt.Sprintf(
				"точку входа %s зовёт %s, а обязан %s (%s:%d)",
				name, sites[0].pkgDir, wantDir, sites[0].file, sites[0].line))
		}
	}

	gotCallers := make([]string, 0, len(found[compositionCall]))
	for _, s := range found[compositionCall] {
		gotCallers = append(gotCallers, s.pkgDir)
	}
	sort.Strings(gotCallers)
	wantCallers := append([]string(nil), compositionCallersUnder(prefix)...)
	sort.Strings(wantCallers)
	if strings.Join(gotCallers, ",") != strings.Join(wantCallers, ",") {
		findings = append(findings, fmt.Sprintf(
			"композицию зовут %v, а объявлено %v — вызывающий вне перечня законен, "+
				"но обязан быть ЗАМЕЧЕН: он и есть место, где стадии начинают выбирать "+
				"по-своему; внесите его сюда осознанно",
			gotCallers, wantCallers))
	}
	return findings, filesRead
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestManifestCheckKeepsOneCompositionAndTwoThinCallers(t *testing.T) {
	root, prefix := platformtree.RequireCorpus(t)
	tree, err := treecorpus.NewTree(root)
	if err != nil {
		t.Fatalf("обход НЕ ИСПОЛНЕН: состав дерева не прочитан: %v", err)
	}
	findings, filesRead := auditCallers(t, tree, prefix)

	t.Logf("перепись: корень обхода %s · приставка модуля %q · прочитано файлов Go %d · "+
		"точек входа %d · находок %d",
		root, prefix, filesRead, len(entryPointsUnder(prefix)), len(findings))
	if filesRead == 0 {
		t.Fatal("обход прочитал НОЛЬ файлов — вердикт беспредметен")
	}
	for _, f := range findings {
		t.Errorf("НАХОДКА: %s", f)
	}
}

func describe(sites []callSite) string {
	out := make([]string, 0, len(sites))
	for _, s := range sites {
		out = append(out, fmt.Sprintf("%s:%d", s.file, s.line))
	}
	return strings.Join(out, " · ")
}
