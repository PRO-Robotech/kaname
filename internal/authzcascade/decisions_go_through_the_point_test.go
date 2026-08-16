// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// decisions_go_through_the_point_test.go — гейт по дереву: решение о доступе,
// принятое внутри iam, не может уйти движку, минуя сравнение форм.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ОН ДЕРЖИТ И ПОЧЕМУ ЭТОГО НЕ ДЕРЖАЛ СОСЕДНИЙ ИНВЕНТАРЬ
//
// `who_asks_the_store_test.go` перечисляет КТО спрашивает хранилище и требует у
// каждого места объявленной полосы. Он был зелёным всё то время, пока пятнадцать
// мест решали доступ мимо сравнения: полоса у них объявлена, и объявлена верно —
// «страж, которого кормит композиционный корень». Вопрос «доходит ли спрошенное
// до сравнения» он не задаёт вовсе, и по построению задать не может.
//
// Здесь задаётся именно он, и ответ выводится из ДВУХ фактов дерева, а не из
// перечня:
//
//	1. какие методы хранилища перекрывает обёртка (разбор её собственных
//	   объявлений), и предъявляет ли каждое перекрытие свой вопрос сравнению;
//	2. какие методы зовут места, стоящие в решающих полосах инвентаря.
//
// Метод, который обёртка НЕ перекрывает, уходит встроенному транспорту напрямую —
// то есть мимо второго шанса и мимо сравнения. Поэтому решающему месту звать
// такой метод нельзя, и это проверяется, а не подразумевается.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО НЕ «ЕЩЁ ОДНА ПРОВЕРКА ИЗМЕРЕНИЯ»
//
// Ближайшая фаза переключает источник вердикта ПОТИПОВО. Страж чтения задаёт
// вопрос типо-независимо, поэтому потиповое переключение не накрывает его никаким
// порядком типов: на первом же переключённом типе один вопрос об одном объекте
// получил бы два действующих ответа — новой формы через край и движка через
// стража, — и ни один из них не сверялся бы с другим. Единая точка нужна дважды:
// сегодня она сравнивает, на переключении она будет единственным местом, где
// источник меняется.
//
// Гейт читает синтаксическое дерево, а не текст: слово `Check` встречается в
// комментарии, объясняющем проверку, и предикат по тексту остался бы зелёным при
// снятой проверке. И он утверждает ОБЪЁМ ОСМОТРЕННОГО — «ноль находок» обязано
// быть отличимо от «ноль прочитанного».

package authzcascade

import (
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

// comparatorSeams — имена, которыми перекрытие предъявляет свой вопрос сравнению.
//
// Их два, потому что вопросов две формы: одиночный и страничный. Держать здесь
// имена, а не «любой вызов чего-нибудь», намеренно: перекрытие, которое зовёт
// сравнение как-то иначе, обязано сначала объявить это здесь — то есть стать
// решением, а не незамеченной правкой.
var comparatorSeams = map[string]bool{
	"present":     true,
	"presentPage": true,
}

// decisionLanes — полосы инвентаря, места которых ПРИНИМАЮТ РЕШЕНИЕ о доступе.
//
// Остальные полосы решения не принимают и в предмет этого гейта не входят:
// доставка (предмет вопроса — сама доставка), перечисление (ответ — сведения для
// оператора, на нём ничего не выдаётся и не отказывается), край (сравнивает сам),
// сама обёртка и совпадение имени. Разделение не изобретается здесь — оно взято
// из соседнего инвентаря, чтобы у двух гейтов не завелось двух перечней об одном
// предмете.
var decisionLanes = map[lane]bool{
	laneOwnGate:     true,
	laneClusterOnly: true,
}

// unwrappedQuestionRemainders — вопросы хранилища, которых обёртка НЕ перекрывает,
// с причиной, по которой это законно.
//
// Каждая запись — утверждение о дереве: «ни одно решающее место этого не зовёт».
// Утверждение проверяется ниже в обе стороны, поэтому запись не может пережить
// свой предмет: как только решающее место позовёт такой метод, гейт покраснеет с
// координатой, а не молча примет причину на веру.
var unwrappedQuestionRemainders = map[string]string{
	"CheckWithContextualTuples": "вопрос, несущий факты о строке; его задаёт сама обёртка " +
		"(её внутренний путь) и край, который сравнивает свои вопросы сам",
	"CheckConsistent": "сильное чтение вердикта; собственные стражи его не задают — " +
		"их вопрос идёт обычными дверями",
	"CheckWithContextConsistent": "то же сильное чтение с доводами; задаётся только краем",
	"BatchCheckItems":            "внутренняя дверь обёртки: несёт факты по объекту, вызывается только ею",
	"ListObjects":                "перечисление — сведения, а не решение (полоса перечисления инвентаря)",
	"ListSubjects":               "перечисление — сведения, а не решение",
	"ListUsers":                  "перечисление — сведения, а не решение",
	"Expand":                     "разворот отношения — сведения, а не решение",
	"ReadTuples":                 "чтение кортежей: предмет — доставка либо аудит, не вердикт",
	"ReadTuplesStrong":           "то же сильное чтение: предмет — доставка",
}

// clientOverrides разбирает объявления пакета и отдаёт: метод → сеамы сравнения,
// найденные в его теле. Только методы с приёмником *Client.
func clientOverrides(t *testing.T) (map[string][]string, int) {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	out := map[string][]string{}
	filesRead := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, e.Name(), nil, parser.SkipObjectResolution)
		require.NoError(t, perr)
		filesRead++
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || len(fd.Recv.List) == 0 || fd.Body == nil {
				continue
			}
			star, ok := fd.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			id, ok := star.X.(*ast.Ident)
			if !ok || id.Name != "Client" {
				continue
			}
			seams := []string{}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !comparatorSeams[sel.Sel.Name] {
					return true
				}
				seams = append(seams, sel.Sel.Name)
				return true
			})
			out[fd.Name.Name] = seams
		}
	}
	return out, filesRead
}

// TestEveryDecisionDoorOfTheWrapperPresentsItsQuestionToTheComparator — половина
// первая: у обёртки нет двери, за которой решение уходит непредъявленным.
func TestEveryDecisionDoorOfTheWrapperPresentsItsQuestionToTheComparator(t *testing.T) {
	overrides, filesRead := clientOverrides(t)

	// Предпосылка: «ноль находок» обязано быть отличимо от «ноль прочитанного».
	require.Greater(t, filesRead, 2, "разобрано %d файла(ов) пакета — раскладка изменилась", filesRead)
	require.Greater(t, len(overrides), 5,
		"найдено %d метод(ов) обёртки — приёмник переименован, и гейт замолчал", len(overrides))

	// Двери решения — те перекрытые методы, что инвентарь считает вопросами.
	var doors, silent []string
	for name, seams := range overrides {
		if !questionMethods[name] {
			continue
		}
		doors = append(doors, name)
		if len(seams) == 0 {
			silent = append(silent, name)
		}
	}
	sort.Strings(doors)
	sort.Strings(silent)

	require.NotEmpty(t, doors,
		"обёртка не перекрывает ни одного вопроса хранилища — тогда собственные стражи "+
			"спрашивают транспорт напрямую, и точки, через которую переключается источник "+
			"вердикта, не существует вовсе")
	require.Emptyf(t, silent,
		"эти двери обёртки принимают решение о доступе и не предъявляют его сравнению: %s\n"+
			"Пока хоть одна дверь так делает, потиповое переключение источника вердикта даёт "+
			"два действующих источника истины на один вопрос — один отвечает новой формой, "+
			"другой прежним движком, и сравнение их не видит. Предъявить вопрос — значит "+
			"позвать %v в теле двери.",
		strings.Join(silent, ", "), seamNames())

	t.Logf("разобрано %d файл(ов) пакета; методов обёртки %d, из них дверей решения %d: %s",
		filesRead, len(overrides), len(doors), strings.Join(doors, ", "))
}

// TestNoDecidingSiteReachesAQuestionTheWrapperDoesNotOverride — половина вторая,
// и это та, которую нельзя заменить перечнем.
//
// Метод, которого обёртка не перекрывает, достаётся встроенному транспорту
// напрямую: второго шанса нет, сравнения нет, и переключать его будет нечем.
// Поэтому решающему месту звать такой метод нельзя. Обратная сторона проверяется
// тут же: остаток, которому больше нечего исключать, — находка, иначе он
// достанется следующей слепой зоне.
func TestNoDecidingSiteReachesAQuestionTheWrapperDoesNotOverride(t *testing.T) {
	overrides, _ := clientOverrides(t)

	root := filepath.Join("..", "..") // services/iam
	found := map[string][]string{}
	files, calls := 0, 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if info.IsDir() {
			if info.Name() == "tests" || info.Name() == "testsupport" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		files++
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		for fn, methods := range questionsIn(f) {
			calls += len(methods)
			found[rel+":"+fn] = append(found[rel+":"+fn], methods...)
		}
		return nil
	})
	require.NoError(t, err)
	require.Greater(t, files, 200, "разобрано только %d файл(ов) — дерево сдвинулось", files)
	require.Greater(t, calls, 15, "найдено только %d вопрос(ов) — совпадение перестало срабатывать", calls)

	var bypass []string
	decidingSites, decidingCalls := 0, 0
	reached := map[string]bool{} // метод → его зовёт решающее место
	for key, methods := range found {
		if !decisionLanes[askingSites[key]] {
			continue
		}
		decidingSites++
		decidingCalls += len(methods)
		for _, m := range methods {
			reached[m] = true
			if _, overridden := overrides[m]; overridden {
				continue
			}
			bypass = append(bypass, key+" → "+m)
		}
	}
	sort.Strings(bypass)

	require.Greater(t, decidingSites, 10,
		"решающих мест найдено %d — полосы инвентаря разъехались с этим гейтом, и он "+
			"перестал рассматривать предмет", decidingSites)
	require.Emptyf(t, bypass,
		"эти места ПРИНИМАЮТ РЕШЕНИЕ О ДОСТУПЕ и зовут вопрос, которого обёртка не "+
			"перекрывает, — значит он уходит встроенному транспорту напрямую, мимо второго "+
			"шанса и мимо сравнения форм:\n  %s\n"+
			"Исходов два: перекрыть этот вопрос в обёртке (и предъявить его сравнению), либо "+
			"перевести место на дверь, которая перекрыта. Третьего нет: пока такой вызов "+
			"существует, потиповое переключение источника вердикта не накрывает его никаким "+
			"порядком типов.", strings.Join(bypass, "\n  "))

	// Остаток обязан истекать сам: запись, которую больше нечего исключать,
	// становится ложным утверждением о дереве.
	var stale []string
	for m := range unwrappedQuestionRemainders {
		if _, overridden := overrides[m]; overridden {
			stale = append(stale, m+" (обёртка его теперь перекрывает)")
			continue
		}
		if !questionMethods[m] {
			stale = append(stale, m+" (инвентарь больше не считает его вопросом)")
		}
	}
	sort.Strings(stale)
	require.Emptyf(t, stale,
		"эти записи остатка больше нечего исключают — снимите их, иначе остаток начинает "+
			"ручаться за то, чего нет:\n  %s", strings.Join(stale, "\n  "))

	// И зеркало: вопрос, который обёртка не перекрывает, обязан быть НАЗВАН в
	// остатке. Молчаливое непокрытие — это ровно та слепая зона, ради которой
	// гейт написан.
	var undeclared []string
	for m := range questionMethods {
		if _, overridden := overrides[m]; overridden {
			continue
		}
		if unwrappedQuestionRemainders[m] == "" {
			undeclared = append(undeclared, m)
		}
	}
	sort.Strings(undeclared)
	require.Emptyf(t, undeclared,
		"эти вопросы хранилища обёртка не перекрывает и причина не названа: %s\n"+
			"Непокрытый вопрос — дверь мимо точки. Либо перекройте её, либо объявите "+
			"причину в unwrappedQuestionRemainders, чтобы следующий читатель проверял "+
			"утверждение, а не догадывался.", strings.Join(undeclared, ", "))

	t.Logf("разобрано %d файл(ов) продукта; вопросов %d в %d месте(ах); "+
		"решающих мест %d с %d вопрос(ами); обёртка перекрывает %d вопрос(ов), "+
		"остаток объявлен на %d",
		files, calls, len(found), decidingSites, decidingCalls,
		countOverriddenQuestions(overrides), len(unwrappedQuestionRemainders))
}

// TestTheCompositionRootWiresTheComparatorIntoThePoint — провязка в пустоту
// выглядит исполненной.
//
// Всё вышенаписанное держится на одном факте: сравнитель дошёл до значения,
// которое стражам выдаёт композиционный корень. Если он туда не дошёл, каждая
// дверь честно зовёт `present`, `present` честно возвращает no-op, гейты выше
// зелёные — и не сравнивается ничего. Поэтому провязка проверяется отдельно, и
// проверяется у СЕБЯ в дереве, а не в памяти ревьюера.
//
// Рантайм это же условие держит отказом в старте (`ownGateWiringComplaint`);
// здесь — тем, что правку нельзя внести незаметно.
func TestTheCompositionRootWiresTheComparatorIntoThePoint(t *testing.T) {
	const root = "../../cmd/kacho-iam"
	entries, err := os.ReadDir(root)
	require.NoError(t, err)

	wired, guarded, filesRead := false, false, 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, filepath.Join(root, e.Name()), nil, parser.SkipObjectResolution)
		require.NoError(t, perr)
		filesRead++
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "WithComparator":
				wired = true
			case "ComparatorWired":
				guarded = true
			}
			return true
		})
	}

	require.Greater(t, filesRead, 1, "разобрано %d файл(ов) корня — раскладка изменилась", filesRead)
	require.True(t, wired,
		"композиционный корень не провязывает сравнение в значение, которое выдаёт стражам. "+
			"Тогда каждая дверь предъявляет вопрос no-op'у: все проверки выше остаются "+
			"зелёными, а сравнивается ноль решений")
	require.True(t, guarded,
		"отсутствие провязки не проверяется при старте. Пропажу сравнения нельзя заметить по "+
			"ответам — они не меняются, — поэтому её обязан ловить отказ в старте, а не "+
			"обзор диффа")
	t.Logf("разобрано %d файл(ов) композиционного корня: провязка найдена, отказ в старте на неё опирается", filesRead)
}

// TestTheSeamMatcherSeesTheCallAndNotItsProse — предпосылка самого гейта.
//
// Гейт выше зелёный ровно настолько, насколько его совпадение отличает вызов от
// разговора о вызове. Над деревом пропущенная форма неотличима от её отсутствия,
// поэтому совпадению подаются исходники с известным ответом — в обе стороны.
func TestTheSeamMatcherSeesTheCallAndNotItsProse(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{
			name: "вызов сеама виден",
			body: "func (c *Client) Check() { settle := c.present(ctx, s, r, o, nil); _ = settle }",
			want: true,
		},
		{
			name: "страничный сеам виден",
			body: "func (c *Client) BatchCheckWithContext() { _ = c.presentPage(ctx, s, r, nil, nil) }",
			want: true,
		},
		{
			name: "комментарий о сеаме — не сеам",
			body: "func (c *Client) Check() {\n\t// c.present(ctx, s, r, o, nil) объясняет дверь ниже\n}",
			want: false,
		},
		{
			name: "строка, похожая на вызов, — не сеам",
			body: `func (c *Client) Check() { _ = "c.present(ctx, s, r, o, nil)" }`,
			want: false,
		},
		{
			name: "дверь без сеама — находка",
			body: "func (c *Client) Check() { _, _ = c.Relations.Check(ctx, s, r, o) }",
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "package p\n\nvar ctx, s, r, o any\n\ntype Client struct{}\n\n" + tc.body + "\n"
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "synthetic.go", src, parser.SkipObjectResolution)
			require.NoError(t, err, "фикстура обязана разбираться")

			seen := false
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if ok && comparatorSeams[sel.Sel.Name] {
					seen = true
				}
				return true
			})
			require.Equal(t, tc.want, seen,
				"совпадение обязано видеть предъявление вопроса в каждой его форме и только "+
					"в настоящей: пропущенная форма — это дверь, за которой спрашивают "+
					"молча, и над деревом такой пропуск неотличим от отсутствия двери")
		})
	}
}

func seamNames() []string {
	out := make([]string, 0, len(comparatorSeams))
	for n := range comparatorSeams {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func countOverriddenQuestions(overrides map[string][]string) int {
	n := 0
	for name := range overrides {
		if questionMethods[name] {
			n++
		}
	}
	return n
}
