// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// history_question_vertex.go — РАЗБОР: какой ВЕРШИНЕ проверка задаёт свой вопрос
// об истории (задача PRO-Robotech/kaname#63).
//
// # ПРЕДМЕТ
//
// Здесь вливают СХЛОПЫВАНИЕМ: коммит полосы предком ствола не становится
// никогда. Значит всякая проверка, чей вопрос звучит «входит ли эта ревизия в
// историю», отвечает о ДВУХ РАЗНЫХ деревьях — о ветке до вливания и о стволе
// после, — и её зелёный на запросе слияния на ствол НЕ ПЕРЕНОСИТСЯ by
// construction.
//
// Цена измерена, а не предположена: ствол службы был красен ДВА вливания подряд
// (`ba43277c`, `c56218b6`) по гейту датировки приёмок, судившему `HEAD`, и оба
// запроса слияния несли зелёный обязательный контекст.
//
// # ЧТО СЧИТАЕТСЯ ВОПРОСОМ ОБ ИСТОРИИ — И ПОЧЕМУ НЕ ВСЯКИЙ ВЫЗОВ git
//
// Вопрос об истории — тот, чей ответ зависит от того, ЧТО ВХОДИТ В ИСТОРИЮ
// названной вершины. Глаголы перечислены в `historyVerbs`, и перечень узкий
// НАМЕРЕННО: широкий сделал бы находкой всякий вызов git, и первое же ложное
// срабатывание сняло бы гейт.
//
// Не считаются вопросом об истории и названы здесь, чтобы их отсутствие не
// читалось как слепота:
//
//   - `rev-parse --show-toplevel` — вопрос про КОРЕНЬ РАБОЧЕГО КАТАЛОГА, истории
//     не касается вовсе;
//   - голый `rev-parse HEAD` — ПРОВЕНАНС: «какая у меня сейчас ревизия». Он не
//     спрашивает о вхождении, он именует. Таких мест в дереве несколько
//     (отпечаток сетки замера, писатель отчётов, сборщик поставки), и все они
//     правы: ревизия прогона и есть ревизия рабочего дерева;
//   - `ls-tree` / `show <ссылка>:<путь>` / `grep <ссылка>` — чтение СОСТАВА по
//     названной ссылке. Ответ от истории не зависит: он про содержимое дерева
//     этой ревизии;
//   - `status --porcelain` — состояние рабочего каталога.
//
// # ФОРМЫ ЗАПИСИ ВЫЗОВА, КОТОРЫЕ РАЗБОР ОБЯЗАН ЗНАТЬ (testing.md §«Гейт на класс», п. 7)
//
// Единица — ВЫЗОВ, а не строка и не файл: два вызова в соседних строках задают
// вопросы разным вершинам, и склейка их в одну единицу дала бы вердикт ни о чём.
//
//	Go     `exec.Command("git", "-C", dir, "merge-base", "--is-ancestor", a, b)`
//	Go     `gitenv.Command(root, "rev-list", "--count", "HEAD")`
//	Go     `git("merge-base", "--is-ancestor", hash, trunk)` — замыкание-помощник
//	shell  `git -C "$dir" merge-base --is-ancestor "$a" HEAD`
//	python `subprocess.run(["git", "-C", root, "rev-list", "--count", "HEAD"])`
//
// Go разбирается ДЕРЕВОМ (`go/parser`): узел-вызов даёт свои аргументы целиком и
// не путает их с соседними. Прочие языки — построчно, и это названо границей, а
// не выдано за разбор.
//
// # ПОЧЕМУ РАЗБОР ЧИТАЕТ ИСПОЛНЯЕМУЮ ЧАСТЬ, А НЕ ТЕКСТ
//
// Корпус этого дерева объясняет свои проверки прозой, и проза поминает и
// `merge-base`, и `HEAD` — вот прямо в этой шапке. Разбор по подстроке краснел бы
// на собственном объяснении (`testing.md` §«Гейт на класс», п. 4). В Go
// комментарий узлом-вызовом не является by construction; в прочих языках строка
// комментария снимается до разбора, и снятое СЧИТАЕТСЯ отдельной величиной.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// historyVerbs — глаголы, задающие вопрос об истории. Значение — условие, при
// котором глагол этот вопрос действительно задаёт: пустое означает «всегда».
//
// Условие есть у трёх глаголов, и у каждого своя причина:
//
//	cat-file   — вопросом о принадлежности он становится с `-e`/`-t` (есть ли
//	             такой объект здесь); `cat-file blob <ссылка>:<путь>` читает
//	             содержимое и об истории не спрашивает;
//	diff       — вопросом об истории он становится на ДИАПАЗОНЕ (`a..b`, `a...b`):
//	             трёхточечная форма считает общего предка, двухточечная сравнивает
//	             две точки истории. Сравнение рабочего дерева с одной ревизией —
//	             не он;
//	rev-parse  — вопросом он становится с `--verify` («разрешается ли эта ссылка
//	             здесь»); без него это именование, см. шапку.
var historyVerbs = map[string]string{
	"merge-base": "",
	"rev-list":   "",
	"log":        "",
	"describe":   "",
	"cat-file":   "-e|-t",
	"diff":       "range",
	"rev-parse":  "--verify",
}

// Vertex — вершина, относительно которой задан вопрос об истории.
type Vertex int

const (
	// VertexUnnamed — вершина ЛИТЕРАЛОМ НЕ НАЗВАНА: она пришла переменной либо
	// оставлена умолчанию (`git log` без ревизии есть `git log HEAD`).
	//
	// Это НЕ «вершина неизвестна разбору» и не молчание: состояние объявлено,
	// считается и требует записанного довода — иначе «сказано, судит она ствол
	// или рабочую вершину» осталось бы необеспеченным ровно там, где вершину и
	// не видно.
	VertexUnnamed Vertex = iota
	// VertexHead — среди литералов стоит рабочая вершина.
	VertexHead
	// VertexTrunk — среди литералов стоит объявленный ствол.
	VertexTrunk
)

// String называет вершину словом вызывающего, а не номером.
func (v Vertex) String() string {
	switch v {
	case VertexHead:
		return "рабочая вершина"
	case VertexTrunk:
		return "ствол"
	default:
		return "не названа литералом"
	}
}

// HistoryQuestion — один вызов git, задающий вопрос об истории.
type HistoryQuestion struct {
	File   string
	Line   int
	Verb   string
	Vertex Vertex
	// Literals — литеральные аргументы вызова, как их прочитал разбор. Нужны
	// читателю находки: без них он не отличит свой вызов от соседнего.
	Literals []string
}

// String — координата и вердикт одной строкой.
func (q HistoryQuestion) String() string {
	return fmt.Sprintf("%s:%d: git %s [%s] — вершина: %s",
		q.File, q.Line, q.Verb, strings.Join(q.Literals, " "), q.Vertex)
}

// HistoryCensus — ОБЪЁМ ОСМОТРЕННОГО. «Ноль находок» обязано быть отличимо от
// «ноль прочитанного», а «ноль вопросов» — от «разбор не дошёл до вызовов».
type HistoryCensus struct {
	// FilesRead — файлов прочитано; GoParsed — из них разобрано деревом.
	FilesRead int
	GoParsed  int
	// GoUnparsed — файлов Go, которые разобрать НЕ УДАЛОСЬ. Отдельная величина:
	// неразобранный файл невидим, и его молчание неотличимо от чистоты.
	GoUnparsed []string
	// LinesStripped — строк комментария, снятых до разбора в не-Go файлах.
	// Печатается затем, чтобы «проза о merge-base не сработала» было ЗАМЕРОМ,
	// а не обещанием.
	LinesStripped int
	// Questions — вопросов об истории всего; по вершинам — три величины ниже.
	Questions int
	Head      int
	Trunk     int
	Unnamed   int
	// ByVerb — сколько вопросов задал каждый глагол. Глагол, давший ноль,
	// означает, что этой формы в дереве нет, а не что разбор её не знает.
	ByVerb map[string]int
}

// ScanHistoryQuestions — все вопросы об истории в названном корпусе.
//
// Корпус приходит ГОТОВЫМ (`rel -> содержимое`), а не читается отсюда: так
// инъекция подаёт разбору свой вход, не заводя второго читателя дерева.
//
// trunkRefs — имена, которые в этом дереве ОБЪЯВЛЕНЫ стволом. Перечень —
// параметр, а не константа: иначе ось «ствол назван» нечем подать синтетике, и
// она осталась бы без доказательства падучести.
func ScanHistoryQuestions(corpus map[string][]byte, trunkRefs []string) ([]HistoryQuestion, HistoryCensus) {
	census := HistoryCensus{ByVerb: map[string]int{}}
	var out []HistoryQuestion

	rels := make([]string, 0, len(corpus))
	for rel := range corpus {
		rels = append(rels, rel)
	}
	sort.Strings(rels)

	for _, rel := range rels {
		census.FilesRead++
		src := corpus[rel]
		var qs []HistoryQuestion
		switch {
		case strings.HasSuffix(rel, ".go"):
			var ok bool
			qs, ok = goHistoryQuestions(rel, src, trunkRefs)
			if ok {
				census.GoParsed++
			} else {
				census.GoUnparsed = append(census.GoUnparsed, rel)
			}
		default:
			var stripped int
			qs, stripped = lineHistoryQuestions(rel, src, trunkRefs)
			census.LinesStripped += stripped
		}
		for _, q := range qs {
			census.Questions++
			census.ByVerb[q.Verb]++
			switch q.Vertex {
			case VertexHead:
				census.Head++
			case VertexTrunk:
				census.Trunk++
			default:
				census.Unnamed++
			}
			out = append(out, q)
		}
	}
	return out, census
}

// goHistoryQuestions — вопросы об истории в одном файле Go.
//
// Единица — узел-вызов: аргументы берутся у него, поэтому соседний вызов в
// вопрос не затекает. Второй возвращаемый — разобрался ли файл: неразобранный
// обязан быть НАЗВАН, а не пропущен молча.
func goHistoryQuestions(rel string, src []byte, trunkRefs []string) ([]HistoryQuestion, bool) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, src, 0)
	if err != nil {
		return nil, false
	}

	// Постоянные файла разрешаются ОДНИМ уровнем: `const trunkRefName =
	// "origin/main"`, переданная аргументом, называет ствол ровно так же, как
	// голый литерал. Глубже разбор не идёт намеренно — вычисление значения
	// произвольного выражения есть интерпретатор, а не разбор, и его молчание
	// было бы неотличимо от ответа.
	consts := fileStringConsts(file)

	var out []HistoryQuestion
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		lits := make([]string, 0, len(call.Args))
		for _, a := range call.Args {
			lits = append(lits, stringParts(a, consts)...)
		}
		if q, ok := questionOf(lits, trunkRefs); ok {
			q.File = rel
			q.Line = fset.Position(call.Lparen).Line
			out = append(out, q)
		}
		return true
	})
	return out, true
}

// fileStringConsts — постоянные и переменные УРОВНЯ ФАЙЛА со строковым
// литералом в значении.
func fileStringConsts(file *ast.File) map[string]string {
	out := map[string]string{}
	for _, d := range file.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
			continue
		}
		for _, s := range gd.Specs {
			vs, ok := s.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				if lit, ok := basicString(vs.Values[i]); ok {
					out[name.Name] = lit
				}
			}
		}
	}
	return out
}

// basicString — строковый литерал выражения, если это он.
func basicString(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return v, true
}

// stringParts — строковые части выражения: сам литерал, значение постоянной
// файла, либо обе стороны склейки (`base + "...HEAD"` даёт и то, и другое).
//
// Склейка разбирается ОБЕИМИ сторонами намеренно: диапазон `<ствол>...HEAD`
// записывается ровно так, и потеряв правую часть, разбор объявил бы вершину
// неназванной там, где она названа прямо.
func stringParts(e ast.Expr, consts map[string]string) []string {
	switch v := e.(type) {
	case *ast.BasicLit:
		if s, ok := basicString(v); ok {
			return []string{s}
		}
	case *ast.Ident:
		if s, ok := consts[v.Name]; ok {
			return []string{s}
		}
	case *ast.BinaryExpr:
		if v.Op == token.ADD {
			return append(stringParts(v.X, consts), stringParts(v.Y, consts)...)
		}
	case *ast.ParenExpr:
		return stringParts(v.X, consts)
	}
	return nil
}

// pyCallForm — форма вызова git в Python: список аргументов, первый — `git`.
// Другой формы в этом дереве нет (замер — перепись гейта), а эта отличает вызов
// от ПРОЗЫ, которой здесь много: предикаты в текстах фикстур записаны теми же
// словами, и разбор по подстроке считал бы их вызовами.
var pyCallForm = regexp.MustCompile(`\[\s*["']git["']`)

// shellCallForm — `git` в КОМАНДНОЙ ПОЗИЦИИ, и позиции ПЕРЕЧИСЛЕНЫ, а не сведены
// к «после пробела».
//
// Замер, ради которого перечень: правило «git после любого пробельного знака»
// прочитало как вызов строку `echo "проверить так: git rev-list --count HEAD"` —
// то есть текст, который печатают человеку. В корпусе этого дерева такие строки
// обычны, и гейт краснел бы на объяснении самого себя.
//
// Перечень выведен из форм, стоящих в дереве: голая команда с начала строки,
// подстановка `$( … )`, её же вид у Make (`$(shell … )`), и команда после
// разделителя (`|`, `;`, `&&`, `||`, `!`, `then`, `do`).
//
// ОБРАТНОЙ КАВЫЧКИ В ПЕРЕЧНЕ НЕТ, и это ЗАМЕР, а не пропуск: старой формы
// подстановки в этом дереве не встречается вовсе, а обратная кавычка ВСТРЕЧАЕТСЯ —
// ею в текстах, печатаемых человеку, выделяют команду. Признав её командной
// позицией, разбор прочитал бы как вызов каждую такую строку.
var shellCallForm = regexp.MustCompile(
	"(^|\\$\\(|\\$\\(shell |\\| |; |&& |\\|\\| |! |then |do )git\\s")

// lineHistoryQuestions — вопросы об истории в файле не на Go: построчно.
//
// ГРАНИЦЫ НАЗВАНЫ, А НЕ ЗАМОЛЧАНЫ, и их две:
//
//  1. вызов, разнесённый переносом строки, этим разбором не читается. В этом
//     дереве таких нет, и появится — попадёт в слепую зону, а не в находки;
//  2. читается ТОЛЬКО форма вызова (`pyCallForm`, `shellCallForm`). Проза,
//     цитирующая предикат теми же словами, вызовом не считается — иначе разбор
//     краснел бы на объяснении проверки, а её самой не видел. Замер, ради
//     которого это написано: без формы вызова разбор дал ЧЕТЫРЕ вопроса об
//     истории в одном файле проб, и все четыре были строковыми литералами с
//     прозой о предикатах.
//
// Строка комментария снимается ДО разбора и считается отдельно.
func lineHistoryQuestions(rel string, src []byte, trunkRefs []string) ([]HistoryQuestion, int) {
	var out []HistoryQuestion
	stripped := 0
	py := strings.HasSuffix(rel, ".py")
	for i, line := range strings.Split(string(src), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
			stripped++
			continue
		}
		if py {
			if !pyCallForm.MatchString(t) {
				continue
			}
		} else if !shellCallForm.MatchString(t) {
			continue
		}
		toks := lineTokens(t)
		if q, ok := questionOf(toks, trunkRefs); ok {
			q.File = rel
			q.Line = i + 1
			out = append(out, q)
		}
	}
	return out, stripped
}

// lineTokens — слова строки, очищенные от кавычек, скобок и запятых. Форма
// списка (`["git", "-C", root, "log"]`) и форма команды (`git -C "$d" log`)
// сводятся к одному перечню слов.
func lineTokens(line string) []string {
	f := strings.FieldsFunc(line, func(r rune) bool {
		switch r {
		case ' ', '\t', ',', '(', ')', '[', ']', '"', '\'', '`':
			return true
		}
		return false
	})
	return f
}

// questionOf — задаёт ли перечень слов вопрос об истории, и какой вершине.
func questionOf(words []string, trunkRefs []string) (HistoryQuestion, bool) {
	verb := ""
	for _, w := range words {
		cond, ok := historyVerbs[w]
		if !ok {
			continue
		}
		if !verbAsks(cond, words) {
			continue
		}
		verb = w
		break
	}
	if verb == "" {
		return HistoryQuestion{}, false
	}
	q := HistoryQuestion{Verb: verb, Vertex: VertexUnnamed, Literals: words}
	// ПОРЯДОК РАЗРЕШЕНИЯ НЕСУЩИЙ: рабочая вершина сильнее ствола. Диапазон
	// `<ствол>...HEAD` называет ОБА, и вопрос в нём задан всё-таки вершине —
	// состав ответа меняется вместе с нею.
	for _, w := range words {
		if namesHead(w) {
			q.Vertex = VertexHead
			return q, true
		}
	}
	for _, w := range words {
		for _, tr := range trunkRefs {
			if w == tr || strings.Contains(w, tr) {
				q.Vertex = VertexTrunk
				return q, true
			}
		}
	}
	return q, true
}

// verbAsks — задаёт ли глагол вопрос об истории при этих аргументах.
func verbAsks(cond string, words []string) bool {
	switch cond {
	case "":
		return true
	case "range":
		for _, w := range words {
			if strings.Contains(w, "..") {
				return true
			}
		}
		return false
	default:
		for _, want := range strings.Split(cond, "|") {
			for _, w := range words {
				if w == want {
					return true
				}
			}
		}
		return false
	}
}

// namesHead — называет ли слово рабочую вершину.
//
// Формы перечислены, а не угаданы: голое `HEAD`, сдвиг (`HEAD~1`, `HEAD^`),
// координата состава (`HEAD:путь`) и хвост диапазона (`...HEAD`). Слово, лишь
// СОДЕРЖАЩЕЕ буквы head (`heading`, `HEADER`), вершиной не является — иначе
// разбор находил бы её в чужих именах.
func namesHead(w string) bool {
	i := strings.Index(w, "HEAD")
	if i < 0 {
		return false
	}
	// Слева от вершины законны только знаки диапазона.
	if i > 0 && strings.Trim(w[:i], ".") != "" {
		return false
	}
	rest := w[i+len("HEAD"):]
	if rest == "" {
		return true
	}
	switch rest[0] {
	case '~', '^', ':', '@':
		return true
	}
	return false
}
