// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// read_path_concat.go — разбор: НА ПУТИ ЧТЕНИЯ СРАВНИВАЮТСЯ КОЛОНКИ, А НЕ ИХ
// СКЛЕЙКА.
//
// # Предмет
//
// Склейка колонки внутри УСЛОВИЯ выводит колонку из-под индекса: сравнивать
// приходится вычисленное значение, а вычисленное значение отбирает строки
// только ПОСЛЕ того, как они прочитаны. Ответ от этого не меняется, стоимость
// растёт с числом строк в системе, и заметно это только под нагрузкой.
//
// Класс измерен, а не предположен. Починка горячего пути перевела на пару
// колонок два места — вердикт и перечисление объектов. Перепись ПО СВОЙСТВУ
// («колонка склеивается там, где значение сравнивается») дала на том же дереве
// ЧЕТЫРЕ: два обратных вопроса и две точки прибора замера, гасившие индекс
// области. У одной из четырёх комментарий рядом обещал «колонками, а не
// склейкой» — то есть был ложен.
//
// Поведенческой пробы для этого мало: она мерит ту точку входа, которую зовёт,
// и молчит об остальных — ровно это и позволило долгу прожить. Свойство —
// свойство ДЕРЕВА, и держать его обязан обход дерева.
//
// # Объём ВЫВОДИТСЯ, а не выписывается
//
// Каталоги берутся у объявления предмета замера (`scalegrid/fingerprint.go`) —
// того же источника, которым определяется предмет прибора. Выписанный перечень
// не двинулся бы от нового каталога и продолжал бы сторожить прежние.
//
// # Читается ИСПОЛНЯЕМАЯ часть
//
// Литералы разбираются по синтаксическому дереву Go (SQL в Go-комментарии кодом
// не является), внутри литерала снимаются SQL-комментарии, а содержимое
// строковых литералов SQL ЗАКРЫВАЕТСЯ с сохранением длины — иначе слово внутри
// литерала читается как ключевое, условие обрывается, и гейт молчит ровно на
// той форме, ради которой написан.
//
// # Порт с монорепо — пара файлов названа, а не умолчана
//
// Перенесено с `PRO-Robotech/kacho:internal/repohygiene/readpathconcat_test.go`
// (снято вынесением службы — `kacho#2598`; предмет жив здесь, задача #17).
// Изменилось: координата объявления предмета замера (приставки `services/iam/`
// в самостоятельном клоне нет), разбор вынесен из пробы в пакет `check`, разбор
// литералов Go взят у соседнего семейства того же дерева и живёт здесь одной
// копией. Осталось дословно: имя гейта, перечни ключевых слов условия, границы
// цепочки склейки и счёт законного близнеца.
//
// Близнеца в платформе нет: семейство снято там вместе со службой (ban #20).
package check

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

	"github.com/PRO-Robotech/kaname/internal/treeposture"
)

// FingerprintSourceRel — объявление предмета замера, из которого ВЫВОДИТСЯ
// объём этого разбора.
//
// Координата дана ОТ КОРНЯ ДЕРЕВА ПЛАТФОРМЫ, как и всё, что резолвится
// `treeposture`: приставка снимается самим резолвом, когда модуль стоит
// самостоятельным клоном. Своя, «модульная» форма здесь была бы вторым
// написанием одной координаты — а сам предмет замера объявляет каталоги именно
// в этой форме, и разбор обязан читать ту же.
const FingerprintSourceRel = "services/iam/internal/repo/kaname/pg/scalegrid/fingerprint.go"

// fingerprintDirDecl — строка вида `verdictDir = "…"` в этом объявлении.
var fingerprintDirDecl = regexp.MustCompile(`(?m)^\s*(\w*[Dd]ir)\s*=\s*"([^"]+)"`)

// concatQualifiedColumn — квалифицированная колонка: `alias.column`.
var concatQualifiedColumn = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\b`)

// predicateOpeners / predicateClosers — где условие начинается и где кончается.
//
// Перечни объявлены здесь, потому что они и есть СОДЕРЖАНИЕ запрета: слово,
// внесённое в закрыватели без основания, немедленно делает разбор слепым на
// целую форму условия.
var (
	predicateOpeners = []string{"ON", "WHERE", "AND", "OR", "HAVING"}
	predicateClosers = []string{
		"SELECT", "FROM", "JOIN", "GROUP", "ORDER", "LIMIT", "UNION", "WITH",
		"VALUES", "RETURNING", "INSERT", "UPDATE", "DELETE", "SET", "CASE", "THEN",
		"ELSE", "END", "AS",
	}
)

// ConcatFinding — одно условие, сравнивающее склейку колонки.
type ConcatFinding struct {
	File    string
	Line    int
	Operand string
}

// ConcatCensus — объём осмотренного.
type ConcatCensus struct {
	Dirs               []string
	Files              int
	Literals           int
	Segments           int
	ConcatsInPredicate int
	// ConcatsElsewhere — законный близнец: склейка в ПРОЕКЦИИ. Без него «находок
	// ноль» неотличимо от «разбор ничего не прочитал».
	ConcatsElsewhere int
}

// ReadPathFile — файл предмета замера: координата для находки и путь на диске.
type ReadPathFile struct {
	// Rel — координата в том виде, в каком её объявляет предмет замера; ею
	// называется находка.
	Rel string
	// Abs — путь, по которому файл читается.
	Abs string
}

// ReadPathGoFiles — не-тестовые .go каталогов, составляющих предмет замера.
//
// Координаты приводятся к посадке ДЕТЕКТОРОМ дерева (`treeposture.PathUnder`), а
// не складываются с корнем здесь: правило приведения живёт в одном месте дерева,
// и второй его копии не заводится. Первая редакция порта складывала путь сама —
// и её поймал гейт дерева `TestPlatformCoordinatesTouchingTheTreeAreAnchoredInTheModule`
// двумя находками: под чужим деревом такой путь указал бы на чужой файл, и
// вердикт был бы о нём.
//
// Каталог, в котором таких файлов нет вовсе (каталог миграций), в объём просто
// не приносит ничего — исключать его СПИСКОМ не нужно, и списка здесь нет.
func ReadPathGoFiles(root string) (files []ReadPathFile, dirs []string, err error) {
	src, err := treeposture.PathUnder(root, FingerprintSourceRel)
	if err != nil {
		return nil, nil, err
	}
	body, err := os.ReadFile(src) // #nosec G304 -- путь получен детектором дерева от СВОЕГО корня
	if err != nil {
		return nil, nil, err
	}
	for _, m := range fingerprintDirDecl.FindAllStringSubmatch(string(body), -1) {
		dirs = append(dirs, m[2])
		abs, derr := treeposture.PathUnder(root, m[2])
		if derr != nil {
			return nil, dirs, derr
		}
		entries, derr := os.ReadDir(abs)
		if derr != nil {
			return nil, dirs, derr
		}
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			files = append(files, ReadPathFile{Rel: m[2] + "/" + n, Abs: filepath.Join(abs, n)})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Rel < files[j].Rel })
	sort.Strings(dirs)
	return files, dirs, nil
}

// CollectPredicateConcats — находки и объём по перечню файлов.
//
// read подаётся вызывающим: инъекция кормит разбор синтетикой, не трогая диск.
func CollectPredicateConcats(files []ReadPathFile, read func(abs string) ([]byte, error)) (
	[]ConcatFinding, ConcatCensus, error,
) {
	var c ConcatCensus
	var out []ConcatFinding
	for _, f := range files {
		rel := f.Rel
		body, err := read(f.Abs)
		if err != nil {
			return nil, c, err
		}
		c.Files++
		for _, lit := range SQLLiteralsOfGo(filepath.Base(rel), body) {
			if !strings.Contains(lit.SQL, "kaname.") {
				continue
			}
			c.Literals++
			sql := stripSQLLineComments(lit.SQL)
			masked := maskSQLStrings(sql)
			for _, seg := range predicateSegmentsOf(masked) {
				c.Segments++
				for _, sp := range concatOperandSpans(masked[seg.at : seg.at+len(seg.text)]) {
					op := sql[seg.at+sp[0] : seg.at+sp[1]]
					if !concatQualifiedColumn.MatchString(masked[seg.at+sp[0] : seg.at+sp[1]]) {
						continue
					}
					c.ConcatsInPredicate++
					out = append(out, ConcatFinding{
						File:    rel,
						Line:    lit.Line + strings.Count(sql[:seg.at+sp[0]], "\n"),
						Operand: strings.Join(strings.Fields(op), " "),
					})
				}
			}
			c.ConcatsElsewhere += countConcatsOutsidePredicates(masked)
		}
	}
	return out, c, nil
}

// GoSQLLiteral — литерал SQL, найденный в исходнике Go.
type GoSQLLiteral struct {
	SQL  string
	Line int
}

// SQLLiteralsOfGo — литералы, разобранные ПО СИНТАКСИЧЕСКОМУ ДЕРЕВУ Go.
//
// Не по тексту файла: SQL, стоящий в Go-комментарии, кодом не является, и
// читать его как код значило бы краснеть на объяснении запрета.
//
// СКЛЕЙКА РАЗБИРАЕТСЯ ЦЕЛИКОМ. Кусок запроса, собранный конкатенацией, сам по
// себе не несёт ни параметров, ни предикатов — они в соседних слагаемых, — и
// судить его отдельно значило бы объявлять находкой каждый второй фрагмент.
// Слагаемые, не являющиеся литералами, подставляются как `$?`: их значение
// неизвестно, но известно, что там стоит ВЫЧИСЛЯЕМОЕ.
func SQLLiteralsOfGo(name string, body []byte) []GoSQLLiteral {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, body, 0)
	if err != nil {
		return nil
	}
	consumed := map[ast.Node]bool{}
	var out []GoSQLLiteral
	ast.Inspect(file, func(n ast.Node) bool {
		be, ok := n.(*ast.BinaryExpr)
		if !ok || be.Op != token.ADD {
			return true
		}
		text, anyLit := flattenGoConcat(be, consumed)
		if anyLit {
			out = append(out, GoSQLLiteral{SQL: text, Line: fset.Position(be.Pos()).Line})
		}
		return true
	})
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || consumed[lit] {
			return true
		}
		s, uerr := strconv.Unquote(lit.Value)
		if uerr != nil {
			return true
		}
		out = append(out, GoSQLLiteral{SQL: s, Line: fset.Position(lit.Pos()).Line})
		return true
	})
	return out
}

// flattenGoConcat — свести выражение сложения строк в один текст.
func flattenGoConcat(e ast.Expr, consumed map[ast.Node]bool) (string, bool) {
	switch v := e.(type) {
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "$?", false
		}
		l, okl := flattenGoConcat(v.X, consumed)
		r, okr := flattenGoConcat(v.Y, consumed)
		return l + r, okl || okr
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "$?", false
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return "$?", false
		}
		consumed[v] = true
		return s, true
	default:
		// Не литерал: значение неизвестно, но известно, что оно ВЫЧИСЛЯЕМОЕ.
		return "$?", false
	}
}

// segment — кусок SQL, стоящий ПОД условием, и его смещение в литерале.
type segment struct {
	text string
	at   int
}

// stripSQLLineComments — снятие `--`-комментариев внутри литерала.
//
// Без него разбор краснеет на ОБЪЯСНЕНИИ собственного запрета: комментарий у
// исправленного места называет прежнюю форму дословно, и это правильно —
// комментарий обязан называть то, что запрещает.
func stripSQLLineComments(sql string) string {
	var b strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// maskSQLStrings — содержимое строковых литералов SQL закрыто, длина сохранена.
//
// Смещения остаются годными для ИСХОДНОГО текста, поэтому сообщение находки
// по-прежнему называет то, что написано, а не маску.
func maskSQLStrings(sql string) string {
	b := []byte(sql)
	in := false
	for i := 0; i < len(b); i++ {
		if b[i] == '\'' {
			in = !in
			continue
		}
		if in && b[i] != '\n' {
			b[i] = '~'
		}
	}
	return string(b)
}

// predicateSegmentsOf — куски, стоящие под условием.
//
// Разбор по ключевым словам, а не по строкам файла: условие переносится, и
// построчный разбор объявил бы находкой то, что стоит в проекции строкой выше.
func predicateSegmentsOf(sql string) []segment {
	words := sqlWordSpans(sql)
	var out []segment
	open := -1
	for _, w := range words {
		up := strings.ToUpper(sql[w[0]:w[1]])
		if containsSQLWord(predicateOpeners, up) {
			if open >= 0 {
				out = append(out, segment{text: sql[open:w[0]], at: open})
			}
			open = w[1]
			continue
		}
		if containsSQLWord(predicateClosers, up) && open >= 0 {
			out = append(out, segment{text: sql[open:w[0]], at: open})
			open = -1
		}
	}
	if open >= 0 {
		out = append(out, segment{text: sql[open:], at: open})
	}
	return out
}

// countConcatsOutsidePredicates — склейки, стоящие ВНЕ условия.
//
// Существует ради законного близнеца: без него «находок ноль» неотличимо от
// «разбор ничего не разобрал».
func countConcatsOutsidePredicates(sql string) int {
	inPredicate := map[int]bool{}
	for _, seg := range predicateSegmentsOf(sql) {
		for i := seg.at; i < seg.at+len(seg.text); i++ {
			inPredicate[i] = true
		}
	}
	n := 0
	for i := 0; i+1 < len(sql); i++ {
		if sql[i] == '|' && sql[i+1] == '|' && !inPredicate[i] {
			n++
			i++
		}
	}
	return n
}

// concatOperandSpans — цепочки склейки внутри условия, каждая целиком.
//
// Цепочка ограничена запятой того же уровня скобок, оператором сравнения и
// границами сегмента: без этого одна находка размазывалась бы на весь предикат,
// и сообщение не называло бы того, что чинить.
func concatOperandSpans(seg string) [][2]int {
	var out [][2]int
	depth := 0
	start := 0
	hasConcat := false
	flush := func(end int) {
		if hasConcat {
			out = append(out, [2]int{start, end})
		}
		hasConcat = false
	}
	for i := 0; i < len(seg); i++ {
		switch {
		case seg[i] == '(':
			depth++
		case seg[i] == ')':
			if depth == 0 {
				flush(i)
				start = i + 1
				continue
			}
			depth--
		case depth == 0 && seg[i] == ',':
			flush(i)
			start = i + 1
		case depth == 0 && (seg[i] == '=' || seg[i] == '<' || seg[i] == '>' || seg[i] == '!'):
			flush(i)
			start = i + 1
		case seg[i] == '|' && i+1 < len(seg) && seg[i+1] == '|':
			hasConcat = true
			i++
		}
	}
	flush(len(seg))
	return out
}

// sqlWordSpans — границы слов SQL, чтобы `ON` в середине имени не считался
// ключевым словом.
func sqlWordSpans(sql string) [][2]int {
	var out [][2]int
	start := -1
	for i := 0; i <= len(sql); i++ {
		isWord := i < len(sql) && (sql[i] == '_' ||
			(sql[i] >= 'a' && sql[i] <= 'z') || (sql[i] >= 'A' && sql[i] <= 'Z') ||
			(sql[i] >= '0' && sql[i] <= '9'))
		switch {
		case isWord && start < 0:
			start = i
		case !isWord && start >= 0:
			out = append(out, [2]int{start, i})
			start = -1
		}
	}
	return out
}

func containsSQLWord(set []string, w string) bool {
	for _, s := range set {
		if s == w {
			return true
		}
	}
	return false
}
