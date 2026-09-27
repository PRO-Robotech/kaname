// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// interactive_client_secret_material_writer_test.go — ГЕЙТ G приёмки
// confidential-interactive-client-secret-shown-once (IC-SECRET-03, Р5; задача
// PRO-Robotech/kaname#405): проверочное значение секрета интерактивного
// клиента и момент его установки кладёт ТОТ ЖЕ оператор вставки, что строку
// клиента, и второго писателя материала в пакете нет.
//
// # Почему гейт, а не проба на базе
//
// Одноместность записи изнутри транзакции не видна, а схема строку со способом
// секретом без материала ПРИНИМАЕТ — обратной связи «способ секретом ⟹ материал
// в строке» у неё нет намеренно (клиент внешнего поставщика). Второй писатель —
// отдельный `UPDATE … SET secret_verifier = …` после вставки — открыл бы окно
// «клиент со способом секретом есть, предъявить нечего», а при сбое между двумя
// операторами — клиента, которого нельзя доказать никогда. Проба на базе такой
// дефект видит только на сбое между операторами, то есть не видит.
//
// # Что опознаётся — по узлу разбора, не по слову
//
// Строковое значение Go (литерал, склейка литералов и объявлений пакета,
// локальная константа) судится как SQL — разбором лексем, а не образцом
// строки: оператор, ПИШУЩИЙ таблицу реестра клиентов (`interactive_clients` без
// схемы либо в схеме `kaname`), кладёт материал, если называет его колонку в
// перечне вставки либо присваивает ей НЕ пустую строку. Формы оператора — по
// грамматике Postgres 16, каждая доказана сценой инъекции:
//
//	UPDATE [ONLY] цель [*] [[AS] псевдоним] SET колонка = … | (колонки) = …
//	INSERT INTO цель [AS псевдоним] (колонки) … [ON CONFLICT … DO UPDATE SET …]
//	MERGE INTO цель [[AS] псевдоним] … THEN UPDATE SET … | THEN INSERT (колонки)
//
// Прежний отбор знал две первые без псевдонима и без upsert: форма с
// псевдонимом и `ON CONFLICT … DO UPDATE SET` проходили зелёными при втором
// писателе (опыты b405_1 и b405_5 проверяющего, круг 1 сборки 435). Таблица,
// названная источником (`FROM`, `USING`), и замок `FOR UPDATE` целью не
// считаются. Присваивание пустой строки — СНЯТИЕ материала
// (`ClearClientSecretVerifier`) — законный близнец и писателем не считается: оно
// материала не несёт. Комментарий и имя функции не судятся.
//
// Судятся тела объявлений функций И литералы функций в объявлениях `var`
// уровня пакета: у писателя `var x = func…` объявления функции нет, и обход
// одних тел его не видел.
//
// # Чего гейт не видит — названо
//
//  1. пакеты, кроме этого (доступ к базе у службы живёт только здесь);
//  2. оператор, собранный во время исполнения (`fmt.Sprintf`, `strings.Join`);
//  3. запись в схеме (триггер) — не Go;
//  4. строка в долларовых кавычках (`$$…$$`) разбирается как слова: цель в
//     ней видна, но присваивание пустой строки внутри неё снятием не
//     опознаётся — в пакете таких строк ноль.
//
// # Перепись печатается всегда
//
// «файлов N · функций M · литералов функций пакета L · строковых значений SQL K ·
// писателей W · снятий C».
// Пустой обход (ноль прод-файлов) — не «чисто», а «не выполнилось». Обход, не
// нашедший законного писателя, — находка с названной причиной: производитель,
// которого гейт держит, обязан существовать, иначе «второго писателя нет»
// было бы верно и о пакете, где материал не пишет никто.

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

	"github.com/stretchr/testify/require"
)

// clientMaterialWriter — единственный законный писатель материала.
const clientMaterialWriter = "InteractiveClientRepo.Insert"

// Колонки материала и момента его установки.
const (
	clientMaterialColumn = "secret_verifier"
	clientMaterialStamp  = "secret_verifier_set_at"
)

// clientMaterialCensus — объём осмотренного и найденное.
type clientMaterialCensus struct {
	files, funcs, funcLits, sqlValues int
	// writers — «Функция @ файл:строка» каждого писателя материала.
	writers []string
	// clears — функций, снимающих материал присваиванием пустой строки.
	clears int
	// writerStamps — пишет ли законный писатель и момент установки.
	writerStamps bool
}

func (c clientMaterialCensus) String() string {
	return fmt.Sprintf("файлов %d · функций %d · литералов функций пакета %d · строковых значений SQL %d · писателей материала %d %v · снятий %d",
		c.files, c.funcs, c.funcLits, c.sqlValues, len(c.writers), c.writers, c.clears)
}

// sqlToken — лексема SQL: слово ('w', в нижнем регистре, без кавычек),
// строковый литерал ('s', содержимое), пунктуация ('p') либо прочее ('o':
// параметр, приведение, оператор). Комментарии SQL выбрасываются. Байт слова —
// `isSQLWordByte` соседнего гейта пакета (scopeedgesource_gate_test.go), а не
// второе определение.
type sqlToken struct {
	kind byte
	text string
}

func sqlTokens(s string) []sqlToken {
	var out []sqlToken
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			if j := strings.Index(s[i+2:], "*/"); j >= 0 {
				i += j + 4
			} else {
				i = len(s)
			}
		case c == '\'':
			var b strings.Builder
			for i++; i < len(s); i++ {
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						b.WriteByte('\'')
						i++
						continue
					}
					break
				}
				b.WriteByte(s[i])
			}
			i++
			out = append(out, sqlToken{'s', b.String()})
		case c == '"':
			j := strings.IndexByte(s[i+1:], '"')
			if j < 0 {
				j = len(s) - i - 1
			}
			out = append(out, sqlToken{'w', strings.ToLower(s[i+1 : i+1+j])})
			i += j + 2
		case isSQLWordByte(c):
			j := i
			for j < len(s) && isSQLWordByte(s[j]) {
				j++
			}
			out = append(out, sqlToken{'w', strings.ToLower(s[i:j])})
			i = j
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case strings.IndexByte("(),;.=*", c) >= 0:
			out = append(out, sqlToken{'p', string(c)})
			i++
		default:
			j := i + 1
			for j < len(s) && !isSQLWordByte(s[j]) && strings.IndexByte(" \t\n\r'\"(),;.=*", s[j]) < 0 {
				j++
			}
			out = append(out, sqlToken{'o', s[i:j]})
			i = j
		}
	}
	return out
}

func sqlWordAt(t []sqlToken, i int, w string) bool {
	return i >= 0 && i < len(t) && t[i].kind == 'w' && t[i].text == w
}

func sqlPunctAt(t []sqlToken, i int, p string) bool {
	return i >= 0 && i < len(t) && t[i].kind == 'p' && t[i].text == p
}

// registryTarget — называет ли имя с позиции i таблицу реестра клиентов
// (`interactive_clients` без схемы либо в схеме `kaname`); j — позиция после
// имени.
func registryTarget(t []sqlToken, i int) (j int, ours bool) {
	if i+2 < len(t) && t[i].kind == 'w' && sqlPunctAt(t, i+1, ".") {
		return i + 3, t[i].text == "kaname" && sqlWordAt(t, i+2, "interactive_clients")
	}
	return i + 1, sqlWordAt(t, i, "interactive_clients")
}

// afterTargetWords — слова, которые стоят сразу за целью оператора записи и
// псевдонимом НЕ являются.
var afterTargetWords = map[string]bool{
	"set": true, "using": true, "where": true, "on": true, "values": true,
	"default": true, "select": true, "overriding": true, "returning": true,
}

// skipAlias — пропускает псевдоним цели: `AS имя` всегда, голое имя — только
// там, где грамматика оператора его допускает (UPDATE, MERGE; у INSERT
// псевдоним только через AS).
func skipAlias(t []sqlToken, j int, bare bool) int {
	if sqlWordAt(t, j, "as") {
		return j + 2
	}
	if bare && j < len(t) && t[j].kind == 'w' && !afterTargetWords[t[j].text] {
		return j + 1
	}
	return j
}

// parenItems — элементы списка в скобках с позиции j (там «(»), разделённые
// запятыми верхнего уровня; next — позиция после парной «)».
func parenItems(t []sqlToken, j int) (items [][]sqlToken, next int) {
	depth, from := 0, j+1
	for k := j; k < len(t); k++ {
		switch {
		case sqlPunctAt(t, k, "("):
			depth++
		case sqlPunctAt(t, k, ")"):
			depth--
			if depth == 0 {
				return append(items, t[from:k]), k + 1
			}
		case sqlPunctAt(t, k, ",") && depth == 1:
			items = append(items, t[from:k])
			from = k + 1
		}
	}
	return append(items, t[from:]), len(t)
}

func firstWord(item []sqlToken) string {
	for _, tk := range item {
		if tk.kind == 'w' {
			return tk.text
		}
	}
	return ""
}

// clearsMaterial — выражение присваивания есть пустая строка (снятие), в
// том числе с приведением к тексту.
func clearsMaterial(expr []sqlToken) bool {
	switch {
	case len(expr) == 1:
		return expr[0].kind == 's' && expr[0].text == ""
	case len(expr) == 3:
		return expr[0].kind == 's' && expr[0].text == "" && expr[1].text == "::" && sqlWordAt(expr, 2, "text")
	}
	return false
}

// setAssignments — список присваиваний `SET …` с позиции j до конца списка:
// ключевое слово верхнего уровня, «;», закрывающая скобка объемлющего
// выражения либо конец. Формы присваивания — `колонка = выражение` и
// `(колонки) = (выражения)`; присваивание кортежу подзапросом — запись
// каждой названной колонки.
func setAssignments(t []sqlToken, j int) (writes, clears bool) {
	stop := map[string]bool{"where": true, "from": true, "returning": true, "when": true}
	var items [][]sqlToken
	depth, from, k := 0, j, j
	for ; k < len(t); k++ {
		if depth == 0 && (sqlPunctAt(t, k, ";") || (t[k].kind == 'w' && stop[t[k].text])) {
			break
		}
		if sqlPunctAt(t, k, "(") {
			depth++
		} else if sqlPunctAt(t, k, ")") {
			if depth == 0 {
				break
			}
			depth--
		} else if depth == 0 && sqlPunctAt(t, k, ",") {
			items = append(items, t[from:k])
			from = k + 1
		}
	}
	items = append(items, t[from:k])
	judge := func(col string, expr []sqlToken) {
		if col != clientMaterialColumn {
			return
		}
		if clearsMaterial(expr) {
			clears = true
		} else {
			writes = true
		}
	}
	for _, it := range items {
		if len(it) == 0 {
			continue
		}
		if !sqlPunctAt(it, 0, "(") {
			eq := 1
			for eq < len(it) && !sqlPunctAt(it, eq, "=") {
				eq++
			}
			if eq < len(it) {
				judge(it[0].text, it[eq+1:])
			}
			continue
		}
		cols, after := parenItems(it, 0)
		if !sqlPunctAt(it, after, "=") {
			continue
		}
		rhs := after + 1
		if sqlWordAt(it, rhs, "row") {
			rhs++
		}
		var exprs [][]sqlToken
		if sqlPunctAt(it, rhs, "(") && !sqlWordAt(it, rhs+1, "select") {
			exprs, _ = parenItems(it, rhs)
		}
		for n, c := range cols {
			if len(exprs) == len(cols) {
				judge(firstWord(c), exprs[n])
			} else {
				judge(firstWord(c), nil)
			}
		}
	}
	return writes, clears
}

// statementEnd — конец оператора, начатого на позиции i: «;» верхнего уровня
// либо закрывающая скобка объемлющего выражения (оператор внутри WITH).
func statementEnd(t []sqlToken, i int) int {
	depth := 0
	for k := i; k < len(t); k++ {
		switch {
		case sqlPunctAt(t, k, "("):
			depth++
		case sqlPunctAt(t, k, ")"):
			if depth == 0 {
				return k
			}
			depth--
		case depth == 0 && sqlPunctAt(t, k, ";"):
			return k
		}
	}
	return len(t)
}

// notStatementUpdate — слово UPDATE после них не начинает оператор: DO UPDATE
// судится в своей вставке, THEN UPDATE — в своём MERGE, FOR/KEY UPDATE —
// замок чтения, ON UPDATE — предложение ключа.
var notStatementUpdate = map[string]bool{"do": true, "then": true, "for": true, "key": true, "on": true}

// sqlMaterialWrite — пишет ли значение SQL материал в реестр клиентов;
// снимает ли его; называет ли вставка момент установки.
//
// Формы — по грамматике операторов записи Postgres 16, и каждая доказана
// сценой инъекции:
//
//	UPDATE [ONLY] цель [*] [[AS] псевдоним] SET колонка = … | (колонки) = …
//	INSERT INTO цель [AS псевдоним] (колонки) … [ON CONFLICT … DO UPDATE SET …]
//	MERGE INTO цель [[AS] псевдоним] … THEN UPDATE SET … | THEN INSERT (колонки)
//
// Цель — `interactive_clients` без схемы либо в схеме `kaname`; таблица,
// названная источником (`FROM`, `USING`), целью не считается.
func sqlMaterialWrite(sql string) (writes, clears, stamps bool) {
	t := sqlTokens(sql)
	insertCols := func(j int) {
		if !sqlPunctAt(t, j, "(") {
			return
		}
		items, _ := parenItems(t, j)
		cols := map[string]bool{}
		for _, it := range items {
			cols[firstWord(it)] = true
		}
		if cols[clientMaterialColumn] {
			writes = true
			stamps = stamps || cols[clientMaterialStamp]
		}
	}
	set := func(j int) {
		w, cl := setAssignments(t, j)
		writes, clears = writes || w, clears || cl
	}
	for i := 0; i < len(t); i++ {
		if t[i].kind != 'w' {
			continue
		}
		switch t[i].text {
		case "insert":
			if !sqlWordAt(t, i+1, "into") {
				continue
			}
			j, ours := registryTarget(t, i+2)
			if !ours {
				continue
			}
			j = skipAlias(t, j, false)
			insertCols(j)
			for end, k := statementEnd(t, i), j; k < end; k++ {
				if sqlWordAt(t, k, "do") && sqlWordAt(t, k+1, "update") && sqlWordAt(t, k+2, "set") {
					set(k + 3)
				}
			}
		case "update":
			if i > 0 && t[i-1].kind == 'w' && notStatementUpdate[t[i-1].text] {
				continue
			}
			j := i + 1
			if sqlWordAt(t, j, "only") {
				j++
			}
			j, ours := registryTarget(t, j)
			if !ours {
				continue
			}
			if sqlPunctAt(t, j, "*") {
				j++
			}
			j = skipAlias(t, j, true)
			if sqlWordAt(t, j, "set") {
				set(j + 1)
			}
		case "merge":
			if !sqlWordAt(t, i+1, "into") {
				continue
			}
			j, ours := registryTarget(t, i+2)
			if !ours {
				continue
			}
			for end, k := statementEnd(t, i), j; k < end; k++ {
				if !sqlWordAt(t, k, "then") {
					continue
				}
				switch {
				case sqlWordAt(t, k+1, "update") && sqlWordAt(t, k+2, "set"):
					set(k + 3)
				case sqlWordAt(t, k+1, "insert"):
					insertCols(k + 2)
				}
			}
		}
	}
	return writes, clears, stamps
}

// auditClientMaterialWriters — перепись писателей материала по каталогу dir.
// Отказ — «не выполнилось», а не находка.
func auditClientMaterialWriters(dir string) ([]string, clientMaterialCensus, error) {
	var c clientMaterialCensus
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, c, fmt.Errorf("не выполнилось: каталог пакета не прочитан: %w", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			return nil, c, fmt.Errorf("не выполнилось: разбор %s: %w", name, perr)
		}
		files = append(files, file)
	}
	c.files = len(files)
	if c.files == 0 {
		return nil, c, fmt.Errorf("не выполнилось: прод-файлов в %s ноль — «писателей 0» значило бы «ничего не прочитано»", dir)
	}

	// Строковые объявления пакета — тем же вычислителем, что перепись путей
	// записи отсечки (`cutoffStringValue`): второй вычислитель разошёлся бы.
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

	var findings []string
	writerSeen := false
	// judge судит одно тело: объявление функции либо литерал функции в
	// объявлении пакета. Литерал функции ВНУТРИ тела судится вместе с ним и
	// приписывается объемлющей функции.
	judge := func(body ast.Node, name string, at token.Pos) {
		var sqls []string
		selected := map[*ast.Ident]struct{}{}
		ast.Inspect(body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				selected[x.Sel] = struct{}{}
			case *ast.BinaryExpr:
				if s, ok := cutoffStringValue(x, values); ok {
					sqls = append(sqls, s)
					return false
				}
			case *ast.BasicLit:
				if s, ok := cutoffStringValue(x, values); ok {
					sqls = append(sqls, s)
				}
			case *ast.Ident:
				if _, sel := selected[x]; sel {
					return true
				}
				if s, ok := values[x.Name]; ok {
					sqls = append(sqls, s)
				}
			}
			return true
		})
		c.sqlValues += len(sqls)
		var writes, clears, stamps bool
		for _, s := range sqls {
			w, cl, st := sqlMaterialWrite(s)
			writes, clears, stamps = writes || w, clears || cl, stamps || st
		}
		if clears {
			c.clears++
		}
		if !writes {
			return
		}
		pos := fset.Position(at)
		coord := fmt.Sprintf("%s @ %s:%d", name, filepath.Base(pos.Filename), pos.Line)
		c.writers = append(c.writers, coord)
		if name == clientMaterialWriter {
			writerSeen = true
			c.writerStamps = stamps
			if !stamps {
				findings = append(findings, coord+": вставка кладёт материал, но не момент его установки тем же оператором")
			}
			return
		}
		findings = append(findings, coord+": второй писатель материала секрета интерактивного клиента — "+
			"материал кладёт только вставка строки тем же оператором (Р5)")
	}
	for _, file := range files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				c.funcs++
				judge(d.Body, funcPathName(d), d.Pos())
			case *ast.GenDecl:
				if d.Tok != token.VAR {
					continue
				}
				// Писатель литералом функции уровня пакета (`var x = func…`):
				// у него нет объявления функции, и обход тел объявлений его не
				// видел — та же слепая зона, что у переписи писателей сессии.
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, v := range vs.Values {
						hasLit := false
						ast.Inspect(v, func(n ast.Node) bool {
							if _, ok := n.(*ast.FuncLit); ok {
								hasLit = true
								return false
							}
							return true
						})
						if !hasLit || i >= len(vs.Names) {
							continue
						}
						c.funcLits++
						judge(v, vs.Names[i].Name, vs.Names[i].Pos())
					}
				}
			}
		}
	}
	sort.Strings(c.writers)
	if !writerSeen {
		findings = append(findings, clientMaterialWriter+": вставка строки клиента материала не кладёт — "+
			"клиент со способом секретом получит строку без проверочного значения")
	}
	sort.Strings(findings)
	return findings, c, nil
}

// TestInteractiveClientSecretMaterialHasOneWriter — гейт G на дереве пакета.
func TestInteractiveClientSecretMaterialHasOneWriter(t *testing.T) {
	findings, census, err := auditClientMaterialWriters(".")
	require.NoError(t, err)
	t.Logf("перепись писателей материала: %s; находок %d", census, len(findings))
	for _, f := range findings {
		t.Error(f)
	}
}
