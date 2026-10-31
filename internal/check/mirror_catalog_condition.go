// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mirror_catalog_condition.go — разбор: УСЛОВИЕ КАТАЛОГА НЕСЁТ КАЖДЫЙ ПИСАТЕЛЬ
// ЗЕРКАЛА.
//
// # Предмет
//
// Зеркало каталога ресурсов — проекция, которую владельцы присылают через
// проксируемую полосу регистрации. Требование «тип обязан иметь живую строку
// каталога» выражено ОПЕРАТОРОМ записи, а не внешним ключом: постоянное
// ограничение запретило бы платформе снять тип, пока у арендатора есть ресурс
// этого типа, то есть сделало бы решение платформы заложником данных арендатора.
//
// Цена выбора: инвариант стал свойством ПОЛОСЫ, а не свойством ТАБЛИЦЫ.
// Инвариант, выраженный в одном операторе из нескольких, — это инвариант,
// которого нет: второй писатель обходит его молча, и обнаруживается это тогда,
// когда данные уже записаны. Этот разбор — второй рубеж под тем же утверждением.
//
// # Требование ВЫВОДИТСЯ из эталонной полосы, а не задаётся литералом
//
// Две копии одного условия разошлись бы молча — и разошлись бы именно там, где
// расхождение не видно: обе выглядели бы исправными. Поэтому условие берётся у
// полосы, через которую идёт регистрация от владельцев, и сверка идёт МЕЖДУ
// полосами. Переедет эталон — разбор объявит ОТКАЗ, а не промолчит.
//
// # Каталог берётся ИЗ ТОГО ЖЕ ЛИТЕРАЛА
//
// Обещание сверки, данное в комментарии рядом, условием не является — иначе
// писателю довольно было бы пообещать её словами.
//
// # Признак таблицы каталога — ПРЕФИКС, а не перечень
//
// Каталог растёт, и выписанный перечень отстал бы от него молча: новое условие
// оказалось бы вне наблюдения, не будучи нарушением.
//
// # Порт с монорепо — пара файлов названа, а не умолчана
//
// Перенесено с
// `PRO-Robotech/kacho:internal/repohygiene/mirrorcatalogcondition_test.go`
// (снято вынесением службы — `kacho#2598`; предмет жив здесь, задача #17).
// Изменилось: координаты эталонной полосы и владельца таблицы (приставки
// `services/iam/` в самостоятельном клоне нет — модуль и есть владелец, поэтому
// проверка «писатель вне владельца» здесь выродилась бы в тождество и заменена
// проверкой, что писатель лежит В ДЕРЕВЕ МОДУЛЯ); разбор вынесен из пробы в
// пакет `check`. Осталось дословно: имя гейта, перечень глаголов записи с
// признаком «вводит строку», вывод условия из эталона и самоистечение ведомости.
//
// Близнеца в платформе нет: семейство снято там вместе со службой (ban #20).
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

const (
	// ResourceMirrorTable — зеркало каталога ресурсов.
	ResourceMirrorTable = "kaname.resource_mirror"
	// MirrorReferenceLane — каталог ЭТАЛОННОЙ полосы: путь, по которому
	// регистрация от владельца ресурса доходит до строки зеркала.
	//
	// Переедет каталог — гейт объявит ОТКАЗ, а не промолчит: сверять «тем же
	// условием» станет не с чем. Правь эту константу тем же изменением, каким
	// двигаешь пакет.
	MirrorReferenceLane = "internal/repo/kaname/pg/resource_mirror/"
)

// catalogTablePattern — таблица каталога модуля. Признак — ПРЕФИКС, а не
// перечень.
var catalogTablePattern = regexp.MustCompile(`kaname\.catalog_[a-z0-9_]+`)

// MirrorWriteVerbs — глаголы записи. Чтение в перечень не входит намеренно:
// читателей у зеркала десятки, все законны, и они служат близнецом, на котором
// разбор обязан молчать.
//
// Introduces — вводит ли оператор НОВУЮ строку. Предмет условия есть только у
// вводящих: правка существующей строки нового типа не заводит, а снятие тем
// более. Требовать сверки у них значило бы требовать её там, где сверять нечего.
var MirrorWriteVerbs = []struct {
	Verb       string
	Introduces bool
}{
	{"INSERT INTO " + ResourceMirrorTable, true},
	{"MERGE INTO " + ResourceMirrorTable, true},
	{"UPDATE " + ResourceMirrorTable, false},
	{"DELETE FROM " + ResourceMirrorTable, false},
}

// MirrorWrite — одна найденная запись в зеркало.
type MirrorWrite struct {
	// File — путь от корня дерева; заполняет обходчик.
	File string
	// Func — объемлющая функция; пустое имя означает пакетный уровень.
	Func string
	// Verb — какой оператор записи найден.
	Verb string
	// Introduces — вводит ли оператор новую строку.
	Introduces bool
	// Catalog — таблицы каталога, названные В ТОМ ЖЕ операторе, по возрастанию.
	Catalog []string
}

// Key — координата писателя в ведомости исключений.
func (w MirrorWrite) Key() string { return w.File + "::" + w.Func }

// MirrorWritesIn разбирает исходник Go и возвращает записи в зеркало,
// приписанные объемлющей функции, плюс число литералов, называющих таблицу
// вообще (перепись предпосылки: читатели тоже считаются).
// MirrorCandidateCorpus — непроверочные файлы Go дерева, среди которых ищутся
// писатели зеркала.
//
// Дерево приходит параметром, отбор объявлен один раз (`ProductionGoFile`), и
// пустой обход даёт отказ, а не «находок ноль». Прежде обход строился в теле
// пробы от корня своего модуля, и его премиса не исполнялась ни разу (#17).
func MirrorCandidateCorpus(tree *treecorpus.Tree) (TreeCorpus, error) {
	return CorpusFrom(tree, ProductionGoFile)
}

func MirrorWritesIn(filename, src string) ([]MirrorWrite, int, error) {
	return MirrorWritesThroughCommands(filename, src, nil)
}

// MirrorWritesThroughCommands прослеживает INSERT в представление команды до
// его INSTEAD OF INSERT триггера. Каталог берётся из тела действующей функции,
// а не из имени команды или обещания в комментарии вызывающего кода.
func MirrorWritesThroughCommands(filename, src string, commands map[string]string) ([]MirrorWrite, int, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, 0, err
	}

	type span struct {
		from, to token.Pos
		name     string
	}
	var spans []span
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		name := fn.Name.Name
		if fn.Recv != nil && len(fn.Recv.List) > 0 {
			name = mirrorTypeName(fn.Recv.List[0].Type) + "." + name
		}
		spans = append(spans, span{from: fn.Body.Pos(), to: fn.Body.End(), name: name})
	}

	var (
		writes   []MirrorWrite
		mentions int
	)
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		value, unquoteErr := strconv.Unquote(lit.Value)
		if unquoteErr != nil {
			return true
		}
		for command, body := range commands {
			if mirrorInsertsRelation(value, command) {
				value += "\n" + body
			}
		}
		if !strings.Contains(value, ResourceMirrorTable) {
			return true
		}
		mentions++
		upper := strings.ToUpper(normalizeSpace(value))
		owner := ""
		for _, s := range spans {
			if lit.Pos() >= s.from && lit.End() <= s.to {
				owner = s.name
				break
			}
		}
		catalog := mirrorUniqueSorted(catalogTablePattern.FindAllString(strings.ToLower(value), -1))
		for _, v := range MirrorWriteVerbs {
			if strings.Contains(upper, strings.ToUpper(v.Verb)) {
				writes = append(writes, MirrorWrite{
					Func:       owner,
					Verb:       v.Verb,
					Introduces: v.Introduces,
					Catalog:    catalog,
				})
			}
		}
		return true
	})
	return writes, mentions, nil
}

// Используется общая SQL-лексика: quoted names точны, комментарии и dollar
// bodies не становятся исполняемыми DDL. Это fold известного протокола команд,
// а не разбор произвольного SQL.
func mirrorRelation(tokens []sqlTok, at int) (string, int) {
	if at >= len(tokens) || tokens[at].kind != sqlTokName {
		return "", at
	}
	component := func(name string) string {
		if strings.Contains(name, ".") {
			return strconv.Quote(name)
		}
		return name
	}
	name := component(tokens[at].name)
	at++
	if at+1 < len(tokens) && tokens[at].op == '.' && tokens[at+1].kind == sqlTokName {
		name += "." + component(tokens[at+1].name)
		at += 2
	}
	return name, at
}

// An unqualified mutation may resolve to the tracked schema through search_path.
// Refuse that ambiguity; another explicitly qualified schema is unrelated.
func mirrorDependencyMatches(name, tracked string) bool {
	if name == tracked {
		return true
	}
	return name != "" && !strings.Contains(name, ".") && strings.HasSuffix(tracked, "."+name)
}

func mirrorInsertsRelation(sql, relation string) bool {
	tokens := sqlTokens(sql)
	for i := 0; i+2 < len(tokens); i++ {
		if tokens[i].name == "insert" && tokens[i+1].name == "into" {
			name, _ := mirrorRelation(tokens, i+2)
			if name == relation {
				return true
			}
		}
	}
	return false
}

type mirrorCommandBinding struct {
	relation string
	trigger  string
	function string
}

// MirrorCommandBodies сводит исполняемые операторы в порядке миграций.
// Непрочитанная функция или неподдержанная смена зависимости — отказ.
func MirrorCommandBodies(upSections []string) (map[string]string, error) {
	functions := map[string]string{}
	bindings := map[string]mirrorCommandBinding{}
	for _, section := range upSections {
		tokens := sqlTokens(section)
		for len(tokens) > 0 {
			end := 0
			for end < len(tokens) && tokens[end].op != ';' {
				end++
			}
			statement := tokens[:end]
			if end < len(tokens) {
				end++
			}
			tokens = tokens[end:]
			if len(statement) == 0 {
				continue
			}
			if err := mirrorFoldStatement(statement, functions, bindings); err != nil {
				return nil, err
			}
		}
	}
	commands := map[string]string{}
	for _, key := range mirrorSortedBindingKeys(bindings) {
		binding := bindings[key]
		body, ok := functions[binding.function]
		if !ok {
			return nil, fmt.Errorf("mirror command %s has unread function %s", binding.relation, binding.function)
		}
		commands[binding.relation] += "\n" + body
	}
	return commands, nil
}

func mirrorSortedBindingKeys(bindings map[string]mirrorCommandBinding) []string {
	keys := make([]string, 0, len(bindings))
	for key := range bindings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func mirrorFoldStatement(s []sqlTok, functions map[string]string, bindings map[string]mirrorCommandBinding) error {
	word := func(i int) string {
		if i < len(s) && s[i].kind == sqlTokName {
			return s[i].name
		}
		return ""
	}
	find := func(name string) int {
		for i := range s {
			if word(i) == name {
				return i
			}
		}
		return -1
	}
	i := 1
	replace := word(1) == "or" && word(2) == "replace"
	if replace {
		i = 3
	}
	if word(0) == "create" && word(i) == "function" {
		name, _ := mirrorRelation(s, i+1)
		for _, b := range bindings {
			if name != b.function && mirrorDependencyMatches(name, b.function) {
				return fmt.Errorf("ambiguous mirror command function definition %s", name)
			}
		}
		returns, as := find("returns"), find("as")
		if returns >= 0 && word(returns+1) == "trigger" && as >= 0 && as+1 < len(s) && s[as+1].kind == sqlTokString && len(s[as+1].readings) == 1 {
			functions[name] = s[as+1].readings[0]
			return nil
		}
		for _, b := range bindings {
			if b.function == name {
				return fmt.Errorf("unsupported mirror command function definition %s", name)
			}
		}
		delete(functions, name)
		return nil
	}
	if word(0) == "create" && word(i) == "trigger" {
		instead, on, execute := find("instead"), find("on"), find("execute")
		if instead < 0 || word(instead+1) != "of" || word(instead+2) != "insert" || on < 0 || execute < 0 {
			if on >= 0 {
				relation, _ := mirrorRelation(s, on+1)
				if _, tracked := bindings[relation+"/"+word(i+1)]; tracked {
					return fmt.Errorf("unsupported mirror command trigger definition %s", relation)
				}
			}
			return nil
		}
		relation, _ := mirrorRelation(s, on+1)
		function, _ := mirrorRelation(s, execute+2)
		trigger := word(i + 1)
		if relation == "" || function == "" || trigger == "" || word(execute+1) != "function" {
			return fmt.Errorf("unread mirror command trigger")
		}
		for _, b := range bindings {
			if relation != b.relation && trigger == b.trigger && mirrorDependencyMatches(relation, b.relation) {
				return fmt.Errorf("ambiguous mirror command trigger definition %s", relation)
			}
		}
		key := relation + "/" + trigger
		binding := mirrorCommandBinding{relation: relation, trigger: trigger, function: function}
		if prior, ok := bindings[key]; replace || (ok && prior != binding) {
			return fmt.Errorf("unsupported mirror command trigger replacement %s", key)
		}
		bindings[key] = binding
		return nil
	}
	if word(0) == "create" && replace && word(i) == "view" {
		name, _ := mirrorRelation(s, i+1)
		for _, b := range bindings {
			if mirrorDependencyMatches(name, b.relation) {
				return fmt.Errorf("unsupported mirror command view replacement %s", name)
			}
		}
	}
	if word(0) != "drop" && word(0) != "alter" {
		return nil
	}
	kind := word(1)
	at := 2
	if word(at) == "if" && word(at+1) == "exists" {
		at += 2
	}
	name, _ := mirrorRelation(s, at)
	for _, b := range bindings {
		touched := false
		switch kind {
		case "function", "routine":
			for j := at; j < len(s); {
				n, next := mirrorRelation(s, j)
				touched = touched || mirrorDependencyMatches(n, b.function)
				if next > j {
					j = next
				} else {
					j++
				}
			}
		case "view", "table":
			for j := at; j < len(s); {
				n, next := mirrorRelation(s, j)
				touched = touched || mirrorDependencyMatches(n, b.relation)
				if next > j {
					j = next
				} else {
					j++
				}
			}
			// A different named trigger on this relation is unrelated.
			if tr := find("trigger"); word(0) == "alter" && tr >= 0 && word(tr+1) != "all" && word(tr+1) != "user" && word(tr+1) != b.trigger {
				touched = false
			}
		case "trigger":
			on := find("on")
			relation := ""
			if on >= 0 {
				relation, _ = mirrorRelation(s, on+1)
			}
			touched = name == b.trigger && mirrorDependencyMatches(relation, b.relation)
		}
		if touched {
			return fmt.Errorf("unsupported %s %s of mirror command dependency %s", word(0), kind, name)
		}
	}
	if kind == "function" || kind == "routine" {
		for j := at; j < len(s); j++ {
			n, _ := mirrorRelation(s, j)
			delete(functions, n)
		}
	}
	return nil
}

// MirrorConditionOutcome — вердикт сверки полос вместе с переписью.
type MirrorConditionOutcome struct {
	// Findings — писатели, обошедшие условие эталонной полосы.
	Findings []string
	// Stale — записи ведомости, которым больше нечего исключать.
	Stale []string
	// Required — условие, выведенное из эталонной полосы (таблицы каталога).
	Required []string
	// Lanes — вводящих писателей всего.
	Lanes int
	// LaneKeys — они же поимённо: число без перечня читатель проверить не может.
	LaneKeys []string
	// Carriers — из них несущих требуемое условие целиком.
	Carriers int
	// Exempt — из них погашенных ведомостью.
	Exempt int
	// ReferenceMissing — эталонной полосы в наборе нет; сверять не с чем.
	ReferenceMissing bool
}

// MirrorConditionReport — ЧИСТАЯ функция сверки: по набору записей и ведомости
// возвращает находки и перепись. Вынесена из обхода дерева намеренно — только
// так её способность краснеть и молчать доказывается инъекцией на синтетическом
// входе, не трогая настоящее дерево.
func MirrorConditionReport(writes []MirrorWrite, ledger map[string]string) MirrorConditionOutcome {
	var out MirrorConditionOutcome

	// Требование выводится из эталонной полосы, а не задаётся литералом.
	var refSeen bool
	requiredSet := map[string]bool{}
	for _, w := range writes {
		if !w.Introduces || !strings.Contains("/"+w.File, "/"+MirrorReferenceLane) {
			continue
		}
		refSeen = true
		for _, c := range w.Catalog {
			requiredSet[c] = true
		}
	}
	out.ReferenceMissing = !refSeen
	for c := range requiredSet {
		out.Required = append(out.Required, c)
	}
	sort.Strings(out.Required)

	// used — записи ведомости, которым нашлось что исключать.
	used := map[string]bool{}

	for _, w := range writes {
		if !w.Introduces {
			continue
		}
		out.Lanes++
		out.LaneKeys = append(out.LaneKeys, w.Key())

		have := map[string]bool{}
		for _, c := range w.Catalog {
			have[c] = true
		}
		var missing []string
		for _, c := range out.Required {
			if !have[c] {
				missing = append(missing, c)
			}
		}
		if len(missing) == 0 {
			out.Carriers++
			continue
		}
		if reason, ok := ledger[w.Key()]; ok && strings.TrimSpace(reason) != "" {
			used[w.Key()] = true
			out.Exempt++
			continue
		}
		out.Findings = append(out.Findings, w.File+"::"+w.Func+
			" — вводит строку зеркала, НЕ спрашивая "+strings.Join(missing, ", ")+
			", тогда как эталонная полоса ("+MirrorReferenceLane+") спрашивает. "+
			"Инвариант, выраженный в одном операторе из нескольких, — это инвариант, которого нет: "+
			"этот писатель положит строку с типом, которого каталог не знает, МОЛЧА. "+
			"Исходов три: спросить каталог тем же условием · снять писателя · назвать его "+
			"исключением с причиной в ведомости")
	}

	// Ведомость истекает сама.
	var keys []string
	for k := range ledger {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if used[k] {
			continue
		}
		if strings.TrimSpace(ledger[k]) == "" {
			out.Stale = append(out.Stale, k+" — исключение БЕЗ ПРИЧИНЫ: следующий читатель "+
				"либо снимет его как непонятное, либо оставит навсегда, не зная предмета")
			continue
		}
		out.Stale = append(out.Stale, k+" — исключению больше нечего исключать: писатель либо "+
			"получил условие, либо исчез из дерева. Снимите запись — послабление обязано истекать само")
	}
	return out
}

// mirrorTypeName — имя типа приёмника метода, без указателя.
func mirrorTypeName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.StarExpr:
		return mirrorTypeName(v.X)
	case *ast.Ident:
		return v.Name
	case *ast.IndexExpr:
		return mirrorTypeName(v.X)
	case *ast.SelectorExpr:
		return v.Sel.Name
	default:
		return ""
	}
}

// mirrorUniqueSorted — различные значения по возрастанию.
func mirrorUniqueSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
