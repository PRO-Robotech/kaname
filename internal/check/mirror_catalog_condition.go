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
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
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
		if !strings.Contains(lit.Value, ResourceMirrorTable) {
			return true
		}
		mentions++
		upper := strings.ToUpper(lit.Value)
		owner := ""
		for _, s := range spans {
			if lit.Pos() >= s.from && lit.End() <= s.to {
				owner = s.name
				break
			}
		}
		catalog := mirrorUniqueSorted(catalogTablePattern.FindAllString(strings.ToLower(lit.Value), -1))
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
