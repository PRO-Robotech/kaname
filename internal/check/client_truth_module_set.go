// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_truth_module_set.go — извлечение для гейта «перечень модулей
// платформы, названный клиентской поверхностью, ПОЛОН» (задача #17, порт
// семейства `clienttruth_iam_moduleset` с монорепо
// `internal/repohygiene/clienttruth_iam_moduleset.go`, снятого выносом службы —
// `kacho#2597`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — и почему цена неполноты в БЕЗОПАСНОСТИ, а не в удобстве
//
// Набор модулей закрыт, и его единственный источник — приставки ключей закрытой
// таблицы типов объекта (`objectTypes` пакета `internal/authzmap`). Модуль — то,
// чем клиент выражает грант (`Rule.module`).
//
// Перечень, назвавший МЕНЬШЕ, чем принимает сервер, читается клиентом как «тонко
// выдать доступ к недостающему домену НЕЛЬЗЯ», а единственный документированный
// выход при таком чтении — системная роль на весь уровень, то есть заведомое
// расширение доступа. Клиент платит доступом за нашу опечатку в прозе.
//
// Замер, на котором семейство заведено (kacho#1627): сервер принимал ШЕСТЬ
// модулей, а называли ЧЕТЫРЕ и справочная страница ролей, и комментарий поля
// контракта; шапка функции членства рядом называла ПЯТЬ. Разошлись не документ с
// кодом, а ТРИ места об одном предмете, из которых верно было ни одно.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИЗМЕНИЛ ПЕРЕЕЗД, А ЧТО НЕТ
//
// Предмет НЕ изменился. Изменились координаты: приставка `services/iam/` ушла
// вместе с монорепо, поверхности стали `docs/content` и `proto/kaname/cloud/iam`
// (копия контракта приехала сюда с `kaname#49`), объявление набора —
// `internal/authzmap`. ОБА операнда лежат в этом дереве, поэтому семейство
// судится здесь целиком, а не половиной.
//
// Прежняя посылка задачи #17 называла семейство кросс-репозиторным. Она
// опровергнута замером операндов: пакет объявления — 61 файл, поверхности — 68.
//
// ─────────────────────────────────────────────────────────────────────────────
// НАБОР ВЫВОДИТСЯ РАЗБОРОМ, А НЕ ЧТЕНИЕМ ТЕКСТА
//
// Считаются узлы-ключи составного литерала. Имена модулей стоят и в
// комментариях рядом с объявлением — и в том самом абзаце, который объясняет
// выбор написания ключа, — поэтому предикат по подстроке краснел бы на
// собственном объяснении таблицы: судящий СЛОВО вместо УЗЛА находит сам себя.
//
// Объявление разрешается по ПАКЕТУ, а не по файлу. В монорепо оно переезжало
// между файлами дважды (`fga_types.go` → `tables_gen.go`), и оба раза привязка к
// имени файла давала не находку, а «анализатор не отработал» — третью категорию,
// поданную как красное. Пакет и есть единица области видимости Go: package-level
// имя в нём ровно одно by construction, и перенос между файлами о нём ничего не
// меняет.
//
// Приставка берётся до ПЕРВОЙ точки — то же разбиение, каким его делает
// `authzmap.SplitObjectType`. Ключ без точки модуля НЕ ДАЁТ и себя целиком не
// отдаёт: он не «модуль без ресурса», а ключ неверной формы, и записать его в
// набор значило бы объявить модулем то, чем таблица его не называет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СЧИТАЕТСЯ ПЕРЕЧНЕМ — И ЧЕГО ГЕЙТ НЕ СУДИТ, НАЗВАНО ЧИСЛОМ
//
// Перечень — имена модулей в КОД-ФОРМАТИРОВАНИИ (`имя` либо <code>имя</code>),
// соединённые косой чертой, ТРИ и более подряд. Каждый такой перечень обязан
// назвать набор целиком.
//
//  1. СПАН ИЗ ДВУХ ИМЁН перечнем не считается — это законная пара
//     («`vpc`/`compute` остаются label-selectable»). Порог в три оставлен
//     потому, что гейт, у которого находки ложные, отключают первым. Сколько
//     таких пар встречено — печатает перепись, а не утверждает эта шапка:
//     прежняя редакция абзаца в монорепо называла четыре, и гейт опроверг её на
//     первом же прогоне. Способность молчать на паре доказана инъекцией.
//  2. ПРОЗА без код-форматирования не судится: «модули iam, vpc и compute»
//     распознавателю не видны. Расширение на голый текст не замерялось и потому
//     не вводится — оно находило бы имена модулей в любом предложении, где они
//     соседствуют законно.
//  3. ПОРЯДОК не судится — только состав.
package check

import (
	"fmt"
	"github.com/PRO-Robotech/corelib/treecorpus"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ModuleSetPkgRel — каталог пакета, объявляющего закрытую таблицу типов.
const ModuleSetPkgRel = "internal/authzmap"

// ModuleSetVarName — имя переменной, чей составной литерал разбирается.
const ModuleSetVarName = "objectTypes"

// ModuleSetSurfaces — КЛИЕНТСКИЕ поверхности: то, что читает арендатор.
//
// Инженерные записки (`docs/engineering`) сюда НЕ входят, и это решение, а не
// пропуск: их предмет — реализация, а не обещание клиенту. Шапка функции
// членства в монорепо чинилась руками ровно по этой границе.
var ModuleSetSurfaces = []string{"docs/content", "proto/kaname/cloud/iam"}

// ModuleSetSurfaceExts — расширения файлов поверхности.
var ModuleSetSurfaceExts = []string{".mdx", ".md", ".proto"}

// moduleSetCodeSpanPattern — образец, которым распознаётся имя в
// код-форматировании. Подставляется через `%[1]s`.
//
// Имя говорит «образец», а не «лексема»: сканер безопасности судит имена
// констант по образцу, включающему `token`, и объявлял на прежнем имени находку
// «potential hardcoded credentials» — регулярка к учётным данным отношения не
// имеет. Подавление было бы лечением экземпляра: имя, читающееся как «учётные
// данные», читается так и человеком.
const moduleSetCodeSpanPattern = "(?:`(%[1]s)`|<code>(%[1]s)</code>)"

// ModuleSetDecl — перепись РАЗРЕШЕНИЯ объявления.
type ModuleSetDecl struct {
	// PkgFiles — сколько не-тестовых файлов пакета осмотрено. Без этой величины
	// «объявление найдено» неотличимо от «прочитан один файл, и повезло».
	PkgFiles int
	// DeclFile — где объявление нашлось. Печатается, потому что именно это место
	// и переезжало: читатель обязан видеть, О ЧЁМ вынесен вердикт, не заглядывая
	// в исходник гейта.
	DeclFile string
	// TypeKeys — сколько ключей прочитано. Приставок мало by construction, и одна
	// их величина не отличила бы «таблица прочитана» от «прочитаны две строки».
	TypeKeys int
}

// ModuleSetFinding — один неполный перечень.
type ModuleSetFinding struct {
	File    string
	Line    int
	Named   []string
	Missing []string
	Span    string
}

func (f ModuleSetFinding) String() string {
	return fmt.Sprintf("%s:%d: перечень называет %d из %d — не назван %s (%s)",
		f.File, f.Line, len(f.Named), len(f.Named)+len(f.Missing),
		strings.Join(f.Missing, ", "), f.Span)
}

// ModuleSetFromDecl выводит закрытый набор модулей РАЗБОРОМ объявления.
//
// `files` — содержимое не-тестовых файлов пакета: координата → исходник.
// Читатель отдаёт их сам, потому что гейт берёт их из индекса git, а инъекция —
// из синтетики, и разводить эти два источника внутри значило бы завести здесь
// вторую посадку.
func ModuleSetFromDecl(files map[string]string, varName string) ([]string, ModuleSetDecl, error) {
	var decl ModuleSetDecl

	rels := make([]string, 0, len(files))
	for rel := range files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)

	var lit *ast.CompositeLit
	for _, rel := range rels {
		decl.PkgFiles++
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path.Base(rel), files[rel], 0)
		if err != nil {
			return nil, decl, fmt.Errorf("разбор %s: %w", rel, err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if name.Name != varName || i >= len(vs.Values) {
						continue
					}
					cl, ok := vs.Values[i].(*ast.CompositeLit)
					if !ok {
						continue
					}
					if lit != nil {
						// Package-level имя в пакете ровно одно by
						// construction; два означают, что читается не пакет.
						return nil, decl, fmt.Errorf(
							"объявление %s найдено дважды (%s и %s) — читается не один пакет, "+
								"и набор вышел бы склейкой двух таблиц", varName, decl.DeclFile, rel)
					}
					lit, decl.DeclFile = cl, rel
				}
			}
		}
	}
	if lit == nil {
		return nil, decl, fmt.Errorf(
			"в пакете не найдено объявление %s (осмотрено файлов %d) — объявление переехало "+
				"либо переименовано; это НЕ находка о продукте, а отказ гейта отработать",
			varName, decl.PkgFiles)
	}

	seen := map[string]bool{}
	var out []string
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		bl, ok := kv.Key.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			continue
		}
		key, err := strconv.Unquote(bl.Value)
		if err != nil {
			continue
		}
		decl.TypeKeys++
		dot := strings.IndexByte(key, '.')
		if dot <= 0 {
			continue
		}
		if m := key[:dot]; !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return nil, decl, fmt.Errorf(
			"в %s объявление %s не дало НИ ОДНОГО ключа вида \"модуль.ресурс\" "+
				"(ключей прочитано %d) — форма ключа сменилась",
			decl.DeclFile, varName, decl.TypeKeys)
	}
	sort.Strings(out)
	return out, decl, nil
}

// ModuleSetScan — перепись обхода поверхностей.
type ModuleSetScan struct {
	// Enumerations — сколько перечней (три имени и более) рассужено.
	Enumerations int
	// PairSpans — сколько спанов РОВНО из двух имён встречено и НЕ рассужено.
	// Объявленная слепая зона, а не находка.
	PairSpans int
}

// ScanModuleSetEnumerations судит перечни ОДНОГО файла поверхности.
//
// Возвращает находки и перепись; вызывающий складывает перепись по файлам сам —
// ему же принадлежит решение, какие файлы читать.
// ModuleSetDeclCorpus — файлы ПАКЕТА, из разбора которого выводится набор.
//
// Дерево параметром, отбор объявлен здесь, пустой обход — отказ (#17).
func ModuleSetDeclCorpus(tree *treecorpus.Tree) (TreeCorpus, error) {
	return CorpusFrom(tree, func(rel string) bool {
		return ProductionGoFile(rel) && path.Dir(rel) == ModuleSetPkgRel
	})
}

// IsModuleSetSurfaceFile — лежит ли файл на КЛИЕНТСКОЙ ПОВЕРХНОСТИ, перечни
// которой сверяются с набором.
func IsModuleSetSurfaceFile(rel string) bool {
	if !HasModuleSetSurfaceExt(rel) {
		return false
	}
	for _, s := range ModuleSetSurfaces {
		if rel == s || strings.HasPrefix(rel, s+"/") {
			return true
		}
	}
	return false
}

// ModuleSetSurfaceCorpus — файлы клиентской поверхности из ДЕРЕВА.
func ModuleSetSurfaceCorpus(tree *treecorpus.Tree) (TreeCorpus, error) {
	return CorpusFrom(tree, IsModuleSetSurfaceFile)
}

func ScanModuleSetEnumerations(rel, body string, modules []string) ([]ModuleSetFinding, ModuleSetScan) {
	var scan ModuleSetScan

	alt := make([]string, 0, len(modules))
	for _, m := range modules {
		alt = append(alt, regexp.QuoteMeta(m))
	}
	one := fmt.Sprintf(moduleSetCodeSpanPattern, "(?:"+strings.Join(alt, "|")+")")
	enumRe := regexp.MustCompile(one + `(?:\s*/\s*` + one + `){2,}`)
	pairRe := regexp.MustCompile(one + `\s*/\s*` + one)
	nameRe := regexp.MustCompile(one)

	want := make(map[string]bool, len(modules))
	for _, m := range modules {
		want[m] = true
	}

	var findings []ModuleSetFinding
	for i, line := range strings.Split(body, "\n") {
		spans := enumRe.FindAllString(line, -1)
		for _, span := range spans {
			scan.Enumerations++
			named := map[string]bool{}
			for _, m := range nameRe.FindAllStringSubmatch(span, -1) {
				named[firstNonEmptyModuleName(m[1:])] = true
			}
			var missing []string
			for m := range want {
				if !named[m] {
					missing = append(missing, m)
				}
			}
			if len(missing) == 0 {
				continue
			}
			sort.Strings(missing)
			namedList := make([]string, 0, len(named))
			for m := range named {
				namedList = append(namedList, m)
			}
			sort.Strings(namedList)
			findings = append(findings, ModuleSetFinding{
				File: rel, Line: i + 1, Named: namedList, Missing: missing, Span: span,
			})
		}
		// Пары считаются ТОЛЬКО там, где перечня нет: иначе перечень из трёх дал
		// бы ещё и две «пары» и раздул объявленную слепую зону.
		if len(spans) == 0 {
			scan.PairSpans += len(pairRe.FindAllString(line, -1))
		}
	}
	return findings, scan
}

// HasModuleSetSurfaceExt — файл поверхности ли это.
func HasModuleSetSurfaceExt(rel string) bool {
	for _, ext := range ModuleSetSurfaceExts {
		if strings.HasSuffix(rel, ext) {
			return true
		}
	}
	return false
}

func firstNonEmptyModuleName(ss []string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
