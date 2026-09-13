// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// list_scope_double.go — разбор: пакет, чей дублёр области видимости объявляет
// её НЕОГРАНИЧЕННОЙ, обязан называть живого держателя настоящего отбора.
//
// # Предмет, и почему требуется именно это
//
// Снисходительность здесь НАМЕРЕННА, и её цена названа в самих пробах: строк
// выдачи у их фикстуры нет вовсе, поэтому назвать кандидатов она не может, а
// сузив набор до пустого — вернула бы пустую страницу везде и стёрла бы предмет
// своих же проб (вердикт: каким отношением судится строка страницы). Требовать
// «почините дублёров» значило бы сломать работающее.
//
// Опасно другое. Отбор кандидатов держит РОВНО ОДИН пакет, и держит он его на
// настоящей базе. Выпадет он из набора — по недосмотру, из-за недоступных
// контейнеров, при переименовании — и свойство перестанет проверяться НИГДЕ, а
// ссылки на него останутся и будут читаться как покрытие. Форма остаётся,
// содержание исчезает молча.
//
// Поэтому разбор требует не сужения у дублёров, а РЕЗОЛВИМОСТИ ссылки: снятие
// держателя роняет прогон с ЕГО ИМЕНЕМ, а не тишиной.
//
// # Почему разбор синтаксиса для одной части и комментарии для другой
//
// Снисходительность — свойство ИСПОЛНЯЕМОГО кода (значение поля в литерале
// области), и ищется разбором: поиск подстроки нашёл бы слово в комментарии,
// объясняющем эту же проверку. Ссылка на держателя — наоборот, живёт ИМЕННО в
// комментарии, потому что адресована читателю; её и ищем в комментариях,
// разобранных парсером, а не в сыром тексте файла.
//
// # ДВА написания координаты — обе законны, и разбор обязан знать обе
//
// Здесь порт расходится с монорепошным оригиналом, и расходится ЗАМЕРОМ. Там
// координата была одна — `services/iam/internal/apps/kaname/api/<пакет>`. Здесь
// в дереве живут ОБЕ формы, и обе законны: приставка `services/iam/` остаётся
// канонической для вызовов `platformtree` (`treeposture.PathOf` принимает
// координату ОТ КОРНЯ ДЕРЕВА ПЛАТФОРМЫ и снимает приставку сам, когда модуль
// стоит самостоятельным клоном), а без приставки пишут там, где адресуют
// каталог этого модуля напрямую.
//
// Замер на дереве: строк-комментариев с приставкой — 53 в 31 файле, строк кода
// с ней же — 20, и КАЖДАЯ из двадцати законна by construction: это аргументы
// `platformtree`.
//
// ЧТО ЭТА ОСЬ СЕГОДНЯ МЕНЯЕТ, НАЗВАНО ЧЕСТНО — вердикта она не меняет, и
// сказать это надо прямо, иначе следующий прочтёт её как закрытый дефект.
// Перемер образцом только с приставкой: пакетов 27, снисходительных 7, держателя
// называют те же 7, находок 0 — то есть ровно столько же. Голая форма слепой не
// бывает by construction (она совпадает и ВНУТРИ приставочной), а приставочная
// теряет сегодня лишь 4 ссылки переписи из 54.
//
// Ось заведена не ради сегодняшнего числа, а ради ЗАВТРАШНЕГО: ссылка, написанная
// в голой форме в пакете, где другой ссылки нет, при однобразцовом распознавателе
// дала бы не красное и не зелёное, а невидимость. Перепись печатает обе величины
// порознь, поэтому смена соотношения будет видна числом, а не догадкой.
//
// # Граница, объявленная самим разбором
//
// Судятся только пакеты, которые снисходительного дублёра ЗАВОДЯТ. Пакет без
// него под разбор не подпадает — там нечему быть снисходительным. «Ноль
// находок» означает «у каждого снисходительного назван живой держатель», а не
// «снисходительных нет»: перепись печатает оба числа.
//
// # Порт с монорепо — пара файлов названа, а не умолчана
//
// Перенесено с `PRO-Robotech/kacho:internal/repohygiene/listscopedoubleisnotlenient_test.go`
// (семейство снято вынесением службы — `kacho#2598`; предмет жив здесь, задача
// #17). Изменилось: корень обхода (приставки `services/iam/` в самостоятельном
// клоне нет), разбор вынесен из пробы в пакет `check`, распознаватель знает обе
// формы координаты. Осталось дословно: имя гейта
// (`TestLenientScopeDoubleNamesALiveHolder`), предмет, граница и то, что
// снисходительность ищется разбором, а ссылка — в комментариях.
//
// Близнеца в платформе нет: семейство снято там вместе со службой (ban #20).
package check

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// UseCaseAPIRootRel — дом пакетов use-case в дереве МОДУЛЯ.
const UseCaseAPIRootRel = "internal/apps/kaname/api"

// lenientHolderRefRe — ссылка на держателя в комментарии, в ОБЕИХ законных
// формах координаты. Приставка необязательна, тело — одно и то же.
//
// Ищется путь, а не имя пакета: имя переживает переезд, путь — нет.
var lenientHolderRefRe = regexp.MustCompile(
	`(?:services/iam/)?` + regexp.QuoteMeta(UseCaseAPIRootRel) + `/([a-z_]+)`)

// LenientScopeCensus — объём осмотренного. Печатается ВСЕГДА: «ноль находок»
// обязано быть отличимо от «ноль прочитанного».
type LenientScopeCensus struct {
	Packages    int
	Lenient     int
	Named       int
	Holders     int
	HolderTests int
	// RefsPrefixed / RefsBare — сколько ссылок пришло в каждой из двух законных
	// форм. Печатаются порознь намеренно: ноль в одной из них означает, что
	// форма перестала встречаться, и это повод перемерить распознаватель, а не
	// повод ему молчать.
	RefsPrefixed int
	RefsBare     int
}

func (c LenientScopeCensus) String() string {
	return fmt.Sprintf(
		"осмотрено: пакетов use-case %d; со снисходительным дублёром %d, из них называют "+
			"держателя %d; держателей различных %d, проб у них суммарно %d; "+
			"ссылок с приставкой платформы %d, без приставки %d",
		c.Packages, c.Lenient, c.Named, c.Holders, c.HolderTests, c.RefsPrefixed, c.RefsBare)
}

// AuditLenientScopes ВОЗВРАЩАЕТ находки, а не роняет прогон сам: инъекция
// обязана уметь их прочитать, чтобы утверждать, ЧТО именно нашлось, а не только
// «покраснело». Отказ предпосылки остаётся ошибкой — на слепом обходе говорить
// не о чем.
func AuditLenientScopes(apiRoot string) (LenientScopeCensus, []string, error) {
	var census LenientScopeCensus

	entries, err := os.ReadDir(apiRoot)
	if err != nil {
		return census, nil, fmt.Errorf("обход пакетов use-case: %w", err)
	}

	holders := map[string][]string{}
	var findings []string

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		census.Packages++
		dir := filepath.Join(apiRoot, e.Name())
		files, gerr := filepath.Glob(filepath.Join(dir, "*_test.go"))
		if gerr != nil {
			return census, nil, fmt.Errorf("обход проб %s: %w", e.Name(), gerr)
		}

		var isLenient bool
		var refs []string
		for _, f := range files {
			fset := token.NewFileSet()
			node, perr := parser.ParseFile(fset, f, nil, parser.ParseComments)
			if perr != nil {
				return census, nil, fmt.Errorf("разбор %s: %w", f, perr)
			}
			if declaresUnrestrictedScope(node) {
				isLenient = true
			}
			for _, cg := range node.Comments {
				for _, m := range lenientHolderRefRe.FindAllStringSubmatch(cg.Text(), -1) {
					if strings.HasPrefix(m[0], "services/iam/") {
						census.RefsPrefixed++
					} else {
						census.RefsBare++
					}
					if m[1] != e.Name() {
						refs = append(refs, m[1])
					}
				}
			}
		}

		if !isLenient {
			continue
		}
		census.Lenient++
		if len(refs) == 0 {
			findings = append(findings, e.Name()+": дублёр области снисходительнее продукта, "+
				"но держатель свойства не назван — исчезновение единственного покрытия будет тихим")
			continue
		}
		census.Named++
		for _, r := range refs {
			if !namesPackageOnce(holders[r], e.Name()) {
				holders[r] = append(holders[r], e.Name())
			}
		}
	}
	census.Holders = len(holders)

	// Названный держатель обязан существовать и нести пробы: ссылка на пустой
	// каталог — та же тишина, только с адресом.
	for _, h := range sortedHolderNames(holders) {
		referrers := holders[h]
		hdir := filepath.Join(apiRoot, h)
		files, gerr := filepath.Glob(filepath.Join(hdir, "*_test.go"))
		if gerr != nil || len(files) == 0 {
			findings = append(findings, h+": назван держателем отбора пакетами ["+
				strings.Join(referrers, ", ")+"], но проб не несёт — "+
				"ссылка читается как покрытие, которого нет")
			continue
		}
		n := 0
		for _, f := range files {
			fset := token.NewFileSet()
			node, perr := parser.ParseFile(fset, f, nil, 0)
			if perr != nil {
				return census, nil, fmt.Errorf("разбор %s: %w", f, perr)
			}
			for _, d := range node.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
					n++
				}
			}
		}
		census.HolderTests += n
		if n == 0 {
			findings = append(findings, h+": назван держателем отбора пакетами ["+
				strings.Join(referrers, ", ")+"], но ни одной пробы в нём нет")
		}
	}

	if census.Packages == 0 {
		return census, nil, fmt.Errorf("пакетов use-case не найдено ни одного — обход слеп, "+
			"и «ноль находок» здесь неотличимо от «ноль прочитанного» (корень %q)", apiRoot)
	}
	if census.Lenient == 0 {
		return census, nil, errors.New("снисходительных дублёров не найдено ни одного — либо " +
			"форма объявления области сменилась, либо разбор слеп; разбор обязан заявить " +
			"об этом, а не выйти зелёным")
	}
	return census, findings, nil
}

// declaresUnrestrictedScope — есть ли в файле литерал `visibility.Scope` с
// `Unrestricted: true`.
//
// Ищется УЗЕЛ, а не слово: то же слово стоит в комментарии, объясняющем эту же
// снисходительность, и разбор по тексту зеленел бы на объяснении.
func declaresUnrestrictedScope(node *ast.File) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel == nil || sel.Sel.Name != "Scope" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "visibility" {
			return true
		}
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); !ok || key.Name != "Unrestricted" {
				continue
			}
			if id, ok := kv.Value.(*ast.Ident); ok && id.Name == "true" {
				found = true
			}
		}
		return true
	})
	return found
}

// namesPackageOnce — членство в срезе; ссылающийся пакет называется РОВНО ОДИН
// раз, иначе перечень в сообщении об отказе нечитаем, а нечитаемый перечень
// перестают читать.
func namesPackageOnce(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// sortedHolderNames — порядок находок детерминирован: обход карты его не задаёт, и без
// сортировки вывод менялся бы от прогона к прогону при неизменном дереве.
func sortedHolderNames(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
