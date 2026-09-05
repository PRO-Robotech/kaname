// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// type_miss_is_a_branch_test.go — промах словаря типов РЕШЁН ВЕТКОЙ, а не
// отброшен (#1980).
//
// # Предмет и ЧТО ЗАМЕР ПОКАЗАЛ
//
// `authzmap.ObjectType(module, resource)` отдаёт ПАРУ: имя типа и «есть ли пара
// в словаре». Задача #1980 называет отброшенное второе значение действующим
// дефектом: «отсутствие пары становится неотличимо от пары с пустым типом».
//
// НА ЭТОМ ДЕРЕВЕ ПОСЫЛКА НЕВЕРНА, и это измерено, а не решено вкусом: законного
// пустого имени в закрытой таблице нет ни одного (27 пар, 0 пустых значений —
// держит `authzmap.TestEmptyTypeNameIsNeverALegalValue` вместе со второй
// половиной эквивалентности `TestMissReturnsTheEmptyName`). Значит пустота ⟺
// промах, и слияние, которого задача опасается, НЕ ПРЕДСТАВИМО.
//
// Из четырёх мест, названных задачей, два уже читают второе значение
// (`permission_catalog/list_catalog.go`, `seed/catalog_parity.go`) — там пустота
// НИКЕМ не декодировалась и попадала арендатору в витрину наравне с честным
// ответом. Оставшиеся живут в `roleexport`, и там пустота — НЕСУЩЕЕ значение с
// живой популяцией: ресурс, у которого пообъектного типа нет вовсе, а право
// спрашивается на области (`vpc.quota`). Её декодируют три ветки, и каждая даёт
// СВОЙ разбор: `producibility.Produces`, `check.emptyClassDetail`,
// `classfit.unsuitableDetail`.
//
// Попытка «починить» их отдельной находкой была сделана и ОТВЕРГНУТА опытом:
// новая ветка перехватывала вердикт раньше и подменяла точный разбор («у пары
// нет типа объекта, право спрашивается `viewer@project`») общим — существующая
// инъекция `TestInjection_ResourceWithoutAnObjectTypeSaysSo` покраснела в тот же
// прогон. То есть предписанная задачей форма делала диагноз ХУЖЕ.
//
// # Что тогда судит этот гейт
//
// Не «прочитано ли второе значение» ради формы, а ГРАНИЦУ послабления: место,
// берущее только первое значение, обязано стоять в ведомости с названным
// декодером пустоты. Новое место, заведённое без записи, — находка: пустота там
// не декодирована никем, и это ровно тот дефект, который задача описывает.
//
// Послабление ИСТЕКАЕТ САМО дважды: запись, чей файл перестал отбрасывать
// признак, роняет гейт; а появление законного пустого имени роняет пробу
// предпосылки в `authzmap` — то есть основание всей ведомости.
//
// # Что этот гейт судит технически
//
// УЗЕЛ ВЫЗОВА, а не слово: `ok` считается прочитанным, если второе значение
// присвоено имени, отличному от `_`. Форма «вызов внутри другого выражения» под
// запрет не подпадает by construction — двузначный вызов там неразбираем
// компилятором, поэтому таких мест в дереве не бывает.
//
// Единица счёта — УЗЕЛ ВЫЗОВА в не-тестовом файле, читающем пакет по его
// локальному имени импорта (псевдоним учитывается: `am "…/authzmap"` — форма
// столь же законная, и не знать её значило бы вывести всё написанное в ней ИЗ
// НАБЛЮДЕНИЯ, а не признать чистым).

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// twoValueSymbols — символы `authzmap`, отдающие ПАРУ (значение, известен ли).
//
// Перечень называет ровно те, у которых второе значение несёт СУЩЕСТВОВАНИЕ
// пары в закрытой таблице. Тотальные переходники (`ModelTypeName`,
// `CatalogTypeName`) сюда не входят и входить не должны: они отдают одно
// значение, и отбрасывать у них нечего.
var twoValueSymbols = map[string]bool{
	"ObjectType":    true,
	"FGAObjectType": true,
	"DottedType":    true,
}

// decodedMissFiles — файлы, которым отбрасывать признак РАЗРЕШЕНО, и причина
// по каждому.
//
// Причина у всех одна по существу и разная по координате: пустое имя типа в этом
// пакете НЕСЁТ смысл «пообъектного указателя на такой ресурс не пишет никто», и
// его декодирует названная ветка, дающая по нему отдельный разбор. Ведомость
// хранит именно КООРДИНАТУ декодера: без неё запись означала бы «мы так решили»,
// а с ней её можно проверить чтением.
var decodedMissFiles = map[string]string{
	"services/iam/internal/manifest/roleexport/check.go": "пустота декодируется " +
		"`emptyClassDetail` (ветка `if fgaType == \"\"`) и даёт разбор «у пары нет типа " +
		"объекта, пообъектного указателя не пишет никто»; подмена этого разбора общим " +
		"отказом краснит `TestInjection_ResourceWithoutAnObjectTypeSaysSo`",
	"services/iam/internal/manifest/roleexport/classfit.go": "пустота декодируется " +
		"`unsuitableDetail` (ветка `case fgaType == \"\"`) — пометка «непригодно для роли» " +
		"со своей причиной, а не отказ",
	"services/iam/internal/manifest/roleexport/namedverbs.go": "значение уходит в " +
		"`Produces` (ветка `if fgaType == \"\"`) и в `unsuitableNamedDetail`, который " +
		"сравнивает объект гейта с типом ресурса; пустота там означает «правило роли не " +
		"пишет на этом ресурсе ни одного кортежа»",
}

// typeMiss — одно место, где промах словаря отброшен.
type typeMiss struct {
	File   string
	Line   int
	Symbol string
}

// discardedTypeMisses разбирает перечень файлов и возвращает узлы вызова, у
// которых второе значение присвоено `_`, плюс числа переписи.
//
// Состав приходит ПАРАМЕТРОМ, а не собирается обходом диска: инъекция подаёт
// сюда синтетический перечень, а доказательство, требующее испортить живое
// дерево, в конвейере не исполняется никогда.
func discardedTypeMisses(root string, files []string, want map[string]bool) (
	misses []typeMiss, importers, calls int, err error) {

	fset := token.NewFileSet()
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil, 0, 0, fmt.Errorf("разбор %s: %w", path, perr)
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		local := localNameOfImport(f, authzmapImportPath)
		if local == "" {
			continue
		}
		importers++
		ast.Inspect(f, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Rhs) != 1 || len(as.Lhs) != 2 {
				return true
			}
			call, ok := as.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != local || !want[sel.Sel.Name] {
				return true
			}
			calls++
			// Второе значение прочитано, когда оно связано ИМЕНЕМ. `_` —
			// единственная форма отбрасывания в этой позиции.
			if snd, isIdent := as.Lhs[1].(*ast.Ident); isIdent && snd.Name == "_" {
				misses = append(misses, typeMiss{
					File: rel, Line: fset.Position(call.Pos()).Line, Symbol: sel.Sel.Name,
				})
			}
			return true
		})
	}
	return misses, importers, calls, nil
}

// TestIAMCT2_TypeMissIsDecidedByABranch — гейт на дереве.
func TestIAMCT2_TypeMissIsDecidedByABranch(t *testing.T) {
	root := catalogRepoRoot(t)
	files, err := treecorpus.UnderWithSuffix(filepath.Join(root, iamTreeRel), ".go")
	if err != nil {
		t.Fatalf("состав дерева: %v", err)
	}
	misses, importers, calls, err := discardedTypeMisses(root, files, twoValueSymbols)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Перепись — ДО вердикта и независимо от него.
	t.Logf("осмотрено файлов дерева: %d; импортёров: %d; двузначных вызовов: %d; "+
		"из них с отброшенным ok: %d", len(files), importers, calls, len(misses))

	// Обход пуст ⇒ вердикт беспредметен. Оба числа проверяются порознь: файлов
	// может быть много при нуле импортёров, и тогда «ноль находок» означает
	// «ноль прочитанного о предмете».
	if len(files) == 0 || importers == 0 {
		t.Fatalf("обход прочитал %d файлов и %d импортёров %s — вердикт беспредметен",
			len(files), importers, authzmapImportPath)
	}
	// Двузначных вызовов ноль означает, что распознаватель ничего не искал: в
	// дереве они есть и остаются (переходник читают семнадцать мест). Ноль здесь
	// — отказ распознавателя, а не чистое дерево.
	if calls == 0 {
		t.Fatalf("распознано ноль двузначных вызовов при %d импортёрах — это отказ "+
			"РАСПОЗНАВАТЕЛЯ, а не чистое дерево", importers)
	}

	seen := map[string]bool{}
	var findings []typeMiss
	for _, m := range misses {
		if _, allowed := decodedMissFiles[m.File]; allowed {
			seen[m.File] = true
			continue
		}
		findings = append(findings, m)
	}

	if len(findings) > 0 {
		var b strings.Builder
		for _, m := range findings {
			fmt.Fprintf(&b, "\n  %s:%d — authzmap.%s", m.File, m.Line, m.Symbol)
		}
		t.Errorf("промах словаря типов отброшен ВНЕ ведомости (%d мест):%s\n\n"+
			"Пустое имя типа — признак промаха (держит authzmap."+
			"TestEmptyTypeNameIsNeverALegalValue). Читатель, который его не декодирует, "+
			"пропустит промах дальше как полноценное значение: оно сравнивается, "+
			"печатается и уезжает в проекции, а вердикт назовёт виновником не ту "+
			"величину. Либо читайте второе значение и решайте промах ВЕТКОЙ, либо "+
			"впишите файл в `decodedMissFiles`, НАЗВАВ координату декодера (kacho#1980)",
			len(findings), b.String())
	}

	// Послабление ИСТЕКАЕТ САМО: запись, которой больше нечего исключать, —
	// находка. Иначе слепая зона переживёт свой предмет и достанется следующему
	// читателю, который положит в неё что угодно.
	for f := range decodedMissFiles {
		if !seen[f] {
			t.Errorf("записи ведомости %q больше нечего исключать: файл второе значение "+
				"словаря не отбрасывает (либо переехал/снят). Снимите запись — послабление "+
				"без предмета становится слепой зоной, заведённой вперёд", f)
		}
	}
}
