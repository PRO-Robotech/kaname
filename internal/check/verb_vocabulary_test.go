// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// verb_vocabulary_test.go — КАЖДЫЙ литеральный словарь глаголов в дереве
// обоснован моделью прав (порт ЯДРА с монорепо
// `internal/repohygiene/verbvocabulary_test.go`, держатель
// `TestVerbVocabularyLiteralsMatchModel`, снят вынесением службы доступа —
// `kacho#2597`).
//
// # Что перенесено, а что НЕТ — сказано прямо
//
// Монорепошный предок несёт ПЯТЬ проверок одного предмета: сам гейт
// (перенесён здесь) и четыре проверки ДИСЦИПЛИНЫ ВЕДЕНИЯ реестра
// (`RosterCoversEveryLiteral` — обнаруживает необнесённые в реестр литералы
// самостоятельным обходом по форме; `RosterEntriesStillHaveSubject`;
// `GateCannotImportEitherSide` / `ImportForbiddenFrom_HasBothControls` —
// гейт не импортирует ни продукт, ни модель, читая обе стороны разбором
// текста). Эти четыре НЕ перенесены за отведённое время — они самостоятельны
// по ценности (держат сам реестр живым и полным), но требуют по-новому
// выверить обнаружение по форме на дереве kaname, а не только перенести
// путь. Перенесён ЯДРОВОЙ гейт — сверка девяти известных литералов с
// моделью, — потому что именно он ловит настоящий класс дефекта (эмиттер
// пишет отношение, которого модель не знает).
//
// Все девять записей реестра ПЕРЕПРОВЕРЕНЫ на дереве kaname (путь, имя
// переменной) — они существуют дословно, только без префикса `services/iam/`.
//
// # Предмет
//
// Ось ТИПОВ давно привязана к модели: гейт дрейфа требует точного равенства
// в обе стороны. Ось ГЛАГОЛОВ не сверялась ни с чем: её сторожили литералы,
// каждый из которых объявлял ожидаемое и ни один — на каком основании именно
// это. Литерал чинится дописыванием в себя, поэтому СОГЛАСОВАННОЕ расширение
// всех литералов проходило молча. Гейт спрашивает МОДЕЛЬ.
//
// Предикат — ВХОЖДЕНИЕ, а не равенство: набор У ТИПА — подмножество словаря
// модели и равенству не обязан. Равенство здесь краснело бы на законном
// расширении набора одного типа.
//
// # Что изменилось при переносе, а что осталось дословно
//
// Изменилось: пакет (`repohygiene` → `check`), путь модели
// (`proto/kaname/cloud/iam/v1/fga_model.fga` → `internal/authzmodel/fga_model.fga`
// — proto остаётся в монорепо, kaname вендорит модель плоским файлом), пути
// всех девяти записей реестра (без префикса `services/iam/`). Осталось
// дословно: обе регулярки/разборщики (`defineRelationName`,
// `stringLiteralElements`, `parseStringSliceVar`, `normalizeVerbToken`),
// форма реестра (`claims`/`checkedBy`/`retireWhen` на запись), имя держателя
// `TestVerbVocabularyLiteralsMatchModel`.
package check_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// canonicalVerbModelRel — каноническая модель прав, от корня модуля kaname.
const canonicalVerbModelRel = "internal/authzmodel/fga_model.fga"

// verbRelationPrefix — приставка, по которой имя отношения модели опознаётся
// как глагольное.
const verbRelationPrefix = "v_"

// verbLiteral — запись реестра: путь и переменная от корня модуля.
type verbLiteral struct {
	path       string
	varName    string
	claims     string
	checkedBy  string
	retireWhen string
}

// verbLiteralRoster — известные литеральные словари глаголов. Перепроверены
// на дереве kaname дословно (путь без `services/iam/`, имя переменной то же).
//
// ГРАНИЦА ПОЛНОТЫ, названная прямо: реестр НЕ подтверждён обнаружением
// (`RosterCoversEveryLiteral` предка сюда не перенесена) — он может не
// покрывать литерал, заведённый ПОСЛЕ переноса. Это остаток, а не тишина:
// следующий, кто заводит десятый словарь глаголов, обязан дописать сюда
// запись сам, зная, что автоматической страховки пока нет.
var verbLiteralRoster = []verbLiteral{
	{
		path:    "internal/apps/kaname/api/permission_catalog/resource_verbs_test.go",
		varName: "previouslyOfferedToEveryResource",
		claims: "что выпадающий список редактора ролей предлагал КАЖДОМУ ресурсу до " +
			"появления словаря по ресурсу — база сравнения «никто не потерял», не словарь платформы",
		checkedBy:  "тот же файл: TestCatalogResourceVerbs_DescribeTheTypesOwnSets",
		retireWhen: "объявление удалено",
	},
	{
		path: "internal/domain/role_effective_verbs.go", varName: "verbDisplayPrecedence",
		claims:     "старшинство ПОКАЗА в превью роли; полноты НЕ утверждает",
		checkedBy:  "domain: TestEffectiveVerbs_UnchangedForEveryRuleShape",
		retireWhen: "объявление удалено",
	},
	{
		path: "internal/modelrender/render.go", varName: "canonicalVerbOrder",
		claims:     "ПОРЯДОК, в котором канон ставит глагольные отношения внутри блока типа",
		checkedBy:  "modelrender: TestCanonicalVerbOrderAgreesWithTheClassRule",
		retireWhen: "объявление удалено",
	},
	{
		path: "internal/manifest/resources.go", varName: "canonicalVerbClasses",
		claims:     "закрытый перечень КЛАССОВ действия манифеста домена; полноты словаря НЕ утверждает",
		checkedBy:  "internal/check: TestVerbClassRuleIsDeclaredOnce (если перенесена)",
		retireWhen: "объявление удалено",
	},
	{
		path: "internal/domain/rule_verbs_test.go", varName: "scopeTypeVerbs",
		claims:     "набор глаголов ТИПА якоря привязки — фикстура домена, не словарь платформы",
		checkedBy:  "тот же файл: разворот подстановки на якоре",
		retireWhen: "объявление удалено",
	},
	{
		path: "internal/domain/scope_self_admin_cascade_source_test.go", varName: "anchorTypeVerbs",
		claims:     "то же во внешнем тестовом пакете домена",
		checkedBy:  "тот же файл: вывод яруса на якоре",
		retireWhen: "объявление удалено",
	},
	{
		path: "internal/domain/role_effective_verbs_typeset_test.go", varName: "commonVocabulary",
		claims:     "ЗАПАСНОЙ словарь для `WithCommonFallback` — вход фикстуры домена, не суждение о платформе",
		checkedBy:  "тот же файл: TestAuthoredVerbs_WildcardRuleFallsBackToCommon и соседний негативный кейс",
		retireWhen: "объявление удалено",
	},
	{
		path:       "internal/repo/kaname/pg/applied_type_reaches_the_verdict_integration_test.go",
		varName:    "verdictProbeVerbs",
		claims:     "набор действий СИНТЕТИЧЕСКОГО ресурса, объявляемого манифестом в пробе последней мили",
		checkedBy:  "тот же файл: TestDoD1_TypeUnknownToTheBuildReachesTheVerdictThroughTheComposedModel",
		retireWhen: "объявление удалено",
	},
	{
		path: "internal/repo/kaname/pg/relverdict/xc12f5_labelcost_test.go", varName: "f5Verbs",
		claims:     "множитель M замера стоимости — сколько глаголов раздаёт ОДНА роль в сценарии",
		checkedBy:  "прогон замера: контроль на отказ постороннего + разрешение субъекта правила",
		retireWhen: "объявление удалено",
	},
}

// TestVerbVocabularyLiteralsMatchModel — несущий гейт оси глаголов.
func TestVerbVocabularyLiteralsMatchModel(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)

	model, defines := modelVerbVocabulary(t, root, prefix)
	if len(model) == 0 {
		t.Fatalf("из канонической модели %s не выведено ни одного глагола — предпосылка "+
			"гейта сломана", canonicalVerbModelRel)
	}
	t.Logf("перепись: из модели выведено глаголов: %d (%s); объявлений `define %s*` "+
		"прочитано: %d", len(model), strings.Join(model, ", "), verbRelationPrefix, defines)

	if len(verbLiteralRoster) == 0 {
		t.Fatalf("реестр литеральных словарей пуст — гейту нечего сверять")
	}
	t.Logf("перепись: литеральных словарей в реестре: %d", len(verbLiteralRoster))

	allowed := map[string]bool{}
	for _, v := range model {
		allowed[v] = true
		allowed[verbRelationPrefix+v] = true
	}

	for _, lit := range verbLiteralRoster {
		t.Run(lit.path+":"+lit.varName, func(t *testing.T) {
			p := platformtree.Under(prefix, lit.path)
			got, ok := parseStringSliceVar(t, filepath.Join(root, filepath.FromSlash(p)), lit.varName)
			if !ok {
				t.Fatalf("%s: объявления %q в дереве нет. Если оно удалено законно — снимите "+
					"запись реестра (условие снятия: %s)", p, lit.varName, lit.retireWhen)
			}
			var stray []string
			for _, v := range got {
				if !allowed[normalizeVerbToken(v)] {
					stray = append(stray, v)
				}
			}
			if len(stray) != 0 {
				sort.Strings(stray)
				t.Fatalf("%s: %s содержит имена, которых каноническая модель %s не знает: %v\n"+
					"литерал: %v\nсловарь модели: %v\n"+
					"Что этот литерал утверждает: %s\nКто проверяет это по существу: %s",
					p, lit.varName, canonicalVerbModelRel, stray, got, model,
					lit.claims, lit.checkedBy)
			}
		})
	}
}

// stringLiteralElements возвращает строковые элементы составного литерала
// `[]string{…}` / `[N]string{…}`; ok=false для любой другой формы.
func stringLiteralElements(expr ast.Expr) ([]string, bool) {
	lit, ok := expr.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	switch at := lit.Type.(type) {
	case *ast.ArrayType:
		id, ok := at.Elt.(*ast.Ident)
		if !ok || id.Name != "string" {
			return nil, false
		}
	default:
		if at != nil {
			return nil, false
		}
	}
	out := make([]string, 0, len(lit.Elts))
	for _, e := range lit.Elts {
		bl, ok := e.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return nil, false
		}
		s, err := strconv.Unquote(bl.Value)
		if err != nil {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// normalizeVerbToken — приведение имени к канонической форме.
func normalizeVerbToken(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// modelVerbVocabulary возвращает отсортированный список глаголов, выведенный
// из имён отношений `v_*` канонической модели, и число прочитанных объявлений.
func modelVerbVocabulary(t *testing.T, root, prefix string) (verbs []string, defines int) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(platformtree.Under(prefix, canonicalVerbModelRel)))
	data, err := os.ReadFile(p) // #nosec G304 -- путь из состава дерева этого модуля
	if err != nil {
		t.Fatalf("каноническая модель %s не прочитана (%v) — у гейта нет источника истины",
			canonicalVerbModelRel, err)
	}
	set := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		name, ok := defineRelationName(line)
		if !ok || !strings.HasPrefix(name, verbRelationPrefix) {
			continue
		}
		defines++
		set[strings.TrimPrefix(name, verbRelationPrefix)] = true
	}
	for v := range set {
		verbs = append(verbs, v)
	}
	sort.Strings(verbs)
	return verbs, defines
}

// defineRelationName достаёт имя отношения из строки вида `    define <name>: …`.
func defineRelationName(line string) (string, bool) {
	trimmed := strings.TrimLeft(line, " \t")
	if len(trimmed) == len(line) {
		return "", false
	}
	const kw = "define "
	if !strings.HasPrefix(trimmed, kw) {
		return "", false
	}
	rest := trimmed[len(kw):]
	i := strings.IndexByte(rest, ':')
	if i <= 0 {
		return "", false
	}
	name := strings.TrimSpace(rest[:i])
	if name == "" || strings.ContainsAny(name, " \t") {
		return "", false
	}
	return name, true
}

// parseStringSliceVar возвращает значения объявления `var <name> = []string{…}`
// верхнего уровня.
func parseStringSliceVar(t *testing.T, path, name string) ([]string, bool) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("%s: разбор не удался (%v)", path, err)
	}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if ident.Name != name || i >= len(vs.Values) {
					continue
				}
				elems, ok := stringLiteralElements(vs.Values[i])
				if !ok {
					t.Fatalf("%s: %s объявлена не списком строковых литералов", path, name)
				}
				return elems, true
			}
		}
	}
	return nil, false
}
