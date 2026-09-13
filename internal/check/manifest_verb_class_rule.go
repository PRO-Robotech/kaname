// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// manifest_verb_class_rule.go — два распознавателя для свойств ДЕРЕВА, которых
// проба пакета утверждать не может.
//
//  1. правило «класс действия из его ИМЕНИ» объявлено в дереве РОВНО ОДИН РАЗ.
//     Проба пакета о числе объявлений не утверждает ничего: она зелена при
//     любом. Единственность объявления делает второе место НЕПРЕДСТАВИМЫМ, и это
//     сильнее тождества импорта: появится генератор — импортировать ему будет
//     нечего, кроме одной функции, by construction;
//
//  2. правило вывода «тип объекта из имени ресурса» СНЯТО и не возвращено тихо.
//     Приёмка сняла его замером, и без держателя его можно вернуть молча: ключ
//     перестал бы быть обязательным, а восстанавливающее правило поселилось бы в
//     ДВУХ местах — в генераторе (когда опускать) и в загрузчике (как
//     восстановить).
//
// # Как распознаётся правило «класс из имени» — и почему НЕ по набору литералов
//
// Наивный распознаватель («объявление, чей набор строковых литералов равен пяти
// каноническим») даёт ЛОЖНУЮ находку: рядом живёт ПОРЯДОК ПОКАЗА глаголов, набор
// у которого тот же, а референт другой. Гейт, краснеющий на верном коде,
// отключают первым.
//
// Поэтому распознаётся ПАРА: функция, отвечающая «класс и получилось ли»
// (результаты `(string, bool)`), и набор ровно пяти канонических токенов, до
// которого она дотягивается — своим телом либо объявлением того же файла.
// Порядок показа под это не подпадает: его читает функция с ОДНИМ результатом.
//
// # Порт с монорепо — пара файлов названа, а не умолчана
//
// Перенесено с `PRO-Robotech/kacho:internal/repohygiene/manifestverbclassrule_test.go`
// (семейство снято вынесением службы, `kacho#2597`; предмет жив здесь — задача
// #17). Изменилось: каталог загрузчика (приставки `services/iam/` в
// самостоятельном клоне нет), пакет, и вход распознавателей — исходник вместо
// уже разобранного узла: разбор живёт теперь в одном месте, а проба и инъекция
// подают ему текст. Осталось дословно: имена обоих гейтов, пара признаков и
// тексты находок.
package check

import (
	"fmt"
	"github.com/PRO-Robotech/corelib/treecorpus"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
)

// ManifestLoaderDir — прод-файлы загрузчика манифеста. Гейт читает их как ТЕКСТ
// дерева: импортировать пакет отсюда нельзя (правило видимости `internal` тут ни
// при чём — импорт завёл бы зависимость гейта от предмета, который он судит).
const ManifestLoaderDir = "internal/manifest"

// canonicalClassTokens — те же пять токенов, что объявляет контракт манифеста.
//
// Здесь они ОБРАЗЕЦ распознавателя, а не второе объявление правила: гейт по ним
// ИЩЕТ, а не выводит из них класс.
var canonicalClassTokens = map[string]bool{
	"get": true, "list": true, "create": true, "update": true, "delete": true,
}

// classRuleStringLiterals — множество НЕПУСТЫХ строковых литералов узла.
//
// Пустая строка исключается намеренно, и это не украшение: правило, написанное
// не общим набором, а собственным `switch`, возвращает пустую строку на
// неканоническом имени — и наивный распознаватель, считая её шестым токеном,
// такую копию НЕ НАШЁЛ БЫ. Форма законна и распространена; распознаватель,
// который её не знает, МОЛЧИТ, а не краснеет. Отсюда требование: перечисли
// все законные формы записи предмета и докажи инъекцией каждую.
func classRuleStringLiterals(n ast.Node) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(n, func(x ast.Node) bool {
		if b, ok := x.(*ast.BasicLit); ok && b.Kind == token.STRING {
			if s, err := strconv.Unquote(b.Value); err == nil && s != "" {
				out[s] = true
			}
		}
		return true
	})
	return out
}

// isCanonicalClassSet — множество литералов РАВНО пяти каноническим.
//
// Равенство, а не включение: включение поймало бы расширенный классификатор
// яруса, который классом действия не занимается вовсе.
func isCanonicalClassSet(set map[string]bool) bool {
	if len(set) != len(canonicalClassTokens) {
		return false
	}
	for k := range set {
		if !canonicalClassTokens[k] {
			return false
		}
	}
	return true
}

// answersClassAndOK — результаты функции суть «класс и получилось ли».
func answersClassAndOK(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 2 {
		return false
	}
	first, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
	if !ok || first.Name != "string" {
		return false
	}
	second, ok := fn.Type.Results.List[1].Type.(*ast.Ident)
	return ok && second.Name == "bool"
}

// ScanClassRuleDeclarations — объявления правила «класс из имени» в одном
// исходнике, с координатой каждого.
//
// Неразбираемый исходник отдаёт признак, а не пустой перечень: «объявлений ноль»
// иначе означало бы и «их нет», и «разбор не состоялся».
// GeneratedStubsPrefix — каталог сгенерированных стабов: правило, найденное
// там, принадлежало бы генератору, а не дереву.
const GeneratedStubsPrefix = "pkg/api/"

// IsVerbClassRuleSource — файл, в котором правило «класс глагола» вправе быть
// объявлено. Тестовый корпус вычитается намеренно: фикстура инъекции обязана
// уметь написать форму дефекта, иначе гейт нельзя проверить.
func IsVerbClassRuleSource(rel string) bool {
	return ProductionGoFile(rel) && !strings.HasPrefix(rel, GeneratedStubsPrefix)
}

// VerbClassRuleCorpus — корпус, в котором ищется объявление правила.
//
// Дерево параметром, отбор объявлен здесь, пустой обход — отказ (#17): прежде
// обход строился в теле пробы от корня своего модуля, и его премиса «обход не
// прочитал ни одного файла» не исполнялась ни разу.
func VerbClassRuleCorpus(tree *treecorpus.Tree) (TreeCorpus, error) {
	return CorpusFrom(tree, IsVerbClassRuleSource)
}

// ManifestLoaderCorpus — прод-файлы ЗАГРУЗЧИКА манифеста.
func ManifestLoaderCorpus(tree *treecorpus.Tree) (TreeCorpus, error) {
	return CorpusFrom(tree, func(rel string) bool {
		return IsVerbClassRuleSource(rel) && strings.HasPrefix(rel, ManifestLoaderDir+"/")
	})
}

func ScanClassRuleDeclarations(rel string, src []byte) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, src, 0)
	if err != nil {
		return nil, fmt.Errorf("%s не разбирается: %w", rel, err)
	}

	// Наборы ровно пяти канонических токенов, объявленные на уровне файла.
	fileSets := map[string]bool{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i < len(vs.Values) && isCanonicalClassSet(classRuleStringLiterals(vs.Values[i])) {
					fileSets[name.Name] = true
				}
			}
		}
	}

	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil || !answersClassAndOK(fn) {
			continue
		}
		reaches := isCanonicalClassSet(classRuleStringLiterals(fn.Body))
		if !reaches {
			ast.Inspect(fn.Body, func(x ast.Node) bool {
				if id, ok := x.(*ast.Ident); ok && fileSets[id.Name] {
					reaches = true
				}
				return !reaches
			})
		}
		if reaches {
			out = append(out, fmt.Sprintf("%s:%d %s", rel,
				fset.Position(fn.Pos()).Line, fn.Name.Name))
		}
	}
	return out, nil
}

// ScanObjectTypeUses — сколько раз поле типа объекта ЧИТАЕТСЯ и где ему
// ПРИСВАИВАЮТ.
//
// Обе величины вместе: «присваиваний ноль» при нуле чтений означает, что
// распознаватель не видит поля вовсе, и тогда вердикт о присваиваниях не значит
// ничего.
func ScanObjectTypeUses(rel string, src []byte) (reads int, writes []string, err error) {
	fset := token.NewFileSet()
	file, perr := parser.ParseFile(fset, rel, src, 0)
	if perr != nil {
		return 0, nil, fmt.Errorf("%s не разбирается: %w", rel, perr)
	}
	isObjectType := func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		return ok && sel.Sel != nil && sel.Sel.Name == "ObjectType"
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				if isObjectType(lhs) {
					writes = append(writes, fmt.Sprintf("%s:%d", rel, fset.Position(lhs.Pos()).Line))
				}
			}
		case *ast.KeyValueExpr:
			if id, ok := node.Key.(*ast.Ident); ok && id.Name == "ObjectType" {
				writes = append(writes, fmt.Sprintf("%s:%d", rel, fset.Position(node.Pos()).Line))
			}
		case *ast.SelectorExpr:
			if isObjectType(node) {
				reads++
			}
		}
		return true
	})
	return reads, writes, nil
}
