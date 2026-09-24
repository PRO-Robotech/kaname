// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// published_key_rule_home.go — разбор обращений к правилу критичных параметров
// заголовка платформы (`tokenpolicy.CriticalHeadersUnderstood`), держатель
// `TestPublishedKeyRuleHasOneHome` (задача PRO-Robotech/kaname#396).
//
// # Предмет
//
// Токен службы проверяют три читателя: читатель предъявленного на публичном
// слушателе, интроспекция для соседей и опознание токена доступа церемонии.
// Ключ проверки каждый из них выбирает из публикуемого набора ОДНИМ правилом —
// форма `kid` → ключ по `kid` → алгоритм, закреплённый за ключом, → критичные
// параметры заголовка → открытая половина ключа. До сведения правило было
// написано трижды; копии уже разошлись в мелочи (одна читала испорченный свой
// ключ как негодный токен), и следующая расходилась бы так же молча: все три
// отвечают «подпись сошлась». Дом правила — `internal/publishedkey`.
//
// # Что здесь считается КОПИЕЙ
//
// Обращение к `tokenpolicy.CriticalHeadersUnderstood` — вызов либо значение
// функции. Иных потребителей правила критичных параметров у продукта нет:
// проверка утверждения клиента (`clientassertion`) судит свой перечень
// понятых параметров над ключом реестра клиентов, и платформенного правила не
// зовёт.
//
// # Распознаватель знает ВСЕ формы обращения by construction
//
// Он связывает имя с ПУТЁМ импорта из разобранного дерева, а не с текстом:
// обычный импорт, псевдоним и точечный импорт опознаются одинаково; пустой
// импорт обращения дать не может и только считается переписью. Метод чужого
// типа с тем же именем обращением не является, и упоминание имени в
// комментарии или строке — тоже: разбор судит узел, а не подстроку.
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
//  1. **копия, не судящая критичных параметров вовсе** — выбор ключа без этой
//     ветви обращения не несёт. Это другой класс (снятая проверка), и держат
//     его пробы ветвей в доме правила, а не этот гейт;
//  2. **имя импорта, перекрытое локальным** — переменная `tokenpolicy` внутри
//     функции. Такой код не собрался бы рядом с настоящим обращением.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
)

// CriticalHeaderRulePackage — путь импорта дома правила критичных параметров.
const CriticalHeaderRulePackage = "github.com/PRO-Robotech/corelib/tokenpolicy"

// CriticalHeaderRuleFunc — имя правила.
const CriticalHeaderRuleFunc = "CriticalHeadersUnderstood"

// CriticalHeaderRuleSite — координата обращения к правилу.
type CriticalHeaderRuleSite struct {
	File string
	Line int
	// Form — форма обращения: `plain` · `alias` · `dot`. Печатается переписью,
	// чтобы «ноль находок» было отличимо от «форму не узнали».
	Form string
}

// CriticalHeaderRuleCensus — объём осмотренного одним файлом.
type CriticalHeaderRuleCensus struct {
	// Selectors — выражений выбора (`x.Y`) прочитано.
	Selectors int
	// PolicyImports — импортов дома правила прочитано, в любой форме.
	PolicyImports int
}

// ScanCriticalHeaderRule разбирает один файл и возвращает обращения к правилу
// критичных параметров вместе с объёмом осмотренного.
func ScanCriticalHeaderRule(path string, src []byte) (sites []CriticalHeaderRuleSite, census CriticalHeaderRuleCensus, err error) {
	fset := token.NewFileSet()
	f, perr := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if perr != nil {
		return nil, CriticalHeaderRuleCensus{}, perr
	}

	forms := map[string]string{} // имя импорта в файле → форма
	dot := false
	for _, spec := range f.Imports {
		p, uerr := strconv.Unquote(spec.Path.Value)
		if uerr != nil || p != CriticalHeaderRulePackage {
			continue
		}
		census.PolicyImports++
		switch {
		case spec.Name == nil:
			forms["tokenpolicy"] = "plain"
		case spec.Name.Name == ".":
			dot = true
		case spec.Name.Name == "_":
		default:
			forms[spec.Name.Name] = "alias"
		}
	}

	v := &criticalHeaderRuleVisitor{fset: fset, path: path, forms: forms, dot: dot, census: &census}
	ast.Walk(v, f)
	return v.sites, census, nil
}

// criticalHeaderRuleVisitor — обход файла.
type criticalHeaderRuleVisitor struct {
	fset   *token.FileSet
	path   string
	forms  map[string]string
	dot    bool
	census *CriticalHeaderRuleCensus
	sites  []CriticalHeaderRuleSite
}

func (v *criticalHeaderRuleVisitor) add(n ast.Node, form string) {
	v.sites = append(v.sites, CriticalHeaderRuleSite{File: v.path, Line: v.fset.Position(n.Pos()).Line, Form: form})
}

// Visit судит выбор и имя; у объявлений функции и поля обходит всё, кроме
// объявленного имени; прочие узлы — только проход вглубь.
func (v *criticalHeaderRuleVisitor) Visit(n ast.Node) ast.Visitor {
	switch x := n.(type) {
	case *ast.SelectorExpr:
		v.census.Selectors++
		if id, ok := x.X.(*ast.Ident); ok && x.Sel.Name == CriticalHeaderRuleFunc {
			if form, bound := v.forms[id.Name]; bound {
				v.add(x, form)
			}
		}
		// Левая часть выбора сама может нести обращение; правая — имя поля или
		// метода, а не обращение по точечному импорту.
		ast.Walk(v, x.X)
		return nil
	case *ast.FuncDecl:
		// Имя объявленной функции или метода — объявление, а не обращение.
		if x.Recv != nil {
			ast.Walk(v, x.Recv)
		}
		ast.Walk(v, x.Type)
		if x.Body != nil {
			ast.Walk(v, x.Body)
		}
		return nil
	case *ast.Field:
		// Имена поля и параметра — объявления.
		if x.Type != nil {
			ast.Walk(v, x.Type)
		}
		return nil
	case *ast.Ident:
		if v.dot && x.Name == CriticalHeaderRuleFunc {
			v.add(x, "dot")
		}
	}
	return v
}
