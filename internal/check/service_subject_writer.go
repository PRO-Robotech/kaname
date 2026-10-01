// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// service_subject_writer.go — разбор «кто в этом дереве производит служебный
// субъект `service:<имя>`» (приёмка NTF-1, NTF1-M10; замысел З13, З17).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Служебный субъект заводится ОДНИМ путём: строка `notifications` манифеста,
// применитель посева, конструктор `moduleseed/service_tuple.go`. Строку субъекта
// там производит фундамент (`authz.ServiceSubject`). Всякое другое место дерева,
// производящее `service:`, — второй писатель: тенантская поверхность, выдающая
// службе право, которого манифест не объявлял и которое отозвать нечем.
//
// Писателя кортежа гейт опознаёт по ПРОИЗВОДСТВУ субъекта: кортеж без строки
// субъекта не пишется, а строку `service:` в этом дереве законно производят
// только три формы, и все три здесь узлы разбора:
//
//	вызов либо значение authz.ServiceSubject     — производитель фундамента;
//	authz.ServiceSubjectType операндом сложения  — склейка из слова типа;
//	строковый литерал, начинающийся с "service:" — склейка вручную;
//
// и четвёртая, отнимающая у разбора имя пакета, — точечный импорт `authz`
// фундамента; она находка сама по себе.
//
// Пакет `authz` опознаётся ПУТЁМ импорта, а не именем: под псевдонимом он тот же,
// а одноимённый чужой пакет — не он. Слово типа вне сложения — СРАВНЕНИЕ
// (тенантская поверхность отвергает тип `service`, сверяясь с ним), и это чтение,
// а не производство.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦА НАЗВАНА, А НЕ УМОЛЧАНА
//
// Разбор НЕ видит: субъекта, собранного по частям («serv» + «ice:», fmt.Sprintf
// со словом "service" отдельным литералом), и субъекта, взятого у читателя второго
// носителя (`authz.CallerSubject(ctx)` → `Caller.Subject()`), и слова типа,
// склеенного не сложением (fmt.Sprintf, strings.Join), и отданного на
// запись. Первое — настоящая слепая зона образца. Второе держит поведение: у
// тенантских поверхностей вызывающий — пересланный человек, и `CallerSubject`
// служебного субъекта для него не производит (пересланный тип `service`
// отвергается фундаментом). Тенантский кодек `domain.FGASubjectRef` служебного
// субъекта не производит by construction: незнакомый тип он пишет `user:`.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
)

// ServiceSubjectWriterFile — единственный разрешённый производитель: конструктор
// служебного кортежа применителя манифеста.
const ServiceSubjectWriterFile = "internal/apps/kaname/moduleseed/service_tuple.go"

// corelibAuthzPath — путь импорта пакета субъекта фундамента.
const corelibAuthzPath = "github.com/PRO-Robotech/corelib/authz"

// serviceSubjectPrefix — начало строки служебного субъекта.
const serviceSubjectPrefix = "service:"

// Формы производства — слова находки.
const (
	FormServiceSubjectCall = "authz.ServiceSubject"
	FormServiceSubjectType = "authz.ServiceSubjectType"
	FormServiceLiteral     = `литерал "service:"`
	FormDotImport          = "точечный импорт corelib/authz"
)

// ServiceSubjectSite — координата производства служебного субъекта.
type ServiceSubjectSite struct {
	File string
	Line int
	Form string
}

// ServiceSubjectCensus — объём осмотренного одним файлом.
type ServiceSubjectCensus struct {
	// Strings — строковых литералов прочитано.
	Strings int
	// AuthzSelectors — обращений к пакету authz фундамента (любых, не только
	// производящих): ненулевое число доказывает, что разбор узнаёт пакет.
	AuthzSelectors int
}

// ScanServiceSubjectProducers разбирает один файл и возвращает места
// производства служебного субъекта вместе с объёмом осмотренного.
func ScanServiceSubjectProducers(path string, src []byte) ([]ServiceSubjectSite, ServiceSubjectCensus, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, ServiceSubjectCensus{}, err
	}

	var census ServiceSubjectCensus
	var out []ServiceSubjectSite
	at := func(n ast.Node, form string) {
		out = append(out, ServiceSubjectSite{File: path, Line: fset.Position(n.Pos()).Line, Form: form})
	}

	// Имена, под которыми пакет authz фундамента виден в этом файле.
	names := map[string]bool{}
	for _, imp := range f.Imports {
		p, uerr := strconv.Unquote(imp.Path.Value)
		if uerr != nil || p != corelibAuthzPath {
			continue
		}
		switch {
		case imp.Name == nil:
			names["authz"] = true
		case imp.Name.Name == ".":
			at(imp, FormDotImport)
		case imp.Name.Name != "_":
			names[imp.Name.Name] = true
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.ImportSpec:
			// Путь импорта — не литерал субъекта.
			return false
		case *ast.BasicLit:
			if x.Kind != token.STRING {
				return true
			}
			census.Strings++
			if v, uerr := strconv.Unquote(x.Value); uerr == nil && strings.HasPrefix(v, serviceSubjectPrefix) {
				at(x, FormServiceLiteral)
			}
		case *ast.BinaryExpr:
			if x.Op != token.ADD {
				return true
			}
			for _, operand := range []ast.Expr{x.X, x.Y} {
				if isAuthzSelector(operand, names, "ServiceSubjectType") {
					at(operand, FormServiceSubjectType)
				}
			}
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			if !ok || !names[id.Name] {
				return true
			}
			census.AuthzSelectors++
			if x.Sel.Name == "ServiceSubject" {
				at(x, FormServiceSubjectCall)
			}
		}
		return true
	})
	return out, census, nil
}

// isAuthzSelector — выражение есть `<имя пакета authz>.<sel>`.
func isAuthzSelector(e ast.Expr, names map[string]bool, sel string) bool {
	x, ok := ast.Unparen(e).(*ast.SelectorExpr)
	if !ok || x.Sel.Name != sel {
		return false
	}
	id, ok := x.X.(*ast.Ident)
	return ok && names[id.Name]
}
