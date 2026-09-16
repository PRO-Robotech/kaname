// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// registration_lanes.go — разбор ОБЪЯВЛЕНИЯ полос регистрации (приёмка Ф4
// `docs/engineering/acceptance/registration-and-its-three-consequences.md`,
// Р4, Ф4-06…Ф4-10; задача PRO-Robotech/kacho#1270).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Полоса регистрации — сущность НАШЕГО кода, перечисленная одним местом:
// `registration.Lanes` в `internal/apps/kaname/api/registration/lanes.go`. Каждая
// полоса объявляет свои следствия, и гейт судит ЭТО объявление: полоса, у
// которой среди следствий нет выдачи сессии, — красное с её именем (Ф4-07);
// объявление, из которого не разобрано ни одной полосы, — не зелёное и не
// красное, а «вердикта нет» (Ф4-09).
//
// Предмет переехал сюда из дома платформы: там свойство «каждая полоса выдаёт
// сессию» держал гейт, читавший объявление ЧУЖОЙ конфигурации по отступам
// (форма Ф-е). После Ф4 полоса — значение Go, и читается оно разбором.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО РАЗБИРАЕТСЯ — И В КАКИХ ФОРМАХ
//
// Объявление — `var Lanes = []Lane{ … }` в файле объявления. Элемент перечня —
// составной литерал полосы; читаются два поля:
//
//	Name         — строковый литерал либо идентификатор константы ТОГО ЖЕ файла;
//	Consequences — составной литерал среза, чьи элементы — идентификаторы
//	               констант того же файла либо строковые литералы.
//
// Формы записи элемента — ключевая (`{Name: …, Consequences: …}`) и позиционная
// (`{…, …}`), обе доказаны инъекцией. Выдача сессии узнаётся по ЗНАЧЕНИЮ
// следствия, а не по имени идентификатора: значение приносит вызывающий от
// производителя (`registration.ConsequenceSession`), и переименование константы
// гейт не ослепит.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОБЪЯВЛЕНИЕ — ОДНО
//
// Второе место, перечисляющее полосы, разошлось бы с первым молча, и гейт судил
// бы перечисленное, а исполнялось бы другое (Ф4-06). Поэтому вторая половина
// разбора обходит ВЕСЬ прод-код и считает составные литералы типа `Lane`
// (`registration.Lane` из чужого пакета): литерал вне файла объявления —
// находка с координатой. Комментарии и строки в счёт не идут by construction —
// разбор ходит по узлам.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
)

const (
	// RegistrationHomeRel — каталог полосы регистрации от корня модуля.
	RegistrationHomeRel = "internal/apps/kaname/api/registration"
	// RegistrationLanesFileRel — файл ЕДИНСТВЕННОГО объявления полос.
	RegistrationLanesFileRel = RegistrationHomeRel + "/lanes.go"
	// RegistrationLanesVar — имя переменной объявления.
	RegistrationLanesVar = "Lanes"
	// RegistrationLaneType — имя типа полосы.
	RegistrationLaneType = "Lane"
)

// RegistrationLane — одна полоса, как её прочитал разбор.
type RegistrationLane struct {
	Name string
	Line int
	// Consequences — значения следствий, как они разрешились (литерал либо
	// константа файла). Неразрешённый идентификатор остаётся именем с
	// приставкой `?` — он виден в переписи, а не теряется.
	Consequences []string
	// IssuesSession — среди следствий есть значение выдачи сессии.
	IssuesSession bool
}

// RegistrationLanesCensus — объём осмотренного объявлением.
type RegistrationLanesCensus struct {
	// Declarations — переменных с именем объявления найдено (обязано быть 1).
	Declarations int
	// Lanes — полос разобрано.
	Lanes int
	// IssuingSession — из них с выдачей сессии.
	IssuingSession int
}

// ScanRegistrationLanes разбирает файл объявления: находит `var Lanes = []Lane{…}`
// и читает каждую полосу. sessionValue — значение следствия «сессия выдана» от
// производителя.
func ScanRegistrationLanes(path string, src []byte, sessionValue string) ([]RegistrationLane, RegistrationLanesCensus, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, RegistrationLanesCensus{}, err
	}
	consts := laneStringConsts(f)

	var (
		census RegistrationLanesCensus
		lanes  []RegistrationLane
	)
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if name.Name != RegistrationLanesVar || i >= len(vs.Values) {
					continue
				}
				census.Declarations++
				lit, ok := vs.Values[i].(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, elt := range lit.Elts {
					laneLit, ok := elt.(*ast.CompositeLit)
					if !ok {
						continue
					}
					lane := readRegistrationLane(fset, laneLit, consts, sessionValue)
					census.Lanes++
					if lane.IssuesSession {
						census.IssuingSession++
					}
					lanes = append(lanes, lane)
				}
			}
		}
	}
	return lanes, census, nil
}

// readRegistrationLane — одна полоса из её составного литерала.
func readRegistrationLane(fset *token.FileSet, lit *ast.CompositeLit, consts map[string]string, sessionValue string) RegistrationLane {
	lane := RegistrationLane{Line: fset.Position(lit.Pos()).Line}
	var nameExpr, consExpr ast.Expr
	for i, elt := range lit.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			key, _ := kv.Key.(*ast.Ident)
			if key == nil {
				continue
			}
			switch key.Name {
			case "Name":
				nameExpr = kv.Value
			case "Consequences":
				consExpr = kv.Value
			}
			continue
		}
		// Позиционная форма: первое поле — имя, второе — следствия.
		switch i {
		case 0:
			nameExpr = elt
		case 1:
			consExpr = elt
		}
	}
	if nameExpr != nil {
		if v, ok := resolveStringExpr(nameExpr, consts); ok {
			lane.Name = v
		} else if id, ok := nameExpr.(*ast.Ident); ok {
			lane.Name = "?" + id.Name
		}
	}
	if consLit, ok := consExpr.(*ast.CompositeLit); ok {
		for _, c := range consLit.Elts {
			v, ok := resolveStringExpr(c, consts)
			if !ok {
				if id, isIdent := c.(*ast.Ident); isIdent {
					v = "?" + id.Name
				} else {
					continue
				}
			}
			lane.Consequences = append(lane.Consequences, v)
			if v == sessionValue {
				lane.IssuesSession = true
			}
		}
	}
	return lane
}

// laneStringConsts — константы файла со строковым значением, по имени. Сверх
// соседского `fileStringConsts` читает форму `Consequence("session")` —
// преобразование типа над литералом; тип константы значения не меняет.
func laneStringConsts(f *ast.File) map[string]string {
	out := fileStringConsts(f)
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				if call, ok := vs.Values[i].(*ast.CallExpr); ok && len(call.Args) == 1 {
					if v, ok := basicString(call.Args[0]); ok {
						out[name.Name] = v
					}
				}
			}
		}
	}
	return out
}

// resolveStringExpr — строковое значение выражения: литерал, преобразование
// типа над литералом либо константа файла.
func resolveStringExpr(e ast.Expr, consts map[string]string) (string, bool) {
	if v, ok := basicString(e); ok {
		return v, true
	}
	switch x := e.(type) {
	case *ast.Ident:
		v, ok := consts[x.Name]
		return v, ok
	case *ast.CallExpr:
		if len(x.Args) == 1 {
			return resolveStringExpr(x.Args[0], consts)
		}
	}
	return "", false
}

// RegistrationLaneLiteralSite — составной литерал типа полосы в прод-коде.
type RegistrationLaneLiteralSite struct {
	File string
	Line int
}

func (s RegistrationLaneLiteralSite) String() string {
	return fmt.Sprintf("%s:%d", s.File, s.Line)
}

// ScanRegistrationLaneLiterals — составные литералы типа `Lane` (в своём пакете)
// либо `<пакет>.Lane` (из чужого) в одном Go-файле. Читатель судит, лежат ли они
// в файле объявления.
func ScanRegistrationLaneLiterals(path string, src []byte) ([]RegistrationLaneLiteralSite, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	var sites []RegistrationLaneLiteralSite
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if typeIsRegistrationLane(lit.Type) {
			sites = append(sites, RegistrationLaneLiteralSite{File: path, Line: fset.Position(lit.Pos()).Line})
			return true
		}
		// Элементы среза `[]Lane{ {…}, {…} }` — литералы без явного типа; их
		// тип задаёт объемлющий срез.
		if at, ok := lit.Type.(*ast.ArrayType); ok && typeIsRegistrationLane(at.Elt) {
			for _, elt := range lit.Elts {
				if inner, ok := elt.(*ast.CompositeLit); ok && inner.Type == nil {
					sites = append(sites, RegistrationLaneLiteralSite{File: path, Line: fset.Position(inner.Pos()).Line})
				}
			}
		}
		return true
	})
	return sites, nil
}

func typeIsRegistrationLane(t ast.Expr) bool {
	switch x := t.(type) {
	case *ast.Ident:
		return x.Name == RegistrationLaneType
	case *ast.SelectorExpr:
		return x.Sel != nil && x.Sel.Name == RegistrationLaneType
	}
	return false
}
