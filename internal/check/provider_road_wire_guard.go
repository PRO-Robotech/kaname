// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_road_wire_guard.go — разбор методов клиента административной дороги,
// УХОДЯЩИХ НА ПРОВОД (задачи `kacho#2573`, `kaname#21`).
//
// # ПРЕДМЕТ — ОБЕЩАНИЕ ОТСТАВЛЕННОГО КЛИЕНТА
//
// На посадке без внешнего поставщика строитель отдаёт клиента БЕЗ АДРЕСА
// (`NewAbsentProviderAdminClient`), и обещание его такое: всякий вызов получает
// ИМЕНОВАННЫЙ отказ, опознаваемый `errors.Is`, а не звонок в никуда. Обещание
// это — предикат снятия `kacho#2573`, п. 2.
//
// Держится оно сегодня ВНИМАНИЕМ: каждый метод, уходящий на провод, спрашивает
// стража сам. Пока методов три и все три спрашивают — обещание исполняется. Метод,
// заведённый завтра и стража не спросивший, соберёт запрос на ПУСТОМ адресе, и
// произойдёт это молча: тип тот же, подпись та же, сборка проходит.
//
// # ЧТО СЧИТАЕТСЯ «УХОДИТ НА ПРОВОД»
//
// Обращение к адресу у получателя — `c.BaseURL`. Признак выбран не по удобству:
// адрес и есть предмет отставленного клиента, его пустота — единственный
// признак несобранной дороги, и сам страж судит по нему же.
//
// # ПОЧЕМУ ПОРЯДОК, А НЕ ПРОСТО НАЛИЧИЕ
//
// Страж, спрошенный ПОСЛЕ того как запрос собран, — это та же ошибка, что дала
// имя всей задаче: полоса выбирается после того, как дорога построена. Поэтому
// находкой является и метод, спросивший стража позже первого касания адреса.
//
// # ЧЕГО РАЗБОР НЕ ВИДИТ — НАЗВАНО, А НЕ СПРЯТАНО
//
//  1. касание адреса через промежуточную переменную, присвоенную ДО стража;
//  2. метод, уходящий на провод по адресу из чужого поля, а не из `BaseURL`;
//  3. страж, спрошенный в вызванной отсюда функции, а не в теле метода, —
//     такой метод здесь находка, и это осознанно: разбор судит одно тело.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
)

// ProviderRoadWireMethod — метод клиента дороги, трогающий адрес.
type ProviderRoadWireMethod struct {
	File        string
	Method      string
	AddressLine int
	GuardLine   int // 0 — страж не спрошен вовсе
}

// Guarded — спрошен ли страж ДО первого касания адреса.
func (m ProviderRoadWireMethod) Guarded() bool {
	return m.GuardLine > 0 && m.GuardLine < m.AddressLine
}

// ProviderRoadWireCensus — объём осмотренного одним файлом.
type ProviderRoadWireCensus struct {
	Methods         int // методов получателя осмотрено
	AddressTouching int // из них трогают адрес
	GuardCalls      int // вызовов стража осмотрено
}

// receiverTypeName — имя типа получателя без указателя; пусто, если метода нет.
func receiverTypeName(fn *ast.FuncDecl) (typeName, recvName string) {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return "", ""
	}
	field := fn.Recv.List[0]
	switch t := field.Type.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			typeName = id.Name
		}
	case *ast.Ident:
		typeName = t.Name
	}
	if len(field.Names) > 0 {
		recvName = field.Names[0].Name
	}
	return typeName, recvName
}

// ScanProviderRoadWireMethods разбирает ОДИН файл.
//
// client — имя типа клиента дороги; addressField — поле адреса; guard — имя
// стража несобранной дороги; exempt — имена методов, которым касание адреса
// разрешено без стража (сам страж по адресу и судит).
func ScanProviderRoadWireMethods(path string, src []byte, client, addressField, guard string,
	exempt map[string]bool,
) ([]ProviderRoadWireMethod, ProviderRoadWireCensus, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, ProviderRoadWireCensus{}, err
	}
	var (
		out    []ProviderRoadWireMethod
		census ProviderRoadWireCensus
	)
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		typeName, recvName := receiverTypeName(fn)
		if typeName != client || recvName == "" {
			continue
		}
		census.Methods++
		if exempt[fn.Name.Name] {
			continue
		}
		var addressLine, guardLine int
		ast.Inspect(fn, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				id, ok := node.X.(*ast.Ident)
				if !ok || id.Name != recvName || node.Sel.Name != addressField {
					return true
				}
				if line := fset.Position(node.Pos()).Line; addressLine == 0 || line < addressLine {
					addressLine = line
				}
			case *ast.CallExpr:
				sel, ok := node.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != guard {
					return true
				}
				census.GuardCalls++
				if line := fset.Position(node.Pos()).Line; guardLine == 0 || line < guardLine {
					guardLine = line
				}
			}
			return true
		})
		if addressLine == 0 {
			continue
		}
		census.AddressTouching++
		out = append(out, ProviderRoadWireMethod{
			File: path, Method: fn.Name.Name,
			AddressLine: addressLine, GuardLine: guardLine,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AddressLine < out[j].AddressLine })
	return out, census, nil
}

// UnguardedProviderRoadWireMethods — методы, не спросившие стража до касания.
func UnguardedProviderRoadWireMethods(ms []ProviderRoadWireMethod) []ProviderRoadWireMethod {
	var out []ProviderRoadWireMethod
	for _, m := range ms {
		if !m.Guarded() {
			out = append(out, m)
		}
	}
	return out
}
