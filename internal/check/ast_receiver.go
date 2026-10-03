// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ast_receiver.go — разбор получателя метода, общий для гейтов пакета.
//
// Жил в гейте проводной стражи дороги к внешнему поставщику; гейт снят вместе с
// дорогой (kaname#363), а разбором пользуются гейты полосы входа и писателей
// адреса человека. Вторая копия одного разбора разошлась бы с первой молча,
// поэтому он вынесен сюда, а не скопирован.
package check

import "go/ast"

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
