// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// withdrawal_producer_arrives_with_the_applier.go — разбор прод-дерева на
// СОГЛАСИЕ двух фактов: применитель ролей модуля приводится в действие, и
// производитель отзыва роли существует (порт с монорепо
// `internal/repohygiene/withdrawalproducerarriveswiththeapplier.go`, снят
// вынесением службы доступа — `kacho#2597`; задача продукта #1913).
//
// # Предмет
//
// Сверка `moduleroles.Reconcile` объявляет вид расхождения `LiveNotDeclared` —
// «строка живёт, объявления у неё больше нет». Пока применитель НЕ приводится
// в действие в проде, отсутствие производителя снятия — остаток, а не дефект.
// Как только применитель начинают звать (`cmd/kaname/serve.go`,
// `moduleroles.NewApplier`, задача #1034/#2010 — В KANAME ЭТО УЖЕ ПРОИЗОШЛО),
// остаток становится дефектом, необратимым ДЛЯ АРЕНДАТОРА: роль, которую
// нельзя снять, живёт вечно, и право, выданное через неё, продолжает
// действовать после того, как модуль перестал её объявлять.
//
// # Что здесь считается находкой — ОДНО согласие, а не два запрета
//
// Находка — состояние «применитель приводится в действие, производителя
// отзыва нет». Ни одна половина по отдельности находкой не является:
//
//	приводится в действие · производитель есть  → норма, работа сделана
//	приводится в действие · производителя нет   → НАХОДКА
//	не приводится        · производителя нет    → остаток
//	не приводится        · производитель есть   → норма, производитель приехал раньше
//
// # Обе половины судятся по УЗЛУ РАЗБОРА, а не по слову
//
// «Применитель приводится в действие» — это ВЫЗОВ через импортированный
// пакет, а не упоминание его имени. «Производитель отзыва» — это оператор
// ЗАПИСИ над `roles`, ставящий пометку снятия В СПИСКЕ ПРИСВОЕНИЙ.
//
// # Что изменилось при переносе, а что осталось дословно
//
// Изменилось: пакет (`repohygiene` → `check`), путь импорта применителя (без
// `services/iam/` — код лежит от корня модуля kaname: путь становится
// `github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles`). Осталось
// дословно: обе регулярки, форма связывания импорта (по псевдониму, а не по
// последнему сегменту пути), различение узла разбора и узла-прозы, имя
// держателя `TestWithdrawalProducerArrivesWithTheApplier`.
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
//  1. миграцию как производителя (запрещена отдельным гейтом её же смысла);
//  2. производителя вне дерева модуля;
//  3. запрос, собранный из кусков в рантайме.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strconv"
	"strings"
)

// WithdrawalApplierImportPath — пакет применителя ролей модуля.
const WithdrawalApplierImportPath = "github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"

// withdrawalApplierDriveNames — имена, которыми применитель ПРИВОДИТСЯ В
// ДЕЙСТВИЕ.
var withdrawalApplierDriveNames = map[string]struct{}{
	"NewApplier": {},
	"Reconcile":  {},
}

// RoleWithdrawalSite — координата одной из двух половин.
type RoleWithdrawalSite struct {
	File string
	Line int
	What string
}

// RoleWithdrawalCensus — объём осмотренного одним файлом.
type RoleWithdrawalCensus struct {
	AppliedImports  int
	Selectors       int
	StringLiterals  int
	Comments        int
	WritesOverRoles int
}

var roleWithdrawalWriteRe = regexp.MustCompile(`(?is)\b(?:update|insert\s+into)\s+(?:kaname\.)?roles\b`)
var roleWithdrawalMarkRe = regexp.MustCompile(`(?i)\b(?:retired_at|live)\s*=`)
var roleWithdrawalSetTailRe = regexp.MustCompile(`(?is)\b(?:where|returning|from)\b`)

// ScanRoleWithdrawalWiring разбирает один файл Go.
//
// Возвращает две половины раздельно — приведение применителя в действие и
// производителя отзыва, — потому что находка есть их НЕСОГЛАСИЕ, а не любая
// из них. Сводит половины вызывающий.
func ScanRoleWithdrawalWiring(path string, src []byte) (drive, mark []RoleWithdrawalSite, census RoleWithdrawalCensus, err error) {
	fset := token.NewFileSet()
	f, perr := parser.ParseFile(fset, path, src, parser.ParseComments)
	if perr != nil {
		return nil, nil, RoleWithdrawalCensus{}, perr
	}
	for _, g := range f.Comments {
		census.Comments += len(g.List)
	}

	binding := ""
	for _, imp := range f.Imports {
		p, uerr := strconv.Unquote(imp.Path.Value)
		if uerr != nil || p != WithdrawalApplierImportPath {
			continue
		}
		census.AppliedImports++
		if imp.Name != nil {
			binding = imp.Name.Name
		} else {
			binding = WithdrawalApplierImportPath[strings.LastIndexByte(WithdrawalApplierImportPath, '/')+1:]
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			id, ok := v.X.(*ast.Ident)
			if !ok {
				return true
			}
			census.Selectors++
			if binding == "" || id.Name != binding {
				return true
			}
			if _, ok := withdrawalApplierDriveNames[v.Sel.Name]; ok {
				drive = append(drive, RoleWithdrawalSite{
					File: path, Line: fset.Position(v.Sel.Pos()).Line, What: v.Sel.Name,
				})
			}
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return true
			}
			census.StringLiterals++
			text := roleDeleteLitText(v.Value)
			hits := roleWithdrawalWriteRe.FindAllStringIndex(text, -1)
			census.WritesOverRoles += len(hits)
			for _, m := range hits {
				if !withdrawalAssignsMark(text[m[1]:]) {
					continue
				}
				mark = append(mark, RoleWithdrawalSite{
					File: path, Line: fset.Position(v.Pos()).Line, What: roleDeleteFirstLineOf(v.Value),
				})
				break
			}
		}
		return true
	})
	return drive, mark, census, nil
}

// withdrawalAssignsMark — стоит ли пометка снятия в СПИСКЕ ПРИСВОЕНИЙ хвоста
// оператора.
func withdrawalAssignsMark(tail string) bool {
	i := strings.Index(strings.ToLower(tail), "set")
	if i < 0 {
		return false
	}
	seg := tail[i+len("set"):]
	if end := roleWithdrawalSetTailRe.FindStringIndex(seg); end != nil {
		seg = seg[:end[0]]
	}
	return roleWithdrawalMarkRe.MatchString(seg)
}
