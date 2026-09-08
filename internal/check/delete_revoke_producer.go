// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// delete_revoke_producer.go — ЯДРО гейта симметрии: у снятия собственного
// объекта iam обязан быть производитель отзыва (задача PRO-Robotech/kacho#2055).
//
// # Предмет
//
// Создание собственного объекта iam СО-КОММИТИТ событие реконсайла в writer-tx:
// пообъектный кортеж владельца материализуется событийно, в ограниченном окне.
// Снятие того же объекта события НЕ эмитировало, а каскад `ON DELETE` на членах
// и журнале кортежей ключуется по идентификатору ПРИВЯЗКИ, а не по
// идентификатору снятого объекта. Значит пообъектный кортеж на снятом объекте
// доживал до ближайшего периодического прохода: форма асимметрична созданию, и
// асимметрия никем не решалась.
//
// # Почему гейт ДЕРЕВА, а не проба сервиса
//
// «Снятие эмитирует отзыв» — свойство ДЕРЕВА, а не одного use-case: оно про то,
// что НИ ОДИН из семи путей снятия не остался без производителя. Проба сервиса
// об этом не утверждает ничего — она зелена при любом числе не покрытых
// соседей, и именно так класс и распространился с двух типов на пять.
//
// # Популяция ВЫВОДИТСЯ, а не выписывается
//
// Перечень каталогов здесь не пишется: рукописный список разошёлся бы с деревом
// молча ровно на том пакете, который заведут завтра. Каталог попадает в
// популяцию, когда о нём верны ОБА факта:
//
//   - его не-тестовый код эмитирует событие реконсайла вида «upsert» на СВОЙ
//     тип — тот, чьё написание после снятия приставки `iam.` и перевода из
//     верблюжьего в змеиный совпадает с ИМЕНЕМ КАТАЛОГА (`serviceAccount` →
//     `service_account`). Совпадение имени и есть вывод: второго словаря
//     «каталог → тип» не заводится, потому что он разошёлся бы с первым;
//   - в каталоге есть `delete.go` — то есть путь снятия существует.
//
// Требование к такому каталогу одно: где-то в его не-тестовом коде есть эмиссия
// события вида «delete» на ТОТ ЖЕ тип.
//
// # Почему судится узел вызова, а не подстрока
//
// Имена `EmitReconcileEvent` и `mirror.delete` встречаются в этом дереве в
// комментариях, в именах дублёров и в прозе приёмок десятками. Проверка по
// подстроке зеленела бы на СОБСТВЕННОМ объяснении — абзац выше содержит оба
// имени дословно. Поэтому разбор идёт по синтаксическому дереву: вызов, его
// второй и третий аргументы.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	// emitFuncName — имя метода писателя, со-коммитящего событие реконсайла.
	emitFuncName = "EmitReconcileEvent"

	// upsertConstName / deleteConstName — имена констант вида события
	// (`shared.ReconcileEventUpsert` / `…Delete`). Судятся вместе с их
	// строковыми значениями: код называет вид обоими способами, и знать надо оба
	// (правило testing.md §«Распознаватель обязан знать ВСЕ законные формы»).
	upsertConstName = "ReconcileEventUpsert"
	deleteConstName = "ReconcileEventDelete"

	upsertLiteral = "mirror.upsert"
	deleteLiteral = "mirror.delete"

	// dottedPrefix — приставка написания собственного типа iam в событии.
	dottedPrefix = "iam."

	// deleteFileName — имя файла пути снятия. Каталог без него в популяцию не
	// входит: снимать нечего, и требовать отзыва не с чего.
	deleteFileName = "delete.go"
)

// DeleteRevokeCensus — перепись одного обхода. Печатается ВСЕГДА: «ноль находок»
// обязано быть отличимо от «ноль прочитанного».
type DeleteRevokeCensus struct {
	Dirs         int // каталогов под api/ осмотрено
	Files        int // не-тестовых файлов Go разобрано
	EmitCalls    int // вызовов EmitReconcileEvent найдено
	OwnTyped     int // каталогов, у которых выведен СВОЙ тип
	WithDeleteGo int // из них несущих delete.go
	Population   int // судимых каталогов (свой тип И delete.go)
	Satisfying   int // из них эмитирующих отзыв своего типа
}

func (c DeleteRevokeCensus) String() string {
	return fmt.Sprintf(
		"перепись: каталогов %d · файлов Go %d · вызовов эмиссии %d · со своим типом %d · "+
			"из них с путём снятия %d · в популяции %d · производитель отзыва есть у %d",
		c.Dirs, c.Files, c.EmitCalls, c.OwnTyped, c.WithDeleteGo, c.Population, c.Satisfying)
}

// emitKind — вид события, выведенный из второго аргумента вызова.
type emitKind int

const (
	emitUnknown emitKind = iota
	emitUpsert
	emitDelete
)

// ScanDeleteRevokeProducers обходит каталоги use-case под apiDir и называет те,
// у которых путь снятия собственного объекта остался без производителя отзыва.
//
// Возвращает перепись, находки (по одной на каталог, в порядке имён — отказ на
// одном и том же дереве читается одинаково от прогона к прогону) и ошибку обхода.
// Пустой обход ошибкой ЗДЕСЬ не объявляется: пустоту судит вызывающий, потому что
// у гейта дерева и у пробы инъекции законные пороги пустоты разные.
func ScanDeleteRevokeProducers(apiDir string) (DeleteRevokeCensus, []string, error) {
	var census DeleteRevokeCensus

	entries, err := os.ReadDir(apiDir)
	if err != nil {
		return census, nil, fmt.Errorf("чтение каталога use-case %s: %w", apiDir, err)
	}

	var findings []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		census.Dirs++
		dir := filepath.Join(apiDir, e.Name())

		upserts, deletes, files, calls, perr := scanDirEmits(dir)
		if perr != nil {
			return census, nil, perr
		}
		census.Files += files
		census.EmitCalls += calls

		own := ownTypeOf(e.Name(), upserts)
		if own == "" {
			continue
		}
		census.OwnTyped++

		if _, serr := os.Stat(filepath.Join(dir, deleteFileName)); serr != nil {
			continue
		}
		census.WithDeleteGo++
		census.Population++

		if deletes[own] {
			census.Satisfying++
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"%s: снятие собственного объекта %q не эмитирует событие отзыва — "+
				"пообъектный кортеж на снятом объекте доживает до периодического прохода "+
				"(создание тот же тип со-коммитит, форма асимметрична)", e.Name(), own))
	}

	sort.Strings(findings)
	return census, findings, nil
}

// scanDirEmits разбирает не-тестовые файлы Go каталога и возвращает множества
// написаний типа, на которые эмитируются события вида upsert и delete.
func scanDirEmits(dir string) (upserts, deletes map[string]bool, files, calls int, err error) {
	upserts = map[string]bool{}
	deletes = map[string]bool{}

	names, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("чтение %s: %w", dir, err)
	}
	fset := token.NewFileSet()
	for _, n := range names {
		if n.IsDir() || !strings.HasSuffix(n.Name(), ".go") || strings.HasSuffix(n.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, n.Name())
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil, nil, 0, 0, fmt.Errorf("разбор %s: %w", path, perr)
		}
		files++
		ast.Inspect(f, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel == nil || sel.Sel.Name != emitFuncName {
				return true
			}
			// Сигнатура: (ctx, eventType, objectType, objectID).
			if len(call.Args) < 4 {
				return true
			}
			calls++
			objType, ok := stringLiteralOf(call.Args[2])
			if !ok {
				return true
			}
			switch emitKindOf(call.Args[1]) {
			case emitUpsert:
				upserts[objType] = true
			case emitDelete:
				deletes[objType] = true
			case emitUnknown:
			}
			return true
		})
	}
	return upserts, deletes, files, calls, nil
}

// emitKindOf выводит вид события из выражения второго аргумента. Признаются обе
// законные формы записи — именованная константа и её строковое значение.
func emitKindOf(arg ast.Expr) emitKind {
	if lit, ok := stringLiteralOf(arg); ok {
		switch lit {
		case upsertLiteral:
			return emitUpsert
		case deleteLiteral:
			return emitDelete
		}
		return emitUnknown
	}
	name := ""
	switch e := arg.(type) {
	case *ast.SelectorExpr:
		if e.Sel != nil {
			name = e.Sel.Name
		}
	case *ast.Ident:
		name = e.Name
	}
	switch name {
	case upsertConstName:
		return emitUpsert
	case deleteConstName:
		return emitDelete
	}
	return emitUnknown
}

// stringLiteralOf возвращает значение строкового литерала, если выражение им и
// является. Вычисляемое написание типа здесь НЕ восстанавливается — и это
// названо: такого в дереве нет, а восстановленное «по образцу» было бы догадкой.
func stringLiteralOf(arg ast.Expr) (string, bool) {
	lit, ok := arg.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return v, true
}

// ownTypeOf выводит СВОЙ тип каталога: то написание среди upsert-эмиссий, чей
// хвост после приставки `iam.`, переведённый из верблюжьего в змеиный, совпадает
// с именем каталога. Чужой тип (пакет `user` эмитирует и `iam.accessBinding`)
// своим не становится — и это несущее различие: требовать от снятия пользователя
// отзыва привязки было бы неверно.
func ownTypeOf(dirName string, upserts map[string]bool) string {
	for t := range upserts {
		if !strings.HasPrefix(t, dottedPrefix) {
			continue
		}
		if camelToSnake(strings.TrimPrefix(t, dottedPrefix)) == dirName {
			return t
		}
	}
	return ""
}

// camelToSnake переводит `serviceAccount` в `service_account`.
func camelToSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r - 'A' + 'a')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
