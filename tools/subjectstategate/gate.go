// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package subjectstategate — состояние личности, которое вернул репозиторий, не
// может быть выброшено.
//
// Класс, который здесь закрывается, живуч тем, что выглядит аккуратно. Путь
// спрашивает у репозитория про личность, репозиторий отвечает вместе с её
// состоянием — и вызывающий записывает состояние в `_`, оставляя себе только
// «строка нашлась». Дальше решение принимается по наличию строки: право
// выдаётся заблокированному, токен чеканится отключённой учётке. Диффом это не
// видно — там стоит подчёркивание, а не отсутствующая проверка.
//
// Гейт разбирает дерево (AST, не текст: строковый литерал и комментарий с тем
// же словом находкой не являются), знает поимённо аксессоры, которые состояние
// ВОЗВРАЩАЮТ, и падает, когда результат-состояние уходит в `_`.
//
// Гейт проверяет СВОЮ предпосылку. Он обоснован тем, что перечисленные
// аксессоры существуют и отдают состояние на объявленной позиции; переименуют
// или изменят их — запрет станет ложью, поэтому объявление каждого аксессора
// разыскивается в дереве, и ненайденный аксессор — находка, а не тишина. И
// объём осмотренного объявляется отдельно: «ноль находок» обязано быть отличимо
// от «ноль прочитанного».
package subjectstategate

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Accessor — аксессор, возвращающий состояние личности вместе с ней.
type Accessor struct {
	// Name — имя метода (селектор вызова).
	Name string
	// StateIndex — позиция результата, несущего состояние.
	StateIndex int
	// Results — сколько результатов у объявления. Часть предпосылки: изменится
	// сигнатура — гейт обязан это заметить, а не молча пропустить.
	Results int
	// Why — что именно решает это состояние (текст попадает в отказ).
	Why string
}

// Accessors — закрытый список. Пополняется вместе с каждым новым аксессором,
// который отдаёт состояние личности.
var Accessors = []Accessor{
	{
		Name: "AccountForUser", StateIndex: 1, Results: 3,
		Why: "вправе ли пользователь аутентифицироваться",
	},
	{
		Name: "AccountForServiceAccount", StateIndex: 1, Results: 3,
		Why: "вправе ли служебная учётка аутентифицироваться",
	},
	{
		Name: "UserInviteStatus", StateIndex: 0, Results: 2,
		Why: "состояние членства пользователя",
	},
	{
		Name: "ServiceAccountEnabled", StateIndex: 0, Results: 2,
		Why: "включена ли служебная учётка",
	},
}

// ExemptionMarker — метка, которой место объявляет, что состояние ему не нужно,
// и НАЗЫВАЕТ причину. Без причины метка не считается: «не смотрим» без
// основания — это и есть дефект, который гейт ищет.
//
// Метка ставится на самом операторе либо в блоке комментария прямо над ним.
// Метка, которой больше нечего исключать (место перестало выбрасывать
// состояние), — находка: исключение живёт, пока у него есть предмет.
const ExemptionMarker = "state-not-consulted:"

// Finding — одно место, где состояние выброшено.
type Finding struct {
	Pos      string // file:line
	Accessor string
	Why      string
}

// Exemption — объявленный и обоснованный отказ судить состояние.
type Exemption struct {
	Pos    string
	Reason string
}

func (f Finding) String() string {
	return fmt.Sprintf("%s: результат %q отдаёт состояние (%s), а оно уходит в `_`", f.Pos, f.Accessor, f.Why)
}

// Report — итог обхода: и находки, и перепись осмотренного.
type Report struct {
	FilesParsed     int
	CallsInspected  int
	AccessorsFound  map[string]int // имя → сколько объявлений найдено в дереве
	Findings        []Finding
	Exemptions      []Exemption
	PremiseFailures []string
}

// Inspect обходит дерево от root (не-тестовые .go), считает вызовы известных
// аксессоров и находит выброшенное состояние.
func Inspect(root string) (Report, error) {
	rep := Report{AccessorsFound: map[string]int{}}
	byName := map[string]Accessor{}
	for _, a := range Accessors {
		byName[a.Name] = a
		rep.AccessorsFound[a.Name] = 0
	}

	fset := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// vendor/generated-деревья не судим.
			if info.Name() == "testdata" || info.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution|parser.ParseComments)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		rep.FilesParsed++
		inspectFile(fset, file, byName, &rep)
		return nil
	})
	if err != nil {
		return rep, err
	}

	// Предпосылка: каждый объявленный аксессор обязан существовать в дереве с
	// объявленным числом результатов. Иначе запрет обоснован фактом, которого
	// больше нет.
	for _, a := range Accessors {
		if rep.AccessorsFound[a.Name] == 0 {
			rep.PremiseFailures = append(rep.PremiseFailures,
				fmt.Sprintf("аксессор %q не найден в дереве: гейт обоснован его существованием — переименовали? тогда правь список", a.Name))
		}
	}
	sort.Slice(rep.Findings, func(i, j int) bool { return rep.Findings[i].Pos < rep.Findings[j].Pos })
	return rep, nil
}

func inspectFile(fset *token.FileSet, file *ast.File, byName map[string]Accessor, rep *Report) {
	// markers: строка → причина. Собираются заранее, чтобы находку можно было
	// сопоставить с объявленным исключением; неиспользованные метки после
	// обхода — находка сами по себе.
	markers := map[int]string{}
	for _, group := range file.Comments {
		for _, c := range group.List {
			idx := strings.Index(c.Text, ExemptionMarker)
			if idx < 0 {
				continue
			}
			reason := strings.TrimSpace(c.Text[idx+len(ExemptionMarker):])
			markers[fset.Position(c.Pos()).Line] = reason
		}
	}
	used := map[int]bool{}

	ast.Inspect(file, func(n ast.Node) bool {
		// Объявления аксессоров — проверка предпосылки.
		if fd, ok := n.(*ast.FuncDecl); ok {
			if a, known := byName[fd.Name.Name]; known {
				rep.AccessorsFound[a.Name]++
				if got := resultCount(fd.Type); got != a.Results {
					rep.PremiseFailures = append(rep.PremiseFailures, fmt.Sprintf(
						"%s: у %q теперь %d результатов вместо объявленных %d — позиция состояния могла сместиться",
						fset.Position(fd.Pos()), a.Name, got, a.Results))
				}
			}
			return true
		}

		asn, ok := n.(*ast.AssignStmt)
		if !ok || len(asn.Rhs) != 1 {
			return true
		}
		call, ok := asn.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		a, known := byName[sel.Sel.Name]
		if !known {
			return true
		}
		rep.CallsInspected++
		if len(asn.Lhs) != a.Results || a.StateIndex >= len(asn.Lhs) {
			// Не многозначное присваивание (или сигнатура разошлась) — про это
			// говорит проверка предпосылки, а не эта ветка.
			return true
		}
		if ident, ok := asn.Lhs[a.StateIndex].(*ast.Ident); ok && ident.Name == "_" {
			pos := fset.Position(call.Pos())
			if line, reason, ok := lookupMarker(markers, pos.Line); ok {
				used[line] = true
				if reason == "" {
					rep.Findings = append(rep.Findings, Finding{
						Pos: pos.String(), Accessor: a.Name,
						Why: "метка исключения без названной причины — «не смотрим» без основания и есть искомый дефект",
					})
					return true
				}
				rep.Exemptions = append(rep.Exemptions, Exemption{Pos: pos.String(), Reason: reason})
				return true
			}
			rep.Findings = append(rep.Findings, Finding{
				Pos:      pos.String(),
				Accessor: a.Name,
				Why:      a.Why,
			})
		}
		return true
	})

	// Метка, которой больше нечего исключать: место перестало выбрасывать
	// состояние, а объявленное исключение осталось и молча покрывает следующий
	// такой случай.
	for line, reason := range markers {
		if used[line] {
			continue
		}
		rep.PremiseFailures = append(rep.PremiseFailures, fmt.Sprintf(
			"%s:%d: метке исключения (%q) больше нечего исключать — снимите её",
			fset.Position(file.Pos()).Filename, line, reason))
	}
}

// lookupMarker ищет метку на строке оператора либо в непрерывном блоке
// комментария прямо над ним (до 12 строк — обоснование обычно в прозе).
func lookupMarker(markers map[int]string, line int) (int, string, bool) {
	for l := line; l >= line-12 && l > 0; l-- {
		if reason, ok := markers[l]; ok {
			return l, reason, true
		}
	}
	return 0, "", false
}

func resultCount(ft *ast.FuncType) int {
	if ft.Results == nil {
		return 0
	}
	n := 0
	for _, f := range ft.Results.List {
		if len(f.Names) == 0 {
			n++
			continue
		}
		n += len(f.Names)
	}
	return n
}
