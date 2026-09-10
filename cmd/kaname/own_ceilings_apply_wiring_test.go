// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// own_ceilings_apply_wiring_test.go — ПРОЕКЦИЯ ПОТОЛКОВ ПОЗВАНА, И ПОЗВАНА ДО
// СЛУШАТЕЛЕЙ (приёмка `KAN-QUOTA-1`, `П25`; задача продукта #2117).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ГЕЙТ, А НЕ ДОВЕРИЕ К КОММЕНТАРИЮ РЯДОМ С ВЫЗОВОМ
//
// Глагол, написанный и НЕ ПОЗВАННЫЙ, отличается от отсутствующего ровно одним: он
// покрыт пробами и потому выглядит работающим. Прецедент в этом же корне — тот же
// класс у применителя каталога модуля (`module_catalog_apply_wiring_test.go`,
// задача #1034): написан, доказан против живой базы, позван нулём файлов.
//
// Здесь цена такого молчания выше: без вызова проекция пуста, и списание
// отказывает КАЖДОМУ созданию аккаунта и удостоверения — то есть служба
// поднимается и не работает, а страж старта при этом доволен.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОРЯДОК — ВТОРАЯ ПОЛОВИНА, И ОНА НЕ ВЫВОДИТСЯ ИЗ ПЕРВОЙ
//
// Вызов, стоящий ПОСЛЕ подъёма слушателя, есть окно, в котором действует величина
// предыдущего пуска, а журнал уже сообщил новую. Обе половины проверяются
// раздельно: «позван» и «позван вовремя» — разные утверждения, и второе ломается
// перестановкой двух строк, которую первая не замечает.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// serveSourcePath — композиционный корень, который судит проба. Относительный
// путь: пакетные пробы Go исполняются из каталога пакета.
const serveSourcePath = "serve.go"

// ownCeilingWiringAnchors — координаты, по которым судится провязка.
type ownCeilingWiringAnchors struct {
	// CallsSeen — объём осмотренного: сколько вызовов вообще разобрано.
	CallsSeen int
	// Project — позиция вызова проекции.
	Project token.Pos
	// FirstListener — позиция ПЕРВОГО подъёма слушателя.
	FirstListener token.Pos
	// ListenerName — имя того вызова, чтобы отказ называл предмет.
	ListenerName string
}

// listenerStarters — имена, которыми композиционный корень ОТКРЫВАЕТ порт.
//
// Перечень ЗАКРЫТ и ВЫВЕДЕН ИЗ КОРНЯ, а не придуман: первая редакция этой пробы
// называла пять правдоподобных имён обёрток, которых в корне нет ни одного, — и
// проба честно упала на отсутствии предпосылки, а не промолчала. Это и есть класс
// «распознаватель не знает формы»: он не даёт ни красного, ни зелёного.
//
// Предмет — САМО ОТКРЫТИЕ ПОРТА (`net.Listen`), а не запуск обслуживания
// (`Serve`): порт, открытый раньше проекции, уже принимает соединения, и окно
// открывается там, а не на `Serve`.
//
// Предикат, которым перечень перемеряется:
//
//	grep -nE 'net\.Listen|\.Serve\(' services/iam/cmd/kaname/serve.go
var listenerStarters = []string{
	"Listen",
	"ListenAndServe",
	"ListenAndServeTLS",
	"Serve",
}

// ownCeilingWiring разбирает композиционный корень и возвращает координаты.
//
// Путь — ПАРАМЕТР, а не литерал внутри: тем же разбором доказывается способность
// пробы упасть (`own_ceilings_apply_wiring_injection_test.go`), и второй разбор
// для инъекции разошёлся бы с первым молча — на верном входе оба отвечают
// одинаково.
func ownCeilingWiring(t *testing.T, path string) ownCeilingWiringAnchors {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("%s не разобран: %v — непрочитанное есть НАХОДКА, а не пустой результат", path, err)
	}

	var a ownCeilingWiringAnchors
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		a.CallsSeen++
		name := calleeName(call.Fun)
		switch {
		case name == "projectOwnCeilings" && !a.Project.IsValid():
			a.Project = call.Lparen
		default:
			for _, l := range listenerStarters {
				if name == l && !a.FirstListener.IsValid() {
					a.FirstListener, a.ListenerName = call.Lparen, l
				}
			}
		}
		return true
	})
	return a
}

// calleeName — имя вызываемого, без квалификатора пакета и получателя.
func calleeName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// TestKANQ25_ServeProjectsOwnCeilingsBeforeAnyListener — обе половины провязки.
func TestKANQ25_ServeProjectsOwnCeilingsBeforeAnyListener(t *testing.T) {
	a := ownCeilingWiring(t, serveSourcePath)
	t.Logf("осмотрено вызовов в serve.go: %d · проекция позвана: %t · первый слушатель: %q",
		a.CallsSeen, a.Project.IsValid(), a.ListenerName)

	if a.CallsSeen == 0 {
		t.Fatal("обход не нашёл ни одного вызова — вердикт беспредметен: " +
			"«ноль находок» неотличимо от «ноль прочитанного»")
	}
	if !a.Project.IsValid() {
		t.Fatal("композиционный корень НЕ ЗОВЁТ проекцию собственных потолков: " +
			"величина, объявленная посадкой, до схемы не доезжает, проекция остаётся " +
			"пустой, и списание отвергает КАЖДОЕ создание аккаунта и удостоверения — " +
			"при том что страж старта доволен, а глагол покрыт пробами (kacho#2117, П25)")
	}
	if !a.FirstListener.IsValid() {
		t.Fatal("в serve.go не найдено ни одного подъёма слушателя — предпосылка " +
			"проверки о ПОРЯДКЕ исчезла, и порядок больше нечем судить; перечень форм " +
			"подъёма обязан быть приведён к корню тем же изменением")
	}
	if a.Project > a.FirstListener {
		t.Errorf("проекция потолков стоит ПОСЛЕ подъёма слушателя %q: открыто окно, "+
			"в котором действует величина ПРЕДЫДУЩЕГО пуска, а журнал уже сообщил новую",
			a.ListenerName)
	}
}
