// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestServeWiresTheKeyMaterialTransitionWindow — страж КОМПОЗИЦИОННОГО КОРНЯ.
//
// Ручка окна перехода #1143 и счётчик его исходов существуют в настройке и в
// реестре метрик; пока корень их не передаёт, оператор задаёт ручку, а полоса
// её не видит — ровно класс «ручка, объявленная и никем не читаемая»: контроль
// на вид есть, предмета у него нет.
//
// # Почему разбор, а не поиск подстроки
//
// Имена обоих полей встречаются в этом же дереве в КОММЕНТАРИЯХ, объясняющих
// саму норму, — поиск по тексту зеленел бы на собственном объяснении. Здесь
// читается РАЗОБРАННЫЙ Go: судятся ключи составного литерала
// `registrytokenwire.BuildConfig{…}`, то есть исполняемая часть.
//
// RED-демонстрация: убрать любое из двух полей из вызова в serve.go → красное.
func TestServeWiresTheKeyMaterialTransitionWindow(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("разбор serve.go: %v", err)
	}

	// Перепись печатается ВСЕГДА: «ноль находок» обязано быть отличимо от «ноль
	// прочитанного» — литерал мог переехать, и тогда молчащий страж означал бы
	// не «провязано», а «не смотрели».
	var literalsSeen int
	wired := map[string]bool{}

	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "BuildConfig" {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "registrytokenwire" {
			return true
		}
		literalsSeen++
		for _, e := range lit.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if key, ok := kv.Key.(*ast.Ident); ok {
				wired[key.Name] = true
			}
		}
		return true
	})

	t.Logf("перепись: литералов registrytokenwire.BuildConfig прочитано %d, ключей в них %d",
		literalsSeen, len(wired))

	if literalsSeen == 0 {
		t.Fatal("в serve.go не найдено ни одного литерала registrytokenwire.BuildConfig — " +
			"страж беспредметен: «ноль находок» здесь означало бы «ноль прочитанного»")
	}

	for field, why := range map[string]string{
		"KeyMaterialWindowUntil": "окно перехода #1143 обязано доезжать из настройки до полосы: " +
			"иначе оператор объявляет окно, а полоса продолжает отвергать прежний вид",
		"CredentialKindObserver": "счётчик исходов обязан быть провязан: наружу закрытое и открытое " +
			"окно отвечают одинаково, и счётчик — единственное наблюдаемое различие между ними",
	} {
		if !wired[field] {
			t.Errorf("serve.go: registrytokenwire.BuildConfig не несёт %s — %s", field, why)
		}
	}
}

// Положительный контроль стража: поле, которого в структуре НЕТ, обязан
// оставаться ненайденным. Без него проба зеленела бы на разборе, помечающем всё
// подряд, — и тогда её отрицание не сужало бы ничего.
func TestServeWiringGateDoesNotInventFields(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("разбор serve.go: %v", err)
	}
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "BuildConfig" {
			return true
		}
		for _, e := range lit.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				if key, ok := kv.Key.(*ast.Ident); ok &&
					strings.EqualFold(key.Name, "KeyMaterialWindowForever") {
					found = true
				}
			}
		}
		return true
	})
	if found {
		t.Fatal("страж нашёл поле, которого у BuildConfig нет — значит он помечает всё подряд")
	}
}
