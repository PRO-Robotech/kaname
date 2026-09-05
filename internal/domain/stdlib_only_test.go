// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// stdlib_only_test.go — вспомогательное утверждение «файл домена не импортирует
// ничего из репозитория».
//
// Зачем проверкой, а не комментарием. Файл `rule_verbs.go` объявляет о себе «pure
// domain (stdlib only)», и именно ради сохранения этого объявления набор глаголов
// приходит ПАРАМЕТРОМ, а не импортом таблицы. Объявление, которое ничем не
// удерживается, — обещание без исполнителя: следующая правка коротким путём
// развернёт стрелку зависимости внутрь домена, и объявление станет ложным молча.

import (
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

const repoModulePrefix = "github.com/PRO-Robotech/kacho/"

// assertNoRepoImports — файл пакета не импортирует ни один пакет репозитория.
// Предикат берётся по объявлению импорта, а не текстовым поиском: имена пакетов
// присутствуют в комментариях файла как ссылки на смежные механизмы.
func assertNoRepoImports(t *testing.T, file string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("%s: разбор импортов не удался: %v", file, err)
	}
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatalf("%s: путь импорта %s не разкавычен: %v", file, imp.Path.Value, err)
		}
		if strings.HasPrefix(p, repoModulePrefix) {
			t.Fatalf("%s импортирует %q. Файл объявляет о себе «pure domain (stdlib only)»; "+
				"набор глаголов приходит параметром именно для того, чтобы это объявление "+
				"оставалось правдой. Либо верните параметр, либо снимите объявление — "+
				"комментарий, противоречащий коду, чинят следующей правкой в неверную сторону",
				file, p)
		}
	}
	t.Logf("перепись: %s — импортов прочитано: %d; из них пакетов репозитория: 0", file, len(f.Imports))
}
