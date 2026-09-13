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
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// repoModulePrefix — модуль ЭТОГО репозитория.
//
// ЗДЕСЬ СТОЯЛ `github.com/PRO-Robotech/kacho/`, И ПРОВЕРКА БЫЛА СЛЕПА ПО
// ПОСТРОЕНИЮ. Служба вынесена отдельным модулем (`github.com/PRO-Robotech/kaname`),
// и своих пакетов она называет ИМ; префикс платформы после ступени S0a
// (kacho#2617, исход C) не совпадает НИ С ОДНИМ узлом импорта дерева — их ноль,
// — значит предикат не мог найти находку ни при каком содержимом файла. Развернув
// стрелку внутрь домена импортом `github.com/PRO-Robotech/kaname/internal/...`,
// автор получил бы зелёное.
//
// Слепота предшествовала S0a: разошлись имена модулей ещё при выносе службы, и
// «ноль находок» с тех пор означало «ноль прочитанного». Проба ниже поэтому
// держит не только сам запрет, но и СПОСОБНОСТЬ его найти.
const repoModulePrefix = "github.com/PRO-Robotech/kaname/"

// repoImportsOf — пакеты РЕПОЗИТОРИЯ, которые импортирует файл, и общее число
// прочитанных импортов.
//
// Отделено от утверждения намеренно: вход приносит вызывающий, поэтому
// способность предиката найти находку проверяется ПОДАЧЕЙ входа (проба
// `TestStdlibOnlyRecognizerCanFail`), а не чтением кода.
func repoImportsOf(file string) ([]string, int, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: разбор импортов не удался: %w", file, err)
	}
	var found []string
	for _, imp := range f.Imports {
		p, uerr := strconv.Unquote(imp.Path.Value)
		if uerr != nil {
			return nil, len(f.Imports), fmt.Errorf("%s: путь импорта %s не разкавычен: %w",
				file, imp.Path.Value, uerr)
		}
		if strings.HasPrefix(p, repoModulePrefix) {
			found = append(found, p)
		}
	}
	return found, len(f.Imports), nil
}

// assertNoRepoImports — файл пакета не импортирует ни один пакет репозитория.
// Предикат берётся по объявлению импорта, а не текстовым поиском: имена пакетов
// присутствуют в комментариях файла как ссылки на смежные механизмы.
func assertNoRepoImports(t *testing.T, file string) {
	t.Helper()
	found, seen, err := repoImportsOf(file)
	if err != nil {
		t.Fatalf("%v", err)
	}
	// Пустой обход — не чистота. Файл без единого импорта прошёл бы проверку
	// «репозиторных ноль» при любом предикате, включая неверный.
	if seen == 0 {
		t.Logf("перепись: %s — импортов НЕ ПРОЧИТАНО НИ ОДНОГО: утверждение о них "+
			"беспредметно, и держит его только проба способности (%s)",
			file, "TestStdlibOnlyRecognizerCanFail")
	}
	for _, p := range found {
		t.Errorf("%s импортирует %q. Файл объявляет о себе «pure domain (stdlib only)»; "+
			"набор глаголов приходит параметром именно для того, чтобы это объявление "+
			"оставалось правдой. Либо верните параметр, либо снимите объявление — "+
			"комментарий, противоречащий коду, чинят следующей правкой в неверную сторону",
			file, p)
	}
	t.Logf("перепись: %s — импортов прочитано: %d; из них пакетов репозитория: %d",
		file, seen, len(found))
}

// TestStdlibOnlyRecognizerCanFail — ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ на синтетическом
// файле: настоящий файл домена править нельзя, а без подачи входа предикат
// остаётся утверждением о самом себе. Ровно этой пробы здесь не было, и ровно
// поэтому неверный префикс модуля жил незамеченным.
func TestStdlibOnlyRecognizerCanFail(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	write := func(name, body string) string {
		full := filepath.Join(dir, name)
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("записать %s: %v", name, err)
		}
		return full
	}

	// КРАСНОЕ: импорт пакета своего модуля.
	red := write("red.go", `package synth

import (
	"strings"

	_ "github.com/PRO-Robotech/kaname/internal/errors"
)

var _ = strings.TrimSpace
`)
	found, seen, err := repoImportsOf(red)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if len(found) != 1 || found[0] != repoModulePrefix+"internal/errors" {
		t.Fatalf("импорт своего модуля не найден: %v (импортов прочитано %d)", found, seen)
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ, отличающийся РОВНО именем модуля в пути: чужой модуль
	// предметом этого запрета не является — запрещён импорт РЕПОЗИТОРИЯ, а не
	// всякая зависимость. Без этой пары предикат «любой github.com» прошёл бы
	// красную пробу и запретил бы лишнее.
	green := write("green.go", `package synth

import (
	"strings"

	_ "github.com/PRO-Robotech/corelib/ids"
)

var _ = strings.TrimSpace
`)
	found, seen, err = repoImportsOf(green)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if len(found) != 0 {
		t.Errorf("импорт ЧУЖОГО модуля назван находкой: %v", found)
	}
	if seen != 2 {
		t.Errorf("объём осмотренного не совпал: импортов %d, ожидалось 2", seen)
	}

	// ОТРИЦАТЕЛЬНЫЙ близнец слепоты, которую эта правка и сняла: прежний
	// префикс платформы не находит НИЧЕГО даже в красном файле. Строка стоит
	// здесь затем, чтобы возврат прежнего значения краснел.
	if strings.HasPrefix(repoModulePrefix, "github.com/PRO-Robotech/kacho") {
		t.Fatal("префикс снова называет модуль платформы: узлов импорта с таким префиксом " +
			"в этом дереве НОЛЬ, и предикат не может найти находку ни при каком содержимом")
	}
}
