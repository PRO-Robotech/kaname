// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Таблица «Зарегистрированные RPC-сервисы» в обзоре компонентов обязана СХОДИТЬСЯ
// с фактической регистрацией — по каждому слушателю отдельно.
//
// # ПОЧЕМУ ГЕЙТ, А НЕ «ДОПИСАТЬ НЕДОСТАЮЩИЕ СТРОКИ»
//
// Рукописный перечень уже разошёлся, и допишешь его — разойдётся снова со
// следующей службой. Задача #1359 это назвала прямо: «дописать три строки»
// предметом не закрывает.
//
// Перемер при заведении гейта показал, что и САМО ЧИСЛО из задачи устарело, и
// устарело оно в обе стороны сразу:
//
//	слушатель :9091 — в таблице 6, в коде 10 (а не 9, как говорила задача);
//	слушатель :9090 — в таблице 11, в коде 15 — расхождение, которого задача
//	не заметила ВОВСЕ, потому что смотрела только на внутренний слушатель.
//
// Отсюда охват: судятся ОБА слушателя. Гейт, судящий половину таблицы, оставил бы
// вторую половину дрейфовать молча — ровно тем способом, каким она уже дрейфовала.
//
// # ПОЧЕМУ РАЗБОР, А НЕ ПОИСК ПО ОБРАЗЦУ
//
// Имя `Register…ServiceServer` законно встречается в прозе — в комментарии у самой
// регистрации, в разборе запрета #6, в этой шапке. Поиск по подстроке считал бы
// объяснение за регистрацию и краснел бы на собственном тексте. Поэтому
// регистрации берутся УЗЛАМИ синтаксического дерева: вызов внутри тела названной
// функции, а не вхождение имени в файл.
//
// # ГРАНИЦА
//
// Гейт судит СОСТАВ таблицы, а не верность колонки «Назначение»: написать
// неверное описание он не помешает. Тот же предел, что у машинного чтения
// вердикта приёмки — оно судит объявление, а не истинность.
const (
	// iamRegisterFileRel — единственное место, где службы садятся на слушатели.
	iamRegisterFileRel = "services/iam/cmd/kacho-iam/grpc_register.go"
	// iamOverviewDocRel — документ с таблицей портов.
	iamOverviewDocRel = "services/iam/docs/engineering/components/00-overview.md"

	publicListener   = ":9090"
	internalListener = ":9091"
)

// registrarFuncs — какая функция какой слушатель наполняет.
var registrarFuncs = map[string]string{
	"registerPublicServices":   publicListener,
	"registerInternalServices": internalListener,
}

// reRegisterCall — имя вызова регистрации; из него добывается имя службы.
var reRegisterCall = regexp.MustCompile(`^Register(\w+)ServiceServer$`)

// reTableRow — строка таблицы портов: слушатель и имя службы, оба в кавычках.
var reTableRow = regexp.MustCompile("(?m)^\\|\\s*`(:\\d+)`\\s*\\|\\s*`(\\w+)`\\s*\\|")

// portTableCensus — объём осмотренного. Печатается всегда: «ноль находок»
// обязано быть отличимо от «ноль прочитанного».
type portTableCensus struct {
	registrarsRead int // функций-регистраторов найдено в разборе
	registered     int // вызовов регистрации прочитано
	tableRows      int // строк таблицы прочитано
	missingInDoc   int // зарегистрировано, но в таблице нет
	extraInDoc     int // в таблице есть, но не регистрируется
}

// registeredServices — службы по слушателям, добытые РАЗБОРОМ файла регистрации.
func registeredServices(src string) (map[string]map[string]bool, int, int, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "grpc_register.go", src, parser.ParseComments)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("разбор файла регистрации: %w", err)
	}

	out := map[string]map[string]bool{}
	funcsSeen, calls := 0, 0

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		listener, watched := registrarFuncs[fn.Name.Name]
		if !watched {
			continue
		}
		funcsSeen++
		if out[listener] == nil {
			out[listener] = map[string]bool{}
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			m := reRegisterCall.FindStringSubmatch(sel.Sel.Name)
			if m == nil {
				return true
			}
			calls++
			out[listener][m[1]+"Service"] = true
			return true
		})
	}
	return out, funcsSeen, calls, nil
}

// tabulatedServices — службы по слушателям, объявленные таблицей документа.
func tabulatedServices(doc string) (map[string]map[string]bool, int) {
	out := map[string]map[string]bool{}
	rows := 0
	for _, m := range reTableRow.FindAllStringSubmatch(doc, -1) {
		listener, svc := m[1], m[2]
		if out[listener] == nil {
			out[listener] = map[string]bool{}
		}
		out[listener][svc] = true
		rows++
	}
	return out, rows
}

// auditPortTable — чистое ядро обеих проб: решает по текстам, а не по дереву.
func auditPortTable(registerSrc, doc string) ([]string, portTableCensus, error) {
	registered, funcsSeen, calls, err := registeredServices(registerSrc)
	if err != nil {
		return nil, portTableCensus{}, err
	}
	tabulated, rows := tabulatedServices(doc)

	c := portTableCensus{registrarsRead: funcsSeen, registered: calls, tableRows: rows}
	var findings []string

	listeners := make([]string, 0, len(registrarFuncs))
	for _, l := range registrarFuncs {
		listeners = append(listeners, l)
	}
	sort.Strings(listeners)

	for _, listener := range listeners {
		for _, svc := range sortedKeys(registered[listener]) {
			if !tabulated[listener][svc] {
				c.missingInDoc++
				findings = append(findings, fmt.Sprintf(
					"слушатель %s: служба %s зарегистрирована, но таблица портов её НЕ называет — "+
						"таблицу читают первой, решая вопрос о поверхности слушателя",
					listener, svc))
			}
		}
		for _, svc := range sortedKeys(tabulated[listener]) {
			if !registered[listener][svc] {
				c.extraInDoc++
				findings = append(findings, fmt.Sprintf(
					"слушатель %s: таблица портов называет службу %s, а регистрации у неё нет — "+
						"утверждение пережило свой предмет",
					listener, svc))
			}
		}
	}
	return findings, c, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestOverviewPortTableMatchesRegistration — несущее утверждение.
func TestOverviewPortTableMatchesRegistration(t *testing.T) {
	root := monorepoRoot(t)

	registerSrc, err := os.ReadFile(filepath.Join(root, iamRegisterFileRel)) // #nosec G304 -- путь собран из корня собственного модуля
	require.NoError(t, err)
	doc, err := os.ReadFile(filepath.Join(root, iamOverviewDocRel)) // #nosec G304 -- путь собран из корня собственного модуля
	require.NoError(t, err)

	findings, c, err := auditPortTable(string(registerSrc), string(doc))
	require.NoError(t, err)

	t.Logf("перепись: функций-регистраторов %d из %d · регистраций прочитано %d · "+
		"строк таблицы прочитано %d · нет в таблице %d · лишних в таблице %d · находок %d",
		c.registrarsRead, len(registrarFuncs), c.registered, c.tableRows,
		c.missingInDoc, c.extraInDoc, len(findings))

	require.Equalf(t, len(registrarFuncs), c.registrarsRead,
		"обход регистраторов неполон — вердикт беспредметен (%s)", iamRegisterFileRel)
	require.NotZerof(t, c.registered, "регистраций не прочитано ни одной — вердикт беспредметен (%s)", iamRegisterFileRel)
	require.NotZerof(t, c.tableRows, "строк таблицы не прочитано ни одной — вердикт беспредметен (%s)", iamOverviewDocRel)

	require.Emptyf(t, findings,
		"таблица портов %s разошлась с фактической регистрацией:\n%s",
		iamOverviewDocRel, strings.Join(findings, "\n"))
}
