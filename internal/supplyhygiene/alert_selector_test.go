// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// alert_selector_test.go — ОТБОР ПО ИМЕНИ КОНТРАКТА в правиле тревоги называет
// имя, которое дерево ПРОИЗВОДИТ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Ряд `kacho_grpc_server_handled_total` общий на платформу: его заводит
// фундамент, а не служба, поэтому доля не-OK ответов ИМЕННО ЭТОЙ службы
// отбирается меткой `grpc_service`, а не именем ряда. Значение метки берётся из
// `ServiceDesc.ServiceName` зарегистрированного контракта — то есть из
// сгенерированных стабов, — и переезд контракта его МЕНЯЕТ.
//
// Соседний гейт (`TestObservabilityPagePromisesOnlyWhatTheServiceProduces`)
// этого класса не видит BY CONSTRUCTION: он судит ИМЯ РЯДА, а имя ряда здесь
// верное. Неверен ОТБОР ВНУТРИ ряда, и он лежит ровно в его слепой зоне.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕМ ЭТОТ ОТКАЗ ХУЖЕ ОБЫЧНОГО
//
// Отбор, не совпадающий ни с одним контрактом, даёт пустой ряд И В ЧИСЛИТЕЛЕ, И
// В ЗНАМЕНАТЕЛЕ. Выражение не превышает порога НИ ПРИ КАКОМ состоянии продукта:
// тревога объявлена и неисполнима. Дежурный, скопировавший правило, получает
// молчание, а «не звонит» неотличимо от «доля не-OK ответов в норме».
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СУДИТСЯ, А ЧТО НЕТ
//
// Судятся ПОЛОЖИТЕЛЬНЫЕ отборы (`=` и `=~`). Отрицательные (`!=`, `!~`) не
// судятся намеренно: отбор, не совпадающий ни с чем, в отрицании НИЧЕГО НЕ
// ИСКЛЮЧАЕТ и вреда не наносит — требовать от него совпадения значило бы
// краснеть на законной записи.
//
// ОТСУТСТВИЕ отбора находкой не является. Опубликованная страница пишется для
// того, кто поставил ОДНУ службу: у него этот ряд производит только она, и
// отбирать не от чего. Требование «отбор обязан быть» судило бы другой предмет
// и краснело бы на верной странице.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ИСТОЧНИК — СТАБЫ, А НЕ `.proto`
//
// Три довода, и каждый самостоятельно достаточен:
//
//  1. `ServiceName` — ровно та строка, которую слушатель кладёт в метку. Файл
//     `.proto` называет ПАКЕТ, а метка несёт пакет И имя службы; сверять с
//     пакетом значило бы сверять с половиной предмета;
//  2. модуль службы `.proto`-файлов НЕ СОДЕРЖИТ (их ноль), они лежат в дереве
//     платформы — выше корня модуля. Подъём туда литеральной цепочкой `../`
//     запрещён и отдельно стережётся (`tree_root_escape_test.go`): в клоне
//     арендатора он указывает в ЧУЖОЕ дерево;
//  3. стабы приезжают модулем, который служба ПИНИТ ВЕРСИЕЙ, поэтому источник
//     разрешается одинаково в обеих посадках — и в монорепо, и в клоне.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ РАЗБОР, А НЕ ПОИСК ПО ОБРАЗЦУ
//
// Строка `kaname.cloud.iam.v1.UserService` встречается в этом дереве и в
// комментариях, и в текстах отказов, и в путях REST. Поиск словом принял бы их
// за объявление контракта. Здесь судится УЗЕЛ: поле `ServiceName` в составном
// литерале, полученное разбором.
package supplyhygiene

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// docsDir — корень документации службы относительно корня модуля. Осматриваются
// ОБА слоя: и опубликованный, и инженерный. Класс не знает, в каком из них его
// внесут в следующий раз.
const docsDir = "docs"

// grpcServiceMatcherRe — позиция отбора по имени контракта: метка, оператор и
// строка PromQL со своим экранированием.
//
// Оператор захватывается НАМЕРЕННО: по нему отбор делится на положительный и
// отрицательный, а судятся только первые.
var grpcServiceMatcherRe = regexp.MustCompile(`grpc_service\s*(=~|!~|=|!=)\s*"((?:[^"\\]|\\.)*)"`)

// grpcServiceNameShape — форма полного имени контракта: строчные сегменты
// пакета и имя службы с заглавной. Отсекает всё, что стоит в поле `ServiceName`
// не будучи контрактом.
var grpcServiceNameShape = regexp.MustCompile(`^(?:[a-z][a-z0-9_]*\.)+[A-Z][A-Za-z0-9_]*$`)

// selectorCensus — объём осмотренного одним обходом.
type selectorCensus struct {
	docFiles      int // прочитано файлов документации
	docLines      int // строк в них
	matchersAll   int // отборов по grpc_service найдено
	matchersJudge int // из них положительных, то есть судимых
	producerFiles int // прочитано файлов Go
	producerMods  int // модулей, давших хотя бы один файл
	contracts     int // собрано имён контрактов
}

// docSelector — один отбор: где написан и что отбирает.
type docSelector struct {
	file string
	line int
	op   string
	expr string
}

// promUnquote снимает экранирование строки PromQL.
//
// Внутри блочного скаляра YAML (`expr: |`) обработки экранирования НЕТ, поэтому
// до PromQL доезжает то, что написано; экранирование снимает уже он сам. Значит
// `\\.` в тексте документа — это `\.` в регулярном выражении, и не снять этот
// слой значило бы сверять НЕ ТО выражение, которое исполнится.
func promUnquote(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// collectContractNames — полные имена контрактов, объявленные В ПОЗИЦИИ имени
// контракта: поле `ServiceName` составного литерала описания службы.
func collectContractNames(roots []string) (map[string]bool, selectorCensus, error) {
	var census selectorCensus
	out := map[string]bool{}
	fset := token.NewFileSet()

	for _, root := range roots {
		filesHere := 0
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // недоступный подкаталог модуля пропускаем молча
			}
			if d.IsDir() {
				if d.Name() == "testdata" || d.Name() == "vendor" || d.Name() == "node_modules" {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil // неразбираемый файл — не предмет этой проверки
			}
			filesHere++
			ast.Inspect(f, func(n ast.Node) bool {
				kv, ok := n.(*ast.KeyValueExpr)
				if !ok {
					return true
				}
				k, ok := kv.Key.(*ast.Ident)
				if !ok || k.Name != "ServiceName" {
					return true
				}
				lit, ok := kv.Value.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				v, uerr := strconv.Unquote(lit.Value)
				if uerr == nil && grpcServiceNameShape.MatchString(v) {
					out[v] = true
				}
				return true
			})
			return nil
		})
		if err != nil {
			return nil, census, err
		}
		if filesHere > 0 {
			census.producerMods++
		}
		census.producerFiles += filesHere
	}

	census.contracts = len(out)
	return out, census, nil
}

// collectDocSelectors — отборы по имени контракта во всех страницах дерева
// документации.
func collectDocSelectors(root string) ([]docSelector, selectorCensus, error) {
	var census selectorCensus
	var out []docSelector

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == "node_modules" || d.Name() == "build" || d.Name() == ".docusaurus" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".md") && !strings.HasSuffix(path, ".mdx") {
			return nil
		}
		raw, rerr := os.ReadFile(path) // #nosec G304 -- путь из обхода дерева службы
		if rerr != nil {
			return rerr
		}
		census.docFiles++
		for i, line := range strings.Split(string(raw), "\n") {
			census.docLines++
			for _, m := range grpcServiceMatcherRe.FindAllStringSubmatch(line, -1) {
				census.matchersAll++
				out = append(out, docSelector{file: path, line: i + 1, op: m[1], expr: promUnquote(m[2])})
			}
		}
		return nil
	})
	if err != nil {
		return nil, census, err
	}

	for _, s := range out {
		if s.op == "=" || s.op == "=~" {
			census.matchersJudge++
		}
	}
	return out, census, nil
}

// scanAlertSelectors — разбор над ПРОИЗВОЛЬНЫМИ деревом документации и корнями
// стабов. Вынесено из пробы затем, чтобы способность упасть доказывалась
// подачей входа, а не чтением.
func scanAlertSelectors(docRoot string, producerRoots []string) (selectorCensus, []string, error) {
	selectors, census, err := collectDocSelectors(docRoot)
	if err != nil {
		return census, nil, err
	}

	contracts, pcensus, err := collectContractNames(producerRoots)
	if err != nil {
		return census, nil, err
	}
	census.producerFiles = pcensus.producerFiles
	census.producerMods = pcensus.producerMods
	census.contracts = pcensus.contracts

	names := make([]string, 0, len(contracts))
	for n := range contracts {
		names = append(names, n)
	}
	sort.Strings(names)

	var findings []string
	for _, s := range selectors {
		if s.op != "=" && s.op != "=~" {
			continue // отрицательный отбор ничего не исключает и вреда не наносит
		}

		matched := false
		switch s.op {
		case "=":
			matched = contracts[s.expr]
		case "=~":
			// Prometheus якорит отбор по метке ЦЕЛИКОМ; без якорей выражение
			// совпадало бы с подстрокой, и вердикт был бы мягче исполняемого.
			re, cerr := regexp.Compile("^(?:" + s.expr + ")$")
			if cerr != nil {
				findings = append(findings, filepath.ToSlash(s.file)+":"+strconv.Itoa(s.line)+
					": отбор grpc_service"+s.op+"\""+s.expr+"\" не компилируется как регулярное "+
					"выражение — правило не примет ни Prometheus, ни читатель")
				continue
			}
			for _, n := range names {
				if re.MatchString(n) {
					matched = true
					break
				}
			}
		}

		if !matched {
			findings = append(findings, filepath.ToSlash(s.file)+":"+strconv.Itoa(s.line)+
				": отбор grpc_service"+s.op+"\""+s.expr+"\" не совпадает НИ С ОДНИМ из "+
				strconv.Itoa(len(names))+" контрактов, которые производит дерево: ряд пуст и в "+
				"числителе, и в знаменателе, поэтому порог не превышается ни при каком "+
				"состоянии продукта — тревога объявлена и неисполнима")
		}
	}

	return census, findings, nil
}

func TestAlertSelectorsNameAContractTheTreeProduces(t *testing.T) {
	roots := producerRoots(t)

	census, findings, err := scanAlertSelectors(filepath.Join(serviceRoot, docsDir), roots)
	require.NoError(t, err, "разбор дерева документации")

	t.Logf("перепись: прочитано страниц %d · строк %d · отборов по grpc_service %d · "+
		"из них положительных (судимых) %d · прочитано файлов Go %d в %d модулях · "+
		"собрано контрактов %d · находок %d",
		census.docFiles, census.docLines, census.matchersAll, census.matchersJudge,
		census.producerFiles, census.producerMods, census.contracts, len(findings))

	// Пустой обход — находка по каждой оси отдельно: «ноль находок» обязано
	// быть отличимо от «ноль прочитанного».
	require.NotZero(t, census.docFiles, "обход пуст: страниц не прочитано ни одной — вердикт беспредметен")
	require.NotZero(t, census.producerFiles, "обход пуст: файлов Go не прочитано ни одного — "+
		"«контракта нет» означало бы «не искали»")
	require.Equal(t, producerRootCount, census.producerMods, "прочитан не тот набор модулей: "+
		"указатель контрактов обязан покрывать дерево службы, модуль фундамента И остаток "+
		"платформенного модуля, где живут контракты доступа — см. producerRoots")
	require.NotZero(t, census.contracts, "обход пуст: контрактов не собрано ни одного — "+
		"распознаватель ослеп, вердикт беспредметен")

	// Предпосылка САМОЙ проверки. Ноль судимых отборов означает, что стеречь
	// нечего, и молчание тогда неотличимо от исправной работы: негативное
	// утверждение, потерявшее предмет, ЗАМОЛКАЕТ, а не краснеет. Исходов ровно
	// два: снять эту проверку вместе с её предметом либо перенацелить на то
	// место, куда отбор переехал.
	require.NotZero(t, census.matchersJudge, "обход пуст: ни одного положительного отбора по "+
		"grpc_service — предмет проверки исчез из дерева, и она замолчала бы, оставаясь на вид "+
		"рабочей. Снимите её вместе с предметом либо перенацельте")

	for _, f := range findings {
		t.Error(f)
	}
}
