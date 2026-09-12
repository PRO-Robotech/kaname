// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// named_verb_form_expiry.go — разбор ПАРЫ: отвергается ли поимённая форма
// права роли прод-кодом манифеста и есть ли в дереве пробы шести сценариев её
// полноты. Находка — ровно одно их сочетание: форма принята, полнота не
// проверяется.
//
// Порт с монорепо (`internal/repohygiene/namedverbformexpiry.go`, снят
// вынесением службы — `kacho#2597`). Изменилось: пакет (`repohygiene` →
// `check`), путь домена (`services/iam/internal/manifest/` →
// `internal/manifest/`, префикс `services/iam/` снят — в kaname код службы
// лежит от корня репозитория). Осталось дословно: разбор узла (не подстроки),
// закрытый перечень шести сценариев, различение двух законных причин
// молчания.
//
// # Почему этот перенос ОБЯЗАТЕЛЕН, а не факультативен
//
// Прод-код `internal/manifest/roleexport/check.go` (написанный ДО выноса
// службы, когда `internal/repohygiene` был тем же репозиторием) буквально
// называет держателя: «ЧЕМ ДЕРЖИТСЯ ЗАПРЕТ ... гейтом дерева
// `internal/repohygiene` `TestNamedVerbFormReturnsOnlyWithItsCompletenessCheck`».
// До этого файла держателя в дереве kaname не было ни одного: цитата
// утверждала присутствие проверки, которой не существует.
//
// # Предмет — ПАРА, а не любая её половина (дословно из монорепо)
//
// Принять перечень ИМЁН, не умея проверить его полноту по классу, значит
// свести его к классу МОЛЧА и выдать право ШИРЕ просимого (замер приёмки: 55
// вхождений из 92 в черновике vpc совпадают с именем класса). Молчание гейта
// законно ПО ДВУМ причинам, и различать их вызывающему не нужно: форма
// отвергается сентинелом (возвратов > 0) ЛИБО она вернулась вместе со своей
// проверкой (все шесть проб MOD-RL найдены).
//
// # Замер на дне переноса (kaname@issue-2597, kacho#2597)
//
// Сентинел `ErrRoleRuleVerbsRetired` в `internal/manifest/` не объявлен и не
// возвращается (задача #1844 сняла его вместе с формой, которую он отвергал —
// `f5bb097046` в истории монорепо). Все шесть проб MOD-RL (04, 04a, 18, 18a,
// 19, 19a) в дереве ЕСТЬ (`internal/manifest/rolenamedverbs_test.go`,
// `internal/manifest/roleexport/namedverbs_test.go`). Гейт сегодня молчит по
// ВТОРОЙ законной причине — форма вернулась вместе со своей проверкой, ровно
// как того требует приёмка #1844, — а не по первой. Это и есть содержание
// переноса: без держателя регресс (снятие одной из шести проб при живом
// возврате перечня имён) не был бы замечен НИЧЕМ.
//
// # Чего разбор НЕ видит — названо, а не спрятано (дословно из монорепо)
//
// Возврат сентинела, собранный в рантайме (через переменную, через таблицу
// видов). Такой формы в этом пакете нет, и появись она — гейт увидит ноль
// возвратов и покраснеет, то есть ошибётся В СТОРОНУ находки, а не молчания.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// VerbFormSentinelCensus — объём, осмотренный разбором ОДНОГО файла.
type VerbFormSentinelCensus struct {
	// CompositeLits — составных литералов прочитано. Предпосылка оси: разбор
	// ищет присваивание внутри литерала, и ноль литералов означает, что
	// искать было негде.
	CompositeLits int
	// Idents — идентификаторов прочитано: объём разбора в самой мелкой единице.
	Idents int
	// SentinelReturns — возвратов сентинела найдено.
	SentinelReturns int
}

// RoleRuleVerbsSentinel — имя сентинела, которым пред-разборная проверка
// отвергает снятый ключ. Объявлено ЗДЕСЬ, потому что гейт живёт в общем
// пакете, а сентинел — в `internal/manifest`, закрытом правилом видимости Go.
// Что имя не разошлось с продуктом, утверждает сам гейт: ноль возвратов на
// живом дереве — находка, а не молчание.
const RoleRuleVerbsSentinel = "ErrRoleRuleVerbsRetired"

// ScanVerbFormSentinel считает ВОЗВРАТЫ сентинела в одном файле Go.
//
// Возвратом считается присваивание `kind: <Сентинел>` в составном литерале,
// стоящем внутри `return` — то есть исход функции, а не упоминание имени.
func ScanVerbFormSentinel(rel string, src []byte) (VerbFormSentinelCensus, error) {
	var census VerbFormSentinelCensus
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, src, 0)
	if err != nil {
		return census, err
	}

	// Составные литералы, лежащие внутри return: только их исход виден снаружи.
	inReturn := map[*ast.CompositeLit]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		ast.Inspect(ret, func(m ast.Node) bool {
			if cl, ok := m.(*ast.CompositeLit); ok {
				inReturn[cl] = true
			}
			return true
		})
		return true
	})

	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Ident:
			census.Idents++
		case *ast.CompositeLit:
			census.CompositeLits++
			if !inReturn[node] {
				return true
			}
			for _, el := range node.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "kind" {
					continue
				}
				if id, ok := kv.Value.(*ast.Ident); ok && id.Name == RoleRuleVerbsSentinel {
					census.SentinelReturns++
				}
			}
		}
		return true
	})
	return census, nil
}

// NamedVerbFormFinding — РЕШЕНИЕ гейта одной функцией: сценарии, оставшиеся
// без пробы, когда форма уже не отвергается.
//
// Объявлено здесь, а не внутри гейта, ровно затем, чтобы инъекция гоняла ТОТ
// ЖЕ предикат, что и прогон дерева: второй, написанный в пробе «по образцу»,
// разошёлся бы с первым молча — и разошёлся бы именно там, где расхождение не
// видно, потому что оба отвечают одинаково на сегодняшнем входе.
//
// Пустой результат означает молчание, и у него ДВЕ законные причины: форма
// отвергается (`sentinelReturns > 0`) либо она вернулась вместе со своей
// проверкой (пробы найдены). Различать их вызывающему не нужно — обе законны.
func NamedVerbFormFinding(sentinelReturns int, probeNames []string) []string {
	if sentinelReturns > 0 {
		return nil
	}
	return MissingScenarioProbes(probeNames)
}

// NamedVerbScenarios — шесть сценариев, чья проверка полноты и есть содержание
// отсрочки. Перечень ЗАКРЫТ и выписан: он приезжает из приёмки `#1090`, а не
// из дерева, и выводить его неоткуда — проб этих сценариев в дереве ноль by
// construction, то есть вывод из дерева дал бы пустой перечень и гейт, которому
// нечего требовать.
var NamedVerbScenarios = []string{"04", "04a", "18", "18a", "19", "19a"}

// ScenarioProbeName — имя пробы сценария в написании этого дерева.
func ScenarioProbeName(scenario string) string { return "TestMODRL" + scenario }

// MissingScenarioProbes — сценарии из закрытого перечня, у которых в дереве
// нет ни одной пробы.
//
// Принимается перечень ИМЁН функций, а не текст файлов: подстрока
// `TestMODRL04` стои́т и внутри `TestMODRL04a`, и гейт, судящий вхождение,
// зачёл бы одну пробу за две. Имя сравнивается с ПРЕФИКСОМ и следующим за ним
// символом.
func MissingScenarioProbes(funcNames []string) []string {
	var missing []string
	for _, s := range NamedVerbScenarios {
		want := ScenarioProbeName(s)
		found := false
		for _, name := range funcNames {
			if !strings.HasPrefix(name, want) {
				continue
			}
			rest := name[len(want):]
			// `TestMODRL04` против `TestMODRL04a`: следующий символ обязан НЕ
			// продолжать номер сценария.
			if rest != "" && (rest[0] >= '0' && rest[0] <= '9' || rest[0] >= 'a' && rest[0] <= 'z') {
				continue
			}
			found = true
			break
		}
		if !found {
			missing = append(missing, s)
		}
	}
	return missing
}
