// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// identity_growth_reader.go — разбор: у величины роста числа личностей есть
// ЧИТАТЕЛЬ, и он назван.
//
// # Предмет
//
// Величина, которую никто не смотрит, наблюдаемостью не является: она
// печатается на витрине, ничего не утверждает и создаёт уверенность, которой
// нет. Задача, заведшая семейство, просила именно наблюдаемость — «число
// личностей и скорость их появления видны, превышение порога порождает
// оповещение», — и ряд без правила закрывал бы её формой, а не существом.
//
// # Что считается читателем
//
// ТОЛЬКО выражение правила оповещения (`expr:`). Упоминание имени ряда в
// пояснении к тревоге или в таблице метрик читателем НЕ является: пояснение не
// срабатывает. Различие несущее — оба текста лежат в одном файле, и разбор,
// ищущий имя по всему документу, зеленел бы на ряде, о котором лишь написано.
//
// # Граница названа
//
// Судится ОДНО семейство, и его состав выводится из файла коллектора, а не из
// выписанного перечня. На прочие ряды службы разбор не распространяется, и это
// не оплошность: у части из них правил сегодня нет, и заведение им читателей —
// отдельная работа с отдельным предметом. Расширение на всё семейство метрик
// обязано прийти ВМЕСТЕ с этими правилами, иначе оно потребует перечня
// исключений — то есть заведёт ровно ту форму, в которой послабление переживает
// свой предмет.
//
// # Порт с монорепо — пара файлов названа, а не умолчана
//
// Перенесено с `PRO-Robotech/kacho:internal/repohygiene/identitygrowthreader_test.go`
// (семейство снято вынесением службы, `kacho#2597`; предмет жив здесь — задача
// #17). Изменилось: координаты обоих операндов (приставки `services/iam/` в
// самостоятельном клоне нет), разбор вынесен из пробы в пакет `check`, приставка
// рядов берётся у того же имени, которым пакет уже называет свой словарь.
// Осталось дословно: имя гейта (`TestIdentityGrowthMetricsHaveANamedReader`),
// разбор выражений и граница «исполняемое против объяснения».
//
// Близнец в платформе снят вместе с предметом — там этих рядов больше нет,
// поэтому пары файлов этот порт НЕ заводит.
package check

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	// IdentityGrowthCollectorFile — где объявлено семейство величин.
	IdentityGrowthCollectorFile = "internal/observability/metrics/identity_growth_collector.go"
	// IdentityGrowthReadersFile — где живут правила оповещений службы.
	//
	// Это ПРОИЗВОДИТЕЛЬ, а не его пересказ, и различие здесь несущее. Прежде
	// координата называла инженерный документ — то есть КОПИЮ, оставшуюся от
	// переноса правил на опубликованную страницу. Гейт был зелен, а свойство не
	// выполнялось: `kaname_identities_total` читало правило, которое жило
	// только в копии и не поставлялось никому (`kacho#2545`). Читатель, которого
	// нет у того, кто поставил продукт, читателем не является.
	//
	// Наведя гейт сюда, мы получили ЧЕСТНЫЙ красный — «ряд объявлен, но его не
	// читает ни одно правило», — и он снялся заведением правила в поставку, а не
	// правкой текста.
	IdentityGrowthReadersFile = "deploy/templates/prometheusrule.yaml"
)

// identityGrowthMetricPrefix — приставка рядов СВОЕГО словаря.
//
// Второго объявления бренда здесь не заводится: приставка берётся у того же
// имени, которым пакет уже называет свой словарь клейм. Выписанная отдельно, она
// на переименовании не краснела бы по существу — она обнулила бы ПРОЧИТАННОЕ, и
// гейт начал бы судить пустоту. Видимым это делает страж предпосылки в самом
// гейте («рядов объявлено 0»), а не эта строка.
const identityGrowthMetricPrefix = TokenClaimOwnNamespace + "_"

var (
	// identityGrowthMetricNameRe — имя ряда в объявлении константы Go.
	identityGrowthMetricNameRe = regexp.MustCompile(
		`"(` + regexp.QuoteMeta(identityGrowthMetricPrefix) + `[a-z0-9_]+)"`)
	// identityGrowthGoCommentRe — строчный комментарий Go.
	identityGrowthGoCommentRe = regexp.MustCompile(`(?m)^\s*//.*$`)
)

// IdentityGrowthMetricNamesIn — имена рядов в исходнике коллектора.
//
// Комментарии снимаются первыми: файл коллектора подробно объясняет, почему
// рядов два, и называет их имена в прозе. Разбор сырого текста засчитал бы
// объявлением упоминание в разборе.
func IdentityGrowthMetricNamesIn(src string) []string {
	src = identityGrowthGoCommentRe.ReplaceAllString(src, "")
	seen := map[string]bool{}
	var out []string
	for _, m := range identityGrowthMetricNameRe.FindAllStringSubmatch(src, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

// AlertExpressionsIn — тела выражений `expr:` правил оповещения.
//
// Берётся ТОЛЬКО исполняемая часть: однострочное выражение целиком либо блок,
// введённый `|`, до первого поля того же или меньшего отступа. Комментарии
// снимаются — иначе имя ряда, УБРАННОГО из выражения и оставшегося в
// объяснении, продолжало бы считаться читателем.
func AlertExpressionsIn(doc string) []string {
	var out []string
	lines := strings.Split(doc, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimLeft(line, " ")
		if !strings.HasPrefix(trimmed, "expr:") {
			continue
		}
		indent := len(line) - len(trimmed)
		body := strings.TrimSpace(strings.TrimPrefix(trimmed, "expr:"))

		if body != "" && body != "|" && body != ">" {
			out = append(out, stripAlertComments(body))
			continue
		}
		// Блочное выражение: всё, что отступлено ГЛУБЖЕ самого `expr:`.
		var block []string
		for j := i + 1; j < len(lines); j++ {
			next := lines[j]
			if strings.TrimSpace(next) == "" {
				continue
			}
			nextIndent := len(next) - len(strings.TrimLeft(next, " "))
			if nextIndent <= indent {
				break
			}
			block = append(block, next)
			i = j
		}
		out = append(out, stripAlertComments(strings.Join(block, "\n")))
	}
	return out
}

// stripAlertComments снимает комментарии — и строчные, и ХВОСТОВЫЕ.
//
// Хвостовая форма и есть предмет, ради которого снятие заведено: имя ряда,
// убранного из выражения и оставленного памяткой в конце строки, продолжало бы
// считаться читателем — в ОБЕИХ формах выражения, однострочной и блочной.
//
// Образец по всему тексту здесь не годится, и разбор YAML тоже. Образец не
// отличает комментарий от знака внутри строкового литерала и вырезал бы
// исполняемую часть выражения. Разбор YAML не годится по другой причине: в
// блочном скаляре YAML комментариев не знает ВОВСЕ — там знак начинает
// комментарий языка выражений, который снять всё равно надо. Поэтому — свой
// обход со знанием кавычек, одно правило на обе формы.
func stripAlertComments(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = stripAlertCommentFromLine(line)
	}
	return strings.Join(lines, "\n")
}

// stripAlertCommentFromLine отрезает хвост строки, начиная со знака, который
// открывает комментарий.
//
// Знак открывает комментарий, когда он первый в строке либо ему предшествует
// пробельный, и он не внутри строкового литерала. Кавычек три вида: двойные и
// одинарные (ими квотирует и YAML, и язык выражений) и обратные — сырая строка.
// Знак, прижатый к предыдущему (`a#b`), комментария не открывает ни там, ни там.
func stripAlertCommentFromLine(line string) string {
	var quote byte // 0 — вне строки; иначе знак, которым она открыта
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == '\\' && quote == '"' {
				i++ // экранированный знак строку не закрывает
				continue
			}
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'' || c == '`':
			quote = c
		case c == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t'):
			return strings.TrimRight(line[:i], " \t")
		}
	}
	return line
}

// IdentityGrowthReaderCensus — ОБЪЁМ ОСМОТРЕННОГО обеих сторон сверки.
type IdentityGrowthReaderCensus struct {
	// Metrics — ряды, объявленные коллектором.
	Metrics []string
	// Expressions — выражения правил оповещения, прочитанные у документа.
	Expressions int
}

// JudgeIdentityGrowthReaders — у каждого объявленного ряда есть читатель.
//
// ПРЕМИСЫ ЖИВУТ ЗДЕСЬ, а не в теле гейта (задача #17). Прежде обе стояли в
// пробе, входом им служили два файла, прочитанные от корня своего модуля, и
// подать им пустую сторону было НЕЧЕМ: ветви читались глазами и не исполнялись
// ни разу. Приняв обе стороны параметрами, они стали проверяемы синтетикой.
//
// Ноль рядов и ноль выражений — РАЗНЫЕ отказы намеренно: первый означает, что
// ослеп разбор коллектора, второй — что ослеп разбор правил, и чинятся они в
// разных местах. Слив их в один текст, гейт посылал бы читателя не туда.
func JudgeIdentityGrowthReaders(collector, doc string) (IdentityGrowthReaderCensus, []string, error) {
	c := IdentityGrowthReaderCensus{Metrics: IdentityGrowthMetricNamesIn(collector)}
	if len(c.Metrics) == 0 {
		return c, nil, fmt.Errorf("%w: в объявлении коллектора не найдено ни одного имени "+
			"ряда — форма объявления либо приставка словаря изменились, и гейт судит пустоту",
			ErrEmptyTraversal)
	}

	exprs := AlertExpressionsIn(doc)
	c.Expressions = len(exprs)
	if c.Expressions == 0 {
		return c, nil, fmt.Errorf("%w: в документе наблюдаемости не найдено ни одного "+
			"выражения правила — разбор перестал их видеть, и «читатель есть» получено даром",
			ErrEmptyTraversal)
	}

	joined := strings.Join(exprs, "\n")
	var findings []string
	for _, metric := range c.Metrics {
		if !strings.Contains(joined, metric) {
			findings = append(findings, "ряд «"+metric+"» объявлен, но его не читает ни одно "+
				"правило оповещения: величина печатается на витрине, ничего не утверждает "+
				"и создаёт уверенность, которой нет")
		}
	}
	sort.Strings(findings)
	return c, findings, nil
}
