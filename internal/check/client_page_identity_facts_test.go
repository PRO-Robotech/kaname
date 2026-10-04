// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	corevalidate "github.com/PRO-Robotech/corelib/validate"

	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/subscriptionjournal"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// Клиентские страницы службы обязаны СХОДИТЬСЯ с теми объявлениями дерева, из
// которых их факты выводятся (задачи kaname#233, kaname#504, kaname#513,
// kaname#514, kacho#2957). Каждое утверждение ниже уже однажды пережило свой
// предмет, и ни одно не стало красным само:
//
//   - врезка обзора объявляла, что журнала подписки у службы «нет и не будет»,
//     когда служба уже была владельцем журнала (kaname#233). Виды журнала
//     страница называет ПОИМЁННО — и поэтому сверяются они с объявлением
//     владельца (`subscriptionjournal.Journal`) в обе стороны;
//   - число путей полосы входа на двух страницах отстало от перечня слушателя
//     (kaname#504). Сверяется с `loginlanehttp.Paths()`;
//   - умолчание размера страницы на обзоре расходилось с общим валидатором
//     (kaname#513). Сверяется с `corevalidate.DefaultPageSize`;
//   - форма идентификатора клиента в `iss`/`sub` на странице токенов шла через
//     подчёркивание, тогда как выпуск чеканит слитную форму (kaname#514);
//   - раздел обзора, на который ссылается страница края о первом вызове после
//     выдачи, отсутствовал, а на его месте стояло «невыразимо by construction»
//     (kacho#2957);
//   - раздел введения о раскладке описывал каталоги монорепо платформы, которых
//     в этом дереве нет (kaname#234). Сверяется с каталогами верхнего уровня.
//
// # ГРАНИЦА
//
// Гейт судит СОСТАВ, ЧИСЛО и ФОРМУ, а не верность прозы вокруг: описать
// предмет неверно он не помешает. Тот же предел, что у гейта страницы полосы
// входа.
const (
	idFactsOverviewRel     = "docs/content/api/overview.mdx"
	idFactsRestSurfaceRel  = "docs/content/api/rest-surface.mdx"
	idFactsArchOverviewRel = "docs/content/architecture/overview.mdx"
	idFactsTokensRel       = "docs/content/api/tokens.mdx"
	idFactsIntroRel        = "docs/content/intro.mdx"
)

// idFactsLayoutHead — раздел введения с раскладкой дерева (kaname#234).
const idFactsLayoutHead = "## Структура репозитория"

// idFactsLayoutRow — строка таблицы раскладки: каталог в первой ячейке.
var idFactsLayoutRow = regexp.MustCompile(`<tr><td><strong>([A-Za-z0-9_.-]+)/</strong></td>`)

// idFactsJournalMarker — то, по чему врезка о журнале службы находится на
// странице: имя владельца в той форме, которую принимает ручка края.
const idFactsJournalMarker = "`owner=iam`"

// idFactsFirstCallHead — заголовок раздела, на который ссылается страница края.
// Имя раздела — адрес чужой ссылки, поэтому оно сверяется дословно.
const idFactsFirstCallHead = "### Первый вызов сразу после выдачи стоит повторить"

// idFactsCodeSpan — код-форматирование страницы: обратные кавычки либо <code>.
// Спан не пересекает перевод строки: тройная кавычка блока кода иначе сдвигает
// пары, и спанами читается проза между ними.
var idFactsCodeSpan = regexp.MustCompile("`([^`\\n]+)`|<code>([^<\\n]+)</code>")

// idFactsKindWord — слово вида журнала: латиница, цифры и подчёркивание, без
// пробела и знаков пути.
var idFactsKindWord = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// idFactsNumerals — числительные, которыми страницы называют число путей.
var idFactsNumerals = map[int]string{
	10: "десять", 11: "одиннадцать", 12: "двенадцать", 13: "тринадцать",
	14: "четырнадцать", 15: "пятнадцать", 16: "шестнадцать", 17: "семнадцать",
	18: "восемнадцать", 19: "девятнадцать", 20: "двадцать",
}

// idFactsCensus — объём осмотренного. Печатается всегда.
type idFactsCensus struct {
	journalKinds   int // видов у владельца журнала
	calloutSpans   int // код-спанов во врезке о журнале
	calloutKinds   int // из них — слов вида
	lanePages      int // страниц, судимых по числу путей полосы
	tokenIDSpans   int // код-спанов страницы токенов с идентификатором клиента
	paginationRead bool
	firstCallRead  bool
	layoutDirs     int // каталогов верхнего уровня в дереве
	layoutRows     int // строк таблицы раскладки
}

func idFactsSpans(text string) []string {
	var out []string
	for _, m := range idFactsCodeSpan.FindAllStringSubmatch(text, -1) {
		s := m[1]
		if s == "" {
			s = m[2]
		}
		out = append(out, strings.TrimSpace(s))
	}
	return out
}

// idFactsCallout — врезка (`:::` … `:::`), внутри которой стоит marker.
func idFactsCallout(page, marker string) string {
	at := strings.Index(page, marker)
	if at < 0 {
		return ""
	}
	start := strings.LastIndex(page[:at], "\n:::")
	if start < 0 {
		return ""
	}
	rest := page[start+1:]
	end := strings.Index(rest[3:], "\n:::")
	if end < 0 {
		return ""
	}
	return rest[:end+3]
}

// auditJournalCallout — виды журнала, названные врезкой, против объявления
// владельца: в обе стороны.
func auditJournalCallout(page string, kinds []string, c *idFactsCensus) []string {
	c.journalKinds = len(kinds)
	if len(kinds) == 0 {
		return []string{"объявление владельца журнала пусто — сверять не с чем; это отказ, а не «ноль находок»"}
	}
	callout := idFactsCallout(page, idFactsJournalMarker)
	if callout == "" {
		return []string{fmt.Sprintf("врезки о журнале службы (маркер %s) на странице нет — "+
			"клиент не узнает, что поток у службы есть", idFactsJournalMarker)}
	}
	var findings []string
	if strings.Contains(callout, "нет и **не будет**") || strings.Contains(callout, "нет и не будет") {
		findings = append(findings, "врезка о журнале обещает его отсутствие «навсегда» — "+
			"утверждение пережило свой предмет")
	}
	declared := map[string]bool{}
	for _, k := range kinds {
		declared[k] = true
	}
	named := map[string]bool{}
	for _, s := range idFactsSpans(callout) {
		c.calloutSpans++
		if !idFactsKindWord.MatchString(s) {
			continue
		}
		if s == "account" || s == "project" || strings.HasPrefix(s, "iam_") {
			c.calloutKinds++
			named[s] = true
		}
	}
	for _, k := range sortedKeys(declared) {
		if !named[k] {
			findings = append(findings, fmt.Sprintf(
				"вид журнала %q объявлен владельцем, а врезка его НЕ называет", k))
		}
	}
	for _, k := range sortedKeys(named) {
		if !declared[k] {
			findings = append(findings, fmt.Sprintf(
				"врезка называет вид %q, которого у владельца журнала нет", k))
		}
	}
	return findings
}

// auditLanePathCount — каждая страница называет число путей полосы числом
// перечня слушателя и никаким другим.
func auditLanePathCount(pages map[string]string, n int, c *idFactsCensus) []string {
	want, ok := idFactsNumerals[n]
	if !ok {
		return []string{fmt.Sprintf("у числа путей полосы %d нет числительного в словаре гейта — "+
			"расширьте словарь, а не снимайте проверку", n)}
	}
	var findings []string
	for _, rel := range sortedKeys(boolKeys(pages)) {
		c.lanePages++
		page := pages[rel]
		if !strings.Contains(page, want+" пут") {
			findings = append(findings, fmt.Sprintf(
				"%s не называет число путей полосы входа (%s, по `loginlanehttp.Paths()`)", rel, want))
		}
		for num, word := range idFactsNumerals {
			if num != n && strings.Contains(page, word+" пут") {
				findings = append(findings, fmt.Sprintf(
					"%s называет «%s пут…», а у слушателя путей %s", rel, word, want))
			}
		}
	}
	sort.Strings(findings)
	return findings
}

// auditClientIDForm — идентификатор клиента на странице токенов пишется той
// формой, которую чеканит выпуск: слитно, без подчёркивания.
func auditClientIDForm(page string, c *idFactsCensus) []string {
	var findings []string
	sawUOC, sawSOC := false, false
	for _, s := range idFactsSpans(page) {
		if !strings.Contains(s, "uoc") && !strings.Contains(s, "soc") {
			continue
		}
		c.tokenIDSpans++
		if strings.Contains(s, "uoc_") || strings.Contains(s, "soc_") {
			findings = append(findings, fmt.Sprintf(
				"идентификатор клиента %q записан через подчёркивание — выпуск чеканит слитную форму", s))
		}
		if strings.HasPrefix(s, "uoc…") || strings.HasPrefix(s, "uoc&lt;17&gt;") || strings.HasPrefix(s, "uoc<17>") {
			sawUOC = true
		}
		if strings.HasPrefix(s, "soc…") || strings.HasPrefix(s, "soc&lt;17&gt;") || strings.HasPrefix(s, "soc<17>") {
			sawSOC = true
		}
	}
	if !sawUOC || !sawSOC {
		findings = append(findings, "страница не называет слитную форму идентификатора клиента "+
			"(`uoc…` и `soc…`) — сверять форму не с чем")
	}
	return findings
}

// auditPaginationDefault — раздел пагинации обзора называет умолчание общего
// валидатора.
func auditPaginationDefault(page string, def int64, c *idFactsCensus) []string {
	const head = "## Пагинация"
	start := strings.Index(page, head)
	if start < 0 {
		return []string{"раздела пагинации на обзоре нет"}
	}
	c.paginationRead = true
	rest := page[start+len(head):]
	if end := strings.Index(rest, "\n## "); end >= 0 {
		rest = rest[:end]
	}
	if !strings.Contains(rest, fmt.Sprintf("по умолчанию %d", def)) {
		return []string{fmt.Sprintf("раздел пагинации не называет умолчание общего валидатора "+
			"(«по умолчанию %d», `corevalidate.DefaultPageSize`)", def)}
	}
	return nil
}

// auditFirstCallSection — раздел, на который ссылается край, на месте, и
// «невыразимо» на странице не осталось.
func auditFirstCallSection(page string, c *idFactsCensus) []string {
	var findings []string
	if strings.Contains(page, idFactsFirstCallHead+"\n") {
		c.firstCallRead = true
	} else {
		findings = append(findings, fmt.Sprintf("раздела %q на обзоре нет — "+
			"страница края ссылается на него по имени", strings.TrimPrefix(idFactsFirstCallHead, "### ")))
	}
	if strings.Contains(page, "ещё не действует» невыразимо") {
		findings = append(findings, "обзор называет «право ещё не действует» невыразимым, "+
			"а производная выдача материализуется после `done`")
	}
	return findings
}

// auditTreeLayout — таблица раскладки введения против каталогов верхнего уровня
// дерева, в обе стороны. Каталоги с точкой в начале (служебные) не судятся.
func auditTreeLayout(page string, dirs []string, c *idFactsCensus) []string {
	if len(dirs) == 0 {
		return []string{"каталогов верхнего уровня не прочитано — сверять не с чем"}
	}
	start := strings.Index(page, idFactsLayoutHead)
	if start < 0 {
		return []string{fmt.Sprintf("раздела %q во введении нет", strings.TrimPrefix(idFactsLayoutHead, "## "))}
	}
	rest := page[start+len(idFactsLayoutHead):]
	if end := strings.Index(rest, "\n## "); end >= 0 {
		rest = rest[:end]
	}
	inTree := map[string]bool{}
	for _, d := range dirs {
		if !strings.HasPrefix(d, ".") {
			inTree[d] = true
		}
	}
	c.layoutDirs = len(inTree)
	onPage := map[string]bool{}
	for _, m := range idFactsLayoutRow.FindAllStringSubmatch(rest, -1) {
		onPage[m[1]] = true
	}
	c.layoutRows = len(onPage)
	var findings []string
	for _, d := range sortedKeys(inTree) {
		if !onPage[d] {
			findings = append(findings, fmt.Sprintf("каталог %s/ есть в дереве, а таблица раскладки его не называет", d))
		}
	}
	for _, d := range sortedKeys(onPage) {
		if !inTree[d] {
			findings = append(findings, fmt.Sprintf("таблица раскладки называет %s/, которого в дереве нет", d))
		}
	}
	return findings
}

// idFactsTopDirs — каталоги верхнего уровня модуля по ОТСЛЕЖИВАЕМЫМ файлам.
// Чтение диска взяло бы и игнорируемое (каталоги сборки), и таблица краснела бы
// у того, кто собрал, — индекс git называет ровно раскладку дерева.
func idFactsTopDirs(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("git", "-C", platformtree.Require(t), "ls-files").Output()
	require.NoError(t, err, "индекс git не прочитан — раскладку выводить не из чего")
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.IndexByte(line, '/'); i > 0 {
			seen[line[:i]] = true
		}
	}
	return sortedKeys(seen)
}

func idFactsRead(t *testing.T, rel string) string {
	t.Helper()
	body, err := os.ReadFile(platformtree.RequirePath(t, rel)) // #nosec G304 -- путь собран из корня собственного модуля
	require.NoError(t, err)
	return string(body)
}

// TestClientPagesAgreeWithTheirProducers — несущее утверждение.
func TestClientPagesAgreeWithTheirProducers(t *testing.T) {
	overview := idFactsRead(t, idFactsOverviewRel)

	kinds := make([]string, 0)
	for k := range subscriptionjournal.Journal().Mapping.Kinds {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)

	var c idFactsCensus
	var findings []string
	findings = append(findings, auditJournalCallout(overview, kinds, &c)...)
	findings = append(findings, auditLanePathCount(map[string]string{
		idFactsRestSurfaceRel:  idFactsRead(t, idFactsRestSurfaceRel),
		idFactsArchOverviewRel: idFactsRead(t, idFactsArchOverviewRel),
	}, len(loginlanehttp.Paths()), &c)...)
	findings = append(findings, auditClientIDForm(idFactsRead(t, idFactsTokensRel), &c)...)
	findings = append(findings, auditPaginationDefault(overview, corevalidate.DefaultPageSize, &c)...)
	findings = append(findings, auditFirstCallSection(overview, &c)...)
	findings = append(findings, auditTreeLayout(idFactsRead(t, idFactsIntroRel), idFactsTopDirs(t), &c)...)

	t.Logf("осмотрено: видов журнала %d, код-спанов врезки %d (слов вида %d), страниц полосы %d, "+
		"спанов идентификатора клиента %d, раздел пагинации прочитан %v, раздел первого вызова найден %v, "+
		"каталогов дерева %d, строк раскладки %d",
		c.journalKinds, c.calloutSpans, c.calloutKinds, c.lanePages, c.tokenIDSpans,
		c.paginationRead, c.firstCallRead, c.layoutDirs, c.layoutRows)
	require.NotZero(t, c.journalKinds, "объявление владельца журнала не прочитано")
	require.NotZero(t, c.lanePages, "страницы полосы не прочитаны")
	require.Empty(t, findings, strings.Join(findings, "\n"))
}
