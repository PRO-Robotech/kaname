// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_page_identity_facts_injection_test.go — доказательство, что гейт
// клиентских страниц СПОСОБЕН упасть и СПОСОБЕН смолчать.
//
// Каждая пара — законный близнец и он же с ОДНИМ изменённым фактом. Инъекция
// зовёт те же функции, что и гейт, а не их копии.
package check_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const injJournalPage = "# Обзор\n\n:::note Поток изменений ресурсов у службы есть\n" +
	"Владелец — `owner=iam`. Виды: `account`, `project`, `iam_user`. Ось — `projectId`.\n" +
	":::\n\n## Дальше\n"

func TestJournalCallout_InjectionBothWays(t *testing.T) {
	kinds := []string{"account", "iam_user", "project"}

	var c idFactsCensus
	require.Empty(t, auditJournalCallout(injJournalPage, kinds, &c), "законный близнец обязан молчать")
	require.Equal(t, 3, c.calloutKinds)

	// Вид пропал со страницы.
	missing := strings.Replace(injJournalPage, "`iam_user`", "пользователи", 1)
	require.NotEmpty(t, auditJournalCallout(missing, kinds, &idFactsCensus{}))

	// Страница называет вид, которого у владельца нет.
	extra := strings.Replace(injJournalPage, "`iam_user`.", "`iam_user`, `iam_quota`.", 1)
	require.NotEmpty(t, auditJournalCallout(extra, kinds, &idFactsCensus{}))

	// Обещание отсутствия вернулось.
	promise := strings.Replace(injJournalPage, "у службы есть", "у службы нет и не будет", 1)
	require.NotEmpty(t, auditJournalCallout(promise, kinds, &idFactsCensus{}))

	// Врезки нет вовсе; пустое объявление — отказ, а не «ноль находок».
	require.NotEmpty(t, auditJournalCallout("# Обзор\n", kinds, &idFactsCensus{}))
	require.NotEmpty(t, auditJournalCallout(injJournalPage, nil, &idFactsCensus{}))
}

func TestLanePathCount_InjectionBothWays(t *testing.T) {
	twin := map[string]string{"a.mdx": "у полосы пятнадцать путей", "b.mdx": "пятнадцать путей `/iam/v1/auth/…`"}
	require.Empty(t, auditLanePathCount(twin, 15, &idFactsCensus{}))

	stale := map[string]string{"a.mdx": "у полосы тринадцать путей", "b.mdx": twin["b.mdx"]}
	require.NotEmpty(t, auditLanePathCount(stale, 15, &idFactsCensus{}))

	silent := map[string]string{"a.mdx": "у полосы свои пути", "b.mdx": twin["b.mdx"]}
	require.NotEmpty(t, auditLanePathCount(silent, 15, &idFactsCensus{}))

	require.NotEmpty(t, auditLanePathCount(twin, 99, &idFactsCensus{}), "число вне словаря — отказ")

	// Числительное, чей хвост — другое числительное, читается целым словом:
	// «восемнадцать» не есть «семнадцать».
	tail := map[string]string{"a.mdx": "у полосы восемнадцать путей", "b.mdx": "(восемнадцать путей)"}
	require.Empty(t, auditLanePathCount(tail, 18, &idFactsCensus{}), "законный близнец с хвостом-числительным молчит")
	require.NotEmpty(t, auditLanePathCount(map[string]string{"a.mdx": "у полосы семнадцать путей", "b.mdx": tail["b.mdx"]}, 18, &idFactsCensus{}),
		"устаревшее «семнадцать» при восемнадцати путях — находка")

	// Формы записи страницы самой полосы (NA8 волны 4): каждая — пара «верное
	// число молчит / устаревшее находится», меняется ровно числительное.
	forms := []string{
		"Путей у полосы **%s**, и объявлены они одним перечнем",
		"Что из %s путей ретранслирует край",
		"Служба обслуживает все %s (`loginlanehttp.Paths()`).",
	}
	right := []string{"восемнадцать", "восемнадцати", "восемнадцать"}
	staleWords := []string{"пятнадцать", "пятнадцати", "пятнадцать"}
	for i, f := range forms {
		require.Emptyf(t, auditLanePathCount(map[string]string{"a.mdx": fmt.Sprintf(f, right[i])}, 18, &idFactsCensus{}),
			"законный близнец формы %q молчит", f)
		got := auditLanePathCount(map[string]string{"a.mdx": fmt.Sprintf(f, right[i]) + "\n" + fmt.Sprintf(f, staleWords[i])}, 18, &idFactsCensus{})
		require.Lenf(t, got, 1, "устаревшее число формы %q находится: %v", f, got)
		require.Containsf(t, got[0], "a.mdx:2 называет «"+staleWords[i]+"»", "находка называет координату и слово: %s", got[0])
	}
	// Составное числительное (kaname#634, 21 путь) читается ДВУМЯ словами:
	// законный близнец молчит каждой падежной формой, а «двадцать» без «один» —
	// устаревшее число и находится.
	for _, f := range []string{"Путей у полосы **двадцать один**", "Что из двадцати одного пути ретранслирует край",
		"Служба обслуживает все двадцать один (`loginlanehttp.Paths()`)."} {
		require.Emptyf(t, auditLanePathCount(map[string]string{"a.mdx": f}, 21, &idFactsCensus{}), "законный близнец %q молчит", f)
	}
	gotCompound := auditLanePathCount(map[string]string{"a.mdx": "у полосы двадцать один путь\nу полосы двадцать путей"}, 21, &idFactsCensus{})
	require.Len(t, gotCompound, 1, "«двадцать» при 21 пути — находка: %v", gotCompound)
	require.Contains(t, gotCompound[0], "a.mdx:2 называет «двадцать»")
	require.NotEmpty(t, auditLanePathCount(map[string]string{"a.mdx": "у полосы двадцать один путь"}, 20, &idFactsCensus{}),
		"«двадцать один» при 20 путях — находка, а не «двадцать» плюс лишнее слово")

	// Числительное вдали от якоря — не о путях.
	far := map[string]string{"a.mdx": "у полосы восемнадцать путей. Срок признака формы — пятнадцать минут, сессия живёт дольше"}
	require.Empty(t, auditLanePathCount(far, 18, &idFactsCensus{}), "числительное вне окна якоря молчит")
}

func TestClientIDForm_InjectionBothWays(t *testing.T) {
	twin := "| `iss` и `sub` | идентификатор клиента (`uoc…` / `soc…`) |\n" +
		"```bash\nexport A=`date`\n```\n"
	var c idFactsCensus
	require.Empty(t, auditClientIDForm(twin, &c))
	require.Equal(t, 2, c.tokenIDSpans)

	underscored := strings.Replace(twin, "`soc…`", "`soc_…`", 1)
	require.NotEmpty(t, auditClientIDForm(underscored, &idFactsCensus{}))
}

func TestPaginationDefault_InjectionBothWays(t *testing.T) {
	twin := "## Пагинация — cursor-based\n\n`pageSize` (по умолчанию 50, максимум 1000)\n\n## Дальше\nпо умолчанию 100\n"
	require.Empty(t, auditPaginationDefault(twin, 50, &idFactsCensus{}))

	other := strings.Replace(twin, "по умолчанию 50", "по умолчанию 100", 1)
	require.NotEmpty(t, auditPaginationDefault(other, 50, &idFactsCensus{}))

	require.NotEmpty(t, auditPaginationDefault("## Другое\n", 50, &idFactsCensus{}))
}

func TestFirstCallSection_InjectionBothWays(t *testing.T) {
	twin := "## Авторизация\n\n" + idFactsFirstCallHead + "\n\nПовторите первый вызов.\n"
	require.Empty(t, auditFirstCallSection(twin, &idFactsCensus{}))

	renamed := strings.Replace(twin, "стоит повторить", "повторите", 1)
	require.NotEmpty(t, auditFirstCallSection(renamed, &idFactsCensus{}))

	claim := twin + "состояние «привязка создана, но право ещё не действует» невыразимо\n"
	require.NotEmpty(t, auditFirstCallSection(claim, &idFactsCensus{}))
}

func TestTreeLayout_InjectionBothWays(t *testing.T) {
	twin := "## Структура репозитория\n\n<tr><td><strong>cmd/</strong></td><td>x</td></tr>\n" +
		"<tr><td><strong>internal/</strong></td><td>y</td></tr>\n\n## Дальше\n" +
		"<tr><td><strong>services/</strong></td><td>не раздел раскладки</td></tr>\n"
	dirs := []string{".github", "cmd", "internal"}
	var c idFactsCensus
	require.Empty(t, auditTreeLayout(twin, dirs, &c))
	require.Equal(t, 2, c.layoutDirs)

	foreign := strings.Replace(twin, "internal/", "services/", 1)
	require.NotEmpty(t, auditTreeLayout(foreign, dirs, &idFactsCensus{}))

	require.NotEmpty(t, auditTreeLayout(twin, append(dirs, "deploy"), &idFactsCensus{}))
	require.NotEmpty(t, auditTreeLayout(twin, nil, &idFactsCensus{}), "пустой обход — отказ")
}
