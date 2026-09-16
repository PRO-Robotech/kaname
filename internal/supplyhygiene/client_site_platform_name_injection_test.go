// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_site_platform_name_injection_test.go — ДОКАЗАТЕЛЬСТВО, что гейт
// клиентского сайта способен упасть и способен смолчать.
//
// Инъекция подаёт ТОГО ЖЕ судью (`JudgeClientSitePlatformName`) и тот же
// распознаватель (`PlatformNameHits`), что исполняются на боевом прогоне:
// доказательство на копии разбора доказывало бы свойство копии.
//
// Каждая проба меняет РОВНО ОДИН факт против положительного контроля, иначе
// неизвестно, какой из них дал красное.
package supplyhygiene

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const (
	injSitePage = "docs/content/api/probe.mdx"
	// injNeighborLine — законная ссылка на соседа: имя платформы называет чужую
	// документацию. Вносится в ведомость и обязана молчать.
	injNeighborLine = "Потолки видов читаются в документации соответствующего сервиса Kachō."
)

var injSiteStay = []ClientSiteStay{
	{Page: injSitePage, Token: "Kachō", Count: 1, Why: "ссылка на соседний сервис"},
}

func judgeInjectedSite(t *testing.T, body string, stay []ClientSiteStay) (ClientSiteCensus, []string) {
	t.Helper()
	return JudgeClientSitePlatformName(map[string]string{injSitePage: body}, stay, clientSiteSurface)
}

func requireOneFinding(t *testing.T, findings []string, want ...string) {
	t.Helper()
	require.Len(t, findings, 1, "находок %d, ожидалась одна: %v", len(findings), findings)
	for _, w := range want {
		require.Contains(t, findings[0], w, "находка не называет %q: %s", w, findings[0])
	}
}

// TestClientSiteInjection_ControlIsSilent — положительный контроль: без него
// всякое «покраснел» ниже доказывало бы лишь то, что гейт краснеет всегда.
func TestClientSiteInjection_ControlIsSilent(t *testing.T) {
	census, findings := judgeInjectedSite(t, injNeighborLine+"\n", injSiteStay)
	require.Empty(t, findings, "законная ссылка на соседа, названная ведомостью, дала находку")
	require.Equal(t, 1, census.Hits, "распознаватель не увидел диакритическую форму")
	require.Equal(t, 1, census.HitsDiacritic)
	require.Equal(t, 1, census.Stayed)
}

// TestClientSiteInjection_DiacriticSelfNameIsFound — несущее отрицание:
// самоназвание диакритической формой, на другой строке той же страницы.
// Проверяется и то, что запись одного вхождения не прощает второго.
func TestClientSiteInjection_DiacriticSelfNameIsFound(t *testing.T) {
	_, findings := judgeInjectedSite(t,
		injNeighborLine+"\nЭта страница объясняет, как Kachō решает, можно ли действие.\n", injSiteStay)
	requireOneFinding(t, findings, injSitePage, "«Kachō»", "2 вхождений", "называет 1")
}

// TestClientSiteInjection_ASCIISelfNameIsFound — вторая форма отдельно:
// распознаватель, знающий одну из двух, недобирает молча.
func TestClientSiteInjection_ASCIISelfNameIsFound(t *testing.T) {
	_, findings := judgeInjectedSite(t,
		injNeighborLine+"\nКлиент называет себя идентификатором строки реестра kacho.\n", injSiteStay)
	requireOneFinding(t, findings, injSitePage+":2", "«kacho»")
}

// TestClientSiteInjection_NeighborTokenDoesNotForgiveProse — запись ведётся
// по ТОКЕНУ: ссылка `kacho-vpc` названа ведомостью, а отдельное слово той же
// основы на той же странице — нет. Запись по подстроке простила бы оба.
func TestClientSiteInjection_NeighborTokenDoesNotForgiveProse(t *testing.T) {
	stay := []ClientSiteStay{{Page: injSitePage, Token: "kacho-vpc", Count: 1, Why: "сосед"}}
	_, findings := judgeInjectedSite(t, "Вызывающий — kacho-vpc.\nМодель Kacho — плоская.\n", stay)
	requireOneFinding(t, findings, injSitePage+":2", "«Kacho»")
}

// TestClientSiteInjection_StaleEntryIsFound — самоистечение: запись, которой
// на странице нечего прощать, — находка.
func TestClientSiteInjection_StaleEntryIsFound(t *testing.T) {
	_, findings := judgeInjectedSite(t, "Страница без имени платформы.\n", injSiteStay)
	requireOneFinding(t, findings, "нечего прощать", injSitePage)
}

// TestClientSiteInjection_EntryOutsideTheSiteIsFound — запись о файле вне
// сайта не прощение, а находка: сайт состоит из объявленного, не шире.
func TestClientSiteInjection_EntryOutsideTheSiteIsFound(t *testing.T) {
	stay := append([]ClientSiteStay{}, injSiteStay...)
	stay = append(stay, ClientSiteStay{Page: "docs/engineering/note.md", Token: "Kachō", Count: 1,
		Why: "запись вне сайта"})
	_, findings := judgeInjectedSite(t, injNeighborLine+"\n", stay)
	requireOneFinding(t, findings, "docs/engineering/note.md", "не страница сайта")
}

// TestClientSiteInjection_EntryShapeIsJudged — запись без причины либо с
// нулевым числом прощением не является.
func TestClientSiteInjection_EntryShapeIsJudged(t *testing.T) {
	for _, bad := range []ClientSiteStay{
		{Page: injSitePage, Token: "Kachō", Count: 1, Why: ""},
		{Page: injSitePage, Token: "Kachō", Count: 0, Why: "сосед"},
	} {
		_, findings := judgeInjectedSite(t, injNeighborLine+"\n", []ClientSiteStay{bad})
		require.GreaterOrEqual(t, len(findings), 2, "запись %+v прошла как прощение: %v", bad, findings)
		require.Contains(t, strings.Join(findings, "\n"), "причина")
	}
}

// TestClientSiteInjection_TwinWithoutThePlatformNameIsSilent — законный
// близнец формы: слова той же основы без последней гласной имени платформы
// находкой не являются.
func TestClientSiteInjection_TwinWithoutThePlatformNameIsSilent(t *testing.T) {
	census, findings := judgeInjectedSite(t, "Kaname, Kachina и kachka — не имя платформы.\n", nil)
	require.Empty(t, findings)
	require.Zero(t, census.Hits)
}

// TestClientSiteInjection_EmptySiteIsRefused — обход, не отобравший ни одной
// страницы, вердикта не выносит: «ноль находок» обязано быть отличимо от
// «ноль прочитанного».
func TestClientSiteInjection_EmptySiteIsRefused(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "docs", "engineering", "note.md")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte("Kachō\n"), 0o600))
	tree, err := treecorpus.SyntheticTree(root)
	require.NoError(t, err)
	_, err = check.CorpusFrom(tree, func(rel string) bool { return InClientSite(rel, clientSiteSurface) })
	require.True(t, errors.Is(err, check.ErrEmptyTraversal),
		"обход без страниц сайта прошёл как вердикт: %v", err)
}

// TestPlatformNameHits_TokenAndForm — распознаватель: обе формы, граница
// токена, знак конца прозы и кириллица, которая токен не продолжает.
func TestPlatformNameHits_TokenAndForm(t *testing.T) {
	hits := PlatformNameHits("Kachō: ряд kacho_grpc_server_handled_total{code}\nплатформыKacho.\n" +
		"https://github.com/PRO-Robotech/kacho/issues/1\n")
	got := make([]string, 0, len(hits))
	for _, h := range hits {
		got = append(got, h.Token)
	}
	require.Equal(t, []string{
		"Kachō",
		"kacho_grpc_server_handled_total",
		"Kacho",
		"https://github.com/PRO-Robotech/kacho/issues/1",
	}, got)
	require.True(t, hits[0].Diacritic)
	require.False(t, hits[1].Diacritic)
	require.Equal(t, 2, hits[2].Line)
}
