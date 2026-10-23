// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package contracttext

// freshness_window_verbs_test.go — каждое описание окна свежести называет ВСЕ
// глаголы, которые окно судит (kaname#734).
//
// # Предмет
//
// Окно `authn.self-service-freshness` описывалось как действующее на заведение
// и подтверждение второго фактора. Полоса требует свежего предъявления ещё у
// заведения первого пароля, запроса смены адреса, регистрации и снятия ключа
// доступа, выхода из выбранной сессии и из всех прочих. Оператор, меняющий
// окно, не видел, что меняет защиту этих глаголов.
//
// # Что судится
//
// Эталон — строка отказа `SESSION_NOT_FRESH` таблицы отказов
// `docs/content/api/auth-lane.mdx`: она перечисляет глаголы под окном. Каждое
// место, описывающее окно оператору (документ установки, страница конфигурации,
// комментарии боевого профиля и профиля по умолчанию, объявление ручки и строка
// таблицы обязательных величин), называет те же глаголы.
//
// # Граница
//
// Судится только перечень глаголов. Срок неподтверждённого заведения второго
// фактора — отдельное свойство окна, его описание не меняется.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// freshnessVerb — глагол под окном: имя для находки и образец его названия.
type freshnessVerb struct {
	name string
	re   *regexp.Regexp
}

// freshnessVerbs — перечень глаголов под окном по таблице отказов auth-lane.
var freshnessVerbs = []freshnessVerb{
	{"второй фактор: заведение и подтверждение", regexp.MustCompile(`(?i)фактора`)},
	{"заведение первого пароля", regexp.MustCompile(`(?i)пароля`)},
	{"запрос смены адреса почты", regexp.MustCompile(`(?i)смены\s+адреса`)},
	{"регистрация ключа доступа", regexp.MustCompile(`(?i)регистраци`)},
	{"снятие ключа доступа", regexp.MustCompile(`(?i)снят\S*\s+ключа\s+доступа`)},
	{"выход из своих сессий", regexp.MustCompile(`(?i)сесси`)},
}

// freshnessSurface — место, описывающее окно: файл и границы блока в нём
// (первая строка по start, последняя по end включительно).
type freshnessSurface struct {
	path  string
	start *regexp.Regexp
	end   *regexp.Regexp
}

func freshnessSurfaces() []freshnessSurface {
	return []freshnessSurface{
		{"docs/content/install/configuration.mdx",
			regexp.MustCompile(`<code>KANAME_AUTHN&#95;&#95;SELF_SERVICE_FRESHNESS</code></td><td>`), nil},
		{"docs/content/install/configuration.mdx",
			regexp.MustCompile(`<code>authn\.self-service-freshness</code> · `), nil},
		{"INSTALL.md",
			regexp.MustCompile("^\\| `authn\\.self-service-freshness` \\|"), nil},
		{"deploy/values.prod.yaml",
			regexp.MustCompile(`ОКНО СВЕЖЕСТИ ПРАВКИ СВОИХ ДАННЫХ`), regexp.MustCompile(`^\s*selfServiceFreshness:`)},
		{"deploy/values.yaml",
			regexp.MustCompile(`selfServiceFreshness: 15m`), regexp.MustCompile(`^\s*#\s+accessKeys:`)},
		{"internal/apps/kaname/config/config.go",
			regexp.MustCompile(`SelfServiceFreshness — окно свежести`), regexp.MustCompile(`SelfServiceFreshness\s+time\.Duration`)},
		{"internal/apps/kaname/config/required_settings.go",
			regexp.MustCompile(`Key:\s+"authn\.self-service-freshness"`), regexp.MustCompile(`Refusal:\s+"authn\.self-service-freshness"`)},
	}
}

var (
	// literalJoin — склейка строковых литералов Go: `"…" +<перевод строки>"…"`.
	literalJoin = regexp.MustCompile(`"\s*\+\s*"`)
	// commentMark — маркер комментария в начале продолженной строки блока.
	commentMark = regexp.MustCompile(`\s(#|//)\s`)
)

// flattenBlock — строки блока одним текстом без маркеров комментария и склейки
// литералов: перенос строки внутри фразы не прячет её от образца.
func flattenBlock(lines []string) string {
	text := " " + strings.Join(lines, " ")
	text = literalJoin.ReplaceAllString(text, "")
	text = commentMark.ReplaceAllString(text, " ")
	return oneLine(text)
}

// surfaceBlock — текст блока места одной строкой; ok=false, если начала нет.
func surfaceBlock(lines []string, s freshnessSurface) (string, bool) {
	for i, l := range lines {
		if !s.start.MatchString(l) {
			continue
		}
		j := i
		if s.end != nil {
			j = -1
			for k := i; k < len(lines); k++ {
				if s.end.MatchString(lines[k]) {
					j = k
					break
				}
			}
			if j < 0 {
				return "", false
			}
		}
		return flattenBlock(lines[i : j+1]), true
	}
	return "", false
}

// freshnessVerbFindings — находки по одному тексту: какие глаголы не названы.
func freshnessVerbFindings(where, text string) []string {
	var found []string
	for _, v := range freshnessVerbs {
		if !v.re.MatchString(text) {
			found = append(found, where+": окно не называет глагол «"+v.name+"»")
		}
	}
	return found
}

// TestFreshnessWindowDescriptionsNameEveryVerb — гейт на дереве.
func TestFreshnessWindowDescriptionsNameEveryVerb(t *testing.T) {
	root := platformtree.Require(t)
	read := func(rel string) []string {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		require.NoErrorf(t, err, "чтение %s", rel)
		return strings.Split(string(b), "\n")
	}

	// Предпосылка: эталон сам называет все глаголы.
	refLines := read("docs/content/api/auth-lane.mdx")
	ref, ok := surfaceBlock(refLines, freshnessSurface{
		path:  "docs/content/api/auth-lane.mdx",
		start: regexp.MustCompile(`<code>SESSION_NOT_FRESH</code></td><td>заведение либо подтверждение`),
	})
	require.True(t, ok, "в таблице отказов auth-lane нет строки SESSION_NOT_FRESH с перечнем глаголов — судить нечем")
	require.Empty(t, freshnessVerbFindings("auth-lane.mdx (эталон)", ref), "эталон не называет глаголы окна")

	var found []string
	judged := 0
	for _, s := range freshnessSurfaces() {
		block, ok := surfaceBlock(read(s.path), s)
		if !ok {
			found = append(found, s.path+": описание окна не найдено по образцу «"+s.start.String()+"»")
			continue
		}
		judged++
		found = append(found, freshnessVerbFindings(s.path, block)...)
	}
	t.Logf("мест осмотрено %d из %d · глаголов в эталоне %d", judged, len(freshnessSurfaces()), len(freshnessVerbs))
	require.Positive(t, judged, "ни одного описания окна не осмотрено")
	require.Emptyf(t, found, "описание окна свежести уже, чем действует полоса:\n  %s\n"+
		"Перечень глаголов — в таблице отказов docs/content/api/auth-lane.mdx.", strings.Join(found, "\n  "))
}

// TestFreshnessWindowVerbPredicateInjection — узкий текст краснит, полный молчит.
func TestFreshnessWindowVerbPredicateInjection(t *testing.T) {
	good := "заведение и подтверждение второго фактора, заведение первого пароля, запрос смены адреса почты, " +
		"регистрация и снятие ключа доступа, выход из выбранной сессии и из всех прочих"
	require.Empty(t, freshnessVerbFindings("good", good))

	narrow := "заведение и подтверждение второго фактора требуют предъявления не старше окна"
	require.Len(t, freshnessVerbFindings("narrow", narrow), len(freshnessVerbs)-1)

	for _, v := range freshnessVerbs {
		cut := v.re.ReplaceAllString(good, "…")
		require.NotEmptyf(t, freshnessVerbFindings("cut", cut), "глагол «%s» вырезан, находки нет", v.name)
	}

	block, ok := surfaceBlock([]string{"a", "# ОКНО", "# текст", "key: 1", "b"}, freshnessSurface{
		start: regexp.MustCompile(`ОКНО`), end: regexp.MustCompile(`^key:`)})
	require.True(t, ok)
	require.Equal(t, "ОКНО текст key: 1", block)
	require.Equal(t, "смены адреса", flattenBlock([]string{"  # смены", "  # адреса"}))
	require.Equal(t, `"смены адреса"`, flattenBlock([]string{`"смены " +`, `"адреса"`}))
	_, ok = surfaceBlock([]string{"a", "b"}, freshnessSurface{start: regexp.MustCompile(`ОКНО`)})
	require.False(t, ok, "несуществующее начало должно быть находкой, а не молчанием")
}
