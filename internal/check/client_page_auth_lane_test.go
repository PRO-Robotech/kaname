// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// Клиентская страница полосы входа обязана СХОДИТЬСЯ со слушателем: перечень
// путей — с `loginlanehttp.Paths()`, тексты отказов и токены причин — с
// константами полосы, имена печений — с объявлением слушателя, ключи тел
// примеров — с производителями тел (задачи kaname#204, kaname#225, kaname#247).
//
// # ПОЧЕМУ ГЕЙТ, А НЕ «ДОПИСАТЬ СТРАНИЦУ»
//
// Перечень путей уже пережил свой предмет однажды: комментарий чарта называл
// четыре глагола, слушатель обслуживал тринадцать, а страницы у полосы не было
// вовсе. Страница, выписанная руками, разойдётся снова со следующей фазой —
// и разойдётся молча, потому что путь, которого на ней нет, красным не станет.
//
// # ЧТО СУДИТСЯ — В ОБЕ СТОРОНЫ
//
//   - каждый путь слушателя назван на странице (в код-форматировании);
//   - каждый путь семейства `/iam/v1/auth/…`, названный на странице, обслуживается
//     слушателем — кроме маршрутов КРАЯ, которые страница обязана называть, чтобы
//     отделить их от полосы (они подаются ядру явным перечнем);
//   - каждый текст отказа и токен причины, которые полоса производит, стоят на
//     странице дословно — клиент ключуется на них;
//   - оба имени печений названы;
//   - ключи объектов `user`, `session`, `assurance` в примерах тел ответа полосы
//     равны ключам, которые печатают производители тел
//     (`loginlanehttp.ResponseObjectKeys`), — в обе стороны для блока json и в
//     одну (лишнего нет) для строчного объекта с многоточием (kaname#247: пример
//     пережил снятое поле `passwordChangeRequired`, гейт ключей не судил).
//
// # ГРАНИЦА
//
// Гейт судит СОСТАВ и ДОСЛОВНОСТЬ, а не верность прозы вокруг: описать глагол
// неверно он не помешает. Тот же предел, что у гейта таблицы портов.
const authLanePageRel = "docs/content/api/auth-lane.mdx"

// reCodeSpan — код-форматирование страницы: обратные кавычки либо <code>.
var reCodeSpan = regexp.MustCompile("`([^`]+)`|<code>([^<]+)</code>")

// reLanePath — путь семейства полосы внутри код-форматирования. Знаки пути —
// латиница, цифры, `/`, `-`, `_`; `?`, `…` и пробел путь заканчивают.
var reLanePath = regexp.MustCompile(`/iam/v1/auth(?:/[A-Za-z0-9_-]+)*/?`)

// authLaneCensus — объём осмотренного. Печатается всегда.
type authLaneCensus struct {
	pathsDeclared   int // путей у слушателя
	pathsNamed      int // из них названо страницей
	pathsForeign    int // путей семейства на странице, которых слушатель не обслуживает
	spansRead       int // код-спанов прочитано
	textsDeclared   int // текстов отказа и токенов причин, которые полоса производит
	textsNamed      int // из них названо дословно
	cookiesDeclared int
	cookiesNamed    int
	bodyBlocks      int // примеров тела в формате json прочитано
	bodyResponses   int // из них — ответы полосы (несут `session` верхним ключом)
	bodyObjects     int // объектов тела, сверенных с производителем в обе стороны
	bodyInline      int // объектов тела в строчном коде, сверенных в одну сторону
}

// authLaneContract — то, что производит полоса и что страница обязана нести.
type authLaneContract struct {
	Paths      []string
	EdgeRoutes []string // маршруты края, которые страница вправе называть в семействе
	Texts      []string // тексты отказов и токены причин
	Cookies    []string
	// BodyKeys — ключи объектов тела ответа полосы по имени объекта
	// (`user`, `session`, `assurance`), снятые с производителей тел.
	BodyKeys map[string][]string
}

// liveAuthLaneContract — контракт, снятый с самого слушателя, а не выписанный.
func liveAuthLaneContract() authLaneContract {
	return authLaneContract{
		Paths: loginlanehttp.Paths(),
		// «Кто я» — маршрут края того же семейства; страница называет его,
		// чтобы отделить от полосы, и это законно.
		EdgeRoutes: []string{"/iam/v1/auth/me"},
		Texts: []string{
			humansession.TextAuthenticationFailed,
			humansession.TextLoginWithSecondFactorFailed,
			humansession.TextAccessNotRestored,
			humansession.TextRecoveryNextStep,
			humansession.TextTooManyAttempts,
			humansession.TextFormTokenRejected,
			humansession.TextLogoutNotPerformed,
			humansession.TextRequestNotPerformed,
			humansession.TextSecondFactorNotEnrolled,
			humansession.TextSecondFactorAlreadyEnrolled,
			humansession.TextEnrollmentNotPending,
			humansession.TextSessionNotFresh,
			humansession.TextSecondFactorUnavailable,
			registration.TextRegistrationRefused,
			loginlanehttp.TextPermissionDenied,
			humansession.ReasonFormTokenRejected,
			humansession.ReasonTooManyAttempts,
			humansession.ReasonSecondFactorNotEnrolled,
			humansession.ReasonSecondFactorAlreadyEnrolled,
			humansession.ReasonEnrollmentNotPending,
			humansession.ReasonSessionNotFresh,
			registration.ReasonRegistrationRefused,
			// Подтверждение адреса и положение подтверждения (kaname#456).
			humansession.TextEmailNotVerified,
			humansession.TextEmailAlreadyVerified,
			humansession.TextInviteNotValid,
			humansession.ReasonEmailNotVerified,
			humansession.ReasonEmailAlreadyVerified,
			humansession.ReasonInviteNotValid,
			// Смена адреса почты (kaname#635).
			humansession.TextEmailInUse,
			humansession.ReasonEmailInUse,
			// Свои сессии (kaname#634).
			humansession.TextSessionNotFound,
			humansession.TextSessionIsCurrent,
			humansession.ReasonSessionNotFound,
			humansession.ReasonSessionIsCurrent,
		},
		Cookies:  []string{loginlanehttp.CookieSession, loginlanehttp.CookieForm},
		BodyKeys: loginlanehttp.ResponseObjectKeys(),
	}
}

// reJSONBlock — пример тела: `<CodeBlock language="json">` с текстом в dedent.
// Других форм блока json на страницах сайта нет — перепись блоков печатается, и
// пример, записанный иной формой, уменьшил бы её, а не исчез молча.
var reJSONBlock = regexp.MustCompile("(?s)<CodeBlock language=\"json\">\\s*\\{dedent`(.*?)`\\}\\s*</CodeBlock>")

// reInlineObject — объект тела в строчном коде: `"имя": { … }` без вложенных скобок.
var reInlineObject = regexp.MustCompile(`"([A-Za-z]+)"\s*:\s*\{([^{}]*)\}`)

// reInlineKey — ключ внутри объекта строчного кода.
var reInlineKey = regexp.MustCompile(`"([A-Za-z0-9_]+)"\s*:`)

// laneResponseMarker — верхний ключ, по которому пример тела ОПОЗНАЁТСЯ ответом
// полосы: его несёт каждый ответ, кладущий сессию. Объект той же буквы в чужом
// теле (сущность `user` испытания церемонии) судом не является.
const laneResponseMarker = "session"

// auditLaneBodies — ключи тел примеров против производителей тел, в обе стороны.
func auditLaneBodies(page string, keys map[string][]string, census *authLaneCensus) []string {
	if len(keys) == 0 {
		return nil
	}
	var findings []string
	names := sortedKeys(func() map[string]bool {
		m := map[string]bool{}
		for k := range keys {
			m[k] = true
		}
		return m
	}())
	for _, m := range reJSONBlock.FindAllStringSubmatch(page, -1) {
		census.bodyBlocks++
		var body map[string]any
		if err := json.Unmarshal([]byte(m[1]), &body); err != nil {
			if strings.Contains(m[1], `"`+laneResponseMarker+`"`) {
				findings = append(findings, fmt.Sprintf(
					"пример тела ответа полосы на странице %s не разбирается как JSON (%v) — его "+
						"ключи вне суда; пример обязан быть телом, которое клиент получает",
					authLanePageRel, err))
			}
			continue
		}
		if _, ok := body[laneResponseMarker]; !ok {
			continue
		}
		census.bodyResponses++
		for _, name := range names {
			obj, ok := body[name].(map[string]any)
			if !ok {
				continue
			}
			census.bodyObjects++
			findings = append(findings, compareBodyKeys(name, mapKeys(obj), keys[name], true)...)
		}
	}
	// Строчный код читается со страницы БЕЗ блоков: текст dedent стоит в обратных
	// кавычках, и блок иначе судился бы второй раз — одной стороной.
	for _, span := range codeSpans(reJSONBlock.ReplaceAllString(page, "")) {
		for _, m := range reInlineObject.FindAllStringSubmatch(span, -1) {
			want, judged := keys[m[1]]
			if !judged {
				continue
			}
			census.bodyInline++
			var got []string
			for _, k := range reInlineKey.FindAllStringSubmatch(m[2], -1) {
				got = append(got, k[1])
			}
			// Строчный объект показывает часть ключей (`{…, "emailVerified": true}`):
			// судится одна сторона — лишнего ключа нет.
			findings = append(findings, compareBodyKeys(m[1], got, want, false)...)
		}
	}
	return findings
}

// compareBodyKeys — находки по одному объекту; both — судить и недостающие.
func compareBodyKeys(name string, got, want []string, both bool) []string {
	produced := map[string]bool{}
	for _, k := range want {
		produced[k] = true
	}
	shown := map[string]bool{}
	var findings []string
	for _, k := range got {
		shown[k] = true
		if !produced[k] {
			findings = append(findings, fmt.Sprintf(
				"пример тела на странице %s показывает в объекте %q ключ %q, которого полоса не "+
					"печатает — клиент напишет обработку поля, которое не приходит никогда",
				authLanePageRel, name, k))
		}
	}
	if both {
		for _, k := range want {
			if !shown[k] {
				findings = append(findings, fmt.Sprintf(
					"пример тела на странице %s не показывает в объекте %q ключ %q, который полоса "+
						"печатает — пример полного объекта обязан нести все его ключи",
					authLanePageRel, name, k))
			}
		}
	}
	return findings
}

func mapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// codeSpans — содержимое код-форматирования страницы в порядке появления.
func codeSpans(page string) []string {
	var out []string
	for _, m := range reCodeSpan.FindAllStringSubmatch(page, -1) {
		if m[1] != "" {
			out = append(out, m[1])
		} else {
			out = append(out, m[2])
		}
	}
	return out
}

// auditAuthLanePage — чистое ядро: решает по тексту страницы и контракту.
func auditAuthLanePage(page string, c authLaneContract) ([]string, authLaneCensus) {
	spans := codeSpans(page)
	census := authLaneCensus{
		pathsDeclared: len(c.Paths), spansRead: len(spans),
		textsDeclared: len(c.Texts), cookiesDeclared: len(c.Cookies),
	}
	served := map[string]bool{}
	for _, p := range c.Paths {
		served[p] = true
	}
	edge := map[string]bool{}
	for _, p := range c.EdgeRoutes {
		edge[p] = true
	}

	namedPaths := map[string]bool{}
	foreign := map[string]bool{}
	spanText := strings.Join(spans, "\n")
	for _, s := range spans {
		for _, p := range reLanePath.FindAllString(s, -1) {
			if strings.HasSuffix(p, "/") {
				// «/iam/v1/auth/…» — приставка семейства в прозе, не путь.
				continue
			}
			switch {
			case served[p]:
				namedPaths[p] = true
			case edge[p]:
			default:
				foreign[p] = true
			}
		}
	}

	var findings []string
	for _, p := range c.Paths {
		if namedPaths[p] {
			census.pathsNamed++
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"путь %s обслуживается слушателем полосы, а страница %s его НЕ называет — "+
				"клиент собирает форму по странице, и глагол для него не существует", p, authLanePageRel))
	}
	for _, p := range sortedKeys(foreign) {
		census.pathsForeign++
		findings = append(findings, fmt.Sprintf(
			"страница называет путь %s, а слушатель полосы его не обслуживает — "+
				"утверждение пережило свой предмет либо путь выдуман", p))
	}
	for _, text := range c.Texts {
		if strings.Contains(spanText, text) {
			census.textsNamed++
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"текст отказа или токен причины %q полоса производит, а страница его не несёт "+
				"дословно — клиент ключуется на него и не найдёт", text))
	}
	for _, cookie := range c.Cookies {
		if strings.Contains(spanText, cookie) {
			census.cookiesNamed++
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"печенье %s слушатель ставит, а страница его не называет", cookie))
	}
	findings = append(findings, auditLaneBodies(page, c.BodyKeys, &census)...)
	sort.Strings(findings)
	return findings, census
}

// TestAuthLanePageMatchesTheListener — несущее утверждение.
func TestAuthLanePageMatchesTheListener(t *testing.T) {
	page, err := os.ReadFile(platformtree.RequirePath(t, authLanePageRel)) // #nosec G304 -- путь собран из корня собственного модуля
	require.NoError(t, err)

	c := liveAuthLaneContract()
	findings, census := auditAuthLanePage(string(page), c)

	t.Logf("перепись: путей у слушателя %d · названо страницей %d · чужих путей на странице %d · "+
		"код-спанов прочитано %d · текстов и токенов %d · названо дословно %d · печений %d · названо %d · находок %d",
		census.pathsDeclared, census.pathsNamed, census.pathsForeign, census.spansRead,
		census.textsDeclared, census.textsNamed, census.cookiesDeclared, census.cookiesNamed, len(findings))
	t.Logf("перепись тел: блоков json %d · ответов полосы %d · объектов сверено в обе стороны %d · "+
		"строчных объектов сверено в одну сторону %d",
		census.bodyBlocks, census.bodyResponses, census.bodyObjects, census.bodyInline)

	require.NotZerof(t, census.pathsDeclared, "слушатель не объявил ни одного пути — вердикт беспредметен")
	require.NotZerof(t, census.bodyObjects,
		"ни один объект тела ответа полосы не сверен с производителем — суд ключей примеров беспредметен "+
			"(производителей объявлено %d)", len(c.BodyKeys))
	require.NotZerof(t, census.spansRead, "на странице %s не прочитано ни одного код-спана — вердикт беспредметен", authLanePageRel)
	require.Emptyf(t, findings, "страница %s разошлась со слушателем полосы:\n%s",
		authLanePageRel, strings.Join(findings, "\n"))
}
