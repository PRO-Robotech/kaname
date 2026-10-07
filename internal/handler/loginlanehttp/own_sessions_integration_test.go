// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_sessions_integration_test.go — сценарии OS-01…OS-14 приёмки
// `docs/engineering/acceptance/own-sessions-are-listed-and-ended-by-their-owner.md`
// (задача PRO-Robotech/kaname#634), уровень I: слушатель полосы формы над
// настоящим хранилищем. Каждый сценарий — на своём посеве (§4.0); шаг, двигающий
// часы, — последний либо со своим посевом.
package loginlanehttp_test

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

// TestOS01_ListShowsOwnLiveSessionsCurrentMarkedInIssueOrder — перечень: свои
// живые записи, текущая помечена, порядок выдачи; близнец — тот же запрос
// носителем `S_B`.
func TestOS01_ListShowsOwnLiveSessionsCurrentMarkedInIssueOrder(t *testing.T) {
	h := newAVLane(t)
	sd := h.seedI(t, "os01", true)
	h.requireOwnSessionVerbs(t, "OS-01")

	r := h.listOf(t, sd.a, "")
	require.Equal(t, http.StatusOK, r.status, "OS-01: %s", r.body)
	p := parseOSPage(t, r.body)
	require.Equal(t, []string{sd.aID, sd.bID, sd.cID}, p.ids(t), "OS-01: ровно три записи в порядке выдачи; S₀ (снятая) отсутствует")
	require.Equal(t, "", p.next, "OS-01: страница последняя")
	require.ElementsMatch(t, []string{"sessions", "nextPageToken"}, p.keys, "OS-01: ключи ответа")

	require.True(t, p.byID(t, sd.aID).current(t), "OS-01: S_A — текущая")
	require.False(t, p.byID(t, sd.bID).current(t), "OS-01: S_B — не текущая")
	require.False(t, p.byID(t, sd.cID).current(t), "OS-01: S_C — не текущая")

	require.Equal(t, "os-agent-A", p.byID(t, sd.aID).str(t, "userAgent"))
	require.Equal(t, "os-agent-B", p.byID(t, sd.bID).str(t, "userAgent"))
	_, has := p.byID(t, sd.cID)["userAgent"]
	require.False(t, has, "OS-01: у S_C ключа userAgent нет — клиент не назвался")

	for _, it := range p.items {
		keys := make([]string, 0, len(it))
		for k := range it {
			keys = append(keys, k)
		}
		want := []string{"id", "current", "authenticatedAt", "lastPresentedAt", "expiresAt"}
		if _, ok := it["userAgent"]; ok {
			want = append(want, "userAgent")
		}
		require.ElementsMatch(t, want, keys, "OS-01: набор ключей элемента закрыт")
		authAt, err := time.Parse(time.RFC3339, it.str(t, "authenticatedAt"))
		require.NoError(t, err)
		_, err = time.Parse(time.RFC3339, it.str(t, "lastPresentedAt"))
		require.NoError(t, err)
		expAt, err := time.Parse(time.RFC3339, it.str(t, "expiresAt"))
		require.NoError(t, err)
		for _, k := range []string{"authenticatedAt", "lastPresentedAt", "expiresAt"} {
			require.NotContains(t, it.str(t, k), ".", "OS-01: %s без долей секунды", k)
		}
		require.Equal(t, laneSessionTTL, expAt.Sub(authAt), "OS-01: expiresAt − authenticatedAt = 24 ч")
	}

	// Близнец пометки: тот же запрос носителем S_B.
	r = h.listOf(t, sd.b, "")
	require.Equal(t, http.StatusOK, r.status, "OS-01 близнец: %s", r.body)
	twin := parseOSPage(t, r.body)
	require.Equal(t, []string{sd.aID, sd.bID, sd.cID}, twin.ids(t), "OS-01 близнец: тот же состав и порядок")
	require.False(t, twin.byID(t, sd.aID).current(t))
	require.True(t, twin.byID(t, sd.bID).current(t), "OS-01 близнец: current у S_B и только у неё")
	require.False(t, twin.byID(t, sd.cID).current(t))
}

// TestOS02_ListHasNoForeignSessions — чужих записей в перечне нет.
func TestOS02_ListHasNoForeignSessions(t *testing.T) {
	h := newAVLane(t)
	sd := h.seedI(t, "os02u", true)
	ta, taID := h.seedIV(t, "os02v")
	h.requireOwnSessionVerbs(t, "OS-02")

	r := h.listOf(t, sd.a, "")
	require.Equal(t, http.StatusOK, r.status, "OS-02: %s", r.body)
	require.Equal(t, []string{sd.aID, sd.bID, sd.cID}, parseOSPage(t, r.body).ids(t), "OS-02: T_A среди записей U нет")

	r = h.listOf(t, ta, "")
	require.Equal(t, http.StatusOK, r.status, "OS-02: %s", r.body)
	p := parseOSPage(t, r.body)
	require.Equal(t, []string{taID}, p.ids(t), "OS-02: у V ровно T_A, записей U нет")
	require.True(t, p.byID(t, taID).current(t))
}

// TestOS03_ExpiredSessionIsNotListed — истёкшая запись в перечень не входит;
// близнец — тот же посев без последнего сдвига часов.
func TestOS03_ExpiredSessionIsNotListed(t *testing.T) {
	run := func(t *testing.T, expire bool) (osPage, []string) {
		h := newAVLane(t)
		u := h.registerWithAgent(t, freshAddress("os03"), osRegisterAgent)
		h.mark(t, u)
		old := h.loginWithAgent(t, u, "os-03-old")
		h.clock.Advance(23*time.Hour + 58*time.Minute)
		fresh := h.loginWithAgent(t, u, "os-03-new")
		ids := []string{h.sessionIDOf(t, u), h.sessionIDOf(t, old), h.sessionIDOf(t, fresh)}
		h.requireOwnSessionVerbs(t, "OS-03")
		if expire {
			h.clock.Advance(3 * time.Minute)
		}
		r := h.listOf(t, fresh, "")
		require.Equal(t, http.StatusOK, r.status, "OS-03: %s", r.body)
		return parseOSPage(t, r.body), ids
	}
	p, ids := run(t, true)
	require.Equal(t, []string{ids[2]}, p.ids(t), "OS-03: ровно S_new — S₀ и S_old истекли")
	require.True(t, p.byID(t, ids[2]).current(t))

	twin, tids := run(t, false)
	require.Equal(t, tids, twin.ids(t), "OS-03 близнец: без последнего сдвига — S₀, S_old, S_new")
}

// TestOS04_ClientDescriptionAsSentTruncatedByRunesInvalidBytesReplaced — описание
// клиента: как прислано; длинное урезано по рунам; байты вне UTF-8 заменены;
// отсутствие — отсутствие; перевыпуск носителя поле не трогает.
func TestOS04_ClientDescriptionAsSentTruncatedByRunesInvalidBytesReplaced(t *testing.T) {
	h := newAVLane(t)
	u := h.registerWithAgent(t, freshAddress("os04"), osRegisterAgent)
	h.mark(t, u)
	h.requireOwnSessionVerbs(t, "OS-04")

	agents := []string{
		"Mozilla/5.0 (X11; Linux x86_64) os-04", // (а)
		strings.Repeat("x", 600),                // (б)
		"",                                      // (в)
		"os-04-\xff\xfe-end",                    // (г)
		strings.Repeat("ж", 600),                // (д)
	}
	sessions := make([]avSession, len(agents))
	for i, ua := range agents {
		r := h.loginWithAgentReply(t, u, ua)
		require.Equal(t, http.StatusOK, r.status, "OS-04 (%d): вход выдан — приведение исход не меняет: %s", i, r.body)
		s := u
		s.bearer = cookieNamed(r.cookies, loginlanehttp.CookieSession)
		s.form = cookieNamed(r.cookies, loginlanehttp.CookieForm)
		require.NotNil(t, s.bearer, "OS-04 (%d): сессия выдана", i)
		sessions[i] = s
	}
	ids := make([]string, len(sessions))
	for i, s := range sessions {
		ids[i] = h.sessionIDOf(t, s)
	}
	regID := h.sessionIDOf(t, u)

	r := h.listOf(t, sessions[0], "pageSize=100")
	require.Equal(t, http.StatusOK, r.status, "OS-04: %s", r.body)
	require.True(t, utf8.Valid([]byte(r.body)), "OS-04: тело перечня — допустимый UTF-8")
	p := parseOSPage(t, r.body)

	require.Equal(t, agents[0], p.byID(t, ids[0]).str(t, "userAgent"), "OS-04 (а): дословно")
	require.Equal(t, strings.Repeat("x", 512), p.byID(t, ids[1]).str(t, "userAgent"), "OS-04 (б): 512 знаков")
	_, has := p.byID(t, ids[2])["userAgent"]
	require.False(t, has, "OS-04 (в): пустое значение — ключа нет")
	require.Equal(t, "os-04-��-end", p.byID(t, ids[3]).str(t, "userAgent"), "OS-04 (г): две руны U+FFFD")
	d := p.byID(t, ids[4]).str(t, "userAgent")
	require.Equal(t, strings.Repeat("ж", 512), d, "OS-04 (д): 512 рун")
	require.Len(t, []byte(d), 1024, "OS-04 (д): 1024 байта")
	require.Equal(t, osRegisterAgent, p.byID(t, regID).str(t, "userAgent"), "OS-04: у записи регистрации — заголовок её запроса")

	// Смена пароля из записи (а) перевыпускает носитель; поле прежнее.
	a := sessions[0]
	cr := h.post(t, a, loginlanehttp.PathPassword, map[string]any{
		"currentPassword": integrationPassword, "newPassword": integrationPassword + "-renewed",
		"csrfToken": h.token(a, "password"),
	})
	require.Equal(t, http.StatusOK, cr.status, "OS-04: смена пароля: %s", cr.body)
	a.bearer = cookieNamed(cr.cookies, loginlanehttp.CookieSession)
	require.NotNil(t, a.bearer, "OS-04: смена пароля перевыпускает носитель")
	r = h.listOf(t, a, "")
	require.Equal(t, http.StatusOK, r.status, "OS-04: %s", r.body)
	after := parseOSPage(t, r.body)
	require.Equal(t, []string{ids[0]}, after.ids(t), "OS-04: прочие записи сняты сменой пароля, (а) — та же запись")
	require.True(t, after.byID(t, ids[0]).current(t))
	require.Equal(t, agents[0], after.byID(t, ids[0]).str(t, "userAgent"), "OS-04: перевыпуск поле не трогает")
}

// TestOS05_PaginationAndParameterRefusals — постраничность и отказы параметров.
func TestOS05_PaginationAndParameterRefusals(t *testing.T) {
	h := newAVLane(t)
	sd := h.seedI(t, "os05", true)
	h.requireOwnSessionVerbs(t, "OS-05")

	r := h.listOf(t, sd.a, "pageSize=2")
	require.Equal(t, http.StatusOK, r.status, "OS-05 (а): %s", r.body)
	pa := parseOSPage(t, r.body)
	require.Equal(t, []string{sd.aID, sd.bID}, pa.ids(t), "OS-05 (а)")
	require.NotEmpty(t, pa.next, "OS-05 (а): nextPageToken непуст")

	r = h.listOf(t, sd.a, "pageSize=2&pageToken="+pa.next)
	require.Equal(t, http.StatusOK, r.status, "OS-05 (б): %s", r.body)
	pb := parseOSPage(t, r.body)
	require.Equal(t, []string{sd.cID}, pb.ids(t), "OS-05 (б)")
	require.Equal(t, "", pb.next, "OS-05 (б): страница последняя")

	refusal := func(text string) string {
		return `{"code":3,"message":"` + text + `","details":[]}`
	}
	cases := []struct {
		label, query, body string
	}{
		{"(в)", "pageSize=1001", refusal("Illegal argument pageSize: must be in [0..1000] (0 means default)")},
		{"(г)", "pageSize=two", refusal("Illegal argument pageSize: must be an integer")},
		{"(д)", "pageToken=not-a-cursor", refusal("Illegal argument pageToken: malformed")},
		{"(е)", "filter=x", refusal("Illegal argument filter: unknown field")},
		{"(з)", "pageSize=-1", refusal("Illegal argument pageSize: must be in [0..1000] (0 means default)")},
	}
	for _, c := range cases {
		r := h.listOf(t, sd.a, c.query)
		require.Equal(t, http.StatusBadRequest, r.status, "OS-05 %s: %s", c.label, r.body)
		require.Equal(t, c.body, r.body, "OS-05 %s: тело отказа", c.label)
	}

	r = h.listOf(t, sd.a, "pageSize=0")
	require.Equal(t, http.StatusOK, r.status, "OS-05 (ж): %s", r.body)
	require.Equal(t, []string{sd.aID, sd.bID, sd.cID}, parseOSPage(t, r.body).ids(t), "OS-05 (ж): как без параметров")
}

// TestOS06_NoLiveSessionIsOneRefusal — без живой сессии: единый отказ на всех
// трёх путях.
func TestOS06_NoLiveSessionIsOneRefusal(t *testing.T) {
	h := newAVLane(t)
	sd := h.seedI(t, "os06", true)
	h.requireOwnSessionVerbs(t, "OS-06")

	noBearer := avSession{form: sd.a.form}
	bodies := []reply{
		h.listOf(t, noBearer, ""),
		h.listOf(t, sd.s0, ""),
		h.endOthers(t, sd.s0),
		h.endOne(t, sd.s0, sd.bID),
	}
	for i, r := range bodies {
		require.Equal(t, http.StatusUnauthorized, r.status, "OS-06 (%c): %s", 'а'+rune(i), r.body)
		require.Equal(t, osBodyAuthFailed, r.body, "OS-06 (%c): тело", 'а'+rune(i))
	}
	for _, s := range []avSession{sd.a, sd.b, sd.c} {
		require.True(t, h.resolveFound(t, s), "OS-06: S_A, S_B, S_C живы")
	}
}

// TestOS07_VerificationPositionRefusesAllThreePaths — положение подтверждения:
// отказ положения на всех трёх путях.
func TestOS07_VerificationPositionRefusesAllThreePaths(t *testing.T) {
	h := newAVLane(t)
	sd := h.seedI(t, "os07", false)
	h.requireOwnSessionVerbs(t, "OS-07")

	for i, r := range []reply{
		h.listOf(t, sd.a, ""),
		h.endOne(t, sd.a, sd.bID),
		h.endOthers(t, sd.a),
	} {
		require.Equal(t, http.StatusForbidden, r.status, "OS-07 (%d): %s", i, r.body)
		require.Equal(t, avRefusalBody, r.body, "OS-07 (%d): значение F6b Р3 дословно", i)
		require.Empty(t, r.cookies, "OS-07 (%d): без Set-Cookie", i)
	}
	require.True(t, h.resolveFound(t, sd.b), "OS-07: S_B жива")
	require.True(t, h.resolveFound(t, sd.c), "OS-07: S_C жива")
}

// TestOS08_EndSelectedEndsItAloneWithoutCutoffWithEvent — выход из выбранной:
// снята она одна, без отсечки, с событием.
func TestOS08_EndSelectedEndsItAloneWithoutCutoffWithEvent(t *testing.T) {
	h := newAVLane(t)
	sd := h.seedI(t, "os08", true)
	h.requireOwnSessionVerbs(t, "OS-08")
	h.clock.Advance(time.Minute)
	cutoffBefore := h.cutoffOf(t, sd.u.user)

	r := h.endOne(t, sd.a, sd.bID)
	require.Equal(t, http.StatusOK, r.status, "OS-08: %s", r.body)
	require.JSONEq(t, `{"ended":true}`, r.body, "OS-08: тело")
	require.Empty(t, r.cookies, "OS-08: Set-Cookie нет")

	require.False(t, h.resolveFound(t, sd.b), "OS-08: S_B снята")
	require.True(t, h.resolveFound(t, sd.a), "OS-08: S_A жива")
	require.True(t, h.resolveFound(t, sd.c), "OS-08: S_C жива")
	require.Equal(t, osEndReason, h.endReasonByID(t, sd.bID), "OS-08: причина снятия")

	cutoffAfter := h.cutoffOf(t, sd.u.user)
	require.Equal(t, cutoffBefore.GetFound(), cutoffAfter.GetFound(), "OS-08: отсечки глагол не пишет")
	require.True(t, cutoffBefore.GetRevokeBefore().AsTime().Equal(cutoffAfter.GetRevokeBefore().AsTime()),
		"OS-08: отсечка та же, что до запроса")

	evs := h.endedEvents(t, sd.u.user)
	require.Len(t, evs, 1, "OS-08: ровно одно событие")
	require.Equal(t, string(sd.u.user), toString(evs[0]["user_id"]))
	require.Equal(t, sd.aID, toString(evs[0]["session_id"]), "OS-08: session_id — запись носителя")
	require.Equal(t, []string{sd.bID}, endedIDs(t, evs[0]))
	require.ElementsMatch(t, []string{"user_id", "session_id", "ended_session_ids"}, mapKeys(evs[0]),
		"OS-08: ни адреса, ни имени, ни описания клиента")

	r = h.listOf(t, sd.a, "")
	require.Equal(t, http.StatusOK, r.status, r.body)
	require.Equal(t, []string{sd.aID, sd.cID}, parseOSPage(t, r.body).ids(t), "OS-08: перечень — S_A, S_C")
}

// TestOS09_ForeignUnknownEndedExpiredAreOneRefusalByteForByte — чужая,
// неизвестная, снятая, истёкшая запись: один отказ, побайтово.
func TestOS09_ForeignUnknownEndedExpiredAreOneRefusalByteForByte(t *testing.T) {
	h := newAVLane(t)
	sd := h.seedI(t, "os09u", true)
	ta, taID := h.seedIV(t, "os09v")
	h.requireOwnSessionVerbs(t, "OS-09")

	bodies := []reply{
		h.endOne(t, sd.a, taID),                    // (а) живая запись V
		h.endOne(t, sd.a, "hss-0000000000000000z"), // (б) годная форма, записи нет
		h.endOne(t, sd.a, sd.s0ID),                 // (в) своя снятая
		h.endOne(t, ta, sd.bID),                    // (г) живая запись U из сессии V
	}
	require.True(t, h.resolveFound(t, ta), "OS-09: T_A жива")
	require.True(t, h.resolveFound(t, sd.b), "OS-09: S_B жива")
	// (д) своя истёкшая — свой посев на тех же часах: S_x в t, затем 24 ч + 1 с.
	x := h.registerWithAgent(t, freshAddress("os09x"), osRegisterAgent)
	h.mark(t, x)
	sx := h.loginWithAgent(t, x, "os-09-x")
	sxID := h.sessionIDOf(t, sx)
	h.clock.Advance(laneSessionTTL + time.Second)
	sy := h.loginWithAgent(t, x, "os-09-y")
	bodies = append(bodies, h.endOne(t, sy, sxID))

	for i, r := range bodies {
		require.Equal(t, http.StatusNotFound, r.status, "OS-09 (%c): %s", 'а'+rune(i), r.body)
		require.Equal(t, osBodyNotFound, r.body, "OS-09 (%c): тело побайтово", 'а'+rune(i))
	}
	// После сдвига часов живость записей посева I судит строка: отметки снятия
	// у T_A и S_B нет.
	require.Equal(t, "", h.endReasonByID(t, taID), "OS-09: T_A не снята")
	require.Equal(t, "", h.endReasonByID(t, sd.bID), "OS-09: S_B не снята")
	require.Empty(t, h.endedEvents(t, sd.u.user), "OS-09: событий нет (U)")
	require.Empty(t, h.endedEvents(t, ta.user), "OS-09: событий нет (V)")
	require.Empty(t, h.endedEvents(t, x.user), "OS-09: событий нет (X)")
}

// TestOS10_CurrentSessionIsNotEndedByThisVerb — текущую запись этот глагол не
// снимает; близнец — OS-08.
func TestOS10_CurrentSessionIsNotEndedByThisVerb(t *testing.T) {
	h := newAVLane(t)
	sd := h.seedI(t, "os10", true)
	h.requireOwnSessionVerbs(t, "OS-10")
	h.clock.Advance(time.Minute)

	r := h.endOne(t, sd.a, sd.aID)
	require.Equal(t, http.StatusBadRequest, r.status, "OS-10: %s", r.body)
	require.Equal(t, osBodyIsCurrent, r.body, "OS-10: тело")
	require.True(t, h.resolveFound(t, sd.a), "OS-10: S_A жива")
	require.Empty(t, h.endedEvents(t, sd.u.user), "OS-10: событий нет")
}

// TestOS11_FormFieldsNamedForeignKindRejected — форма: поле названо, признак
// чужого вида отвергнут.
func TestOS11_FormFieldsNamedForeignKindRejected(t *testing.T) {
	h := newAVLane(t)
	sd := h.seedI(t, "os11", true)
	h.requireOwnSessionVerbs(t, "OS-11")
	tok := h.endToken(t, sd.a)
	ref := func(text string) string { return `{"code":3,"message":"` + text + `","details":[]}` }
	cases := []struct {
		label, path string
		body        map[string]any
		status      int
		want        string
	}{
		{"(а)", osPathEnd, map[string]any{"sessionId": sd.bID}, 400, ref("Illegal argument csrfToken: required")},
		{"(б)", osPathEnd, map[string]any{"sessionId": sd.bID, "csrfToken": h.token(sd.a, "logout")}, 403,
			`{"code":7,"message":"form token rejected","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"FORM_TOKEN_REJECTED","domain":"iam.kaname.cloud"}]}`},
		{"(в)", osPathEnd, map[string]any{"sessionId": sd.bID, "csrfToken": tok, "all": true}, 400, ref("Illegal argument all: unknown field")},
		{"(г)", osPathEnd, map[string]any{"csrfToken": tok}, 400, ref("Illegal argument sessionId: required")},
		{"(д)", osPathEnd, map[string]any{"sessionId": "hss-123", "csrfToken": tok}, 400,
			ref("Illegal argument sessionId: must match ^hss-[crockford-base32]{17}$")},
		{"(е)", osPathEndOthers, map[string]any{"csrfToken": tok, "sessionId": sd.bID}, 400, ref("Illegal argument sessionId: unknown field")},
		{"(ж)", osPathEndOthers, map[string]any{}, 400, ref("Illegal argument csrfToken: required")},
	}
	for _, c := range cases {
		r := h.post(t, sd.a, c.path, c.body)
		require.Equal(t, c.status, r.status, "OS-11 %s: %s", c.label, r.body)
		require.Equal(t, c.want, r.body, "OS-11 %s: тело", c.label)
	}
	require.True(t, h.resolveFound(t, sd.b), "OS-11: S_B жива")
	require.True(t, h.resolveFound(t, sd.c), "OS-11: S_C жива")
	require.Empty(t, h.endedEvents(t, sd.u.user))
}

// TestOS12_EndAllButCurrent — выход из всех, кроме текущей; (б) — прочих живых
// нет.
func TestOS12_EndAllButCurrent(t *testing.T) {
	h := newAVLane(t)
	sd := h.seedI(t, "os12u", true)
	ta, _ := h.seedIV(t, "os12v")
	h.requireOwnSessionVerbs(t, "OS-12")
	h.clock.Advance(time.Minute)

	r := h.endOthers(t, sd.a)
	require.Equal(t, http.StatusOK, r.status, "OS-12: %s", r.body)
	require.JSONEq(t, `{"ended":2}`, r.body)
	require.Empty(t, r.cookies, "OS-12: без Set-Cookie")
	require.True(t, h.resolveFound(t, sd.a), "OS-12: S_A жива")
	require.False(t, h.resolveFound(t, sd.b), "OS-12: S_B снята")
	require.False(t, h.resolveFound(t, sd.c), "OS-12: S_C снята")
	require.True(t, h.resolveFound(t, ta), "OS-12: T_A (человек V) жива")
	require.Equal(t, osEndReason, h.endReasonByID(t, sd.bID))
	require.Equal(t, osEndReason, h.endReasonByID(t, sd.cID))
	require.Equal(t, "logout", h.endReasonByID(t, sd.s0ID), "OS-12: у S₀ причина прежняя")

	evs := h.endedEvents(t, sd.u.user)
	require.Len(t, evs, 1, "OS-12: одно событие")
	require.Equal(t, sd.aID, toString(evs[0]["session_id"]))
	require.Equal(t, sortedCopy([]string{sd.bID, sd.cID}), endedIDs(t, evs[0]), "OS-12: набор снятых")

	d := h.loginWithAgent(t, sd.u, "os-12-d")
	dID := h.sessionIDOf(t, d)
	require.True(t, h.resolveFound(t, d), "OS-12: запись после снятия жива")
	r = h.listOf(t, sd.a, "")
	require.Equal(t, http.StatusOK, r.status, r.body)
	require.Equal(t, []string{sd.aID, dID}, parseOSPage(t, r.body).ids(t), "OS-12: перечень — S_A, S_D")

	// (б) Прочих живых нет.
	one := h.registerWithAgent(t, freshAddress("os12b"), osRegisterAgent)
	h.mark(t, one)
	s1 := h.loginWithAgent(t, one, "os-12-1")
	h.logoutOf(t, one)
	r = h.endOthers(t, s1)
	require.Equal(t, http.StatusOK, r.status, "OS-12 (б): %s", r.body)
	require.JSONEq(t, `{"ended":0}`, r.body)
	require.Empty(t, h.endedEvents(t, one.user), "OS-12 (б): события нет")
	require.True(t, h.resolveFound(t, s1), "OS-12 (б): S_1 жива")
}

// TestOS13_FreshnessRequiredForEndingNotForListingBoundaryIncluded — свежесть:
// снятие требует, перечень — нет; граница включена; повышение освежает.
func TestOS13_FreshnessRequiredForEndingNotForListingBoundaryIncluded(t *testing.T) {
	t.Run("(а) W+1с — оба снятия отказ, перечень проходит", func(t *testing.T) {
		h := newAVLane(t)
		sd := h.seedI(t, "os13a", true)
		h.requireOwnSessionVerbs(t, "OS-13")
		h.clock.Advance(laneFreshness + time.Second)
		for i, r := range []reply{h.endOne(t, sd.a, sd.bID), h.endOthers(t, sd.a)} {
			require.Equal(t, http.StatusForbidden, r.status, "OS-13 (а)(%d): %s", i, r.body)
			require.Equal(t, osBodyNotFresh, r.body, "OS-13 (а)(%d): тело", i)
		}
		require.True(t, h.resolveFound(t, sd.b), "OS-13 (а): ничего не снято")
		require.True(t, h.resolveFound(t, sd.c), "OS-13 (а): ничего не снято")
		r := h.listOf(t, sd.a, "")
		require.Equal(t, http.StatusOK, r.status, "OS-13 (а): перечень свежести не требует: %s", r.body)
		require.Len(t, parseOSPage(t, r.body).items, 3)
	})
	t.Run("(б) ровно W — снятие проходит", func(t *testing.T) {
		h := newAVLane(t)
		sd := h.seedI(t, "os13b", true)
		h.requireOwnSessionVerbs(t, "OS-13")
		h.clock.Advance(laneFreshness)
		r := h.endOne(t, sd.a, sd.bID)
		require.Equal(t, http.StatusOK, r.status, "OS-13 (б): %s", r.body)
		require.JSONEq(t, `{"ended":true}`, r.body)
	})
	t.Run("(в) повышение освежает", func(t *testing.T) {
		h := newAVLane(t)
		sd := h.seedI(t, "os13c", true)
		h.requireOwnSessionVerbs(t, "OS-13")
		h.clock.Advance(laneFreshness + time.Second)
		su := h.post(t, sd.a, loginlanehttp.PathStepUp, map[string]any{
			"method": "password", "password": integrationPassword, "csrfToken": h.token(sd.a, "step-up"),
		})
		require.Equal(t, http.StatusOK, su.status, "OS-13 (в): повышение: %s", su.body)
		a2 := sd.a
		a2.bearer = cookieNamed(su.cookies, loginlanehttp.CookieSession)
		require.NotNil(t, a2.bearer, "OS-13 (в): повышение перевыпускает носитель")
		r := h.endOne(t, a2, sd.bID)
		require.Equal(t, http.StatusOK, r.status, "OS-13 (в): %s", r.body)
		require.JSONEq(t, `{"ended":true}`, r.body)
	})
}

// TestOS14_RacesOneRecordOneEndCrossEndOthersLeavesExactlyOne — гонки: одна
// запись — одно снятие; встречные «все, кроме текущей» — жива ровно одна. Каждая
// буква — 20 повторов на свежем посеве.
func TestOS14_RacesOneRecordOneEndCrossEndOthersLeavesExactlyOne(t *testing.T) {
	const repeats = 20
	h := newAVLane(t)
	probe := h.seedI(t, "os14p", true)
	_ = probe
	h.requireOwnSessionVerbs(t, "OS-14")

	race := func(f1, f2 func() reply) (reply, reply) {
		var (
			wg     sync.WaitGroup
			r1, r2 reply
			start  = make(chan struct{})
		)
		wg.Add(2)
		go func() { defer wg.Done(); <-start; r1 = f1() }()
		go func() { defer wg.Done(); <-start; r2 = f2() }()
		close(start)
		wg.Wait()
		return r1, r2
	}

	t.Run("(а) одна запись — одно снятие", func(t *testing.T) {
		for i := 0; i < repeats; i++ {
			sd := h.seedI(t, "os14a", true)
			h.clock.Advance(time.Second)
			ta, tb := h.endToken(t, sd.a), h.endToken(t, sd.b)
			r1, r2 := race(
				func() reply { return h.post(t, sd.a, osPathEnd, map[string]any{"sessionId": sd.cID, "csrfToken": ta}) },
				func() reply { return h.post(t, sd.b, osPathEnd, map[string]any{"sessionId": sd.cID, "csrfToken": tb}) },
			)
			got := []int{r1.status, r2.status}
			require.ElementsMatch(t, []int{http.StatusOK, http.StatusNotFound}, got, "OS-14 (а) повтор %d: %s | %s", i, r1.body, r2.body)
			for _, r := range []reply{r1, r2} {
				if r.status == http.StatusOK {
					require.JSONEq(t, `{"ended":true}`, r.body)
				} else {
					require.Equal(t, osBodyNotFound, r.body)
				}
			}
			require.Len(t, h.endedEvents(t, sd.u.user), 1, "OS-14 (а) повтор %d: событие одно", i)
		}
	})
	t.Run("(б) встречные end-others — жива ровно одна", func(t *testing.T) {
		for i := 0; i < repeats; i++ {
			sd := h.seedI(t, "os14b", true)
			h.clock.Advance(time.Second)
			ta, tb := h.endToken(t, sd.a), h.endToken(t, sd.b)
			r1, r2 := race(
				func() reply { return h.post(t, sd.a, osPathEndOthers, map[string]any{"csrfToken": ta}) },
				func() reply { return h.post(t, sd.b, osPathEndOthers, map[string]any{"csrfToken": tb}) },
			)
			aLive, bLive := h.resolveFound(t, sd.a), h.resolveFound(t, sd.b)
			require.NotEqual(t, aLive, bLive, "OS-14 (б) повтор %d: жива ровно одна из S_A, S_B (A=%v B=%v): %s | %s",
				i, aLive, bLive, r1.body, r2.body)
			winner, loser := r1, r2
			if bLive {
				winner, loser = r2, r1
			}
			require.Equal(t, http.StatusOK, winner.status, "OS-14 (б) повтор %d: %s", i, winner.body)
			require.JSONEq(t, `{"ended":2}`, winner.body, "OS-14 (б) повтор %d: сняты другая действующая и S_C", i)
			require.Equal(t, http.StatusUnauthorized, loser.status, "OS-14 (б) повтор %d: %s", i, loser.body)
			require.Equal(t, osBodyAuthFailed, loser.body)
			require.False(t, h.resolveFound(t, sd.c), "OS-14 (б) повтор %d: S_C снята", i)
			require.Len(t, h.endedEvents(t, sd.u.user), 1, "OS-14 (б) повтор %d: событие одно — проигравший не снял ничего", i)
		}
	})
}

func mapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
