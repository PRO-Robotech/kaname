// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_authorize_integration_test.go — группа A приёмки LINE-A-1: эндпоинт
// авторизации (выдача кода): 02, 03, 04, 05, 06, 07, 08, 09, 29, 30 и заказы
// разбора классов к ним (хвостовой слэш, цель с собственной строкой запроса,
// состав строки запроса отказа, побайтовое равенство отказов 04 и 05, `state`
// длиннее пола, некэшируемость ответа с кодом).
//
// Мир, ступени пробы и слова исхода — `ceremony_world_integration_test.go`.
package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// targetBase — цель без собственной строки запроса.
func targetBase(u *url.URL) string { return u.Scheme + "://" + u.Host + u.Path }

// requireRedirectOnlyError — перенаправляемый отказ: 302 на зарегистрированную
// цель, в строке запроса — её собственные параметры и ровно `error` (Р13 п. 3,
// паритет 06/07/29; заказ LAX-16 — состав, а не «содержит»).
func requireRedirectOnlyError(t *testing.T, id, what string, rec *httptest.ResponseRecorder, target, wantErr string) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("%s: %s: ожидалось 302 на цель с error=%s, получено %d; тело %q", id, what, wantErr, rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("%s: %s: Location неразбираем: %v", id, what, err)
	}
	want, _ := url.Parse(target)
	if targetBase(loc) != targetBase(want) {
		t.Fatalf("%s: %s: перенаправление на %q, ожидалась зарегистрированная цель %q", id, what, targetBase(loc), targetBase(want))
	}
	expect := want.Query()
	expect.Set("error", wantErr)
	if got := loc.Query(); !reflect.DeepEqual(got, expect) {
		t.Errorf("%s: %s: строка запроса перенаправления %v, ожидалась ровно %v (ни code, ни state, ни описания отказа)", id, what, got, expect)
	}
}

// requireCodeDelivered — 302 на цель с кодом и дословным `state`; собственная
// строка запроса цели сохранена.
func requireCodeDelivered(t *testing.T, id, what string, rec *httptest.ResponseRecorder, target, state string) string {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("%s: %s: ожидалось 302 с кодом, получено %d; тело %q", id, what, rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("%s: %s: Location неразбираем: %v", id, what, err)
	}
	want, _ := url.Parse(target)
	if targetBase(loc) != targetBase(want) {
		t.Fatalf("%s: %s: перенаправление на %q, ожидалась цель %q", id, what, targetBase(loc), targetBase(want))
	}
	q := loc.Query()
	if q.Get("code") == "" {
		t.Fatalf("%s: %s: кода в перенаправлении нет: %q", id, what, loc.String())
	}
	if q.Has("error") {
		t.Errorf("%s: %s: успешная выдача несёт error=%q", id, what, q.Get("error"))
	}
	if got := q.Get("state"); got != state {
		t.Errorf("%s: %s: state вернулся %q, ожидался дословно %q", id, what, got, state)
	}
	for k, v := range want.Query() {
		if !reflect.DeepEqual(q[k], v) {
			t.Errorf("%s: %s: собственный параметр цели %s=%v не сохранён (получено %v)", id, what, k, v, q[k])
		}
	}
	requireNoStore(t, id, what, rec)
	return q.Get("code")
}

// requireNoCodeDelivered — ни 302 на цель клиента, ни кода нигде в ответе.
func requireNoCodeDelivered(t *testing.T, id, what string, rec *httptest.ResponseRecorder, targets ...string) {
	t.Helper()
	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "code=") || strings.Contains(rec.Body.String(), "code=") {
		t.Errorf("%s: %s: код доставлен (Location %q)", id, what, loc)
	}
	for _, target := range targets {
		if rec.Code == http.StatusFound && strings.HasPrefix(loc, target) {
			t.Errorf("%s: %s: перенаправление на цель клиента %q", id, what, loc)
		}
	}
}

// TestLINEA1_02_AuthorizeIssuesCodeWithStateVerbatimAndBindingFromTheSeam —
// LINE-A-1-02: валидный запрос → 302 на R?code=…&state=… (state дословно);
// код непрозрачен; запись кода связывает (субъект, клиент, цель, область,
// code_challenge); назначаемые выдачей величины из запроса не берутся (Р5).
func TestLINEA1_02_AuthorizeIssuesCodeWithStateVerbatimAndBindingFromTheSeam(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-02", "1")
	w.requireAuthorizeEndpoint()

	_, challenge := pkcePair()
	state := stateOfLen(lineA1StateFloor + 8)
	q := authorizeQuery(w.ic1, lineA1R, state, challenge)
	// Вызывающий называет назначаемое выдачей неверно — оно обязано быть
	// проигнорировано, а не принято и не потребовано.
	const foreignSubject = "usr-caller-named-subject"
	q.Set("sub", foreignSubject)
	q.Set("acr", "3")
	q.Set("auth_time", "1")
	rec := w.get(lineA1AuthorizePath, q, true)
	code := requireCodeDelivered(t, w.id, "валидный запрос", rec, lineA1R, state)

	for _, leak := range []string{string(w.user), string(w.ic1.rec.ID), lineA1Scope, w.email} {
		if strings.Contains(code, leak) {
			t.Errorf("%s: код несёт %q в открытом виде", w.id, leak)
		}
	}
	for _, part := range strings.Split(code, ".") {
		if raw, err := base64.RawURLEncoding.DecodeString(part); err == nil && strings.Contains(string(raw), string(w.user)) {
			t.Errorf("%s: код несёт субъекта в разбираемом виде", w.id)
		}
	}

	recs := w.codeRecords()
	if len(recs) != 1 {
		t.Fatalf("%s: записей кода %d, ожидалась одна", w.id, len(recs))
	}
	for _, want := range []string{string(w.user), string(w.ic1.rec.ID), lineA1R, challenge, lineA1Scope} {
		if !strings.Contains(recs[0], want) {
			t.Errorf("%s: запись кода не связывает %q: %s", w.id, want, recs[0])
		}
	}
	if strings.Contains(recs[0], foreignSubject) {
		t.Errorf("%s: запись кода приняла субъекта из запроса", w.id)
	}
	if strings.Contains(recs[0], code) {
		t.Errorf("%s: код хранится в открытом виде", w.id)
	}

	// Заказ разбора классов: цель с собственной строкой запроса — код
	// добавлен к РАЗОБРАННОЙ цели, её `tenant=a` сохранён.
	_, challenge2 := pkcePair()
	state2 := stateOfLen(lineA1StateFloor + 8)
	requireCodeDelivered(t, w.id, "цель с собственной строкой запроса",
		w.get(lineA1AuthorizePath, authorizeQuery(w.ic1, lineA1RQ, state2, challenge2), true), lineA1RQ, state2)
}

// TestLINEA1_03_UnauthenticatedSeamIssuesNoCode — LINE-A-1-03: шов отвечает
// «не-аутентифицирован» → код не выдаётся, записи кода не создаётся.
// Близнец — тот же запрос при сессии (02); отличие ровно в ответе шва.
func TestLINEA1_03_UnauthenticatedSeamIssuesNoCode(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-03", "1")
	w.requireAuthorizeEndpoint()

	_, challenge := pkcePair()
	state := stateOfLen(lineA1StateFloor + 8)
	q := authorizeQuery(w.ic1, lineA1R, state, challenge)

	requireCodeDelivered(t, w.id, "близнец: сессия есть", w.get(lineA1AuthorizePath, q, true), lineA1R, state)
	before := len(w.codeRecords())

	rec := w.get(lineA1AuthorizePath, q, false)
	requireNoCodeDelivered(t, w.id, "сессии нет", rec, lineA1R)
	if rec.Code != http.StatusFound && rec.Code != http.StatusUnauthorized {
		t.Errorf("%s: без сессии ожидался вызов аутентификации (302 на наш вход либо 401), получено %d", w.id, rec.Code)
	}
	if after := len(w.codeRecords()); after != before {
		t.Errorf("%s: без сессии создана запись кода (было %d, стало %d)", w.id, before, after)
	}
}

// TestLINEA1_04_UnregisteredRedirectRefusedWithoutRedirect — LINE-A-1-04:
// незарегистрированная цель → отказ БЕЗ перенаправления, код не выдаётся.
// Точное равенство: чужой хост и тот же адрес с хвостовым слэшем (заказ
// разбора классов) — оба незарегистрированы.
func TestLINEA1_04_UnregisteredRedirectRefusedWithoutRedirect(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-04", "1")
	w.requireAuthorizeEndpoint()

	state := stateOfLen(lineA1StateFloor + 8)
	_, challenge := pkcePair()
	requireCodeDelivered(t, w.id, "близнец: зарегистрированная цель", w.get(lineA1AuthorizePath,
		authorizeQuery(w.ic1, lineA1R, state, challenge), true), lineA1R, state)
	before := len(w.codeRecords())

	for _, bad := range []string{lineA1Foreign, lineA1Trailing} {
		rec := w.get(lineA1AuthorizePath, authorizeQuery(w.ic1, bad, state, challenge), true)
		if rec.Code == http.StatusFound || rec.Header().Get("Location") != "" {
			t.Errorf("%s: цель %q: перенаправление при незарегистрированной цели (код %d, Location %q)", w.id, bad, rec.Code, rec.Header().Get("Location"))
		}
		requireNoCodeDelivered(t, w.id, "цель "+bad, rec, bad, lineA1R)
		for _, leak := range []string{string(w.ic1.rec.ID), string(w.user), "postgres", "SQLSTATE"} {
			if strings.Contains(rec.Body.String(), leak) {
				t.Errorf("%s: отказ несёт %q", w.id, leak)
			}
		}
	}
	if after := len(w.codeRecords()); after != before {
		t.Errorf("%s: отказ создал запись кода (было %d, стало %d)", w.id, before, after)
	}
}

// TestLINEA1_05_UnknownOrRemovedClientRefusedWithoutRedirect — LINE-A-1-05:
// клиента нет либо он снят (`DELETING`) → отказ без перенаправления, и тон
// одинаков для «нет» и «снят». Близнец — ACTIVE клиент (02).
func TestLINEA1_05_UnknownOrRemovedClientRefusedWithoutRedirect(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-05", "1")
	w.requireAuthorizeEndpoint()

	state := stateOfLen(lineA1StateFloor + 8)
	_, challenge := pkcePair()
	requireCodeDelivered(t, w.id, "близнец: ACTIVE клиент", w.get(lineA1AuthorizePath,
		authorizeQuery(w.ic1, lineA1R, state, challenge), true), lineA1R, state)

	unknown := &ceremonyClient{}
	unknown.rec.ID = domain.InteractiveClientID(ids.NewHyphenID(ids.PrefixInteractiveClientHyphen))
	recUnknown := w.get(lineA1AuthorizePath, authorizeQuery(unknown, lineA1R, state, challenge), true)
	recGone := w.get(lineA1AuthorizePath, authorizeQuery(w.gone, lineA1R, state, challenge), true)
	for what, rec := range map[string]*httptest.ResponseRecorder{"клиента нет": recUnknown, "клиент снят": recGone} {
		if rec.Code == http.StatusFound || rec.Header().Get("Location") != "" {
			t.Errorf("%s: %s: перенаправление (код %d, Location %q)", w.id, what, rec.Code, rec.Header().Get("Location"))
		}
		requireNoCodeDelivered(t, w.id, what, rec, lineA1R)
	}
	if recUnknown.Code != recGone.Code || recUnknown.Body.String() != recGone.Body.String() {
		t.Errorf("%s: «клиента нет» и «клиент снят» различимы: %d %q против %d %q",
			w.id, recUnknown.Code, recUnknown.Body.String(), recGone.Code, recGone.Body.String())
	}
}

// TestLINEA1_0405_RefusalsWithoutRedirectAreByteIdentical — заказ разбора
// классов (LAX-20): отказ «цель не та» и отказ «клиента нет/снят» побайтово
// одинаковы для человека; различие — только в счётчике и журнале.
func TestLINEA1_0405_RefusalsWithoutRedirectAreByteIdentical(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-04/05", "1")
	w.requireAuthorizeEndpoint()

	state := stateOfLen(lineA1StateFloor + 8)
	_, challenge := pkcePair()
	requireCodeDelivered(t, w.id, "близнец", w.get(lineA1AuthorizePath,
		authorizeQuery(w.ic1, lineA1R, state, challenge), true), lineA1R, state)

	unknown := &ceremonyClient{}
	unknown.rec.ID = domain.InteractiveClientID(ids.NewHyphenID(ids.PrefixInteractiveClientHyphen))
	foreign := w.get(lineA1AuthorizePath, authorizeQuery(w.ic1, lineA1Foreign, state, challenge), true)
	for what, rec := range map[string]*httptest.ResponseRecorder{
		"клиента нет": w.get(lineA1AuthorizePath, authorizeQuery(unknown, lineA1R, state, challenge), true),
		"клиент снят": w.get(lineA1AuthorizePath, authorizeQuery(w.gone, lineA1R, state, challenge), true),
	} {
		if rec.Code != foreign.Code || rec.Body.String() != foreign.Body.String() {
			t.Errorf("%s: «%s» отличим от «цель не та»: %d %q против %d %q", w.id, what, rec.Code, rec.Body.String(), foreign.Code, foreign.Body.String())
		}
	}
}

// TestLINEA1_06_PKCEMissingOrNotS256RefusedByRedirect — LINE-A-1-06: без
// code_challenge либо с методом plain → 302 на R, в запросе ровно error=
// invalid_request. Близнец — S256 (02).
func TestLINEA1_06_PKCEMissingOrNotS256RefusedByRedirect(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-06", "1")
	w.requireAuthorizeEndpoint()

	state := stateOfLen(lineA1StateFloor + 8)
	verifier, challenge := pkcePair()
	requireCodeDelivered(t, w.id, "близнец: S256", w.get(lineA1AuthorizePath,
		authorizeQuery(w.ic1, lineA1R, state, challenge), true), lineA1R, state)
	before := len(w.codeRecords())

	noChallenge := authorizeQuery(w.ic1, lineA1R, state, challenge)
	noChallenge.Del("code_challenge")
	noChallenge.Del("code_challenge_method")
	plain := authorizeQuery(w.ic1, lineA1R, state, verifier)
	plain.Set("code_challenge_method", "plain")
	for what, q := range map[string]url.Values{"без code_challenge": noChallenge, "метод plain": plain} {
		requireRedirectOnlyError(t, w.id, what, w.get(lineA1AuthorizePath, q, true), lineA1R, "invalid_request")
	}
	if after := len(w.codeRecords()); after != before {
		t.Errorf("%s: отказ PKCE создал запись кода (было %d, стало %d)", w.id, before, after)
	}
}

// TestLINEA1_07_ResponseTypeNotCodeRefusedByRedirect — LINE-A-1-07:
// response_type=token → 302 на R с ровно error=unsupported_response_type.
func TestLINEA1_07_ResponseTypeNotCodeRefusedByRedirect(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-07", "1")
	w.requireAuthorizeEndpoint()

	state := stateOfLen(lineA1StateFloor + 8)
	_, challenge := pkcePair()
	requireCodeDelivered(t, w.id, "близнец: response_type=code", w.get(lineA1AuthorizePath,
		authorizeQuery(w.ic1, lineA1R, state, challenge), true), lineA1R, state)

	q := authorizeQuery(w.ic1, lineA1R, state, challenge)
	q.Set("response_type", "token")
	requireRedirectOnlyError(t, w.id, "response_type=token", w.get(lineA1AuthorizePath, q, true), lineA1R, "unsupported_response_type")
}

// TestLINEA1_08_StepUpIsServedAndReachedLevelIsCarried — LINE-A-1-08: сессия
// уровня "1" и acr_values=2 → код на цель НЕ доставляется (поднимается
// повторная аутентификация). Близнец — сессия уже уровня "2": код выдаётся, и
// обмен несёт уровень "2". Отличие — исходный уровень сессии.
//
// Прохождение второго фактора браузером — уровень P (playwright), следующий шаг.
func TestLINEA1_08_StepUpIsServedAndReachedLevelIsCarried(t *testing.T) {
	low := newCeremonyWorld(t, "LINE-A-1-08", "1")
	low.requireAuthorizeEndpoint()
	low.requireGrant(grantAuthorizationCode)

	state := stateOfLen(lineA1StateFloor + 8)
	_, challenge := pkcePair()
	q := authorizeQuery(low.ic1, lineA1R, state, challenge)
	q.Set("acr_values", "2")
	rec := low.get(lineA1AuthorizePath, q, true)
	requireNoCodeDelivered(t, low.id, "уровень сессии ниже запрошенного", rec, lineA1R)

	high := newCeremonyWorld(t, "LINE-A-1-08", "2")
	verifier, challenge2 := pkcePair()
	q2 := authorizeQuery(high.ic1, lineA1R, state, challenge2)
	q2.Set("acr_values", "2")
	code := requireCodeDelivered(t, high.id, "близнец: сессия уровня 2", high.get(lineA1AuthorizePath, q2, true), lineA1R, state)
	tr := high.redeem(issuedCode{code: code, verifier: verifier, redirect: lineA1R, client: high.ic1})
	if got := claimACR(high.bearerClaims(tr.AccessToken)); got != "2" {
		t.Errorf("%s: код после шага вверх несёт уровень %q, ожидался достигнутый \"2\"", high.id, got)
	}
}

// TestLINEA1_09_FirstPartyConsentIsSkipped — LINE-A-1-09: первопартийный
// клиент — согласия нет: первый же ответ есть 302 на цель клиента с кодом.
func TestLINEA1_09_FirstPartyConsentIsSkipped(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-09", "1")
	w.requireAuthorizeEndpoint()

	state := stateOfLen(lineA1StateFloor + 8)
	_, challenge := pkcePair()
	rec := w.get(lineA1AuthorizePath, authorizeQuery(w.ic1, lineA1R, state, challenge), true)
	if ct := rec.Header().Get("Content-Type"); rec.Code == http.StatusOK && strings.Contains(ct, "html") {
		t.Fatalf("%s: между запросом и перенаправлением стоит страница (%s) — согласие не пропущено", w.id, ct)
	}
	requireCodeDelivered(t, w.id, "один переход до цели", rec, lineA1R, state)
	if n := len(w.codeRecords()); n != 1 {
		t.Errorf("%s: записей кода %d после одного перехода, ожидалась одна", w.id, n)
	}
}

// TestLINEA1_29_StateAbsentOrBelowFloorRefusedByRedirect — LINE-A-1-29:
// `state` не прислан либо короче пола на один знак → 302 на R с ровно
// error=invalid_request; обе ветви дают ОДИН исход. Цель с собственной строкой
// запроса сохраняет её и в отказе (заказ разбора классов). Близнец — 30.
func TestLINEA1_29_StateAbsentOrBelowFloorRefusedByRedirect(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-29", "1")
	w.requireAuthorizeEndpoint()

	_, challenge := pkcePair()
	absent := w.get(lineA1AuthorizePath, authorizeQuery(w.ic1, lineA1R, "", challenge), true)
	short := w.get(lineA1AuthorizePath, authorizeQuery(w.ic1, lineA1R, stateOfLen(lineA1StateFloor-1), challenge), true)
	requireRedirectOnlyError(t, w.id, "state не прислан", absent, lineA1R, "invalid_request")
	requireRedirectOnlyError(t, w.id, "state короче пола", short, lineA1R, "invalid_request")
	if absent.Code != short.Code || absent.Header().Get("Location") != short.Header().Get("Location") {
		t.Errorf("%s: две ветви дали разный исход: %d %q против %d %q", w.id,
			absent.Code, absent.Header().Get("Location"), short.Code, short.Header().Get("Location"))
	}
	requireRedirectOnlyError(t, w.id, "цель с собственной строкой запроса",
		w.get(lineA1AuthorizePath, authorizeQuery(w.ic1, lineA1RQ, stateOfLen(lineA1StateFloor-1), challenge), true),
		lineA1RQ, "invalid_request")
	if n := len(w.codeRecords()); n != 0 {
		t.Errorf("%s: отказ по state создал %d запис(ей) кода", w.id, n)
	}
}

// TestLINEA1_30_StateAtOrAboveFloorIssuesCode — LINE-A-1-30: `state` ровно на
// поле → код и `state` дословно. Заказ разбора классов: и длиннее пола —
// тоже код (сравнение «не ниже», а не «ровно»).
func TestLINEA1_30_StateAtOrAboveFloorIssuesCode(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-30", "1")
	w.requireAuthorizeEndpoint()

	for _, n := range []int{lineA1StateFloor, 43} {
		_, challenge := pkcePair()
		state := stateOfLen(n)
		requireCodeDelivered(t, w.id, "state длиной "+strconv.Itoa(n), w.get(lineA1AuthorizePath,
			authorizeQuery(w.ic1, lineA1R, state, challenge), true), lineA1R, state)
	}
	if n := len(w.codeRecords()); n != 2 {
		t.Errorf("%s: записей кода %d, ожидалось две", w.id, n)
	}
}
