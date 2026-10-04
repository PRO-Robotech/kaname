// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_no_session_outcome_integration_test.go — группа I приёмки
// `docs/engineering/acceptance/ceremony-pace-is-named-by-number.md` (ред. 5,
// Р11, задача kaname#525): исход точки авторизации без сессии и при уровне
// сессии ниже запрошенного.
//
// Годный запрос авторизации — клиент известен, адрес возврата
// зарегистрирован, `state` не короче пола — без годной сессии получает `302`
// на зарегистрированный адрес возврата с ровно `error=login_required` и
// `state` дословно; при уровне ниже `acr_values` — то же с
// `error=insufficient_user_authentication`. Ответ без перенаправления остался
// бы у браузера, и приложение его не получило бы. Незарегистрированный адрес
// ответа не получает ни при какой сессии (KN-PACE-45).
//
// Перепись исходов читается в мире (посев Ц): её клетки производит та же
// поверхность, что собрана сборкой корня.
package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	cellLoginRequired  = "authorize-login-required"
	cellStepUpRequired = "authorize-step-up-required"
)

// requireErrorReachesTheApplication — Р11: 302 на зарегистрированную цель; в
// строке запроса — её собственные параметры, `error` и `state` дословно, и
// ничего сверх (ни `code`, ни `error_description`, ни `acr_values`); тела JSON
// нет; ответ не кэшируется.
func requireErrorReachesTheApplication(t *testing.T, id, what string, rec *httptest.ResponseRecorder, target, wantErr, state string) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("%s: %s: ожидалось 302 на цель с error=%s и state, получено %d; тело %q", id, what, wantErr, rec.Code, rec.Body.String())
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
	expect.Set("state", state)
	if got := loc.Query(); !reflect.DeepEqual(got, expect) {
		t.Errorf("%s: %s: строка запроса %v, ожидалась ровно %v", id, what, got, expect)
	}
	if strings.Contains(rec.Header().Get("Content-Type"), "json") || strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "{") {
		t.Errorf("%s: %s: ответ несёт тело JSON (%q, %q)", id, what, rec.Header().Get("Content-Type"), rec.Body.String())
	}
	requireNoStore(t, id, what, rec)
}

// cells — показания двух клеток переписи.
func (w *ceremonyWorld) cells() [2]uint64 {
	return [2]uint64{w.censusOf(cellLoginRequired), w.censusOf(cellStepUpRequired)}
}

// requireCellsGrew — клетки выросли ровно на (login, stepUp).
func requireCellsGrew(t *testing.T, id, what string, before, after [2]uint64, login, stepUp uint64) {
	t.Helper()
	if after[0]-before[0] != login || after[1]-before[1] != stepUp {
		t.Errorf("%s: %s: перепись %s +%d, %s +%d; ожидалось +%d и +%d", id, what,
			cellLoginRequired, after[0]-before[0], cellStepUpRequired, after[1]-before[1], login, stepUp)
	}
}

// TestKNPACE43_WithoutSessionTheErrorReachesTheApplication — KN-PACE-43,
// строки а (`R`) и б (`RQ`); близнец каждой — тот же запрос с годной сессией.
func TestKNPACE43_WithoutSessionTheErrorReachesTheApplication(t *testing.T) {
	for _, row := range []struct{ name, target string }{
		{"а: R", lineA1R},
		{"б: RQ — цель с собственной строкой запроса", lineA1RQ},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := newCeremonyWorld(t, "KN-PACE-43", "1")
			w.requireAuthorizeEndpoint()
			_, challenge := pkcePair()
			state := stateOfLen(30)
			q := authorizeQuery(w.ic1, row.target, state, challenge)

			// Близнец: годная сессия — код; клетки не меняются.
			before := w.cells()
			requireCodeDelivered(t, w.id, "близнец: сессия есть", w.get(lineA1AuthorizePath, q, true), row.target, state)
			requireCellsGrew(t, w.id, "близнец", before, w.cells(), 0, 0)

			codes := len(w.codeRecords())
			before = w.cells()
			rec := w.get(lineA1AuthorizePath, q, false)
			requireErrorReachesTheApplication(t, w.id, "без сессии", rec, row.target, "login_required", state)
			requireCellsGrew(t, w.id, "без сессии", before, w.cells(), 1, 0)
			if after := len(w.codeRecords()); after != codes {
				t.Errorf("%s: без сессии создана запись кода (было %d, стало %d)", w.id, codes, after)
			}
		})
	}
}

// TestKNPACE43c_SubjectCutOffAfterTheSessionIsLoginRequired — KN-PACE-43,
// строка в: сессия есть, субъект отсечён через секунду после её
// аутентификации — исход строки а. Близнец — отсечка за секунду до
// аутентификации: код.
func TestKNPACE43c_SubjectCutOffAfterTheSessionIsLoginRequired(t *testing.T) {
	for _, cell := range []struct {
		name    string
		shift   time.Duration
		refused bool
	}{
		{"в: отсечка через секунду после аутентификации сессии", time.Second, true},
		{"близнец: отсечка за секунду до аутентификации сессии", -time.Second, false},
	} {
		t.Run(cell.name, func(t *testing.T) {
			w := newCeremonyWorld(t, "KN-PACE-43в", "1")
			w.requireAuthorizeEndpoint()
			w.cutSubject(w.session.authAt.Add(cell.shift))
			_, challenge := pkcePair()
			state := stateOfLen(30)
			codes := len(w.codeRecords())
			before := w.cells()
			rec := w.get(lineA1AuthorizePath, authorizeQuery(w.ic1, lineA1R, state, challenge), true)
			if !cell.refused {
				requireCodeDelivered(t, w.id, cell.name, rec, lineA1R, state)
				requireCellsGrew(t, w.id, cell.name, before, w.cells(), 0, 0)
				return
			}
			requireErrorReachesTheApplication(t, w.id, cell.name, rec, lineA1R, "login_required", state)
			requireCellsGrew(t, w.id, cell.name, before, w.cells(), 1, 0)
			if after := len(w.codeRecords()); after != codes {
				t.Errorf("%s: создана запись кода (было %d, стало %d)", w.id, codes, after)
			}
		})
	}
}

// TestKNPACE44_LevelBelowRequestedTheErrorReachesTheApplication — KN-PACE-44;
// близнец KN-PACE-44+ — сессия уровня "2": код, клетки не меняются.
func TestKNPACE44_LevelBelowRequestedTheErrorReachesTheApplication(t *testing.T) {
	state := stateOfLen(30)

	low := newCeremonyWorld(t, "KN-PACE-44", "1")
	low.requireAuthorizeEndpoint()
	_, challenge := pkcePair()
	q := authorizeQuery(low.ic1, lineA1R, state, challenge)
	q.Set("acr_values", "2")
	codes := len(low.codeRecords())
	before := low.cells()
	rec := low.get(lineA1AuthorizePath, q, true)
	requireErrorReachesTheApplication(t, low.id, "сессия уровня 1, acr_values=2", rec, lineA1R, "insufficient_user_authentication", state)
	requireCellsGrew(t, low.id, "сессия уровня 1, acr_values=2", before, low.cells(), 0, 1)
	if after := len(low.codeRecords()); after != codes {
		t.Errorf("%s: создана запись кода (было %d, стало %d)", low.id, codes, after)
	}

	high := newCeremonyWorld(t, "KN-PACE-44+", "2")
	_, challenge2 := pkcePair()
	q2 := authorizeQuery(high.ic1, lineA1R, state, challenge2)
	q2.Set("acr_values", "2")
	before = high.cells()
	requireCodeDelivered(t, high.id, "близнец: сессия уровня 2", high.get(lineA1AuthorizePath, q2, true), lineA1R, state)
	requireCellsGrew(t, high.id, "близнец: сессия уровня 2", before, high.cells(), 0, 0)
}

// TestKNPACE45_UnregisteredTargetGetsNoAnswer — KN-PACE-45: незарегистрированный
// адрес возврата ответа не получает ни без сессии, ни при недостатке уровня.
// Отказ побайтово равен отказу той же цели при годной сессии
// (`TestLINEA1_04_…`).
func TestKNPACE45_UnregisteredTargetGetsNoAnswer(t *testing.T) {
	w := newCeremonyWorld(t, "KN-PACE-45", "1")
	w.requireAuthorizeEndpoint()
	_, challenge := pkcePair()
	state := stateOfLen(30)

	// Образец: незарегистрированная цель при годной сессии.
	sample := w.get(lineA1AuthorizePath, authorizeQuery(w.ic1, lineA1Foreign, state, challenge), true)
	if sample.Code != http.StatusBadRequest || sample.Header().Get("Location") != "" {
		t.Fatalf("%s: образец (цель чужого хоста при сессии) ответил %d, Location %q — сравнивать не с чем",
			w.id, sample.Code, sample.Header().Get("Location"))
	}

	stepUp := func(target string) url.Values {
		q := authorizeQuery(w.ic1, target, state, challenge)
		q.Set("acr_values", "2")
		return q
	}
	codes := len(w.codeRecords())
	for _, row := range []struct {
		name    string
		q       url.Values
		session bool
	}{
		{"а: RF без сессии", authorizeQuery(w.ic1, lineA1Foreign, state, challenge), false},
		{"б: RT без сессии", authorizeQuery(w.ic1, lineA1Trailing, state, challenge), false},
		{"в: RF, сессия уровня 1, acr_values=2", stepUp(lineA1Foreign), true},
	} {
		before := w.cells()
		rec := w.get(lineA1AuthorizePath, row.q, row.session)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %s: ответ %d, ожидалось 400", w.id, row.name, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
			t.Errorf("%s: %s: Content-Type %q", w.id, row.name, ct)
		}
		if rec.Body.String() != sample.Body.String() {
			t.Errorf("%s: %s: тело %q, ожидался текст недоверенной цели %q", w.id, row.name, rec.Body.String(), sample.Body.String())
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Errorf("%s: %s: перенаправление на %q", w.id, row.name, loc)
		}
		for _, leak := range []string{"login_required", "insufficient_user_authentication", state} {
			if strings.Contains(rec.Body.String(), leak) {
				t.Errorf("%s: %s: тело несёт %q", w.id, row.name, leak)
			}
		}
		requireCellsGrew(t, w.id, row.name, before, w.cells(), 0, 0)
	}
	if after := len(w.codeRecords()); after != codes {
		t.Errorf("%s: создана запись кода (было %d, стало %d)", w.id, codes, after)
	}
}
