// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_exchange_integration_test.go — группа B (обмен кода) и группа I
// (инварианты хранилища) приёмки LINE-A-1: 10, 11, 12, 13, 14, 15, 16, 17, 24,
// 26, 27 и заказ разбора классов о гранулярности отзыва семейства.
//
// Мир, ступени пробы и слова исхода — `ceremony_world_integration_test.go`.
package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
)

// audiences — `aud` предъявителя в обеих законных формах (строка и список).
func audiences(c jwt.MapClaims) []string {
	switch v := c["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// requireSessionFacts — предъявитель несёт субъекта, вид принципала, уровень и
// момент аутентификации СЕССИИ, породившей код (Р6).
func (w *ceremonyWorld) requireSessionFacts(what string, c jwt.MapClaims) {
	w.t.Helper()
	if sub, _ := c["sub"].(string); sub != string(w.user) {
		w.t.Errorf("%s: %s: sub=%q, ожидался субъект сессии %q", w.id, what, sub, w.user)
	}
	if pt, _ := c[domain.ClaimPrincipalType].(string); pt != "user" {
		w.t.Errorf("%s: %s: вид принципала %q, ожидался user", w.id, what, pt)
	}
	if got := claimACR(c); got != w.session.level {
		w.t.Errorf("%s: %s: уровень %q, ожидался уровень сессии %q", w.id, what, got, w.session.level)
	}
	if at, ok := claimAuthTime(c); !ok || at != w.session.authAt.Unix() {
		w.t.Errorf("%s: %s: auth_time %d (есть: %v), ожидался момент сессии %d", w.id, what, at, ok, w.session.authAt.Unix())
	}
}

// TestLINEA1_10_CodeExchangeIssuesOurSignedBearer — LINE-A-1-10: обмен кода с
// верным verifier и аутентификацией конфиденциального клиента → 200 и наш
// подписанный предъявитель стандартной формы; субъект, уровень и момент
// прочитаны из кода; адресат штампуется нами (присланный — не берётся).
func TestLINEA1_10_CodeExchangeIssuesOurSignedBearer(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-10", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	ic := w.issueCode(w.ic1, lineA1R)
	form := exchangeForm(ic)
	const callerAudience = "https://caller-named-audience.invalid"
	form.Set("audience", callerAudience)
	rec := w.exchangeAs(w.ic1, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: обмен ответил %d, ожидалось 200; тело %q", w.id, rec.Code, rec.Body.String())
	}
	requireNoStore(t, w.id, "ответ обмена", rec)
	tr := decodeToken(t, w.id, rec)
	if !strings.EqualFold(tr.TokenType, "Bearer") || tr.ExpiresIn <= 0 || tr.AccessToken == "" {
		t.Errorf("%s: ответ обмена не стандартной формы RFC 6749 §5.1: %q", w.id, rec.Body.String())
	}
	claims := w.bearerClaims(tr.AccessToken)
	w.requireSessionFacts("предъявитель обмена", claims)
	aud := audiences(claims)
	if len(aud) == 0 {
		t.Errorf("%s: у предъявителя нет адресата", w.id)
	}
	for _, a := range aud {
		if a == callerAudience {
			t.Errorf("%s: адресат взят у вызывающего (%q) — он штампуется нами", w.id, a)
		}
	}
}

// TestLINEA1_11_WrongVerifierRefused — LINE-A-1-11: verifier не даёт
// code_challenge → invalid_grant/400. Близнец — верный verifier (10).
func TestLINEA1_11_WrongVerifierRefused(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-11", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	bad := w.issueCode(w.ic1, lineA1R)
	form := exchangeForm(bad)
	other, _ := pkcePair()
	form.Set("code_verifier", other)
	requireInvalidGrant(t, w.id, "неверный code_verifier", w.exchangeAs(w.ic1, form))

	w.redeem(w.issueCode(w.ic1, lineA1R))
}

// TestLINEA1_12_ConfidentialClientAuthenticationRequired — LINE-A-1-12: без
// аутентификации клиента либо с неверным секретом → invalid_client/401, и
// решается это ДО именования кода (неизвестный код с неверным секретом — тоже
// invalid_client). Близнец — верная аутентификация (10).
func TestLINEA1_12_ConfidentialClientAuthenticationRequired(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-12", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()
	w.giveSecret(w.ic1)

	ic := w.issueCode(w.ic1, lineA1R)
	unknown := exchangeForm(ic)
	unknown.Set("code", randomToken(32))
	cases := map[string]*httptest.ResponseRecorder{
		"без аутентификации клиента": w.post(clienttokenhttp.TokenPath, exchangeForm(ic), nil),
		"неверный секрет":            w.post(clienttokenhttp.TokenPath, exchangeForm(ic), []string{string(w.ic1.rec.ID), "not-the-secret"}),
		"неизвестный код и неверный секрет": w.post(clienttokenhttp.TokenPath, unknown,
			[]string{string(w.ic1.rec.ID), "not-the-secret"}),
	}
	for what, rec := range cases {
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %s: ожидался 401 invalid_client, получен %d; тело %q", w.id, what, rec.Code, rec.Body.String())
			continue
		}
		if tr := decodeToken(t, w.id, rec); tr.Error != "invalid_client" || tr.AccessToken != "" {
			t.Errorf("%s: %s: ожидался invalid_client, получено %q", w.id, what, rec.Body.String())
		}
	}

	w.redeem(w.issueCode(w.ic1, lineA1R))
}

// TestLINEA1_13_CodeReplayRefusedAndRevokesWhatItIssued — LINE-A-1-13: второй
// обмен тем же кодом → invalid_grant, и выданный первым обменом предъявитель
// ОТВЕРГАЕТСЯ на предъявлении. Близнец — свежий код: 200, ранее выданное не
// тронуто.
func TestLINEA1_13_CodeReplayRefusedAndRevokesWhatItIssued(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-13", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	ic := w.issueCode(w.ic1, lineA1R)
	first := w.redeem(ic)
	if refused, why := w.presentation(first.AccessToken); refused {
		t.Fatalf("%s: предъявитель первого обмена отвергнут ещё до повтора: %s", w.id, why)
	}
	requireInvalidGrant(t, w.id, "повтор кода", w.exchangeAs(w.ic1, exchangeForm(ic)))
	if refused, _ := w.presentation(first.AccessToken); !refused {
		t.Errorf("%s: повтор кода не отозвал выданный по нему предъявитель — отказ второму обмену без отзыва первого исходом не является", w.id)
	}

	fresh := w.redeem(w.issueCode(w.ic1, lineA1R))
	if refused, why := w.presentation(fresh.AccessToken); refused {
		t.Errorf("%s: близнец: предъявитель свежего кода отвергнут: %s", w.id, why)
	}
}

// TestLINEA1_14_ExpiredCodeRefused — LINE-A-1-14: код, чей срок истёк по
// времени базы, → invalid_grant. Близнец — обмен в пределах срока (10).
func TestLINEA1_14_ExpiredCodeRefused(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-14", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	w.redeem(w.issueCode(w.ic1, lineA1R))

	stale := w.issueCode(w.ic1, lineA1R)
	w.ageCodes()
	requireInvalidGrant(t, w.id, "истёкший код", w.exchangeAs(w.ic1, exchangeForm(stale)))
}

// TestLINEA1_15_RedirectMismatchOnExchangeRefused — LINE-A-1-15: код выдан для
// R, обмен называет R2 (зарегистрированную у того же клиента) → invalid_grant.
func TestLINEA1_15_RedirectMismatchOnExchangeRefused(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-15", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	ic := w.issueCode(w.ic1, lineA1R)
	form := exchangeForm(ic)
	form.Set("redirect_uri", lineA1R2)
	requireInvalidGrant(t, w.id, "redirect_uri обмена не тот", w.exchangeAs(w.ic1, form))

	w.redeem(w.issueCode(w.ic1, lineA1R))
}

// TestLINEA1_16_CodePresentedByAnotherClientRefused — LINE-A-1-16: код клиента
// ic-1 предъявлен клиентом ic-2 с его валидной аутентификацией → invalid_grant.
func TestLINEA1_16_CodePresentedByAnotherClientRefused(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-16", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	ic := w.issueCode(w.ic1, lineA1R)
	form := exchangeForm(ic)
	form.Set("client_id", string(w.ic2.rec.ID))
	requireInvalidGrant(t, w.id, "код чужого клиента", w.exchangeAs(w.ic2, form))

	w.redeem(w.issueCode(w.ic1, lineA1R))
}

// raceExchange — n одновременных обменов форм клиентом c; ответы по порядку.
func (w *ceremonyWorld) raceExchange(c *ceremonyClient, forms []url.Values) []*httptest.ResponseRecorder {
	w.t.Helper()
	w.giveSecret(c)
	out := make([]*httptest.ResponseRecorder, len(forms))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, f := range forms {
		wg.Add(1)
		go func(i int, f url.Values) {
			defer wg.Done()
			<-start
			out[i] = w.post(clienttokenhttp.TokenPath, f, []string{string(c.rec.ID), c.secret})
		}(i, f)
	}
	close(start)
	wg.Wait()
	return out
}

// requireExactlyOneWinner — ровно один 200, прочие — invalid_grant/400.
func requireExactlyOneWinner(t *testing.T, id, what string, recs []*httptest.ResponseRecorder) {
	t.Helper()
	won := 0
	for _, rec := range recs {
		switch rec.Code {
		case http.StatusOK:
			won++
		case http.StatusBadRequest:
			if tr := decodeToken(t, id, rec); tr.Error != "invalid_grant" {
				t.Errorf("%s: %s: проигравший получил %q, ожидался invalid_grant", id, what, rec.Body.String())
			}
		default:
			t.Errorf("%s: %s: исход %d вне {200, 400}: %q", id, what, rec.Code, rec.Body.String())
		}
	}
	if won != 1 {
		t.Errorf("%s: %s: из %d одновременных обменов прошло %d, ожидался ровно один", id, what, len(recs), won)
	}
}

// TestLINEA1_17_ConcurrentExchangeOfOneCodeHasOneWinner — LINE-A-1-17: обмены
// одним кодом, дошедшие до потребления одновременно, → ровно один 200.
// Близнец — одновременные обмены РАЗНЫМИ кодами проходят все.
func TestLINEA1_17_ConcurrentExchangeOfOneCodeHasOneWinner(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-17", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	ic := w.issueCode(w.ic1, lineA1R)
	same := make([]url.Values, 8)
	for i := range same {
		same[i] = exchangeForm(ic)
	}
	requireExactlyOneWinner(t, w.id, "один код", w.raceExchange(w.ic1, same))

	distinct := []url.Values{exchangeForm(w.issueCode(w.ic1, lineA1R)), exchangeForm(w.issueCode(w.ic1, lineA1R))}
	for i, rec := range w.raceExchange(w.ic1, distinct) {
		if rec.Code != http.StatusOK {
			t.Errorf("%s: близнец: обмен %d разным кодом ответил %d — отрицание зеленело бы на реализации, отвергающей любой второй обмен; тело %q",
				w.id, i, rec.Code, rec.Body.String())
		}
	}
}

// TestLINEA1_24_RefusalsAfterCodeIsNamedAreByteIdentical — LINE-A-1-24: шесть
// отказов после именования кода отдают побайтово одно и то же; различимы
// только отказы до именования кода. На каждый отказ — запись журнала.
func TestLINEA1_24_RefusalsAfterCodeIsNamedAreByteIdentical(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-24", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()
	w.giveSecret(w.ic1)
	w.giveSecret(w.ic2)

	// Истёкший код заводится первым и один: перенос срока задевает все записи.
	expired := w.issueCode(w.ic1, lineA1R)
	w.ageCodes()
	used := w.issueCode(w.ic1, lineA1R)
	w.redeem(used)
	verifierCode := w.issueCode(w.ic1, lineA1R)
	clientCode := w.issueCode(w.ic1, lineA1R)
	redirectCode := w.issueCode(w.ic1, lineA1R)

	unknownForm := exchangeForm(used)
	unknownForm.Set("code", randomToken(32))
	verifierForm := exchangeForm(verifierCode)
	other, _ := pkcePair()
	verifierForm.Set("code_verifier", other)
	clientForm := exchangeForm(clientCode)
	clientForm.Set("client_id", string(w.ic2.rec.ID))
	redirectForm := exchangeForm(redirectCode)
	redirectForm.Set("redirect_uri", lineA1R2)

	type refusal struct {
		what string
		c    *ceremonyClient
		form url.Values
	}
	var first *httptest.ResponseRecorder
	for _, r := range []refusal{
		{"код неизвестен", w.ic1, unknownForm},
		{"код истёк", w.ic1, exchangeForm(expired)},
		{"код уже использован", w.ic1, exchangeForm(used)},
		{"неверный code_verifier", w.ic1, verifierForm},
		{"клиент не тот", w.ic2, clientForm},
		{"redirect_uri не тот", w.ic1, redirectForm},
	} {
		logged := w.logs.Records()
		rec := w.exchangeAs(r.c, r.form)
		requireInvalidGrant(t, w.id, r.what, rec)
		if w.logs.Records() <= logged {
			t.Errorf("%s: %s: отказ не оставил записи журнала — различимость для нас мертва", w.id, r.what)
		}
		if first == nil {
			first = rec
			continue
		}
		if rec.Code != first.Code || rec.Body.String() != first.Body.String() {
			t.Errorf("%s: «%s» отличим от «код неизвестен»: %d %q против %d %q", w.id, r.what, rec.Code, rec.Body.String(), first.Code, first.Body.String())
		}
	}

	// Отказы ДО именования кода различимы и своих кодов.
	get := httptest.NewRequest(http.MethodGet, clienttokenhttp.TokenPath, nil)
	gotGet := httptest.NewRecorder()
	w.surface.ServeHTTP(gotGet, get)
	if gotGet.Code != http.StatusMethodNotAllowed {
		t.Errorf("%s: метод GET на обмене ответил %d, ожидалось 405", w.id, gotGet.Code)
	}
	bigForm := exchangeForm(w.issueCode(w.ic1, lineA1R))
	bigForm.Set("padding", strings.Repeat("x", 128<<10))
	big := w.exchangeAs(w.ic1, bigForm)
	if big.Body.String() == first.Body.String() {
		t.Errorf("%s: превышение потолка тела отвечает как «неверный код»: %q", w.id, big.Body.String())
	}
	noAuth := w.post(clienttokenhttp.TokenPath, exchangeForm(w.issueCode(w.ic1, lineA1R)), nil)
	if noAuth.Code != http.StatusUnauthorized || noAuth.Body.String() == first.Body.String() {
		t.Errorf("%s: отказ аутентификации клиента неотличим от invalid_grant: %d %q", w.id, noAuth.Code, noAuth.Body.String())
	}

	// Положительный контроль: валидный обмен возвращает предъявитель.
	w.redeem(w.issueCode(w.ic1, lineA1R))
}

// TestLINEA1_26_CodeSingleUseAndExpiryHeldByTheDatabase — LINE-A-1-26:
// одноразовость держит база (конкуренция даёт ровно один успех), срок — её
// время (истёкший не потребляется и без конкуренции). Близнец — два разных
// кода проходят оба.
func TestLINEA1_26_CodeSingleUseAndExpiryHeldByTheDatabase(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-26", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	distinct := []url.Values{exchangeForm(w.issueCode(w.ic1, lineA1R)), exchangeForm(w.issueCode(w.ic1, lineA1R))}
	for i, rec := range w.raceExchange(w.ic1, distinct) {
		if rec.Code != http.StatusOK {
			t.Errorf("%s: близнец: разный код %d ответил %d; тело %q", w.id, i, rec.Code, rec.Body.String())
		}
	}

	ic := w.issueCode(w.ic1, lineA1R)
	same := make([]url.Values, 16)
	for i := range same {
		same[i] = exchangeForm(ic)
	}
	requireExactlyOneWinner(t, w.id, "потребление одного кода", w.raceExchange(w.ic1, same))

	stale := w.issueCode(w.ic1, lineA1R)
	w.ageCodes()
	requireInvalidGrant(t, w.id, "истёкший код без конкуренции", w.exchangeAs(w.ic1, exchangeForm(stale)))
}

// TestLINEA1_27_ExchangeIgnoresCallerNamedSessionFacts — LINE-A-1-27: обмен
// присылает subject/acr/auth_time другими — они игнорируются, предъявитель
// несёт значения кода. Контроль: без этих полей — тот же предъявитель.
func TestLINEA1_27_ExchangeIgnoresCallerNamedSessionFacts(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-27", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	named := exchangeForm(w.issueCode(w.ic1, lineA1R))
	named.Set("subject", "usr-caller-named-subject")
	named.Set("sub", "usr-caller-named-subject")
	named.Set("acr", "3")
	named.Set("auth_time", "1")
	rec := w.exchangeAs(w.ic1, named)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: обмен с названными вызывающим полями ответил %d — поля обязаны игнорироваться, а не отвергаться; тело %q",
			w.id, rec.Code, rec.Body.String())
	}
	w.requireSessionFacts("поля названы вызывающим", w.bearerClaims(decodeToken(t, w.id, rec).AccessToken))

	plain := w.redeem(w.issueCode(w.ic1, lineA1R))
	w.requireSessionFacts("контроль без полей", w.bearerClaims(plain.AccessToken))
}

// TestLINEA1_1321_FamilyRevocationTouchesOnlyItsOwnAuthorization — заказ
// разбора классов (гранулярность отзыва семейства): две независимые
// авторизации одного человека; повтор кода первой отзывает её предъявитель и
// НЕ отзывает предъявитель второй.
func TestLINEA1_1321_FamilyRevocationTouchesOnlyItsOwnAuthorization(t *testing.T) {
	w := newCeremonyWorld(t, "LINE-A-1-13/21", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()

	other := w.redeem(w.issueCode(w.ic1, lineA1R))
	mine := w.issueCode(w.ic1, lineA1R)
	issued := w.redeem(mine)
	requireInvalidGrant(t, w.id, "повтор кода", w.exchangeAs(w.ic1, exchangeForm(mine)))

	if refused, _ := w.presentation(issued.AccessToken); !refused {
		t.Errorf("%s: отзыв своего семейства не отверг его предъявитель", w.id)
	}
	if refused, why := w.presentation(other.AccessToken); refused {
		t.Errorf("%s: отзыв одного семейства отверг предъявитель другой авторизации того же человека: %s", w.id, why)
	}
}
