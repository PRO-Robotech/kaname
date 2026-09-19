// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_exchange_red_test.go — Группа B приёмки LINE-A-1: обмен кода
// (grant_type=authorization_code). Свежие утверждения против нашей поверхности;
// заимствованные векторы (S256 verifier↔challenge, коды ошибок RFC 6749) — в
// `ceremony_fosite_vectors_test.go`.
//
// Общий честный красный группы: токен-эндпоинт на dd66b5be принимает РОВНО два
// вида выдачи (client_credentials, jwt-bearer); `authorization_code` отвергается
// на шаге 3 разбора вида выдачи → 400 `unsupported_grant_type`, ДО обращения к
// базе/подписанту. Значит полосы обмена кода нет — предмет отсутствует.

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

// exchangeForm — валидный обмен сценария 10.
func exchangeForm(code, verifier, redirectURI, clientID string) url.Values {
	return url.Values{
		"grant_type":    {grantAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
		// Аутентификация конфиденциального клиента (Р3): секрет либо подписанное
		// утверждение. На dd66b5be до неё дело не доходит — вид выдачи отвергнут
		// раньше; поле для полноты формы.
		"client_secret": {"ic-first-party-secret"},
	}
}

// decodeOAuthErr читает поле `error` тела ответа.
func decodeOAuthErr(rec *httptest.ResponseRecorder) string {
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return body.Error
}

// assertExchangeGrantWired — честный красный полосы обмена: если вид выдачи
// authorization_code отвергается как неподдерживаемый, полосы обмена нет.
func assertExchangeGrantWired(t *testing.T, rec *httptest.ResponseRecorder, scenario string) {
	t.Helper()
	if rec.Code == http.StatusBadRequest && decodeOAuthErr(rec) == oauthErrUnsupportedGrant {
		t.Fatalf("%s КРАСНЫЙ: вид выдачи %q не принят токен-эндпоинтом (400 %s) — полосы обмена кода на dd66b5be нет",
			scenario, grantAuthorizationCode, oauthErrUnsupportedGrant)
	}
}

// TestLINEA1_10_CodeExchangeHappyPath — LINE-A-1-10 (E): happy path обмена.
// Валидный код + code_verifier (S256) + аутентификация клиента → 200 и наш
// подписанный предъявитель (sub=usr-X, principal=user, acr, auth_time из КОДА).
//
// RED на dd66b5be: authorization_code не принят → 400 unsupported_grant_type.
func TestLINEA1_10_CodeExchangeHappyPath(t *testing.T) {
	mux := buildCeremonyIssuanceSurface(t)
	rec := ceremonyTokenPOST(mux, exchangeForm("code-from-02", fositePKCEVerifier, fositeRedirectRegistered, "ic-first-party"))

	assertExchangeGrantWired(t, rec, "LINE-A-1-10")

	// Целевая форма (исполнится по реализации): 200 + предъявитель.
	if rec.Code != http.StatusOK {
		t.Fatalf("LINE-A-1-10: ожидался 200, получен %d (%s)", rec.Code, decodeOAuthErr(rec))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil {
		t.Fatalf("LINE-A-1-10: ответ не разобрать чужой библиотекой: %v", err)
	}
	if tok.AccessToken == "" {
		t.Error("LINE-A-1-10: подписанный предъявитель не выдан")
	}
}

// TestLINEA1_11_WrongCodeVerifierInvalidGrant — LINE-A-1-11 (E): неверный
// code_verifier → invalid_grant/400. S256-сверка: BASE64URL(SHA256(verifier)) ==
// code_challenge; иначе invalid_grant (fosite pkce/handler.go).
//
// RED на dd66b5be: положительный близнец (верный verifier → 200) не достижим —
// вид выдачи отвергнут.
func TestLINEA1_11_WrongCodeVerifierInvalidGrant(t *testing.T) {
	mux := buildCeremonyIssuanceSurface(t)

	// Положительный близнец: верный verifier → 200 (10) — отличие в одном факте.
	twin := ceremonyTokenPOST(mux, exchangeForm("code-from-02", fositePKCEVerifier, fositeRedirectRegistered, "ic-first-party"))
	assertExchangeGrantWired(t, twin, "LINE-A-1-11")
	if twin.Code != http.StatusOK {
		t.Fatalf("LINE-A-1-11: положительный близнец ожидал 200, получил %d", twin.Code)
	}

	// Неверный verifier: тот же по форме, другой по SHA256 → invalid_grant/400.
	rec := ceremonyTokenPOST(mux, exchangeForm("code-from-02", fositePKCEVerifierWrong, fositeRedirectRegistered, "ic-first-party"))
	if rec.Code != http.StatusBadRequest || decodeOAuthErr(rec) != oauthErrInvalidGrant {
		t.Errorf("LINE-A-1-11: ожидался 400/%s, получено %d/%s", oauthErrInvalidGrant, rec.Code, decodeOAuthErr(rec))
	}
}

// TestLINEA1_12_ClientAuthMissingInvalidClient — LINE-A-1-12 (E): аутентификация
// конфиденциального клиента отсутствует/неверна → invalid_client/401, различимо
// и решается ДО того, как назван код (о клиенте, не о коде, Р10). Единственный
// отказ полосы обмена (кроме отказов формы), отличимый от invalid_grant.
//
// RED на dd66b5be: положительный близнец (верная аутентификация → 200) не достижим.
func TestLINEA1_12_ClientAuthMissingInvalidClient(t *testing.T) {
	mux := buildCeremonyIssuanceSurface(t)

	twin := ceremonyTokenPOST(mux, exchangeForm("code-from-02", fositePKCEVerifier, fositeRedirectRegistered, "ic-first-party"))
	assertExchangeGrantWired(t, twin, "LINE-A-1-12")
	if twin.Code != http.StatusOK {
		t.Fatalf("LINE-A-1-12: положительный близнец ожидал 200, получил %d", twin.Code)
	}

	noAuth := exchangeForm("code-from-02", fositePKCEVerifier, fositeRedirectRegistered, "ic-first-party")
	noAuth.Del("client_secret")
	rec := ceremonyTokenPOST(mux, noAuth)
	if rec.Code != http.StatusUnauthorized || decodeOAuthErr(rec) != oauthErrInvalidClient {
		t.Errorf("LINE-A-1-12: ожидался 401/%s (различимо от invalid_grant), получено %d/%s",
			oauthErrInvalidClient, rec.Code, decodeOAuthErr(rec))
	}
}

// TestLINEA1_13_CodeReplayRejectedAndPriorRevoked — LINE-A-1-13 (E+I): повтор
// кода → первый 200, второй invalid_grant/400 (одноразовость). Атомарность
// потребления держит база (§группа I) — здесь утверждается ПОВЕДЕНИЕ поверхности
// (первый успех, второй отказ), DB-атомарность закрывает GREEN вместе с типом
// хранилища кода, которого на dd66b5be нет.
//
// RED на dd66b5be: первый обмен не даёт 200 — полосы обмена нет.
func TestLINEA1_13_CodeReplayRejectedAndPriorRevoked(t *testing.T) {
	mux := buildCeremonyIssuanceSurface(t)

	first := ceremonyTokenPOST(mux, exchangeForm("code-single-use", fositePKCEVerifier, fositeRedirectRegistered, "ic-first-party"))
	assertExchangeGrantWired(t, first, "LINE-A-1-13")
	if first.Code != http.StatusOK {
		t.Fatalf("LINE-A-1-13: первый обмен ожидал 200, получил %d", first.Code)
	}

	second := ceremonyTokenPOST(mux, exchangeForm("code-single-use", fositePKCEVerifier, fositeRedirectRegistered, "ic-first-party"))
	if second.Code != http.StatusBadRequest || decodeOAuthErr(second) != oauthErrInvalidGrant {
		t.Errorf("LINE-A-1-13: второй обмен тем же кодом ожидал 400/%s, получил %d/%s",
			oauthErrInvalidGrant, second.Code, decodeOAuthErr(second))
	}
}

// TestLINEA1_15_ExchangeRedirectURIMismatchInvalidGrant — LINE-A-1-15 (E):
// redirect_uri обмена не совпадает с redirect_uri кода → invalid_grant/400
// (связка кода нарушена, Р5), даже если R2 зарегистрирован у того же клиента.
//
// RED на dd66b5be: положительный близнец (R → 200) не достижим.
func TestLINEA1_15_ExchangeRedirectURIMismatchInvalidGrant(t *testing.T) {
	mux := buildCeremonyIssuanceSurface(t)

	twin := ceremonyTokenPOST(mux, exchangeForm("code-from-02", fositePKCEVerifier, fositeRedirectRegistered, "ic-first-party"))
	assertExchangeGrantWired(t, twin, "LINE-A-1-15")
	if twin.Code != http.StatusOK {
		t.Fatalf("LINE-A-1-15: положительный близнец ожидал 200, получил %d", twin.Code)
	}

	rec := ceremonyTokenPOST(mux, exchangeForm("code-from-02", fositePKCEVerifier, fositeRedirectTrailing, "ic-first-party"))
	if rec.Code != http.StatusBadRequest || decodeOAuthErr(rec) != oauthErrInvalidGrant {
		t.Errorf("LINE-A-1-15: несовпадающий redirect_uri ожидал 400/%s, получил %d/%s",
			oauthErrInvalidGrant, rec.Code, decodeOAuthErr(rec))
	}
}

// TestLINEA1_16_CodePresentedByAnotherClientInvalidGrant — LINE-A-1-16 (E): код,
// выданный ic-1, предъявлен ic-2 (с валидной аутентификацией ic-2) →
// invalid_grant/400.
//
// RED на dd66b5be: положительный близнец (ic-1 → 200) не достижим.
func TestLINEA1_16_CodePresentedByAnotherClientInvalidGrant(t *testing.T) {
	mux := buildCeremonyIssuanceSurface(t)

	twin := ceremonyTokenPOST(mux, exchangeForm("code-for-ic-1", fositePKCEVerifier, fositeRedirectRegistered, "ic-1"))
	assertExchangeGrantWired(t, twin, "LINE-A-1-16")
	if twin.Code != http.StatusOK {
		t.Fatalf("LINE-A-1-16: положительный близнец ожидал 200, получил %d", twin.Code)
	}

	rec := ceremonyTokenPOST(mux, exchangeForm("code-for-ic-1", fositePKCEVerifier, fositeRedirectRegistered, "ic-2"))
	if rec.Code != http.StatusBadRequest || decodeOAuthErr(rec) != oauthErrInvalidGrant {
		t.Errorf("LINE-A-1-16: код, предъявленный чужим клиентом, ожидал 400/%s, получил %d/%s",
			oauthErrInvalidGrant, rec.Code, decodeOAuthErr(rec))
	}
}

// TestLINEA1_17_ConcurrentExchangeExactlyOneWins — LINE-A-1-17 (I): два
// одновременных обмена одним кодом → проходит ровно один (200), второй
// invalid_grant/400. Одноразовость держит атомарное потребление под row-lock
// (ban #10). Близнец: два обмена РАЗНЫМИ кодами проходят оба.
//
// RED на dd66b5be: ни один обмен не даёт 200 — полосы обмена нет, «ровно один
// победитель» невыразим.
func TestLINEA1_17_ConcurrentExchangeExactlyOneWins(t *testing.T) {
	mux := buildCeremonyIssuanceSurface(t)

	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := ceremonyTokenPOST(mux, exchangeForm("code-contended", fositePKCEVerifier, fositeRedirectRegistered, "ic-first-party"))
			codes[i] = rec.Code
		}(i)
	}
	wg.Wait()

	// Честный красный: ни одного 200 — вид выдачи отвергнут обоими.
	won := 0
	for _, c := range codes {
		if c == http.StatusOK {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("LINE-A-1-17 КРАСНЫЙ: победителей %d из 2 (коды %v), ожидался ровно один 200 — конкурентная одноразовость обмена отсутствует (вид выдачи authorization_code не принят)", won, codes)
	}
}
