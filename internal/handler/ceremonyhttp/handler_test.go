// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyhttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/ceremony"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/ceremonyhttp"
)

type decider struct {
	d    ceremony.AuthorizeDecision
	seen ceremony.AuthorizeParams
}

func (s *decider) Execute(_ context.Context, p ceremony.AuthorizeParams) ceremony.AuthorizeDecision {
	s.seen = p
	return s.d
}

func serve(h http.Handler, method, target string, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "kaname_session", Value: cookie})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestRedirectKeepsTheTargetsOwnQueryVerbatim — параметры добавляются к
// разобранной цели; её собственная строка запроса — дословно, первой.
func TestRedirectKeepsTheTargetsOwnQueryVerbatim(t *testing.T) {
	code := domain.PresentedCeremonySecret("the-code")
	for _, tc := range []struct {
		d    ceremony.AuthorizeDecision
		want string
	}{
		{ceremony.AuthorizeDecision{Kind: ceremony.DecisionDeliverCode, Target: "https://c.test/cb?tenant=a%2Fb", Code: code, State: "st"},
			"https://c.test/cb?tenant=a%2Fb&code=the-code&state=st"},
		{ceremony.AuthorizeDecision{Kind: ceremony.DecisionDeliverCode, Target: "https://c.test/cb", Code: code, State: "st"},
			"https://c.test/cb?code=the-code&state=st"},
		{ceremony.AuthorizeDecision{Kind: ceremony.DecisionRedirectError, Target: "https://c.test/cb?x=1", Error: "invalid_request"},
			"https://c.test/cb?x=1&error=invalid_request"},
	} {
		rec := serve(ceremonyhttp.NewAuthorizeHandler(&decider{d: tc.d}), http.MethodGet, ceremonyhttp.AuthorizePath, "")
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != tc.want {
			t.Errorf("перенаправление %d %q, ожидалось 302 %q", rec.Code, rec.Header().Get("Location"), tc.want)
		}
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Pragma") != "no-cache" {
			t.Errorf("ответ с удостоверением кэшируем: %v", rec.Header())
		}
	}
}

// TestAuthorizeParsesRepetitionAndTheSessionCookie — повтор параметра назван;
// носитель сессии — из печенья нашего входа; иной метод — 405 с перечнем.
func TestAuthorizeParsesRepetitionAndTheSessionCookie(t *testing.T) {
	s := &decider{d: ceremony.AuthorizeDecision{Kind: ceremony.DecisionRefuseWithoutRedirect}}
	h := ceremonyhttp.NewAuthorizeHandler(s)
	q := url.Values{"client_id": {"a", "b"}, "state": {"x"}}
	rec := serve(h, http.MethodGet, ceremonyhttp.AuthorizePath+"?"+q.Encode(), "bearer-value")
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("отказ без перенаправления: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if len(s.seen.Repeated) != 1 || s.seen.Repeated[0] != "client_id" || s.seen.Session.CookieValue() != "bearer-value" {
		t.Fatalf("разбор: повторы %v, носитель пуст %v", s.seen.Repeated, s.seen.Session.IsZero())
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if rec := serve(h, m, ceremonyhttp.AuthorizePath, ""); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
			t.Errorf("%s: %d, Allow %q", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
}

// TestAuthorizeAnswersEveryDecisionKind — у каждого вида решения свой ответ.
func TestAuthorizeAnswersEveryDecisionKind(t *testing.T) {
	for kind, want := range map[ceremony.DecisionKind]struct {
		status int
		errw   string
	}{
		ceremony.DecisionAuthenticate:          {http.StatusUnauthorized, "login_required"},
		ceremony.DecisionStepUp:                {http.StatusUnauthorized, "insufficient_user_authentication"},
		ceremony.DecisionUnavailable:           {http.StatusServiceUnavailable, "temporarily_unavailable"},
		ceremony.DecisionRefuseWithoutRedirect: {http.StatusBadRequest, "invalid_request"},
	} {
		rec := serve(ceremonyhttp.NewAuthorizeHandler(&decider{d: ceremony.AuthorizeDecision{Kind: kind, RequiredLevel: "2"}}),
			http.MethodGet, ceremonyhttp.AuthorizePath, "")
		var body map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != want.status || body["error"] != want.errw || rec.Header().Get("Location") != "" {
			t.Errorf("вид %d: %d %q, ожидалось %d %s", kind, rec.Code, rec.Body.String(), want.status, want.errw)
		}
	}
}

// TestDiscoveryIsPublicMaterialOnly — координаты церемонии от издателя, метод
// только GET, ни слова о секретах.
func TestDiscoveryIsPublicMaterialOnly(t *testing.T) {
	h, err := ceremonyhttp.NewDiscoveryHandler("https://issuer.test")
	if err != nil {
		t.Fatalf("документ: %v", err)
	}
	rec := serve(h, http.MethodGet, ceremonyhttp.DiscoveryPath, "")
	var md map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &md) != nil {
		t.Fatalf("обнаружение: %d %q", rec.Code, rec.Body.String())
	}
	if md["issuer"] != "https://issuer.test" || md["authorization_endpoint"] != "https://issuer.test/iam/v1/authorize" ||
		md["token_endpoint"] != "https://issuer.test/iam/v1/token" {
		t.Fatalf("координаты: %v", md)
	}
	if strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("документ говорит о секрете: %s", rec.Body.String())
	}
	if rec := serve(h, http.MethodPost, ceremonyhttp.DiscoveryPath, ""); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST: %d, Allow %q", rec.Code, rec.Header().Get("Allow"))
	}

	slashed, err := ceremonyhttp.NewDiscoveryHandler("https://issuer.test/")
	if err != nil {
		t.Fatalf("документ: %v", err)
	}
	if body := serve(slashed, http.MethodGet, ceremonyhttp.DiscoveryPath, "").Body.String(); strings.Contains(body, "test//iam") {
		t.Fatalf("хвостовой слэш издателя удвоен в координатах: %s", body)
	}
	if _, err := ceremonyhttp.NewDiscoveryHandler(" "); err == nil {
		t.Fatal("документ без издателя построен")
	}
}
