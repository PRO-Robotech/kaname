// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyhttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/oauthceremony"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// untouchedEngine — церемония, которую отказ до доверия цели звать не вправе.
type untouchedEngine struct{ calls int }

func (e *untouchedEngine) Authorize(context.Context, oauthceremony.AuthorizationRequest) (oauthceremony.AuthorizationIntent, error) {
	e.calls++
	return oauthceremony.AuthorizationIntent{}, errors.New("engine reached")
}

func (e *untouchedEngine) CompleteAuthorization(context.Context, oauthceremony.AuthorizationIntent, oauthceremony.AuthorizationGrant) (oauthceremony.AuthorizationResult, error) {
	e.calls++
	return oauthceremony.AuthorizationResult{}, errors.New("engine reached")
}

func (e *untouchedEngine) Exchange(context.Context, oauthceremony.TokenRequest) (oauthceremony.TokenResult, error) {
	e.calls++
	return oauthceremony.TokenResult{}, errors.New("engine reached")
}

// directory — справочник пробы: один ACTIVE клиент с одной целью.
type directory struct {
	err error
}

const (
	knownClient = "ic-known"
	knownTarget = "https://app.example.test/cb"
)

func (d directory) LookupClient(_ context.Context, id string) (oauthceremony.ClientRegistration, error) {
	if d.err != nil {
		return oauthceremony.ClientRegistration{}, d.err
	}
	if id != knownClient {
		return oauthceremony.ClientRegistration{}, oauthceremony.ErrGrantNotFound
	}
	return oauthceremony.ClientRegistration{ClientID: knownClient, RedirectURIs: []string{knownTarget},
		Audiences: []string{"https://api.example.test"}}, nil
}

// silentAuthority — шов входа, которого отказ до доверия цели не спрашивает.
type silentAuthority struct{ calls int }

func (a *silentAuthority) Resolve(context.Context, domain.SessionBearer) (Login, bool, error) {
	a.calls++
	return Login{}, false, nil
}

func newTestAuthorize(t *testing.T, d Clients) (*Authorize, *untouchedEngine, *silentAuthority, *Census) {
	t.Helper()
	engine, authority, census := &untouchedEngine{}, &silentAuthority{}, NewCensus()
	a, err := NewAuthorize(AuthorizeConfig{Engine: engine, Clients: d, Authority: authority, Census: census,
		Logger: slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)), Clock: time.Now})
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}
	return a, engine, authority, census
}

func authorizeGet(a *Authorize, q url.Values) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, AuthorizePath+"?"+q.Encode(), nil))
	return rec
}

// Отказ ДО доверия цели — без перенаправления, одним ответом на все причины, и
// ни церемония, ни шов входа не спрошены. Близнец — цель доверена: такой отказ
// не наступает (запрос доходит до протокола).
func TestAuthorize_UntrustedTargetRefusalsAreOneAnswerWithoutRedirect(t *testing.T) {
	a, engine, authority, census := newTestAuthorize(t, directory{})
	cases := map[string]url.Values{
		"клиента нет":          {"client_id": {"ic-unknown"}, "redirect_uri": {knownTarget}},
		"цель не та":           {"client_id": {knownClient}, "redirect_uri": {knownTarget + "/"}},
		"клиент не назван":     {"redirect_uri": {knownTarget}},
		"цель названа дважды":  {"client_id": {knownClient}, "redirect_uri": {knownTarget, knownTarget}},
		"клиент назван дважды": {"client_id": {knownClient, knownClient}, "redirect_uri": {knownTarget}},
	}
	var first *httptest.ResponseRecorder
	for what, q := range cases {
		rec := authorizeGet(a, q)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Errorf("%s: %d, Location %q — ожидался 400 без перенаправления", what, rec.Code, rec.Header().Get("Location"))
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: ответ кэшируем", what)
		}
		if first == nil {
			first = rec
		} else if rec.Body.String() != first.Body.String() {
			t.Errorf("%s: тело отличимо от прочих отказов до доверия цели: %q", what, rec.Body.String())
		}
	}
	if engine.calls != 0 || authority.calls != 0 {
		t.Errorf("отказ до доверия цели позвал церемонию (%d) либо шов входа (%d)", engine.calls, authority.calls)
	}
	read := census.Read()
	if read[string(OutcomeAuthorizeClientUnknown)] != 1 || read[string(OutcomeAuthorizeRedirectUnregistered)] != 1 ||
		read[string(OutcomeAuthorizeRequestMalformed)] != 3 {
		t.Errorf("перепись отказов до доверия цели: %v", read)
	}

	twin := authorizeGet(a, url.Values{"client_id": {knownClient}, "redirect_uri": {knownTarget}})
	if twin.Code == http.StatusBadRequest && twin.Body.String() == first.Body.String() {
		t.Errorf("близнец: доверенная цель получила отказ до доверия")
	}
}

// Справочник не ответил, пока цель не доверена, — 503 без перенаправления.
func TestAuthorize_DirectoryFailureIsUnavailableWithoutRedirect(t *testing.T) {
	a, _, _, _ := newTestAuthorize(t, directory{err: errors.New("store down")})
	rec := authorizeGet(a, url.Values{"client_id": {knownClient}, "redirect_uri": {knownTarget}})
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Location") != "" ||
		strings.Contains(rec.Body.String(), "store down") {
		t.Fatalf("отказ справочника: %d %q Location %q", rec.Code, rec.Body.String(), rec.Header().Get("Location"))
	}
}

// После доверия цели отказ пола `state` — перенаправление с ровно `error`;
// собственная строка запроса цели сохранена. Протокол до церемонии не дошёл.
func TestAuthorize_StateBelowTheFloorIsRedirectedWithOnlyTheError(t *testing.T) {
	a, engine, _, _ := newTestAuthorize(t, directory{})
	q := url.Values{"client_id": {knownClient}, "redirect_uri": {knownTarget}, "state": {strings.Repeat("s", StateFloor-1)}}
	rec := authorizeGet(a, q)
	if rec.Code != http.StatusFound {
		t.Fatalf("короткий state: %d, ожидалось 302", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Scheme+"://"+loc.Host+loc.Path != knownTarget {
		t.Fatalf("перенаправление не на цель клиента: %q", rec.Header().Get("Location"))
	}
	if got := loc.Query(); len(got) != 1 || got.Get("error") != "invalid_request" {
		t.Errorf("строка запроса отказа %v, ожидалась ровно error=invalid_request", got)
	}
	if engine.calls != 0 {
		t.Errorf("отказ пола state позвал церемонию")
	}
}

func TestAuthorize_OnlyGetIsServed(t *testing.T) {
	a, _, _, _ := newTestAuthorize(t, directory{})
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		a.ServeHTTP(rec, httptest.NewRequest(m, AuthorizePath, nil))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodGet {
			t.Errorf("%s: %d, Allow %q", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
}

// Уровень запроса — наименьший из перечисленных; значение вне оси — отказ, а не
// «нет требования».
func TestRequiredLevel(t *testing.T) {
	for in, want := range map[string]int{"": 0, "2": 2, "3 2": 2, " 1  3 ": 1} {
		got, ok := requiredLevel(in)
		if !ok || got != want {
			t.Errorf("acr_values %q: %d (%v), ожидалось %d", in, got, ok, want)
		}
	}
	for _, bad := range []string{"0", "4", "2 gold", "silver"} {
		if _, ok := requiredLevel(bad); ok {
			t.Errorf("acr_values %q принят", bad)
		}
	}
}

// Словарь отказов точки авторизации — RFC 6749 §4.1.2.1; прочие случаи
// церемонии уезжают ближайшим словом, пятисотые — server_error.
func TestAuthorizeWire(t *testing.T) {
	for code, want := range map[oauthceremony.FailureCode]string{
		oauthceremony.CodeInvalidRequest:          "invalid_request",
		oauthceremony.CodeUnsupportedResponseType: "unsupported_response_type",
		oauthceremony.CodeInvalidScope:            "invalid_scope",
		oauthceremony.CodeUnsupportedResponseMode: "invalid_request",
		oauthceremony.CodeInvalidState:            "invalid_request",
		oauthceremony.CodePortContract:            "server_error",
		oauthceremony.CodePortDeadline:            "temporarily_unavailable",
	} {
		if got := authorizeWire(code); got != want {
			t.Errorf("%s → %q, ожидалось %q", code, got, want)
		}
	}
}

// Адреса точек — от издателя без пути; издатель с путём, строкой запроса,
// сведениями пользователя или не https — отказ сборки.
func TestEndpoints(t *testing.T) {
	for _, issuer := range []string{"https://iam.example.test", "https://iam.example.test/"} {
		authz, token, err := Endpoints(issuer)
		if err != nil || authz != "https://iam.example.test"+AuthorizePath || token != "https://iam.example.test/iam/v1/token" {
			t.Errorf("издатель %q: %q %q %v", issuer, authz, token, err)
		}
	}
	for _, bad := range []string{"", "iam.example.test", "http://iam.example.test", "https://iam.example.test/iam",
		"https://iam.example.test?x=1", "https://u:p@iam.example.test", "https://iam.example.test#f"} {
		if _, _, err := Endpoints(bad); err == nil {
			t.Errorf("издатель %q принят", bad)
		}
	}
}

// Метаданные — публичный документ RFC 8414: наши координаты и словари, метод —
// только GET.
func TestDiscovery(t *testing.T) {
	d, err := NewDiscovery(DiscoveryConfig{
		Issuer: "https://iam.example.test", AuthorizationEndpoint: "https://iam.example.test" + AuthorizePath,
		TokenEndpoint: "https://iam.example.test/iam/v1/token", GrantTypes: []string{"authorization_code", "refresh_token"},
		Scopes: domain.CeremonyScopes(),
	})
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, DiscoveryPath, nil))
	var md map[string]any
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &md) != nil {
		t.Fatalf("метаданные: %d %q", rec.Code, rec.Body.String())
	}
	if md["issuer"] != "https://iam.example.test" || md["code_challenge_methods_supported"].([]any)[0] != "S256" {
		t.Errorf("метаданные: %v", md)
	}
	post := httptest.NewRecorder()
	d.ServeHTTP(post, httptest.NewRequest(http.MethodPost, DiscoveryPath, nil))
	if post.Code != http.StatusMethodNotAllowed || post.Header().Get("Allow") != http.MethodGet {
		t.Errorf("POST: %d Allow %q", post.Code, post.Header().Get("Allow"))
	}
	if _, err := NewDiscovery(DiscoveryConfig{Issuer: "https://iam.example.test"}); err == nil {
		t.Errorf("метаданные без адресов точек собраны")
	}
}
