// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// handler_test.go — HTTP-контракт полосы формы (фаза Ф3, `kacho#1269`): четыре
// глагола Р2, формы запроса и ответа, печенья Р3, отказы с фиксированными
// текстами, допуск слушателя РОВНО краем (Р16, Ф3-29, Ф3-51), один адрес
// источника (Р10). Варианты использования подставлены дублёрами: предмет проб —
// транспорт.
package loginlanehttp_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

const (
	trustDomain = "kacho.cloud"
	gatewaySAN  = "spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"
	vpcSAN      = "spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc"
	strangerSAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-stranger"
)

var base = time.Date(2026, 9, 16, 12, 0, 0, 123456000, time.UTC)

// stubLane — дублёр глаголов: отвечает объявленным исходом и записывает вход.
type stubLane struct {
	loginOut  humansession.LoginOutput
	loginErr  error
	logoutErr error
	changeOut humansession.ChangePasswordOutput
	changeErr error

	loginIn   []humansession.LoginInput
	logoutIn  []domain.SessionBearer
	changeIn  []humansession.ChangePasswordInput
	logoutHit int

	// Восстановление доступа (Ф5) — методы в recovery_test.go.
	requestErr  error
	completeOut humansession.CompleteRecoveryOutput
	completeErr error
	requestIn   []humansession.RequestRecoveryInput
	completeIn  []humansession.CompleteRecoveryInput
}

func (s *stubLane) Login(_ context.Context, in humansession.LoginInput) (humansession.LoginOutput, error) {
	s.loginIn = append(s.loginIn, in)
	return s.loginOut, s.loginErr
}

func (s *stubLane) Logout(_ context.Context, b domain.SessionBearer) (bool, error) {
	s.logoutIn = append(s.logoutIn, b)
	s.logoutHit++
	return s.logoutErr == nil, s.logoutErr
}

func (s *stubLane) ChangePassword(_ context.Context, in humansession.ChangePasswordInput) (humansession.ChangePasswordOutput, error) {
	s.changeIn = append(s.changeIn, in)
	return s.changeOut, s.changeErr
}

func sessionView() humansession.SessionView {
	return humansession.SessionView{
		User: domain.User{ID: "usr-a", Email: "a@example.invalid", DisplayName: "Ann"},
		Session: domain.HumanSession{ID: "hss-1", UserID: "usr-a", AuthenticatedAt: base, LastPresentedAt: base,
			ExpiresAt: base.Add(24 * time.Hour), AssuranceLevel: "1", PresentedMethods: []string{"password"}},
		EmailVerified: true,
	}
}

type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
	der  []byte
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "probe-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &testCA{key: key, cert: parsed, der: der}
}

func (c *testCA) leaf(t *testing.T, san string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	if san != "" {
		u, err := url.Parse(san)
		require.NoError(t, err)
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type lane struct {
	srv  *httptest.Server
	ca   *testCA
	stub *stubLane
}

func newLane(t *testing.T, stub *stubLane, cookieDomain string) *lane {
	t.Helper()
	ca := newCA(t)
	h, err := loginlanehttp.New(loginlanehttp.Config{
		SessionTTL:    24 * time.Hour,
		CookieDomain:  cookieDomain,
		TrustDomain:   grpcsrv.NewTrustDomain(trustDomain),
		RefusalDomain: "iam.kaname.cloud",
		Logger:        slog.New(slog.DiscardHandler),
	}, stub)
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(h)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.leaf(t, "", x509.ExtKeyUsageServerAuth)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &lane{srv: srv, ca: ca, stub: stub}
}

func (l *lane) client(t *testing.T, san string) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(l.ca.cert)
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if san != "" {
		cfg.Certificates = []tls.Certificate{l.ca.leaf(t, san, x509.ExtKeyUsageClientAuth)}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
}

type reply struct {
	status  int
	body    string
	cookies []*http.Cookie
	header  http.Header
}

func (l *lane) do(t *testing.T, c *http.Client, method, path string, body any, headers map[string]string, cookies ...*http.Cookie) reply {
	t.Helper()
	var rd io.Reader
	if body != nil {
		if s, ok := body.(string); ok {
			rd = strings.NewReader(s)
		} else {
			b, err := json.Marshal(body)
			require.NoError(t, err)
			rd = bytes.NewReader(b)
		}
	}
	req, err := http.NewRequest(method, l.srv.URL+path, rd)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	resp, err := c.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return reply{status: resp.StatusCode, body: string(b), cookies: resp.Cookies(), header: resp.Header}
}

func cookieNamed(cs []*http.Cookie, name string) *http.Cookie {
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// csrf — признак вида для контекста: контекст берётся из ответа csrf-глагола.
func (l *lane) csrf(t *testing.T, c *http.Client, kind string, ctxCookie *http.Cookie) (string, *http.Cookie) {
	t.Helper()
	var r reply
	if ctxCookie != nil {
		r = l.do(t, c, http.MethodGet, "/iam/v1/auth/csrf?form="+kind, nil, nil, ctxCookie)
	} else {
		r = l.do(t, c, http.MethodGet, "/iam/v1/auth/csrf?form="+kind, nil, nil)
	}
	require.Equal(t, http.StatusOK, r.status, r.body)
	var out struct {
		CSRFToken string `json:"csrfToken"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &out))
	if ck := cookieNamed(r.cookies, "kaname_form"); ck != nil {
		return out.CSRFToken, ck
	}
	return out.CSRFToken, ctxCookie
}

// TestLane_F3_35_CSRFIssuesAContextAndAToken — признак выдаётся держателю
// контекста; печенье контекста без срока и с атрибутами; повтор контекст не
// меняет; вид вне перечня — 400 с полем.
func TestLane_F3_35_CSRFIssuesAContextAndAToken(t *testing.T) {
	l := newLane(t, &stubLane{}, "")
	c := l.client(t, gatewaySAN)
	r := l.do(t, c, http.MethodGet, "/iam/v1/auth/csrf?form=login", nil, nil)
	require.Equal(t, http.StatusOK, r.status, r.body)
	ck := cookieNamed(r.cookies, "kaname_form")
	require.NotNil(t, ck, "Set-Cookie: kaname_form")
	require.True(t, ck.HttpOnly)
	require.True(t, ck.Secure)
	require.Equal(t, http.SameSiteLaxMode, ck.SameSite)
	require.Equal(t, "/", ck.Path)
	require.Zero(t, ck.MaxAge, "без срока — сеансовое")
	require.True(t, ck.Expires.IsZero())
	var out struct {
		CSRFToken string `json:"csrfToken"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &out))
	require.NotEmpty(t, out.CSRFToken)
	require.NotContains(t, out.CSRFToken, ck.Value[:6], "из признака контекст не читается")

	again := l.do(t, c, http.MethodGet, "/iam/v1/auth/csrf?form=login", nil, nil, ck)
	require.Nil(t, cookieNamed(again.cookies, "kaname_form"), "повторный запрос контекст не меняет")

	bad := l.do(t, c, http.MethodGet, "/iam/v1/auth/csrf?form=register", nil, nil, ck)
	require.Equal(t, http.StatusBadRequest, bad.status)
	require.Contains(t, bad.body, `"Illegal argument form:`)
}

// TestLane_F3_01_LoginIssuesTheSessionCookieAndANewFormContext — успешный вход:
// тело Ф3-01, `Set-Cookie: kaname_session` с атрибутами Р3 и НОВЫЙ `kaname_form`;
// адрес источника — ровно из `X-Forwarded-For`.
func TestLane_F3_01_LoginIssuesTheSessionCookieAndANewFormContext(t *testing.T) {
	bearer, _ := domain.NewSessionBearer()
	stub := &stubLane{loginOut: humansession.LoginOutput{View: sessionView(), Bearer: bearer}}
	l := newLane(t, stub, "console.example.invalid")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "login", nil)

	r := l.do(t, c, http.MethodPost, "/iam/v1/auth/login",
		map[string]string{"email": "a@example.invalid", "password": "pw", "csrfToken": tok},
		map[string]string{"X-Forwarded-For": "203.0.113.7"}, ctxCk)
	require.Equal(t, http.StatusOK, r.status, r.body)
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.body), &body))
	user := body["user"].(map[string]any)
	require.Equal(t, "usr-a", user["id"])
	require.Equal(t, "a@example.invalid", user["email"])
	require.Equal(t, "Ann", user["displayName"])
	sess := body["session"].(map[string]any)
	require.Equal(t, "1", sess["assuranceLevel"])
	require.Equal(t, true, sess["emailVerified"])
	require.Equal(t, false, sess["passwordChangeRequired"])
	require.Equal(t, base.Add(24*time.Hour).Format(time.RFC3339), sess["expiresAt"], "expiresAt с точностью до секунды")
	require.NotContains(t, r.body, bearer.CookieValue(), "носитель не в теле")

	sc := cookieNamed(r.cookies, "kaname_session")
	require.NotNil(t, sc)
	require.Equal(t, bearer.CookieValue(), sc.Value)
	require.Equal(t, 86400, sc.MaxAge, "Ф3-06: Max-Age=86400")
	require.True(t, sc.HttpOnly)
	require.True(t, sc.Secure)
	require.Equal(t, http.SameSiteLaxMode, sc.SameSite)
	require.Equal(t, "/", sc.Path)
	require.Equal(t, "console.example.invalid", sc.Domain, "Ф3-06: Domain на посадке с именем")
	fc := cookieNamed(r.cookies, "kaname_form")
	require.NotNil(t, fc, "Ф3-37: контекст сменён входом")
	require.NotEqual(t, ctxCk.Value, fc.Value)

	require.Len(t, stub.loginIn, 1)
	require.Equal(t, "203.0.113.7", stub.loginIn[0].Source, "источник — заголовок допущенного, один адрес")
	require.Equal(t, "a@example.invalid", stub.loginIn[0].Email)
}

// TestLane_F3_07_NoDomainKeyOnAddressPosture — на адресной посадке ключ Domain
// не печатается вовсе (Ф1-10, kacho#1222).
func TestLane_F3_07_NoDomainKeyOnAddressPosture(t *testing.T) {
	bearer, _ := domain.NewSessionBearer()
	stub := &stubLane{loginOut: humansession.LoginOutput{View: sessionView(), Bearer: bearer}}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "login", nil)
	r := l.do(t, c, http.MethodPost, "/iam/v1/auth/login",
		map[string]string{"email": "a@example.invalid", "password": "pw", "csrfToken": tok}, nil, ctxCk)
	require.Equal(t, http.StatusOK, r.status, r.body)
	for _, raw := range r.header.Values("Set-Cookie") {
		require.NotContains(t, strings.ToLower(raw), "domain=", "Ф3-07: ключа Domain нет: %s", raw)
	}
}

// TestLane_F3_02_RefusalsAreFixedTextsWithoutSetCookie — 401 authentication
// failed без Set-Cookie; 429 с reason и Retry-After; 400 с полем; лишнее поле
// отвергается; 503 фиксированным текстом; форма без признака — 400, чужой
// признак — 403 FORM_TOKEN_REJECTED и глагол не исполнен.
func TestLane_F3_02_RefusalsAreFixedTextsWithoutSetCookie(t *testing.T) {
	stub := &stubLane{loginErr: humansession.ErrAuthenticationFailed}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "login", nil)
	form := map[string]string{"email": "a@example.invalid", "password": "pw", "csrfToken": tok}

	r := l.do(t, c, http.MethodPost, "/iam/v1/auth/login", form, nil, ctxCk)
	require.Equal(t, http.StatusUnauthorized, r.status)
	require.JSONEq(t, `{"code":16,"message":"authentication failed","details":[]}`, r.body)
	require.Empty(t, r.cookies, "без Set-Cookie")
	first := r.body

	stub.loginErr = &humansession.TooManyAttemptsError{Scope: humansession.FailureByAddress, RetryAfter: 90 * time.Second}
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/login", form, nil, ctxCk)
	require.Equal(t, http.StatusTooManyRequests, r.status)
	require.Equal(t, "90", r.header.Get("Retry-After"))
	require.Contains(t, r.body, `"reason":"TOO_MANY_ATTEMPTS"`)
	require.Contains(t, r.body, `"too many attempts; try again later"`)
	require.Contains(t, r.body, `"domain":"iam.kaname.cloud"`)

	stub.loginErr = humansession.ErrStoreUnavailable
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/login", form, nil, ctxCk)
	require.Equal(t, http.StatusServiceUnavailable, r.status)
	require.JSONEq(t, `{"code":14,"message":"request not performed; try again later","details":[]}`, r.body)
	require.Empty(t, r.cookies)

	stub.loginErr = humansession.ErrAuthenticationFailed
	hits := len(stub.loginIn)
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/login", map[string]string{"email": "a@example.invalid", "csrfToken": tok}, nil, ctxCk)
	require.Equal(t, http.StatusBadRequest, r.status)
	require.Contains(t, r.body, `"Illegal argument password: required"`)
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/login", map[string]string{"email": "a@example.invalid", "password": "pw", "csrfToken": tok, "remember": "yes"}, nil, ctxCk)
	require.Equal(t, http.StatusBadRequest, r.status)
	require.Contains(t, r.body, `remember`, "лишнее поле называется")
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/login", map[string]string{"email": "a@example.invalid", "password": "pw"}, nil, ctxCk)
	require.Equal(t, http.StatusBadRequest, r.status)
	require.Contains(t, r.body, `"Illegal argument csrfToken: required"`)
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/login", map[string]string{"email": "a@example.invalid", "password": "pw", "csrfToken": "not-it"}, nil, ctxCk)
	require.Equal(t, http.StatusForbidden, r.status)
	require.Contains(t, r.body, `"reason":"FORM_TOKEN_REJECTED"`)
	require.Contains(t, r.body, `"form token rejected"`)
	require.Equal(t, hits, len(stub.loginIn), "отказы формы глагол не исполняют")
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/login", "{not json", nil, ctxCk)
	require.Equal(t, http.StatusBadRequest, r.status)

	// Отказ входа — один текст: второй раз тело побайтово то же.
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/login", form, nil, ctxCk)
	require.Equal(t, first, r.body)
}

// TestLane_F3_15_18_LogoutEndsTheCarrierAndIsTheSameWithoutASession — выход:
// 200 {}, `kaname_session=; Max-Age=0`, контекст формы не тронут; без носителя —
// побайтово тот же ответ; при недоступном хранилище — 503 своим текстом без
// Set-Cookie.
func TestLane_F3_15_18_LogoutEndsTheCarrierAndIsTheSameWithoutASession(t *testing.T) {
	stub := &stubLane{}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "logout", nil)
	sess := &http.Cookie{Name: "kaname_session", Value: "opaque-bearer-value"}

	r := l.do(t, c, http.MethodPost, "/iam/v1/auth/logout", map[string]string{"csrfToken": tok}, nil, ctxCk, sess)
	require.Equal(t, http.StatusOK, r.status, r.body)
	require.JSONEq(t, `{}`, r.body)
	sc := cookieNamed(r.cookies, "kaname_session")
	require.NotNil(t, sc)
	require.Empty(t, sc.Value)
	require.Equal(t, -1, sc.MaxAge, "Max-Age=0 на проводе")
	require.True(t, sc.HttpOnly)
	require.True(t, sc.Secure)
	require.Nil(t, cookieNamed(r.cookies, "kaname_form"), "выход контекст не трогает (Р12)")
	require.Equal(t, "opaque-bearer-value", stub.logoutIn[0].CookieValue())
	withSession := r.body
	setCookie := r.header.Get("Set-Cookie")

	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/logout", map[string]string{"csrfToken": tok}, nil, ctxCk)
	require.Equal(t, http.StatusOK, r.status)
	require.Equal(t, withSession, r.body, "Ф3-18: побайтово тот же ответ")
	require.Equal(t, setCookie, r.header.Get("Set-Cookie"))

	stub.logoutErr = humansession.ErrStoreUnavailable
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/logout", map[string]string{"csrfToken": tok}, nil, ctxCk, sess)
	require.Equal(t, http.StatusServiceUnavailable, r.status)
	require.JSONEq(t, `{"code":14,"message":"logout not performed; try again later","details":[]}`, r.body)
	require.Empty(t, r.cookies, "Ф1-58: носитель цел")
}

// TestLane_F3_19_20_ChangePasswordReissuesTheCarrier — смена: 200 с телом
// {session}, новый kaname_session; отказы: поле, 401, правило пароля с полем.
func TestLane_F3_19_20_ChangePasswordReissuesTheCarrier(t *testing.T) {
	fresh, _ := domain.NewSessionBearer()
	stub := &stubLane{changeOut: humansession.ChangePasswordOutput{View: sessionView(), Bearer: fresh}}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, c, "password", nil)
	sess := &http.Cookie{Name: "kaname_session", Value: "old-bearer"}

	r := l.do(t, c, http.MethodPost, "/iam/v1/auth/password",
		map[string]string{"currentPassword": "old", "newPassword": "new passphrase", "csrfToken": tok},
		map[string]string{"X-Forwarded-For": "203.0.113.7"}, ctxCk, sess)
	require.Equal(t, http.StatusOK, r.status, r.body)
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.body), &body))
	require.Contains(t, body, "session")
	sc := cookieNamed(r.cookies, "kaname_session")
	require.NotNil(t, sc)
	require.Equal(t, fresh.CookieValue(), sc.Value)
	require.Equal(t, 86400, sc.MaxAge)
	require.Equal(t, "old-bearer", stub.changeIn[0].Bearer.CookieValue())
	require.Equal(t, "203.0.113.7", stub.changeIn[0].Source)

	stub.changeErr = &humansession.FieldError{Field: "newPassword", Rule: humansession.RuleTooShort}
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/password",
		map[string]string{"currentPassword": "old", "newPassword": "x", "csrfToken": tok}, nil, ctxCk, sess)
	require.Equal(t, http.StatusBadRequest, r.status)
	require.Contains(t, r.body, `"Illegal argument newPassword: shorter than the declared minimum length"`)
	stub.changeErr = humansession.ErrAuthenticationFailed
	r = l.do(t, c, http.MethodPost, "/iam/v1/auth/password",
		map[string]string{"currentPassword": "old", "newPassword": "new passphrase", "csrfToken": tok}, nil, ctxCk)
	require.Equal(t, http.StatusUnauthorized, r.status)
	require.JSONEq(t, `{"code":16,"message":"authentication failed","details":[]}`, r.body)
	require.Empty(t, r.cookies)
}

// TestLane_F3_29_51_OnlyTheGatewayIsAdmitted — пир с сертификатом, чьё имя
// службы не край — из круга (kacho-vpc) и вне его — получает 403 `permission
// denied`, тело не читается и глагол не исполнен; пир без сертификата — отказ
// рукопожатия; край — исполнение. Переданная личность (заголовки x-kacho-*)
// не читается: исход с ними побайтово равен исходу без них.
func TestLane_F3_29_51_OnlyTheGatewayIsAdmitted(t *testing.T) {
	stub := &stubLane{logoutErr: nil}
	l := newLane(t, stub, "")
	gw := l.client(t, gatewaySAN)
	tok, ctxCk := l.csrf(t, gw, "password", nil)
	form := map[string]string{"currentPassword": "old", "newPassword": "new passphrase", "csrfToken": tok}
	sess := &http.Cookie{Name: "kaname_session", Value: "bearer"}

	for name, san := range map[string]string{"из круга, не край": vpcSAN, "вне круга": strangerSAN} {
		t.Run(name, func(t *testing.T) {
			before := len(stub.changeIn)
			r := l.do(t, l.client(t, san), http.MethodPost, "/iam/v1/auth/password", form, nil, ctxCk, sess)
			require.Equal(t, http.StatusForbidden, r.status)
			require.JSONEq(t, `{"code":7,"message":"permission denied","details":[]}`, r.body)
			require.Equal(t, before, len(stub.changeIn), "глагол не исполнен")
			r = l.do(t, l.client(t, san), http.MethodGet, "/iam/v1/auth/csrf?form=login", nil, nil)
			require.Equal(t, http.StatusForbidden, r.status)
		})
	}
	t.Run("без сертификата — отказ рукопожатия", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, l.srv.URL+"/iam/v1/auth/csrf?form=login", nil)
		require.NoError(t, err)
		_, err = l.client(t, "").Do(req)
		require.Error(t, err)
	})
	t.Run("край исполняет; переданная личность не читается", func(t *testing.T) {
		stub.changeOut = humansession.ChangePasswordOutput{View: sessionView(), Bearer: domain.PresentedSessionBearer("fresh")}
		plain := l.do(t, gw, http.MethodPost, "/iam/v1/auth/password", form, nil, ctxCk, sess)
		require.Equal(t, http.StatusOK, plain.status, plain.body)
		withHeaders := l.do(t, gw, http.MethodPost, "/iam/v1/auth/password", form, map[string]string{
			"x-kacho-principal-type": "user", "x-kacho-principal-id": "usr-b",
			"Grpc-Metadata-x-kacho-principal-id": "usr-b",
		}, ctxCk, sess)
		require.Equal(t, plain.status, withHeaders.status)
		require.Equal(t, plain.body, withHeaders.body, "Ф3-51: исход с заголовками принципала чужого субъекта побайтово тот же")
		require.Equal(t, "bearer", stub.changeIn[len(stub.changeIn)-1].Bearer.CookieValue(), "субъект — по носителю, не по заголовку")
	})
}

// TestLane_F3_23_CSRFIsIssuedWithoutASession — признак формы выдаётся и без
// сессии (Р8: шаг смены обязан быть конструируем).
func TestLane_F3_23_CSRFIsIssuedWithoutASession(t *testing.T) {
	l := newLane(t, &stubLane{}, "")
	r := l.do(t, l.client(t, gatewaySAN), http.MethodGet, "/iam/v1/auth/csrf?form=password", nil, nil)
	require.Equal(t, http.StatusOK, r.status)
}

// TestLane_UnknownPathAndMethod — путь семейства вне четырёх глаголов — 404;
// метод не тот — 405.
func TestLane_UnknownPathAndMethod(t *testing.T) {
	l := newLane(t, &stubLane{}, "")
	c := l.client(t, gatewaySAN)
	r := l.do(t, c, http.MethodGet, "/iam/v1/auth/me", nil, nil)
	require.Equal(t, http.StatusNotFound, r.status, "«кто я» — маршрут края, не службы")
	r = l.do(t, c, http.MethodGet, "/iam/v1/auth/login", nil, nil)
	require.Equal(t, http.StatusMethodNotAllowed, r.status)
}
