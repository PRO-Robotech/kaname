// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyhttp

// pace_test.go — оси П4 и П5 точки авторизации и правило адреса источника на
// настоящем слушателе (приёмка ceremony-pace-is-named-by-number.md, kaname#315,
// группы E и F, KN-PACE-37).
//
// Посев А: клиент C (knownClient) с адресом возврата r (knownTarget); «годный
// запрос А» — `client_id=C`, `redirect_uri=r`, `response_type=code`,
// `code_challenge` по S256, `state` длиной 22 знака, без печенья сессии. Его
// ответ — исход без сессии по Р11 (ред. 5, задача kaname#525): 302 на r с
// ровно `error=login_required` и `state` дословно («ответ без сессии»). Пробы
// групп E и F утверждают о нём только то, что он не отказ по темпу; форму
// утверждает группа I. Для удержаний — клиент D, обращения за которым
// справочник держит до сигнала.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/oauthceremony"

	ceremonyapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/oauth_ceremony"
	"github.com/PRO-Robotech/kaname/internal/exchangepace"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
	"github.com/PRO-Robotech/kaname/internal/issuingsource"
	"github.com/PRO-Robotech/kaname/internal/testsupport/issuinglistener"
)

// Числа §3 приёмки.
const (
	authorizePace    = 10
	authorizeCeiling = 32
	heldClient       = "ic-held"
)

const (
	sourceP = "198.51.100.1"
	sourceQ = "198.51.100.2"
)

const tooManyAuthorizeText = "Too many authorization requests: retry later.\n"

var paceT0 = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

type paceClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *paceClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *paceClock) At(offset time.Duration) {
	c.mu.Lock()
	c.now = paceT0.Add(offset)
	c.mu.Unlock()
}

// holdingDirectory — справочник посева А: обращения за D стоят до сигнала,
// прочие отвечает справочник пробы тем же кодом.
type holdingDirectory struct {
	calls   atomic.Int64
	entered chan string
	release chan struct{}
}

func newHoldingDirectory() *holdingDirectory {
	return &holdingDirectory{entered: make(chan string, 64), release: make(chan struct{})}
}

func (d *holdingDirectory) LookupClient(ctx context.Context, id string) (oauthceremony.ClientRegistration, error) {
	d.calls.Add(1)
	if id == heldClient {
		d.entered <- id
		select {
		case <-d.release:
		case <-ctx.Done():
			return oauthceremony.ClientRegistration{}, ctx.Err()
		}
		return oauthceremony.ClientRegistration{ClientID: heldClient, RedirectURIs: []string{knownTarget},
			Audiences: []string{"https://api.example.test"}}, nil
	}
	return directory{}.LookupClient(ctx, id)
}

// seedA — посев А над эндпоинтом авторизации.
type seedA struct {
	t       *testing.T
	clock   *paceClock
	dir     *holdingDirectory
	census  *Census
	a       *Authorize
	held    []chan *httptest.ResponseRecorder
	release sync.Once
}

func newSeedA(t *testing.T, source func(*http.Request) string) *seedA {
	t.Helper()
	s := &seedA{t: t, clock: &paceClock{now: paceT0}, dir: newHoldingDirectory(), census: NewCensus()}
	uc, err := ceremonyapp.NewAuthorizeUseCase(ceremonyapp.AuthorizeDeps{Engine: &protocolPassingEngine{},
		Clients: s.dir, Authority: &silentAuthority{}, Clock: time.Now, CallTimeout: 30 * time.Second,
		FamilyTTL: 2 * time.Hour})
	if err != nil {
		t.Fatalf("сборка варианта использования: %v", err)
	}
	pace, err := exchangepace.New(authorizePace, s.clock.Now)
	if err != nil {
		t.Fatalf("темп: %v", err)
	}
	s.a, err = NewAuthorize(AuthorizeConfig{UseCase: uc, Census: s.census,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Pace: pace, InFlightCeiling: authorizeCeiling,
		Source: source})
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}
	t.Cleanup(s.releaseHolds)
	return s
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// goodQueryA — годный запрос А для клиента.
func goodQueryA(client string) url.Values {
	sum := sha256.Sum256([]byte(strings.Repeat("v", 43)))
	return url.Values{
		"client_id": {client}, "redirect_uri": {knownTarget}, "response_type": {"code"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"state": {strings.Repeat("s", StateFloor)}, "scope": {"openid"},
	}
}

func (s *seedA) do(from, method string, q url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, AuthorizePath+"?"+q.Encode(), nil)
	req.RemoteAddr = from + ":40000"
	rec := httptest.NewRecorder()
	s.a.ServeHTTP(rec, req)
	return rec
}

// hold — «N запросов авторизации удерживаются»: клиент D с адресов A1 … AN.
func (s *seedA) hold(n int) {
	s.t.Helper()
	for i := 1; i <= n; i++ {
		from := fmt.Sprintf("203.0.113.%d", len(s.held)+1)
		done := make(chan *httptest.ResponseRecorder, 1)
		s.held = append(s.held, done)
		go func() { done <- s.do(from, http.MethodGet, goodQueryA(heldClient)) }()
		select {
		case <-s.dir.entered:
		case <-time.After(10 * time.Second):
			s.t.Fatalf("удержание %d не дошло до справочника за 10 с", i)
		}
	}
}

func (s *seedA) releaseHolds() {
	s.release.Do(func() { close(s.dir.release) })
	for _, done := range s.held {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			s.t.Fatal("удержанный запрос не получил ответа после сигнала")
		}
	}
	s.held = nil
}

func (s *seedA) outcome(o Outcome) uint64 { return s.census.Read()[string(o)] }

// requireNoSessionAnswer — ответ без сессии (Р11): 302 на r с ровно
// `error=login_required` и `state` годного запроса А дословно.
func requireNoSessionAnswer(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("ожидался ответ без сессии (302 на r с login_required), получено %d %q", rec.Code, rec.Body.String())
	}
	want := knownTarget + "?" + url.Values{"error": {"login_required"}, "state": {strings.Repeat("s", StateFloor)}}.Encode()
	if loc := rec.Header().Get("Location"); loc != want {
		t.Fatalf("ответ без сессии: Location %q, ожидался %q", loc, want)
	}
}

func requirePaceRefusal(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	requireTextRefusal(t, rec, http.StatusTooManyRequests, tooManyAuthorizeText)
}

func requireCeilingRefusal(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	requireTextRefusal(t, rec, http.StatusServiceUnavailable, "The authorization server is temporarily unavailable.\n")
}

func requireTextRefusal(t *testing.T, rec *httptest.ResponseRecorder, status int, text string) {
	t.Helper()
	if rec.Code != status || rec.Body.String() != text {
		t.Fatalf("ожидалось %d %q, получено %d %q", status, text, rec.Code, rec.Body.String())
	}
	for header, want := range map[string]string{
		"Content-Type": "text/plain; charset=utf-8", "X-Content-Type-Options": "nosniff",
		"Cache-Control": "no-store", "Retry-After": "1", "Location": "",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("заголовок %s = %q, ожидалось %q", header, got, want)
		}
	}
}

// tenFromP — десять годных запросов А с P в t0, каждый получил ответ без сессии.
func (s *seedA) tenFromP() {
	s.t.Helper()
	for i := 0; i < authorizePace; i++ {
		requireNoSessionAnswer(s.t, s.do(sourceP, http.MethodGet, goodQueryA(knownClient)))
	}
}

// ── Группа E — П4 и П5 ──────────────────────────────────────────────────────

func TestKNPACE26_EleventhRequestFromASourceIs429(t *testing.T) {
	s := newSeedA(t, remoteHost)
	s.tenFromP()
	before := s.dir.calls.Load()

	requirePaceRefusal(t, s.do(sourceP, http.MethodGet, goodQueryA(knownClient)))
	if got := s.outcome(OutcomeAuthorizeSourcePaceExceeded); got != 1 {
		t.Errorf("authorize-source-pace-exceeded = %d, ожидалось 1", got)
	}
	if s.dir.calls.Load() != before {
		t.Error("по отказу П4 справочник клиентов спрашивался")
	}
}

func TestKNPACE27_EleventhRequestAfter100msPasses(t *testing.T) {
	s := newSeedA(t, remoteHost)
	s.tenFromP()
	s.clock.At(100 * time.Millisecond)
	requireNoSessionAnswer(t, s.do(sourceP, http.MethodGet, goodQueryA(knownClient)))
}

func TestKNPACE28_PaceSpendsAnyOutcomeButTheMethodRefusal(t *testing.T) {
	t.Run("a неизвестный клиент", func(t *testing.T) {
		s := newSeedA(t, remoteHost)
		for i := 0; i < authorizePace; i++ {
			rec := s.do(sourceP, http.MethodGet, goodQueryA("ic-unknown"))
			if rec.Code != http.StatusBadRequest || rec.Body.String() != untrustedTargetRefusal {
				t.Fatalf("запрос %d: %d %q — ожидался текст недоверенной цели", i+1, rec.Code, rec.Body.String())
			}
		}
		requirePaceRefusal(t, s.do(sourceP, http.MethodGet, goodQueryA(knownClient)))
	})
	t.Run("b POST", func(t *testing.T) {
		s := newSeedA(t, remoteHost)
		for i := 0; i < authorizePace; i++ {
			if rec := s.do(sourceP, http.MethodPost, goodQueryA(knownClient)); rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("запрос %d: %d — ожидался 405", i+1, rec.Code)
			}
		}
		requireNoSessionAnswer(t, s.do(sourceP, http.MethodGet, goodQueryA(knownClient)))
	})
}

func TestKNPACE29_SourcesAreCountedSeparately(t *testing.T) {
	s := newSeedA(t, remoteHost)
	s.tenFromP()
	requireNoSessionAnswer(t, s.do(sourceQ, http.MethodGet, goodQueryA(knownClient)))
}

func TestKNPACE30_RequestAboveTheAuthorizeCeilingIs503(t *testing.T) {
	s := newSeedA(t, remoteHost)
	s.hold(authorizeCeiling)
	before := s.dir.calls.Load()

	requireCeilingRefusal(t, s.do(sourceQ, http.MethodGet, goodQueryA(knownClient)))
	if got := s.outcome(OutcomeAuthorizeInFlightCeilingReached); got != 1 {
		t.Errorf("authorize-in-flight-ceiling-reached = %d, ожидалось 1", got)
	}
	if s.dir.calls.Load() != before {
		t.Error("по отказу П5 справочник клиентов спрашивался")
	}
}

func TestKNPACE30b_OneHeldFewerRequestIsServed(t *testing.T) {
	s := newSeedA(t, remoteHost)
	s.hold(authorizeCeiling - 1)
	requireNoSessionAnswer(t, s.do(sourceQ, http.MethodGet, goodQueryA(knownClient)))
}

func TestKNPACE31_SourcePaceIsDecidedBeforeTheCeiling(t *testing.T) {
	s := newSeedA(t, remoteHost)
	s.tenFromP()
	s.hold(authorizeCeiling)

	requirePaceRefusal(t, s.do(sourceP, http.MethodGet, goodQueryA(knownClient)))
	if got := s.outcome(OutcomeAuthorizeSourcePaceExceeded); got != 1 {
		t.Errorf("authorize-source-pace-exceeded = %d, ожидалось 1", got)
	}
	requireCeilingRefusal(t, s.do(sourceQ, http.MethodGet, goodQueryA(knownClient)))
	if got := s.outcome(OutcomeAuthorizeInFlightCeilingReached); got != 1 {
		t.Errorf("authorize-in-flight-ceiling-reached = %d, ожидалось 1", got)
	}
}

// ── Группа F — адрес источника на настоящем слушателе ───────────────────────

// listenerA — посев А на настоящем слушателе выдачи в режиме optional-mutual,
// ключ — правило Р7.
type listenerA struct {
	*seedA
	stand *issuinglistener.Stand
	rule  *issuingsource.Rule
}

func newListenerA(t *testing.T) *listenerA {
	t.Helper()
	rule := issuingsource.New(grpcsrv.NewTrustDomain(issuinglistener.TrustDomain))
	s := newSeedA(t, func(r *http.Request) string { return rule.Of(r, issuingsource.PointAuthorize) })
	return &listenerA{seedA: s, stand: issuinglistener.Start(t, s.a), rule: rule}
}

// get — годный запрос А через слушатель: san пуст — пир без сертификата;
// forwarded — значения X-Forwarded-For, каждое отдельным заголовком.
func (l *listenerA) get(san string, forwarded ...string) (int, string) {
	l.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		l.stand.URL+AuthorizePath+"?"+goodQueryA(knownClient).Encode(), nil)
	if err != nil {
		l.t.Fatal(err)
	}
	for _, v := range forwarded {
		req.Header.Add("X-Forwarded-For", v)
	}
	client := l.stand.Client(l.t, san)
	// Перенаправлению ответа без сессии не следуем: судится ответ слушателя,
	// а не адрес возврата приложения.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		l.t.Fatalf("запрос к слушателю: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func (l *listenerA) cells() map[issuingsource.Cell]uint64 { return l.rule.Read() }

func requireOnlyCell(t *testing.T, got map[issuingsource.Cell]uint64, want issuingsource.Cell, n uint64) {
	t.Helper()
	for _, c := range issuingsource.Cells() {
		exp := uint64(0)
		if c == want {
			exp = n
		}
		if got[c] != exp {
			t.Errorf("клетка %s/%s = %d, ожидалось %d", c.Point, c.Reason, got[c], exp)
		}
	}
}

func TestKNPACE32_EdgeRequestCarriesTheClientAddressAndTheKeyIsIt(t *testing.T) {
	l := newListenerA(t)
	for i := 0; i < authorizePace; i++ {
		if code, body := l.get(issuinglistener.EdgeSAN, "203.0.113.7"); code != http.StatusFound {
			t.Fatalf("запрос %d: %d %q — ожидался ответ без сессии", i+1, code, body)
		}
	}
	if code, body := l.get(issuinglistener.EdgeSAN, "203.0.113.7"); code != http.StatusTooManyRequests {
		t.Errorf("первый: %d %q — ожидался 429", code, body)
	}
	if code, body := l.get(issuinglistener.EdgeSAN, "203.0.113.8"); code != http.StatusFound {
		t.Errorf("второй: %d %q — ожидался ответ без сессии", code, body)
	}
	requireOnlyCell(t, l.cells(), issuingsource.Cell{}, 0)
}

func TestKNPACE33_HeaderWithoutEdgeCertificateDoesNotChangeTheKey(t *testing.T) {
	l := newListenerA(t)
	for i := 1; i <= authorizePace+1; i++ {
		code, body := l.get("", fmt.Sprintf("203.0.113.%d", i))
		want := http.StatusFound
		if i == authorizePace+1 {
			want = http.StatusTooManyRequests
		}
		if code != want {
			t.Errorf("запрос %d: %d %q — ожидался %d: ключ всех одиннадцати — адрес пира", i, code, body, want)
		}
	}
	requireOnlyCell(t, l.cells(), issuingsource.Cell{Point: issuingsource.PointAuthorize,
		Reason: issuingsource.ReasonForwardedFromNonEdge}, 11)
}

func TestKNPACE34_NeighborCertificateIsNotTheEdgeCertificate(t *testing.T) {
	l := newListenerA(t)
	var last int
	for i := 1; i <= authorizePace+1; i++ {
		last, _ = l.get(issuinglistener.NeighborSAN, fmt.Sprintf("203.0.113.%d", i))
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("одиннадцатый: %d — ожидался 429", last)
	}
	requireOnlyCell(t, l.cells(), issuingsource.Cell{Point: issuingsource.PointAuthorize,
		Reason: issuingsource.ReasonForwardedFromNonEdge}, 11)
}

func TestKNPACE35_EdgeWithoutUsableAddressSharesItsPeerKey(t *testing.T) {
	for _, row := range []struct {
		name          string
		ten, eleventh []string
	}{
		{"а заголовка нет", nil, nil},
		{"б два значения", []string{"203.0.113.7", "198.51.100.2"}, []string{"203.0.113.8", "198.51.100.3"}},
		{"в список", []string{"203.0.113.7, 198.51.100.2"}, []string{"203.0.113.8, 198.51.100.3"}},
		{"г не адрес", []string{"not-an-address"}, []string{"still-not-an-address"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			l := newListenerA(t)
			for i := 0; i < authorizePace; i++ {
				if code, body := l.get(issuinglistener.EdgeSAN, row.ten...); code != http.StatusFound {
					t.Fatalf("запрос %d: %d %q — ожидался ответ без сессии", i+1, code, body)
				}
			}
			if code, body := l.get(issuinglistener.EdgeSAN, row.eleventh...); code != http.StatusTooManyRequests {
				t.Errorf("одиннадцатый: %d %q — ожидался 429: ключ — адрес пира-края", code, body)
			}
			requireOnlyCell(t, l.cells(), issuingsource.Cell{Point: issuingsource.PointAuthorize,
				Reason: issuingsource.ReasonEdgeWithoutAddress}, 11)
		})
	}
}

// ── Полоса обмена сообщает эндпоинту об отказе доказательства клиента ──────

func TestTokenLaneReportsTheClientProofRefusal(t *testing.T) {
	serve := func(lane *TokenLane, form url.Values, basicUser string) (*httptest.ResponseRecorder, clienttokenhttp.LaneVerdict) {
		req := httptest.NewRequest(http.MethodPost, "/iam/v1/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if basicUser != "" {
			req.SetBasicAuth(basicUser, "secret")
		}
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		return rec, lane.ServeGrant(rec, req, form.Get("grant_type"))
	}
	code := url.Values{"grant_type": {"authorization_code"}, "code": {"c"}, "redirect_uri": {knownTarget},
		"code_verifier": {strings.Repeat("v", 43)}}

	for name, cell := range map[string]struct {
		engine *exchangeEngine
		basic  string
	}{
		"Basic не разбирается":         {&exchangeEngine{}, "%zz"},
		"церемония: клиент не доказан": {&exchangeEngine{err: oauthceremony.ErrInvalidClient}, "C"},
	} {
		lane, _, _ := newLane(t, cell.engine, &countingUnits{})
		rec, verdict := serve(lane, code, cell.basic)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: предпосылка — invalid_client, получено %d %q", name, rec.Code, rec.Body.String())
		}
		if verdict != clienttokenhttp.LaneProofRefused {
			t.Errorf("%s: полоса ответила invalid_client, но эндпоинту сообщила %v", name, verdict)
		}
	}

	// Близнецы: отказ формы до доказательства и отказ гранта после него — не
	// отказы доказательства клиента.
	for name, cell := range map[string]struct {
		engine *exchangeEngine
		form   url.Values
		status int
	}{
		"код назван дважды": {&exchangeEngine{}, url.Values{"grant_type": {"authorization_code"}, "code": {"a", "b"}},
			http.StatusBadRequest},
		"invalid_grant": {&exchangeEngine{err: oauthceremony.ErrInvalidGrant}, code, http.StatusBadRequest},
	} {
		lane, _, _ := newLane(t, cell.engine, &countingUnits{})
		rec, verdict := serve(lane, cell.form, "C")
		if rec.Code != cell.status {
			t.Fatalf("%s: предпосылка близнеца — %d, получено %d %q", name, cell.status, rec.Code, rec.Body.String())
		}
		if verdict == clienttokenhttp.LaneProofRefused {
			t.Errorf("%s: засчитан отказом доказательства клиента", name)
		}
	}
}

// ── KN-PACE-37 ───────────────────────────────────────────────────────────────

func TestKNPACE37_AuthorizePaceOutcomesAreSeededWithZeroes(t *testing.T) {
	read := NewCensus().Read()
	for _, o := range []Outcome{OutcomeAuthorizeSourcePaceExceeded, OutcomeAuthorizeInFlightCeilingReached} {
		v, seeded := read[string(o)]
		if !seeded || v != 0 {
			t.Errorf("ряд %s: засеян %v, значение %d — ожидался засеянный ноль", o, seeded, v)
		}
	}
	declared := map[string]bool{}
	for _, o := range DeclaredOutcomes() {
		declared[o] = true
	}
	for _, o := range []Outcome{OutcomeAuthorizeSourcePaceExceeded, OutcomeAuthorizeInFlightCeilingReached} {
		if !declared[string(o)] {
			t.Errorf("ряд %s не выходит на витрину", o)
		}
	}
}

// Построение без осей — отказ.
func TestAuthorizeRefusesToBuildWithoutItsPaceAxes(t *testing.T) {
	uc, err := ceremonyapp.NewAuthorizeUseCase(ceremonyapp.AuthorizeDeps{Engine: &untouchedEngine{},
		Clients: directory{}, Authority: &silentAuthority{}, Clock: time.Now, CallTimeout: time.Second,
		FamilyTTL: 2 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	pace, err := exchangepace.New(authorizePace, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	full := AuthorizeConfig{UseCase: uc, Census: NewCensus(), Logger: slog.New(slog.DiscardHandler),
		Pace: pace, InFlightCeiling: authorizeCeiling, Source: remoteHost}
	if _, err := NewAuthorize(full); err != nil {
		t.Fatalf("полная провязка обязана строиться: %v", err)
	}
	for name, mutate := range map[string]func(*AuthorizeConfig){
		"без темпа":   func(c *AuthorizeConfig) { c.Pace = nil },
		"без потолка": func(c *AuthorizeConfig) { c.InFlightCeiling = 0 },
		"без правила": func(c *AuthorizeConfig) { c.Source = nil },
	} {
		c := full
		mutate(&c)
		if _, err := NewAuthorize(c); err == nil {
			t.Errorf("%s: построение прошло", name)
		}
	}
}
