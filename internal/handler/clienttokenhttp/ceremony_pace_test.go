// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_pace_test.go — оси П1 и П3 токен-эндпоинта по приёмке
// `docs/engineering/acceptance/ceremony-pace-is-named-by-number.md` (kaname#315,
// группы B и D, KN-PACE-17 и KN-PACE-37).
//
// Посев Т в форме пробы обработчика: потолок одновременных 32, окно отказов
// доказательства на источник 50 за 15 мин, управляемые часы. Источник здесь —
// адрес пира соединения (правило Р7 при пире без сертификата); правило адреса
// целиком — в пробах группы F на настоящем слушателе.
//
// Проверяющий и выдача — дублёры, чей исход задаёт предъявление: «accept:X» —
// принятое предъявление X, «reject:X» — отвергнутое предъявление, называющее X.
// Удерживает дублёр выдачи — обмены клиентов H1 … H32 стоят на выдаче до
// сигнала, прочие выдаются сразу. Полосы церемонии — дублёр с клиентом C,
// секретом «s» и одноразовыми кодами.
package clienttokenhttp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/client_token"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/failurewindow"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
	"github.com/PRO-Robotech/kaname/internal/issuingsource"
	"github.com/PRO-Robotech/kaname/internal/testsupport/issuinglistener"
)

// Числа §3 приёмки.
const (
	paceCeiling      = 32
	paceFailedProofs = 50
	paceWindow       = 15 * time.Minute
)

// Адреса посева Т: P, Q и R — три разных адреса.
const (
	addrP = "198.51.100.1"
	addrQ = "198.51.100.2"
	addrR = "198.51.100.3"
)

var paceT0 = time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)

// paceClock — управляемые часы.
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

// scriptedVerifier — проверяющий, чей исход назван в предъявлении.
//
// «hold-reject:X» — отвергнутое предъявление, чьё обращение к реестру дублёр
// держит до сигнала gate (KN-PACE-18b).
type scriptedVerifier struct {
	mu       sync.Mutex
	calls    int
	entered  chan struct{}
	gate     chan struct{}
	lastSeen string
}

func newScriptedVerifier() *scriptedVerifier {
	return &scriptedVerifier{entered: make(chan struct{}, 64), gate: make(chan struct{})}
}

func (s *scriptedVerifier) Verify(_ context.Context, _ string, raw string) (clientassertion.Result, error) {
	s.mu.Lock()
	s.calls++
	s.lastSeen = raw
	s.mu.Unlock()
	verdict, client, _ := strings.Cut(raw, ":")
	switch verdict {
	case "accept":
		return clientassertion.Result{Outcome: clientassertion.OutcomeAccepted,
			Client: domain.AssertionClient{ID: client}}, nil
	case "reject":
		return clientassertion.Refuse(clientassertion.OutcomeSignatureMismatch, "probe: foreign key")
	case "hold-reject":
		s.entered <- struct{}{}
		<-s.gate
		return clientassertion.Refuse(clientassertion.OutcomeSignatureMismatch, "probe: foreign key")
	case "registry-down":
		return clientassertion.Refuse(clientassertion.OutcomeRegistryUnavailable, "probe: registry")
	case "replay-down":
		return clientassertion.Refuse(clientassertion.OutcomeReplayStoreUnavailable, "probe: replay store")
	case "paced":
		res, err := clientassertion.Refuse(clientassertion.OutcomeClientPaceExceeded, "probe: pace")
		res.RetryAfter = 200 * time.Millisecond
		return res, err
	}
	panic("probe: unknown verdict " + raw)
}

func (s *scriptedVerifier) VerifyFederated(ctx context.Context, raw string) (clientassertion.Result, error) {
	return s.Verify(ctx, "", raw)
}

func (s *scriptedVerifier) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// holdingIssuer — выдача посева Т: H* стоят до сигнала, прочие выдаются тем же
// ответом, что у настоящей выдачи; fail — исход отказа нашей стороны.
type holdingIssuer struct {
	mu      sync.Mutex
	entered chan string
	release chan struct{}
	fail    clientassertion.Outcome
}

func newHoldingIssuer() *holdingIssuer {
	return &holdingIssuer{entered: make(chan string, 64), release: make(chan struct{})}
}

func (h *holdingIssuer) Issue(_ context.Context, in client_token.Input) (client_token.Output, clientassertion.Outcome, error) {
	if strings.HasPrefix(in.Client.ID, "H") {
		h.entered <- in.Client.ID
		<-h.release
	}
	h.mu.Lock()
	fail := h.fail
	h.mu.Unlock()
	if fail != "" {
		return client_token.Output{}, fail, fmt.Errorf("probe: %s", fail)
	}
	return client_token.Output{AccessToken: "tok-" + in.Client.ID, TokenType: "Bearer", ExpiresIn: 900},
		clientassertion.OutcomeAccepted, nil
}

func (h *holdingIssuer) failWith(o clientassertion.Outcome) {
	h.mu.Lock()
	h.fail = o
	h.mu.Unlock()
}

// ceremonyLane — полосы церемонии посева Т: клиент C с секретом «s»; коды и
// токены обновления одноразовы.
type ceremonyLane struct {
	mu    sync.Mutex
	calls int
	used  map[string]bool
}

func (l *ceremonyLane) Grants() []string {
	return []string{"authorization_code", "refresh_token"}
}

func (l *ceremonyLane) ServeGrant(w http.ResponseWriter, r *http.Request, grant string) clienttokenhttp.LaneVerdict {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if r.PostForm.Get("client_id") != "C" || r.PostForm.Get("client_secret") != "s" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
		return clienttokenhttp.LaneProofRefused
	}
	named := r.PostForm.Get("code")
	if grant == "refresh_token" {
		named = r.PostForm.Get("refresh_token")
	}
	if l.used == nil {
		l.used = map[string]bool{}
	}
	if l.used[named] {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
		return clienttokenhttp.LaneProofNotRefused
	}
	l.used[named] = true
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"access_token":"at","token_type":"Bearer","refresh_token":"rt"}`)
	return clienttokenhttp.LaneProofNotRefused
}

func (l *ceremonyLane) Calls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// seedT — посев Т.
type seedT struct {
	t      *testing.T
	clock  *paceClock
	h      *clienttokenhttp.Handler
	v      *scriptedVerifier
	issuer *holdingIssuer
	lane   *ceremonyLane
	held   []chan *httptest.ResponseRecorder
}

func newSeedT(t *testing.T) *seedT {
	t.Helper()
	clock := &paceClock{now: paceT0}
	window, err := failurewindow.New(paceFailedProofs, paceWindow, clock.Now)
	require.NoError(t, err)
	s := &seedT{t: t, clock: clock, v: newScriptedVerifier(), issuer: newHoldingIssuer(), lane: &ceremonyLane{}}
	s.h, err = clienttokenhttp.NewHandler(clienttokenhttp.Config{
		BodyCeiling:     testBodyCeiling,
		InFlightCeiling: paceCeiling,
		FailedProofs:    window,
		Source:          peerHost,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Ceremony:        s.lane,
	}, s.v, s.issuer)
	require.NoError(t, err)
	t.Cleanup(s.releaseHolds)
	return s
}

// peerHost — источник по правилу Р7 для пира без сертификата: адрес пира.
func peerHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func machineForm(assertion string) url.Values {
	return url.Values{
		"grant_type":            {tokenpolicy.GrantTypeClientCredentials},
		"client_assertion_type": {tokenpolicy.ClientAssertionType},
		"client_assertion":      {assertion},
	}
}

func codeForm(secret, code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {"C"}, "client_secret": {secret},
		"code": {code}, "redirect_uri": {"https://app.example.test/cb"}, "code_verifier": {strings.Repeat("v", 43)}}
}

func refreshForm(secret, token string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "client_id": {"C"}, "client_secret": {secret},
		"refresh_token": {token}}
}

func (s *seedT) send(from, method string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, clienttokenhttp.TokenPath, body)
	req.RemoteAddr = from + ":40000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	return rec
}

func (s *seedT) post(from string, form url.Values) *httptest.ResponseRecorder {
	return s.send(from, http.MethodPost, strings.NewReader(form.Encode()))
}

// hold — «N обменов удерживаются»: H1 … HN с R, каждый стоит на выдаче.
func (s *seedT) hold(n int) {
	s.t.Helper()
	for i := 1; i <= n; i++ {
		id := fmt.Sprintf("H%d", len(s.held)+1)
		done := make(chan *httptest.ResponseRecorder, 1)
		s.held = append(s.held, done)
		go func() { done <- s.post(addrR, machineForm("accept:"+id)) }()
		select {
		case got := <-s.issuer.entered:
			require.Equal(s.t, id, got, "удерживаемый обмен %s не дошёл до выдачи", id)
		case <-time.After(10 * time.Second):
			s.t.Fatalf("удержание %s не дошло до выдачи за 10 с", id)
		}
	}
}

// releaseHolds — «удержания сняты»: сигнал дан, и все удержанные получили 200.
func (s *seedT) releaseHolds() {
	select {
	case <-s.issuer.release:
		return
	default:
		close(s.issuer.release)
	}
	for i, done := range s.held {
		select {
		case rec := <-done:
			require.Equalf(s.t, http.StatusOK, rec.Code, "удержанный обмен H%d после сигнала", i+1)
		case <-time.After(10 * time.Second):
			s.t.Fatalf("удержанный обмен H%d не получил ответа после сигнала", i+1)
		}
	}
	s.held = nil
}

func (s *seedT) outcome(o clientassertion.Outcome) uint64 { return s.h.Outcomes()[o] }

// authRefusals — сумма счётчиков отказов аутентификации: всех исходов, кроме
// исходов формы, темпа и приёма.
func (s *seedT) authRefusals() uint64 {
	var n uint64
	for o, c := range s.h.Outcomes() {
		switch o {
		case clientassertion.OutcomeAccepted, clientassertion.OutcomeMethodNotAllowed,
			clientassertion.OutcomeBodyAboveCeiling, clientassertion.OutcomeMalformedRequest,
			clientassertion.OutcomeMultipleAssertions, clientassertion.OutcomeUnsupportedGrantType,
			clientassertion.OutcomeInFlightCeilingReached, clientassertion.OutcomeClientPaceExceeded,
			clientassertion.OutcomeSourceFailuresExceeded:
			continue
		}
		n += c
	}
	return n
}

func requireJSONError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	require.Equalf(t, status, rec.Code, "тело %q", rec.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body), "тело не JSON: %q", rec.Body.String())
	require.Equal(t, map[string]any{"error": code}, body)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.Equal(t, "no-cache", rec.Header().Get("Pragma"))
}

func requireCeilingRefusal(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	requireJSONError(t, rec, http.StatusServiceUnavailable, "temporarily_unavailable")
	require.Equal(t, "1", rec.Header().Get("Retry-After"))
}

func requireSourceRefusal(t *testing.T, rec *httptest.ResponseRecorder, retryAfter string) {
	t.Helper()
	requireJSONError(t, rec, http.StatusTooManyRequests, "temporarily_unavailable")
	require.Equal(t, retryAfter, rec.Header().Get("Retry-After"))
}

// failFromP — n отвергнутых предъявлений, называющих X, с P в t0, t0+1 с, ….
func (s *seedT) failFromP(n int) {
	s.t.Helper()
	for i := 0; i < n; i++ {
		s.clock.At(time.Duration(i) * time.Second)
		require.Equal(s.t, http.StatusUnauthorized, s.post(addrP, machineForm("reject:X")).Code, "отказ %d", i+1)
	}
}

// ── Группа B — П1 ────────────────────────────────────────────────────────────

func TestKNPACE07_ExchangeAboveTheCeilingIs503BeforeVerification(t *testing.T) {
	s := newSeedT(t)
	s.hold(32)
	before, authBefore := s.v.Calls(), s.authRefusals()

	rec := s.post(addrP, machineForm("accept:Y"))
	requireCeilingRefusal(t, rec)
	require.EqualValues(t, 1, s.outcome(clientassertion.OutcomeInFlightCeilingReached))
	require.Equal(t, before, s.v.Calls(), "по отказу потолка проверяющий утверждения не вызывался")
	require.Equal(t, authBefore, s.authRefusals(), "счётчики отказов аутентификации не изменились")
}

func TestKNPACE08_ExchangeOnTheLastPlacePasses(t *testing.T) {
	s := newSeedT(t)
	s.hold(31)
	rec := s.post(addrP, machineForm("accept:Y"))
	require.Equalf(t, http.StatusOK, rec.Code, "тело %q", rec.Body.String())
	require.Contains(t, rec.Body.String(), "access_token")
	require.Zero(t, s.outcome(clientassertion.OutcomeInFlightCeilingReached))
}

func TestKNPACE09_CeilingCoversTheCeremonyGrants(t *testing.T) {
	for _, row := range []struct {
		grant string
		form  url.Values
	}{
		{"authorization_code", codeForm("s", "code-1")},
		{"refresh_token", refreshForm("s", "refresh-1")},
	} {
		t.Run(row.grant, func(t *testing.T) {
			s := newSeedT(t)
			s.hold(32)
			rec := s.post(addrP, row.form)
			requireCeilingRefusal(t, rec)
			require.Zero(t, s.lane.Calls(), "полоса церемонии не вызывалась")
			require.EqualValues(t, 1, s.outcome(clientassertion.OutcomeInFlightCeilingReached))
		})
		t.Run(row.grant+"/близнец 09b: 31 удержание", func(t *testing.T) {
			s := newSeedT(t)
			s.hold(31)
			rec := s.post(addrP, row.form)
			require.Equalf(t, http.StatusOK, rec.Code, "тело %q", rec.Body.String())
			require.Contains(t, rec.Body.String(), "access_token")
			require.Contains(t, rec.Body.String(), "refresh_token")
			require.Equal(t, 1, s.lane.Calls())
		})
	}
}

func TestKNPACE10_CeilingDoesNotHideRequestFormRefusals(t *testing.T) {
	big := strings.Repeat("x", int(testBodyCeiling)+1)
	twoAssertions := machineForm("accept:X")
	twoAssertions.Add("client_assertion", "accept:X")
	rows := []struct {
		name   string
		send   func(s *seedT) *httptest.ResponseRecorder
		expect func(t *testing.T, rec *httptest.ResponseRecorder)
		counts bool
	}{
		{"а GET", func(s *seedT) *httptest.ResponseRecorder { return s.send(addrP, http.MethodGet, nil) },
			func(t *testing.T, rec *httptest.ResponseRecorder) {
				requireJSONError(t, rec, http.StatusMethodNotAllowed, "invalid_request")
				require.Equal(t, http.MethodPost, rec.Header().Get("Allow"))
			}, false},
		{"б тело сверх потолка", func(s *seedT) *httptest.ResponseRecorder {
			return s.send(addrP, http.MethodPost, strings.NewReader("grant_type="+big))
		}, func(t *testing.T, rec *httptest.ResponseRecorder) {
			requireJSONError(t, rec, http.StatusRequestEntityTooLarge, "invalid_request")
		}, false},
		{"в неизвестный grant_type", func(s *seedT) *httptest.ResponseRecorder {
			return s.post(addrP, url.Values{"grant_type": {"password"}})
		}, func(t *testing.T, rec *httptest.ResponseRecorder) {
			requireJSONError(t, rec, http.StatusBadRequest, "unsupported_grant_type")
		}, false},
		{"г два client_assertion", func(s *seedT) *httptest.ResponseRecorder {
			return s.post(addrP, twoAssertions)
		}, requireCeilingRefusal, true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			s := newSeedT(t)
			s.hold(32)
			row.expect(t, row.send(s))
			want := uint64(0)
			if row.counts {
				want = 1
			}
			require.Equal(t, want, s.outcome(clientassertion.OutcomeInFlightCeilingReached))
		})
	}
	t.Run("близнец строки г: без удержаний", func(t *testing.T) {
		s := newSeedT(t)
		requireJSONError(t, s.post(addrP, twoAssertions), http.StatusBadRequest, "invalid_request")
	})
}

func TestKNPACE11_PlaceIsReleasedOnAnyOutcome(t *testing.T) {
	s := newSeedT(t)
	s.hold(31)
	require.Equal(t, http.StatusUnauthorized, s.post(addrP, machineForm("reject:X")).Code,
		"отвергнутое предъявление заняло тридцать второе место и получило 401")

	s.hold(1) // H32 с R доходит до выдачи: отвергнутый обмен вернул своё место
	rec := s.post(addrP, machineForm("accept:Y"))
	requireCeilingRefusal(t, rec)
	require.EqualValues(t, 1, s.outcome(clientassertion.OutcomeInFlightCeilingReached))
	s.releaseHolds()
}

// ── KN-PACE-17 — П2 не действует на полосах церемонии ───────────────────────

func TestKNPACE17_ClientPaceDoesNotApplyToCeremonyGrants(t *testing.T) {
	s := newSeedT(t)
	for i := 1; i <= 6; i++ {
		rec := s.post(addrP, codeForm("s", fmt.Sprintf("code-%d", i)))
		require.Equalf(t, http.StatusOK, rec.Code, "обмен %d: %q", i, rec.Body.String())
		require.Contains(t, rec.Body.String(), "access_token")
	}
	require.Zero(t, s.outcome(clientassertion.OutcomeClientPaceExceeded))
	require.Zero(t, s.v.Calls(), "полосы церемонии не идут через проверяющего машинных полос")
}

// ── Группа D — П3 ────────────────────────────────────────────────────────────

func TestKNPACE18_FiftyFailuresFromASourceAre429WithTheWindowTerm(t *testing.T) {
	s := newSeedT(t)
	s.failFromP(50)
	s.clock.At(60 * time.Second)
	before := s.v.Calls()

	rec := s.post(addrP, machineForm("accept:X"))
	requireSourceRefusal(t, rec, "840")
	require.EqualValues(t, 1, s.outcome(clientassertion.OutcomeSourceFailuresExceeded))
	require.Equal(t, before, s.v.Calls(), "по отказу П3 проверяющий утверждения не вызывался")
	// Место под потолком отказ П3 не занимает: это держит порядок П3 → П1, и
	// судит его KN-PACE-24 — при занятом потолке тот же запрос получает 429,
	// а не 503.
}

func TestKNPACE18b_CountAboveTheLimitNamesTheTermToLimitMinusOne(t *testing.T) {
	s := newSeedT(t)
	s.failFromP(49)
	s.clock.At(49 * time.Second)
	done := make(chan *httptest.ResponseRecorder, 2)
	for i := 0; i < 2; i++ {
		go func() { done <- s.post(addrP, machineForm("hold-reject:X")) }()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-s.v.entered:
		case <-time.After(10 * time.Second):
			t.Fatal("оба предъявления обязаны быть допущены П3 при счёте 49 и дойти до реестра")
		}
	}
	close(s.v.gate)
	for i := 0; i < 2; i++ {
		require.Equal(t, http.StatusUnauthorized, (<-done).Code)
	}

	s.clock.At(60 * time.Second)
	requireSourceRefusal(t, s.post(addrP, machineForm("accept:X")), "841")
	require.EqualValues(t, 1, s.outcome(clientassertion.OutcomeSourceFailuresExceeded))
}

func TestKNPACE19_FortyNineFailuresStillServed(t *testing.T) {
	s := newSeedT(t)
	s.failFromP(49)
	s.clock.At(60 * time.Second)
	require.Equal(t, http.StatusOK, s.post(addrP, machineForm("accept:X")).Code)
	require.Zero(t, s.outcome(clientassertion.OutcomeSourceFailuresExceeded))
}

func TestKNPACE20_WindowSlides(t *testing.T) {
	s := newSeedT(t)
	s.failFromP(50)
	s.clock.At(900 * time.Second)
	require.Equal(t, http.StatusOK, s.post(addrP, machineForm("accept:X")).Code,
		"отказ из t0 старше окна, в окне их 49")
}

func TestKNPACE21_SourcesAreCountedSeparately(t *testing.T) {
	s := newSeedT(t)
	s.failFromP(50)
	s.clock.At(60 * time.Second)
	require.Equal(t, http.StatusOK, s.post(addrQ, machineForm("accept:X")).Code)
}

func TestKNPACE22_CeremonyInvalidGrantIsNotCountedInvalidClientIs(t *testing.T) {
	t.Run("a секрет верен, код уже обменян", func(t *testing.T) {
		s := newSeedT(t)
		require.Equal(t, http.StatusOK, s.post(addrQ, codeForm("s", "spent")).Code)
		for i := 0; i < 50; i++ {
			s.clock.At(time.Duration(i) * time.Second)
			requireJSONError(t, s.post(addrP, codeForm("s", "spent")), http.StatusBadRequest, "invalid_grant")
		}
		s.clock.At(60 * time.Second)
		require.Equal(t, http.StatusOK, s.post(addrP, codeForm("s", "fresh")).Code)
		require.Zero(t, s.outcome(clientassertion.OutcomeSourceFailuresExceeded))
	})
	t.Run("b секрет неверен", func(t *testing.T) {
		s := newSeedT(t)
		for i := 0; i < 50; i++ {
			s.clock.At(time.Duration(i) * time.Second)
			requireJSONError(t, s.post(addrP, codeForm("wrong", fmt.Sprintf("c-%d", i))), http.StatusUnauthorized,
				"invalid_client")
		}
		s.clock.At(60 * time.Second)
		requireSourceRefusal(t, s.post(addrP, codeForm("s", "fresh")), "840")
		require.EqualValues(t, 1, s.outcome(clientassertion.OutcomeSourceFailuresExceeded))
	})
}

func TestKNPACE23_OurSideRefusalsAreNotCounted(t *testing.T) {
	for _, row := range []struct {
		name      string
		assertion string
		issuance  clientassertion.Outcome
	}{
		{"а registry-unavailable", "registry-down:X", ""},
		{"б replay-store-unavailable", "replay-down:X", ""},
		{"в revocation-check-failed", "accept:X", clientassertion.OutcomeRevocationCheckFailed},
		{"г issuance-failed", "accept:X", clientassertion.OutcomeIssuanceFailed},
	} {
		t.Run(row.name, func(t *testing.T) {
			s := newSeedT(t)
			s.issuer.failWith(row.issuance)
			for i := 0; i < 50; i++ {
				s.clock.At(time.Duration(i) * time.Second)
				requireJSONError(t, s.post(addrP, machineForm(row.assertion)), http.StatusUnauthorized, "invalid_client")
			}
			s.issuer.failWith("")
			s.clock.At(60 * time.Second)
			require.Equal(t, http.StatusOK, s.post(addrP, machineForm("accept:X")).Code)
			require.Zero(t, s.outcome(clientassertion.OutcomeSourceFailuresExceeded))
		})
	}
}

func TestKNPACE24_BlockedSourceTakesNoPlaceUnderTheCeiling(t *testing.T) {
	s := newSeedT(t)
	s.failFromP(50)
	s.clock.At(50 * time.Second)
	s.hold(32)
	s.clock.At(60 * time.Second)

	requireSourceRefusal(t, s.post(addrP, machineForm("accept:X")), "840")
	require.EqualValues(t, 1, s.outcome(clientassertion.OutcomeSourceFailuresExceeded))
	requireCeilingRefusal(t, s.post(addrQ, machineForm("accept:Y")))
	require.EqualValues(t, 1, s.outcome(clientassertion.OutcomeInFlightCeilingReached))
}

func TestKNPACE25_FormAndPaceRefusalsAreNotCounted(t *testing.T) {
	big := strings.Repeat("x", int(testBodyCeiling)+1)
	twoAssertions := machineForm("accept:X")
	twoAssertions.Add("client_assertion", "accept:X")
	rows := []struct {
		name   string
		before func(s *seedT)
		after  func(s *seedT)
		send   func(s *seedT) *httptest.ResponseRecorder
		expect func(t *testing.T, rec *httptest.ResponseRecorder)
		row    clientassertion.Outcome
	}{
		{name: "а GET", send: func(s *seedT) *httptest.ResponseRecorder { return s.send(addrP, http.MethodGet, nil) },
			expect: func(t *testing.T, rec *httptest.ResponseRecorder) {
				requireJSONError(t, rec, http.StatusMethodNotAllowed, "invalid_request")
			}},
		{name: "б тело сверх потолка", send: func(s *seedT) *httptest.ResponseRecorder {
			return s.send(addrP, http.MethodPost, strings.NewReader("grant_type="+big))
		}, expect: func(t *testing.T, rec *httptest.ResponseRecorder) {
			requireJSONError(t, rec, http.StatusRequestEntityTooLarge, "invalid_request")
		}},
		{name: "в тело не форма", send: func(s *seedT) *httptest.ResponseRecorder {
			return s.send(addrP, http.MethodPost, strings.NewReader("grant_type=%zz"))
		}, expect: func(t *testing.T, rec *httptest.ResponseRecorder) {
			requireJSONError(t, rec, http.StatusBadRequest, "invalid_request")
		}},
		{name: "г неизвестный grant_type", send: func(s *seedT) *httptest.ResponseRecorder {
			return s.post(addrP, url.Values{"grant_type": {"password"}})
		}, expect: func(t *testing.T, rec *httptest.ResponseRecorder) {
			requireJSONError(t, rec, http.StatusBadRequest, "unsupported_grant_type")
		}},
		{name: "д два client_assertion", send: func(s *seedT) *httptest.ResponseRecorder {
			return s.post(addrP, twoAssertions)
		}, expect: func(t *testing.T, rec *httptest.ResponseRecorder) {
			requireJSONError(t, rec, http.StatusBadRequest, "invalid_request")
		}},
		{name: "е П2", send: func(s *seedT) *httptest.ResponseRecorder {
			// Темп X исчерпан на этом показании часов: решение П2 принадлежит
			// проверяющему (его пробы — TestClientPace*), здесь его исход
			// отдаёт дублёр.
			return s.post(addrP, machineForm("paced:X"))
		}, expect: func(t *testing.T, rec *httptest.ResponseRecorder) {
			requireJSONError(t, rec, http.StatusTooManyRequests, "temporarily_unavailable")
			require.Equal(t, "1", rec.Header().Get("Retry-After"))
		}, row: clientassertion.OutcomeClientPaceExceeded},
		{name: "ж П1", before: func(s *seedT) { s.hold(32) }, after: func(s *seedT) { s.releaseHolds() },
			send:   func(s *seedT) *httptest.ResponseRecorder { return s.post(addrP, machineForm("accept:X")) },
			expect: requireCeilingRefusal, row: clientassertion.OutcomeInFlightCeilingReached},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			s := newSeedT(t)
			if row.before != nil {
				row.before(s)
			}
			for i := 0; i < 50; i++ {
				s.clock.At(time.Duration(i) * time.Second)
				row.expect(t, row.send(s))
			}
			if row.after != nil {
				row.after(s)
			}
			if row.row != "" {
				require.EqualValues(t, 50, s.outcome(row.row), "счётчик строки +50")
			}
			s.clock.At(60 * time.Second)
			rec := s.post(addrP, machineForm("accept:X"))
			require.Equalf(t, http.StatusOK, rec.Code, "П3 засчитал отказы строки: %q", rec.Body.String())
			require.Zero(t, s.outcome(clientassertion.OutcomeSourceFailuresExceeded))
		})
	}
}

// ── KN-PACE-37 — новые исходы засеяны нулями ────────────────────────────────

func TestKNPACE37_PaceOutcomesAreSeededWithZeroes(t *testing.T) {
	s := newSeedT(t)
	got := s.h.Outcomes()
	for _, o := range []clientassertion.Outcome{
		clientassertion.OutcomeClientPaceExceeded,
		clientassertion.OutcomeInFlightCeilingReached,
		clientassertion.OutcomeSourceFailuresExceeded,
	} {
		v, seeded := got[o]
		require.Truef(t, seeded, "ряд %s не засеян до первого запроса", o)
		require.Zero(t, v)
	}
	declared := map[string]bool{}
	for _, o := range clienttokenhttp.DeclaredOutcomes() {
		declared[o] = true
	}
	require.True(t, declared[string(clientassertion.OutcomeSourceFailuresExceeded)],
		"ряд source-failures-exceeded обязан выходить на витрину: набор рядов — словарь")

	// Близнец: после отказа П2 ряд client-pace-exceeded равен 1, прочие — 0.
	require.Equal(t, http.StatusTooManyRequests, s.post(addrP, machineForm("paced:X")).Code)
	got = s.h.Outcomes()
	require.EqualValues(t, 1, got[clientassertion.OutcomeClientPaceExceeded])
	require.Zero(t, got[clientassertion.OutcomeInFlightCeilingReached])
	require.Zero(t, got[clientassertion.OutcomeSourceFailuresExceeded])
}

// Построение без окна отказов либо без правила источника — отказ: П3 без
// своей единицы не решался бы ни разу.
func TestHandlerRefusesToBuildWithoutTheSourceAxis(t *testing.T) {
	clock := &paceClock{now: paceT0}
	window, err := failurewindow.New(paceFailedProofs, paceWindow, clock.Now)
	require.NoError(t, err)
	full := clienttokenhttp.Config{BodyCeiling: testBodyCeiling, InFlightCeiling: paceCeiling,
		FailedProofs: window, Source: peerHost}
	_, err = clienttokenhttp.NewHandler(full, newScriptedVerifier(), newHoldingIssuer())
	require.NoError(t, err, "полная провязка обязана строиться")

	noWindow := full
	noWindow.FailedProofs = nil
	_, err = clienttokenhttp.NewHandler(noWindow, newScriptedVerifier(), newHoldingIssuer())
	require.Error(t, err)

	noSource := full
	noSource.Source = nil
	_, err = clienttokenhttp.NewHandler(noSource, newScriptedVerifier(), newHoldingIssuer())
	require.Error(t, err)
}

// ── KN-PACE-36 — правило адреса источника на токен-эндпоинте ────────────────

func TestKNPACE36_SourceRuleOnTheTokenEndpoint(t *testing.T) {
	clock := &paceClock{now: paceT0}
	window, err := failurewindow.New(paceFailedProofs, paceWindow, clock.Now)
	require.NoError(t, err)
	rule := issuingsource.New(grpcsrv.NewTrustDomain(issuinglistener.TrustDomain))
	h, err := clienttokenhttp.NewHandler(clienttokenhttp.Config{
		BodyCeiling:     testBodyCeiling,
		InFlightCeiling: paceCeiling,
		FailedProofs:    window,
		Source:          func(r *http.Request) string { return rule.Of(r, issuingsource.PointToken) },
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, newScriptedVerifier(), newHoldingIssuer())
	require.NoError(t, err)
	stand := issuinglistener.Start(t, h)

	post := func(san, forwarded, assertion string) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, stand.URL+clienttokenhttp.TokenPath,
			strings.NewReader(machineForm(assertion).Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", forwarded)
		resp, err := stand.Client(t, san).Do(req)
		require.NoError(t, err)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp
	}

	for i := 0; i < paceFailedProofs; i++ {
		clock.At(time.Duration(i) * time.Second)
		require.Equal(t, http.StatusUnauthorized, post(issuinglistener.EdgeSAN, "203.0.113.7", "reject:X").StatusCode)
	}
	clock.At(60 * time.Second)
	first := post(issuinglistener.EdgeSAN, "203.0.113.7", "accept:X")
	require.Equal(t, http.StatusTooManyRequests, first.StatusCode)
	require.Equal(t, "840", first.Header.Get("Retry-After"))
	require.Equal(t, http.StatusOK, post(issuinglistener.EdgeSAN, "203.0.113.8", "accept:X").StatusCode)
	require.Equal(t, http.StatusOK, post("", "203.0.113.7", "accept:X").StatusCode,
		"заголовок пира без сертификата края ключа не меняет")

	cells := rule.Read()
	for _, c := range issuingsource.Cells() {
		want := uint64(0)
		if c == (issuingsource.Cell{Point: issuingsource.PointToken, Reason: issuingsource.ReasonForwardedFromNonEdge}) {
			want = 1
		}
		require.Equalf(t, want, cells[c], "клетка %s/%s", c.Point, c.Reason)
	}
}

// ── KN-PACE-06 — optional-mutual обслуживает вызывающего без сертификата ────

func TestKNPACE06_OptionalMutualServesACallerWithoutACertificate(t *testing.T) {
	s := newSeedT(t)
	stand := issuinglistener.Start(t, s.h)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, stand.URL+clienttokenhttp.TokenPath,
		strings.NewReader(machineForm("accept:X").Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := stand.Client(t, "").Do(req)
	require.NoError(t, err, "рукопожатие без клиентского сертификата обязано проходить")
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equalf(t, http.StatusOK, resp.StatusCode, "тело %q", body)
	require.Contains(t, string(body), "access_token")
	require.NotNil(t, resp.TLS, "ответ пришёл по TLS")
}
