// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyhttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

// exchangeEngine — церемония пробы: отвечает на обмен заданным исходом и
// запоминает запрос.
type exchangeEngine struct {
	result oauthceremony.TokenResult
	err    error
	got    oauthceremony.TokenRequest
	calls  int
}

func (e *exchangeEngine) Authorize(context.Context, oauthceremony.AuthorizationRequest) (oauthceremony.AuthorizationIntent, error) {
	return oauthceremony.AuthorizationIntent{}, errors.New("not in this probe")
}

func (e *exchangeEngine) CompleteAuthorization(context.Context, oauthceremony.AuthorizationIntent, oauthceremony.AuthorizationGrant) (oauthceremony.AuthorizationResult, error) {
	return oauthceremony.AuthorizationResult{}, errors.New("not in this probe")
}

func (e *exchangeEngine) Exchange(_ context.Context, req oauthceremony.TokenRequest) (oauthceremony.TokenResult, error) {
	e.calls++
	e.got = req
	return e.result, e.err
}

// countingUnits — единица запроса пробы: считает открытия и урегулирования.
type countingUnits struct {
	opened, settled int
	settleErr       error
}

func (u *countingUnits) OpenRequest(ctx context.Context) (context.Context, func(context.Context) error) {
	u.opened++
	return ctx, func(context.Context) error {
		u.settled++
		return u.settleErr
	}
}

func newLane(t *testing.T, e Engine, u RequestUnits) (*TokenLane, *Census, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	census := NewCensus()
	lane, err := NewTokenLane(e, u, census, slog.New(slog.NewJSONHandler(&buf, nil)))
	if err != nil {
		t.Fatalf("сборка полосы: %v", err)
	}
	return lane, census, &buf
}

func post(t *testing.T, lane *TokenLane, form url.Values, basic []string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/iam/v1/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(basic) == 2 {
		req.SetBasicAuth(url.QueryEscape(basic[0]), url.QueryEscape(basic[1]))
	}
	if err := req.ParseForm(); err != nil {
		t.Fatalf("разбор формы: %v", err)
	}
	rec := httptest.NewRecorder()
	lane.ServeGrant(rec, req, form.Get("grant_type"))
	return rec
}

// Отказ записи выпуска потому, что семейство гранта умерло во время операции
// (одновременный повтор отозвал его), — отказ ГРАНТА: `invalid_grant`, тот же
// побайтово, что прочие отказы после именования токена (Р10), а не отказ
// сервера. Близнец — отказ порта иной природы остаётся отказом сервера.
func TestTokenLane_IssuanceIntoADeadFamilyIsAnInvalidGrant(t *testing.T) {
	dead := fmt.Errorf("oauthceremony: server_error: %w",
		fmt.Errorf("ceremonyport: record access token issuance: %w", domain.ErrAccessTokenFamilyNotLive))
	grantRefused := `{"error":"invalid_grant"}` + "\n"

	lane, census, _ := newLane(t, &exchangeEngine{err: dead}, &countingUnits{})
	rec := post(t, lane, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"rt"}}, []string{"ic-1", "s"})
	if rec.Code != http.StatusBadRequest || rec.Body.String() != grantRefused {
		t.Fatalf("выпуск в умершее семейство: %d %q, ожидалось 400 %q", rec.Code, rec.Body.String(), grantRefused)
	}
	if got := census.Read()[string(OutcomeTokenGrantRefused)]; got != 1 {
		t.Errorf("исход «отказ гранта» сосчитан %d раз, ожидался один", got)
	}

	lane, _, _ = newLane(t, &exchangeEngine{err: errors.New("store down")}, &countingUnits{})
	twin := post(t, lane, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"rt"}}, []string{"ic-1", "s"})
	if twin.Code != http.StatusInternalServerError {
		t.Errorf("близнец: отказ хранилища ответил %d, ожидалось 500", twin.Code)
	}
}

// Занятый проверяющий секрета — отказ повторяемый и наш: 503 с Retry-After, а
// не 500 и не «клиент не доказан».
func TestTokenLane_SecretCheckerAtCapacityIsTemporarilyUnavailable(t *testing.T) {
	busy := fmt.Errorf("oauthceremony: server_error: %w", domain.ErrVerifierAtCapacity)
	lane, _, _ := newLane(t, &exchangeEngine{err: busy}, &countingUnits{})
	rec := post(t, lane, url.Values{"grant_type": {"authorization_code"}, "code": {"c"}}, []string{"ic-1", "s"})
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" ||
		rec.Body.String() != `{"error":"temporarily_unavailable"}`+"\n" {
		t.Fatalf("занятый проверяющий: %d %q Retry-After %q", rec.Code, rec.Body.String(), rec.Header().Get("Retry-After"))
	}
}

// Единица запроса открывается на каждый обмен и урегулируется ровно один раз —
// и на успехе, и на отказе; отказ урегулирования на успехе — отказ сервера, а не
// выданный токен при незакреплённом погашении.
func TestTokenLane_EveryExchangeIsSettledOnce(t *testing.T) {
	for _, tc := range []struct {
		name      string
		engineErr error
		settleErr error
		want      int
	}{
		{"успех", nil, nil, http.StatusOK},
		{"отказ гранта", oauthceremony.ErrInvalidGrant, nil, http.StatusBadRequest},
		{"успех, урегулирование не состоялось", nil, errors.New("commit lost"), http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			units := &countingUnits{settleErr: tc.settleErr}
			engine := &exchangeEngine{err: tc.engineErr, result: oauthceremony.TokenResult{
				AccessToken: "at", RefreshToken: "rt", ExpiresIn: time.Minute, Scopes: []string{"openid"},
			}}
			lane, _, _ := newLane(t, engine, units)
			rec := post(t, lane, url.Values{"grant_type": {"authorization_code"}, "code": {"c"}}, []string{"ic-1", "s"})
			if rec.Code != tc.want {
				t.Errorf("исход %d, ожидался %d; тело %q", rec.Code, tc.want, rec.Body.String())
			}
			if units.opened != 1 || units.settled != 1 {
				t.Errorf("единица запроса: открыта %d, урегулирована %d — ожидалось по одному", units.opened, units.settled)
			}
		})
	}
}

// Доказательство клиента: Basic с частями, кодированными формой, уезжает
// церемонии раскодированным и способом Basic; назначаемое выдачей (субъект,
// уровень, момент, получатель) церемонии не передаётся вовсе.
func TestTokenLane_ClientProofAndIssuanceFactsAreNotTakenFromTheCaller(t *testing.T) {
	engine := &exchangeEngine{result: oauthceremony.TokenResult{AccessToken: "at", ExpiresIn: time.Minute}}
	lane, _, _ := newLane(t, engine, &countingUnits{})
	rec := post(t, lane, url.Values{
		"grant_type": {"authorization_code"}, "code": {"c"}, "code_verifier": {"v"}, "redirect_uri": {"https://r"},
		"sub": {"usr-caller"}, "acr": {"3"}, "auth_time": {"1"}, "audience": {"https://caller"},
	}, []string{"ic-1 x", "p:w&d"})
	if rec.Code != http.StatusOK {
		t.Fatalf("обмен ответил %d; тело %q", rec.Code, rec.Body.String())
	}
	got := engine.got
	if got.ClientID != "ic-1 x" || got.ClientSecret != "p:w&d" || got.AuthMethod != oauthceremony.ClientAuthBasic {
		t.Errorf("доказательство клиента: %q %q %q", got.ClientID, got.ClientSecret, got.AuthMethod)
	}
	if len(got.Audiences) != 0 || len(got.Additional) != 0 {
		t.Errorf("назначаемое выдачей уехало церемонии: получатели %v, прочее %v", got.Audiences, got.Additional)
	}
}

// Двумя способами сразу клиент себя не доказывает (RFC 6749 §2.3): Basic и
// секрет в теле — отказ формы, до церемонии.
func TestTokenLane_TwoClientProofsAreRefusedBeforeTheCeremony(t *testing.T) {
	engine := &exchangeEngine{}
	lane, _, _ := newLane(t, engine, &countingUnits{})
	rec := post(t, lane, url.Values{"grant_type": {"authorization_code"}, "code": {"c"}, "client_secret": {"s"}},
		[]string{"ic-1", "s"})
	if rec.Code != http.StatusBadRequest || rec.Body.String() != `{"error":"invalid_request"}`+"\n" || engine.calls != 0 {
		t.Fatalf("два способа доказательства: %d %q, вызовов церемонии %d", rec.Code, rec.Body.String(), engine.calls)
	}
}
