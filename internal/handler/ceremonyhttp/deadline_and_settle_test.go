// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyhttp

// deadline_and_settle_test.go — возвраты ревью сборки 425 по поверхности
// церемонии (задача PRO-Robotech/kaname#423):
//
//   - каждый вызов хранилища эндпоинта авторизации — справочник клиентов и шов
//     входа — идёт под СВОИМ сроком, названным сборкой: хранилище, которое не
//     отвечает, даёт отказ «временно недоступно» в пределах этого срока, а не
//     держит запрос, пока клиент не уйдёт;
//   - единица запроса обмена урегулируется на КАЖДОМ выходе, и на панике
//     посреди операции тоже: иначе транзакция запроса остаётся открытой, связь
//     пула не возвращается, а замок строки кода живёт до потолка простоя.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/oauthceremony"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/ceremony"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// stalledDirectory — справочник, который не отвечает, пока вызов не кончится.
type stalledDirectory struct{}

func (stalledDirectory) LookupClient(ctx context.Context, _ string) (oauthceremony.ClientRegistration, error) {
	<-ctx.Done()
	return oauthceremony.ClientRegistration{}, ctx.Err()
}

// stalledAuthority — шов входа, который не отвечает, пока вызов не кончится.
type stalledAuthority struct{}

func (stalledAuthority) Resolve(ctx context.Context, _ domain.SessionBearer) (ceremony.Login, bool, error) {
	<-ctx.Done()
	return ceremony.Login{}, false, ctx.Err()
}

// protocolPassingEngine — церемония, пропускающая протокол: запрос доходит до
// шва входа.
type protocolPassingEngine struct{ untouchedEngine }

func (protocolPassingEngine) Authorize(context.Context, oauthceremony.AuthorizationRequest) (oauthceremony.AuthorizationIntent, error) {
	return oauthceremony.AuthorizationIntent{}, nil
}

// serveWithin — ответ эндпоинта и признак «ответил раньше, чем пробе надоело
// ждать». Не ответивший за patience запрос отменяется, чтобы проба не оставила
// горутину.
func serveWithin(h http.Handler, target string, patience time.Duration) (*httptest.ResponseRecorder, time.Duration, bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, target, nil).WithContext(ctx)
	done := make(chan time.Duration, 1)
	start := time.Now()
	go func() {
		h.ServeHTTP(rec, req)
		done <- time.Since(start)
	}()
	select {
	case took := <-done:
		return rec, took, true
	case <-time.After(patience):
		cancel()
		return rec, <-done, false
	}
}

func TestAuthorize_EachStoreCallCarriesTheConfiguredDeadline(t *testing.T) {
	const callTimeout = 100 * time.Millisecond
	q := url.Values{
		"client_id": {knownClient}, "redirect_uri": {knownTarget}, "state": {strings.Repeat("s", StateFloor)},
		"scope": {"openid"}, "response_type": {"code"},
	}
	for _, cell := range []struct {
		name      string
		clients   ceremony.Clients
		authority ceremony.LoginAuthority
		answered  func(*httptest.ResponseRecorder) bool
	}{
		{"справочник клиентов", stalledDirectory{}, &silentAuthority{}, func(r *httptest.ResponseRecorder) bool {
			return r.Code == http.StatusServiceUnavailable && r.Header().Get("Location") == ""
		}},
		{"шов входа", directory{}, stalledAuthority{}, func(r *httptest.ResponseRecorder) bool {
			loc, err := url.Parse(r.Header().Get("Location"))
			return r.Code == http.StatusFound && err == nil && loc.Query().Get("error") == "temporarily_unavailable"
		}},
	} {
		t.Run(cell.name, func(t *testing.T) {
			a := authorizeEndpoint(t, &protocolPassingEngine{}, cell.clients, cell.authority, NewCensus(), callTimeout)
			rec, took, answered := serveWithin(a, AuthorizePath+"?"+q.Encode(), 2*time.Second)
			if !answered {
				t.Fatalf("%s не ответил за 2s при сроке вызова %s: вызов идёт без своего срока", cell.name, callTimeout)
			}
			if took > callTimeout+time.Second {
				t.Errorf("отказ пришёл через %s при сроке вызова %s", took, callTimeout)
			}
			if !cell.answered(rec) {
				t.Errorf("%s не ответил в срок: %d %q Location %q — ожидалось «временно недоступно»",
					cell.name, rec.Code, rec.Body.String(), rec.Header().Get("Location"))
			}
		})
	}
}

// panickingEngine — церемония, падающая посреди обмена.
type panickingEngine struct{ untouchedEngine }

func (panickingEngine) Exchange(context.Context, oauthceremony.TokenRequest) (oauthceremony.TokenResult, error) {
	panic("ceremony exchange broke mid-operation")
}

func TestTokenLane_ARequestIsSettledOnAPanicMidExchange(t *testing.T) {
	units := &countingUnits{}
	lane, _, _ := newLane(t, &panickingEngine{}, units)
	func() {
		defer func() {
			if recover() == nil {
				t.Errorf("паника церемонии проглочена полосой")
			}
		}()
		post(t, lane, url.Values{"grant_type": {"authorization_code"}, "code": {"c"}}, []string{"ic-1", "s"})
	}()
	if units.opened != 1 || units.settled != 1 {
		t.Fatalf("паника посреди обмена: единица запроса открыта %d, урегулирована %d — ожидалось по одному",
			units.opened, units.settled)
	}
}
