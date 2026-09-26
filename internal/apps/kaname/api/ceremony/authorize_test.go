// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremony

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/oauthceremony"
	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

const (
	knownClient = "ic-known"
	knownTarget = "https://app.example.test/cb"
)

// directory — справочник пробы: один клиент с одной целью. Запоминает, нёс ли
// контекст вызова срок.
type directory struct {
	err       error
	audiences []string
	deadline  time.Duration
}

func (d *directory) LookupClient(ctx context.Context, id string) (oauthceremony.ClientRegistration, error) {
	if dl, ok := ctx.Deadline(); ok {
		d.deadline = time.Until(dl)
	}
	if d.err != nil {
		return oauthceremony.ClientRegistration{}, d.err
	}
	if id != knownClient {
		return oauthceremony.ClientRegistration{}, oauthceremony.ErrGrantNotFound
	}
	auds := d.audiences
	if auds == nil {
		auds = []string{"https://api.example.test"}
	}
	return oauthceremony.ClientRegistration{ClientID: knownClient, RedirectURIs: []string{knownTarget}, Audiences: auds}, nil
}

// authority — шов входа пробы.
type authority struct {
	login    Login
	found    bool
	err      error
	calls    int
	deadline time.Duration
}

func (a *authority) Resolve(ctx context.Context, _ domain.SessionBearer) (Login, bool, error) {
	a.calls++
	if dl, ok := ctx.Deadline(); ok {
		a.deadline = time.Until(dl)
	}
	return a.login, a.found, a.err
}

// engine — церемония пробы: запоминает запрос и грант выдачи.
type engine struct {
	authorizeErr error
	completeErr  error
	result       oauthceremony.AuthorizationResult
	req          oauthceremony.AuthorizationRequest
	grant        oauthceremony.AuthorizationGrant
	authorized   int
	completed    int
}

func (e *engine) Authorize(_ context.Context, req oauthceremony.AuthorizationRequest) (oauthceremony.AuthorizationIntent, error) {
	e.authorized++
	e.req = req
	return oauthceremony.AuthorizationIntent{}, e.authorizeErr
}

func (e *engine) CompleteAuthorization(_ context.Context, _ oauthceremony.AuthorizationIntent, grant oauthceremony.AuthorizationGrant) (oauthceremony.AuthorizationResult, error) {
	e.completed++
	e.grant = grant
	return e.result, e.completeErr
}

var clockAt = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func newAuthorizeRig(t *testing.T, d *directory, a *authority, e *engine) *AuthorizeUseCase {
	t.Helper()
	uc, err := NewAuthorizeUseCase(AuthorizeDeps{Engine: e, Clients: d, Authority: a,
		Clock: func() time.Time { return clockAt }, CallTimeout: time.Second})
	if err != nil {
		t.Fatalf("сборка: %v", err)
	}
	return uc
}

func trusted(t *testing.T, uc *AuthorizeUseCase) Target {
	t.Helper()
	target, verdict, err := uc.Trust(context.Background(), knownClient, knownTarget)
	if err != nil || verdict != TrustGranted {
		t.Fatalf("доверие цели: %v %v", verdict, err)
	}
	return target
}

func issued() oauthceremony.AuthorizationResult {
	return oauthceremony.AuthorizationResult{RedirectURI: knownTarget + "?code=c", Delivery: oauthceremony.DeliveryQuery}
}

func liveLogin(level string, expires time.Time) *authority {
	return &authority{found: true, login: Login{Subject: "usr-1", SessionID: "hss-1", AuthTime: clockAt.Add(-time.Minute),
		Level: level, ExpiresAt: expires}}
}

func baseInput() AuthorizeInput {
	return AuthorizeInput{Scopes: []string{"openid"}, ResponseKinds: []string{"code"}, State: "s"}
}

// Доверие цели: клиента нет, цель не та, справочник не ответил, цель доверена —
// четыре исхода; вызов справочника идёт под сроком, названным сборкой.
func TestAuthorizeTrust_FourVerdictsUnderTheCallDeadline(t *testing.T) {
	for _, tc := range []struct {
		name, client, target string
		err                  error
		want                 TrustVerdict
	}{
		{"клиента нет", "ic-unknown", knownTarget, nil, TrustClientUnknown},
		{"цель не та", knownClient, knownTarget + "/", nil, TrustRedirectUnregistered},
		{"справочник не ответил", knownClient, knownTarget, errors.New("store down"), TrustDirectoryUnavailable},
		{"цель доверена", knownClient, knownTarget, nil, TrustGranted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &directory{err: tc.err}
			uc := newAuthorizeRig(t, d, &authority{}, &engine{})
			target, verdict, err := uc.Trust(context.Background(), tc.client, tc.target)
			if verdict != tc.want {
				t.Fatalf("исход %v, ожидался %v (ошибка %v)", verdict, tc.want, err)
			}
			if (tc.want == TrustDirectoryUnavailable) != (err != nil) {
				t.Errorf("ошибка %v при исходе %v", err, verdict)
			}
			if tc.want == TrustGranted && (target.ClientID != knownClient || target.RedirectURI != knownTarget) {
				t.Errorf("доверенная цель %+v", target)
			}
			if d.deadline <= 0 || d.deadline > time.Second {
				t.Errorf("вызов справочника без срока сборки: остаток %s", d.deadline)
			}
		})
	}
}

// Отказы протокола до входа: уровень вне словаря, пустая область, клиент без
// получателя — каждый своим словом, и шов входа не спрошен.
func TestAuthorizeExecute_ProtocolRefusalsBeforeTheLogin(t *testing.T) {
	for _, tc := range []struct {
		name      string
		in        func(AuthorizeInput) AuthorizeInput
		audiences []string
		wire      string
	}{
		{"уровень вне словаря", func(i AuthorizeInput) AuthorizeInput { i.AcrValues = "gold"; return i }, nil, "invalid_request"},
		{"область не названа", func(i AuthorizeInput) AuthorizeInput { i.Scopes = nil; return i }, nil, "invalid_scope"},
		{"клиент без получателя", func(i AuthorizeInput) AuthorizeInput { return i }, []string{}, "unauthorized_client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, e := liveLogin("1", clockAt.Add(time.Hour)), &engine{result: issued()}
			uc := newAuthorizeRig(t, &directory{audiences: tc.audiences}, a, e)
			res := uc.Execute(context.Background(), trusted(t, uc), tc.in(baseInput()))
			if res.Verdict != VerdictRefusedByRedirect || res.Wire != tc.wire {
				t.Fatalf("исход %+v, ожидался отказ перенаправлением %q", res, tc.wire)
			}
			if a.calls != 0 || e.authorized != 0 {
				t.Errorf("отказ протокола спросил шов входа (%d) либо церемонию (%d)", a.calls, e.authorized)
			}
		})
	}
}

// Получатель — регистрация клиента, а не запрос (Р6).
func TestAuthorizeExecute_AudienceComesFromTheRegistration(t *testing.T) {
	e := &engine{result: issued()}
	uc := newAuthorizeRig(t, &directory{audiences: []string{"https://api.example.test"}}, liveLogin("1", time.Time{}), e)
	res := uc.Execute(context.Background(), trusted(t, uc), baseInput())
	if res.Verdict != VerdictIssued {
		t.Fatalf("выдача: %+v", res)
	}
	if len(e.req.Audiences) != 1 || e.req.Audiences[0] != "https://api.example.test" {
		t.Errorf("получатель запроса церемонии %v", e.req.Audiences)
	}
}

// Шаг вверх: уровень сессии ниже наименьшего из запрошенных — вызов шага вверх
// с запрошенными уровнями; близнец — уровень сессии равен наименьшему.
func TestAuthorizeExecute_StepUpIsJudgedAgainstTheLowestRequestedLevel(t *testing.T) {
	for _, tc := range []struct {
		acr  string
		want Verdict
	}{
		{"2 3", VerdictStepUpRequired},
		{"1 3", VerdictIssued},
	} {
		in := baseInput()
		in.AcrValues = " " + tc.acr + " "
		uc := newAuthorizeRig(t, &directory{}, liveLogin("1", time.Time{}), &engine{result: issued()})
		res := uc.Execute(context.Background(), trusted(t, uc), in)
		if res.Verdict != tc.want {
			t.Errorf("acr_values %q при уровне 1: %+v, ожидался %v", tc.acr, res, tc.want)
		}
		if tc.want == VerdictStepUpRequired && (res.AcrValues != tc.acr || res.Subject != "usr-1") {
			t.Errorf("вызов шага вверх: %+v", res)
		}
	}
}

// Граница семейства — одно правило домена: не позже сессии и не позже потолка
// семейства от момента выдачи.
func TestAuthorizeExecute_TheFamilyBoundIsTheDomainRule(t *testing.T) {
	for _, expires := range []time.Time{clockAt.Add(time.Hour), clockAt.Add(tokenpolicy.MaxRefreshTokenFamilyTTL + time.Hour), {}} {
		e := &engine{result: issued()}
		uc := newAuthorizeRig(t, &directory{}, liveLogin("1", expires), e)
		if res := uc.Execute(context.Background(), trusted(t, uc), baseInput()); res.Verdict != VerdictIssued {
			t.Fatalf("выдача: %+v", res)
		}
		want := domain.CeremonyFamilyBound(clockAt, expires)
		for kind, got := range e.grant.ExpiresAt {
			if !got.Equal(want) {
				t.Errorf("срок сессии %s: граница %s у %s, ожидалась %s", expires, got, kind, want)
			}
		}
		if len(e.grant.ExpiresAt) != 3 {
			t.Errorf("граница названа не всем видам: %v", e.grant.ExpiresAt)
		}
	}
}

// Шов входа: сессии нет — вызов аутентификации; не ответил — временная
// недоступность перенаправлением; сессия кончилась между швом и выдачей — вызов
// аутентификации. Вызов шва идёт под сроком, названным сборкой.
func TestAuthorizeExecute_LoginSeamOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		a           *authority
		completeErr error
		want        Verdict
		wire        string
	}{
		{"сессии нет", &authority{}, nil, VerdictLoginRequired, ""},
		{"шов не ответил", &authority{err: errors.New("store down")}, nil, VerdictUnavailable, "temporarily_unavailable"},
		{"сессия кончилась до выдачи", liveLogin("1", time.Time{}),
			fmt.Errorf("oauthceremony: server_error: %w", domain.ErrCeremonySessionNotLive), VerdictLoginRequired, ""},
		{"сессии не стало до выдачи", liveLogin("1", time.Time{}),
			fmt.Errorf("oauthceremony: server_error: %w", domain.ErrCeremonySessionUnknown), VerdictLoginRequired, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uc := newAuthorizeRig(t, &directory{}, tc.a, &engine{result: issued(), completeErr: tc.completeErr})
			res := uc.Execute(context.Background(), trusted(t, uc), baseInput())
			if res.Verdict != tc.want || res.Wire != tc.wire {
				t.Fatalf("исход %+v, ожидался %v %q", res, tc.want, tc.wire)
			}
			if tc.a.deadline <= 0 || tc.a.deadline > time.Second {
				t.Errorf("вызов шва входа без срока сборки: остаток %s", tc.a.deadline)
			}
		})
	}
}

// Отказ церемонии без цели — отказ без перенаправления; с целью —
// перенаправлением словом словаря точки авторизации.
func TestAuthorizeExecute_EngineRefusal(t *testing.T) {
	refusal := &oauthceremony.ProtocolError{Code: oauthceremony.CodeInvalidScope}
	uc := newAuthorizeRig(t, &directory{}, liveLogin("1", time.Time{}), &engine{authorizeErr: refusal})
	res := uc.Execute(context.Background(), trusted(t, uc), baseInput())
	if res.Verdict != VerdictRefusedUntrusted || res.Why == "" {
		t.Fatalf("отказ церемонии без цели: %+v", res)
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

func TestNewAuthorizeUseCase_RefusesAnIncompleteWiring(t *testing.T) {
	full := AuthorizeDeps{Engine: &engine{}, Clients: &directory{}, Authority: &authority{},
		Clock: time.Now, CallTimeout: time.Second}
	for name, broken := range map[string]func(AuthorizeDeps) AuthorizeDeps{
		"церемонии нет":   func(d AuthorizeDeps) AuthorizeDeps { d.Engine = nil; return d },
		"справочника нет": func(d AuthorizeDeps) AuthorizeDeps { d.Clients = nil; return d },
		"шва входа нет":   func(d AuthorizeDeps) AuthorizeDeps { d.Authority = nil; return d },
		"часов нет":       func(d AuthorizeDeps) AuthorizeDeps { d.Clock = nil; return d },
		"срок не назван":  func(d AuthorizeDeps) AuthorizeDeps { d.CallTimeout = 0; return d },
	} {
		if _, err := NewAuthorizeUseCase(broken(full)); err == nil {
			t.Errorf("%s: собрано", name)
		}
	}
	if _, err := NewAuthorizeUseCase(full); err != nil {
		t.Errorf("близнец: полная провязка отвергнута: %v", err)
	}
}
