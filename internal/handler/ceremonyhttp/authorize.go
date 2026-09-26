// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyhttp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	ceremonyapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/oauth_ceremony"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

// untrustedTargetRefusal — отказ, наступивший ДО того, как цель доверена:
// клиента нет, клиент снимается, адрес возврата не зарегистрирован, клиент или
// адрес не названы либо названы дважды. Один текст и одно состояние на все
// случаи (Р4, заказ разбора классов LAX-20): человеку не сообщается, какой из
// них, и перенаправлять некуда. Различимость — в счётчике и журнале.
const untrustedTargetRefusal = "The authorization request cannot be served: " +
	"the client or its return address is not recognised.\n"

// unavailableRefusal — справочник клиентов не ответил, пока цель не доверена.
const unavailableRefusal = "The authorization server is temporarily unavailable.\n"

// singleValued — параметры, которые запрос называет не более одного раза:
// параметр, названный дважды, делает запрос неоднозначным (RFC 6749 §3.1), и
// разбор, берущий первое значение, судил бы не то, что прислано.
var singleValued = []string{
	"client_id", "redirect_uri", "response_type", "scope", "state",
	"code_challenge", "code_challenge_method", "acr_values", "response_mode",
}

// AuthorizeConfig — зависимости эндпоинта авторизации. Все обязательны.
type AuthorizeConfig struct {
	// UseCase — выдача кода: доверие цели, решения домена и сроки вызовов
	// хранилища (`internal/apps/kaname/api/oauth_ceremony`).
	UseCase *ceremonyapp.AuthorizeUseCase
	Census  *Census
	Logger  *slog.Logger
}

// Authorize — эндпоинт авторизации `GET /iam/v1/authorize`.
type Authorize struct {
	cfg AuthorizeConfig
}

// NewAuthorize строит эндпоинт. Неполная провязка — отказ построения.
func NewAuthorize(cfg AuthorizeConfig) (*Authorize, error) {
	switch {
	case cfg.UseCase == nil:
		return nil, errors.New("ceremonyhttp: authorize endpoint needs the authorize use-case")
	case cfg.Census == nil:
		return nil, errors.New("ceremonyhttp: authorize endpoint needs the outcome census")
	case cfg.Logger == nil:
		return nil, errors.New("ceremonyhttp: authorize endpoint needs a logger")
	}
	return &Authorize{cfg: cfg}, nil
}

// ServeHTTP — см. порядок решений в шапке пакета.
func (a *Authorize) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if r.Method != http.MethodGet {
		a.cfg.Census.count(OutcomeAuthorizeMethodNotAllowed)
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("invalid_request"))
		return
	}
	ctx := r.Context()
	q := r.URL.Query()

	// (2) Клиент и адрес возврата — до всякого доверия.
	clientID, redirect := q.Get("client_id"), q.Get("redirect_uri")
	if len(q["client_id"]) != 1 || len(q["redirect_uri"]) != 1 || clientID == "" || redirect == "" {
		a.refuseUntrusted(ctx, w, OutcomeAuthorizeRequestMalformed, clientID, "client or return address not named once")
		return
	}
	target, trust, err := a.cfg.UseCase.Trust(ctx, clientID, redirect)
	switch trust {
	case ceremonyapp.TrustGranted:
	case ceremonyapp.TrustClientUnknown:
		a.refuseUntrusted(ctx, w, OutcomeAuthorizeClientUnknown, clientID, "client unknown")
		return
	case ceremonyapp.TrustRedirectUnregistered:
		a.refuseUntrusted(ctx, w, OutcomeAuthorizeRedirectUnregistered, clientID, "return address unregistered")
		return
	default:
		a.cfg.Census.count(OutcomeAuthorizeUnavailable)
		a.cfg.Logger.ErrorContext(ctx, "authorization request: client directory did not answer",
			slog.String("outcome", string(OutcomeAuthorizeUnavailable)), slog.String("client", clientID),
			slog.Any("err", err))
		writeText(w, http.StatusServiceUnavailable, unavailableRefusal)
		return
	}

	// С этого места цель доверена, и отказ уезжает перенаправлением.
	for _, name := range singleValued {
		if len(q[name]) > 1 {
			a.refuseByRedirect(ctx, w, target.RedirectURI, "invalid_request", OutcomeAuthorizeProtocolRefused, clientID,
				"parameter "+name+" is named more than once")
			return
		}
	}

	// (3) Пол `state`: не прислан (длина 0) и короче пола — один исход (Р13 п. 1).
	if utf8.RuneCountInString(q.Get("state")) < StateFloor {
		a.refuseByRedirect(ctx, w, target.RedirectURI, "invalid_request", OutcomeAuthorizeStateBelowFloor, clientID,
			"state below the floor")
		return
	}

	// (4)–(6) Протокол, шов входа, выдача — вариант использования.
	res := a.cfg.UseCase.Execute(ctx, target, ceremonyapp.AuthorizeInput{
		Scopes:              strings.Fields(q.Get("scope")),
		ResponseKinds:       strings.Fields(q.Get("response_type")),
		ResponseMode:        q.Get("response_mode"),
		State:               q.Get("state"),
		AcrValues:           q.Get("acr_values"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Session:             presentedSession(r),
	})
	switch res.Verdict {
	case ceremonyapp.VerdictRefusedByRedirect:
		a.refuseByRedirect(ctx, w, target.RedirectURI, res.Wire, OutcomeAuthorizeProtocolRefused, clientID, res.Why)
	case ceremonyapp.VerdictRefusedUntrusted:
		a.refuseUntrusted(ctx, w, OutcomeAuthorizeProtocolRefused, clientID, res.Why)
	case ceremonyapp.VerdictLoginRequired:
		a.challenge(ctx, w, OutcomeAuthorizeLoginRequired, clientID, res.Subject, errorBody("login_required"))
	case ceremonyapp.VerdictStepUpRequired:
		a.challenge(ctx, w, OutcomeAuthorizeStepUpRequired, clientID, res.Subject, map[string]string{
			"error":      "insufficient_user_authentication",
			"acr_values": res.AcrValues,
		})
	case ceremonyapp.VerdictIssued:
		// Согласие первопартийного клиента не спрашивается (приёмка §4, 09):
		// ответ выдачи — сразу перенаправление с кодом. Адрес собрал движок; код
		// состояния — поверхности (302, приёмка 02).
		a.cfg.Census.count(OutcomeAuthorizeIssued)
		a.cfg.Logger.InfoContext(ctx, "authorization code issued",
			slog.String("outcome", string(OutcomeAuthorizeIssued)), slog.String("client", clientID),
			slog.String("subject", res.Subject), slog.String("acr", res.Level))
		w.Header().Set("Location", res.RedirectURI)
		w.WriteHeader(http.StatusFound)
	default:
		// VerdictUnavailable и всякий исход, которого словарь поверхности не знает,
		// — отказ по нашей причине перенаправлением на доверенную цель.
		wire := res.Wire
		if wire == "" {
			wire = "server_error"
		}
		a.refuseByRedirect(ctx, w, target.RedirectURI, wire, OutcomeAuthorizeUnavailable, clientID, res.Why)
	}
}

// presentedSession — носитель нашей сессии из печенья полосы входа.
func presentedSession(r *http.Request) domain.SessionBearer {
	c, err := r.Cookie(loginlanehttp.CookieSession)
	if err != nil {
		return domain.SessionBearer{}
	}
	return domain.PresentedSessionBearer(c.Value)
}

// refuseUntrusted — отказ без перенаправления (см. untrustedTargetRefusal).
// Причина — только в журнал: наружу ответ один на все причины.
func (a *Authorize) refuseUntrusted(ctx context.Context, w http.ResponseWriter, outcome Outcome, clientID, why string) {
	a.cfg.Census.count(outcome)
	a.cfg.Logger.WarnContext(ctx, "authorization request refused without redirect",
		slog.String("outcome", string(outcome)), slog.String("client", clientID), slog.String("why", why))
	writeText(w, http.StatusBadRequest, untrustedTargetRefusal)
}

// refuseByRedirect — перенаправляемый отказ: 302 на доверенную цель, в строке
// запроса — её собственные параметры и ровно `error` (Р13 п. 3). Ни `state`, ни
// описания отказа: строка запроса уезжает в историю браузера и в заголовок
// источника перехода.
func (a *Authorize) refuseByRedirect(ctx context.Context, w http.ResponseWriter, target, wire string,
	outcome Outcome, clientID, why string,
) {
	a.cfg.Census.count(outcome)
	a.cfg.Logger.WarnContext(ctx, "authorization request refused by redirect",
		slog.String("outcome", string(outcome)), slog.String("client", clientID),
		slog.String("error", wire), slog.String("why", why))
	u, err := url.Parse(target)
	if err != nil {
		// Цель — зарегистрированный адрес, прошедший разбор домена ресурса;
		// неразбираемой она быть не может. Если всё же стала — отвечать ею
		// нельзя.
		writeText(w, http.StatusBadRequest, untrustedTargetRefusal)
		return
	}
	params := u.Query()
	params.Set("error", wire)
	u.RawQuery = params.Encode()
	w.Header().Set("Location", u.String())
	w.WriteHeader(http.StatusFound)
}

// challenge — вызов аутентификации (нет сессии либо уровень ниже запрошенного):
// кода нет, и цель не получает ничего — вход проводит наша полоса входа.
func (a *Authorize) challenge(ctx context.Context, w http.ResponseWriter, outcome Outcome, clientID, subject string,
	body map[string]string,
) {
	a.cfg.Census.count(outcome)
	attrs := []any{slog.String("outcome", string(outcome)), slog.String("client", clientID)}
	if subject != "" {
		attrs = append(attrs, slog.String("subject", subject))
	}
	a.cfg.Logger.InfoContext(ctx, "authorization request needs authentication", attrs...)
	writeJSON(w, http.StatusUnauthorized, body)
}

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	noStore(w)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
