// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyhttp

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/PRO-Robotech/corelib/acrlevel"
	"github.com/PRO-Robotech/corelib/oauthceremony"
	"github.com/PRO-Robotech/corelib/tokenpolicy"

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
	Engine    Engine
	Clients   Clients
	Authority LoginAuthority
	Census    *Census
	Logger    *slog.Logger
	// Clock — источник времени границы семейства. Вход, а не окружение.
	Clock func() time.Time
}

// Authorize — эндпоинт авторизации `GET /iam/v1/authorize`.
type Authorize struct {
	cfg AuthorizeConfig
}

// NewAuthorize строит эндпоинт. Неполная провязка — отказ построения.
func NewAuthorize(cfg AuthorizeConfig) (*Authorize, error) {
	switch {
	case cfg.Engine == nil:
		return nil, errors.New("ceremonyhttp: authorize endpoint needs the ceremony")
	case cfg.Clients == nil:
		return nil, errors.New("ceremonyhttp: authorize endpoint needs the client directory")
	case cfg.Authority == nil:
		return nil, errors.New("ceremonyhttp: authorize endpoint needs the login authority")
	case cfg.Census == nil:
		return nil, errors.New("ceremonyhttp: authorize endpoint needs the outcome census")
	case cfg.Logger == nil:
		return nil, errors.New("ceremonyhttp: authorize endpoint needs a logger")
	case cfg.Clock == nil:
		return nil, errors.New("ceremonyhttp: authorize endpoint needs a clock")
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
		a.refuseUntrusted(ctx, w, OutcomeAuthorizeRequestMalformed, clientID)
		return
	}
	reg, err := a.cfg.Clients.LookupClient(ctx, clientID)
	switch {
	case oauthceremony.CodeOf(err) == oauthceremony.CodeGrantNotFound:
		a.refuseUntrusted(ctx, w, OutcomeAuthorizeClientUnknown, clientID)
		return
	case err != nil:
		a.cfg.Census.count(OutcomeAuthorizeUnavailable)
		a.cfg.Logger.ErrorContext(ctx, "authorization request: client directory did not answer",
			slog.String("outcome", string(OutcomeAuthorizeUnavailable)), slog.String("client", clientID),
			slog.String("err", err.Error()))
		writeText(w, http.StatusServiceUnavailable, unavailableRefusal)
		return
	}
	// Точное равенство, без нормализации: хвостовой слэш, регистр, порядок
	// параметров — другой адрес (Р4, LAX-4).
	if !slices.Contains(reg.RedirectURIs, redirect) {
		a.refuseUntrusted(ctx, w, OutcomeAuthorizeRedirectUnregistered, clientID)
		return
	}

	// С этого места цель доверена, и отказ уезжает перенаправлением.
	target := redirect
	for _, name := range singleValued {
		if len(q[name]) > 1 {
			a.refuseByRedirect(ctx, w, target, "invalid_request", OutcomeAuthorizeProtocolRefused, clientID,
				"parameter "+name+" is named more than once")
			return
		}
	}

	// (3) Пол `state`: не прислан (длина 0) и короче пола — один исход (Р13 п. 1).
	if utf8.RuneCountInString(q.Get("state")) < StateFloor {
		a.refuseByRedirect(ctx, w, target, "invalid_request", OutcomeAuthorizeStateBelowFloor, clientID,
			"state below the floor")
		return
	}
	required, ok := requiredLevel(q.Get("acr_values"))
	if !ok {
		a.refuseByRedirect(ctx, w, target, "invalid_request", OutcomeAuthorizeProtocolRefused, clientID,
			"acr_values names a level outside the platform vocabulary")
		return
	}
	scopes := strings.Fields(q.Get("scope"))
	if len(scopes) == 0 {
		a.refuseByRedirect(ctx, w, target, "invalid_scope", OutcomeAuthorizeProtocolRefused, clientID,
			"no scope requested")
		return
	}
	if len(reg.Audiences) == 0 {
		// Получателя штампуем мы по регистрации клиента (Р6); клиент без
		// зарегистрированного получателя токена получить не может.
		a.refuseByRedirect(ctx, w, target, "unauthorized_client", OutcomeAuthorizeProtocolRefused, clientID,
			"the client registers no audience")
		return
	}

	// (4) Протокол — церемонией фундамента. Назначаемое выдачей (субъект,
	// уровень, момент, получатель) из запроса не берётся: такие параметры
	// церемонии не передаются вовсе (Р5).
	req := oauthceremony.AuthorizationRequest{
		ClientID:    clientID,
		RedirectURI: redirect,
		Scopes:      scopes,
		Audiences:   append([]string(nil), reg.Audiences...),
		State:       q.Get("state"),
		Delivery:    oauthceremony.ResponseDelivery(q.Get("response_mode")),
		Additional:  map[string][]string{},
	}
	for _, kind := range strings.Fields(q.Get("response_type")) {
		req.ResponseKinds = append(req.ResponseKinds, oauthceremony.ResponseKind(kind))
	}
	for _, name := range []string{"code_challenge", "code_challenge_method"} {
		if v := q.Get(name); v != "" {
			req.Additional[name] = []string{v}
		}
	}
	intent, err := a.cfg.Engine.Authorize(ctx, req)
	if err != nil {
		if intent.RedirectURI() == "" {
			a.refuseUntrusted(ctx, w, OutcomeAuthorizeProtocolRefused, clientID)
			return
		}
		a.refuseByRedirect(ctx, w, target, authorizeWire(oauthceremony.CodeOf(err)), OutcomeAuthorizeProtocolRefused,
			clientID, oauthceremony.CodeOf(err).String())
		return
	}

	// (5) Шов входа.
	login, found, err := a.cfg.Authority.Resolve(ctx, presentedSession(r))
	switch {
	case err != nil:
		a.refuseByRedirect(ctx, w, target, "temporarily_unavailable", OutcomeAuthorizeUnavailable, clientID,
			"login authority did not answer: "+err.Error())
		return
	case !found:
		a.challenge(ctx, w, OutcomeAuthorizeLoginRequired, clientID, "", errorBody("login_required"))
		return
	case required > 0 && acrlevel.Rank(login.Level) < required:
		a.challenge(ctx, w, OutcomeAuthorizeStepUpRequired, clientID, login.Subject, map[string]string{
			"error":      "insufficient_user_authentication",
			"acr_values": strings.TrimSpace(q.Get("acr_values")),
		})
		return
	}

	// (6) Выдача. Граница семейства — не позже сессии, в которой оно выдано, и
	// не позже потолка семейства фундамента.
	bound := a.cfg.Clock().Add(tokenpolicy.MaxRefreshTokenFamilyTTL)
	if !login.ExpiresAt.IsZero() && login.ExpiresAt.Before(bound) {
		bound = login.ExpiresAt
	}
	result, err := a.cfg.Engine.CompleteAuthorization(ctx, intent, oauthceremony.AuthorizationGrant{
		Subject:          login.Subject,
		SessionID:        login.SessionID,
		ACR:              login.Level,
		AuthTime:         login.AuthTime,
		GrantedScopes:    intent.RequestedScopes(),
		GrantedAudiences: intent.RequestedAudiences(),
		ExpiresAt: map[oauthceremony.TokenKind]time.Time{
			oauthceremony.TokenKindAuthorizationCode: bound,
			oauthceremony.TokenKindAccess:            bound,
			oauthceremony.TokenKindRefresh:           bound,
		},
	})
	if errors.Is(err, domain.ErrCeremonySessionNotLive) || errors.Is(err, domain.ErrCeremonySessionUnknown) {
		// Сессия кончилась между ответом шва и выдачей: входа, в котором идёт
		// церемония, больше нет.
		a.challenge(ctx, w, OutcomeAuthorizeLoginRequired, clientID, login.Subject, errorBody("login_required"))
		return
	}
	if err != nil {
		a.refuseByRedirect(ctx, w, target, authorizeWire(oauthceremony.CodeOf(err)), OutcomeAuthorizeUnavailable,
			clientID, oauthceremony.CodeOf(err).String()+": "+err.Error())
		return
	}
	if result.RedirectURI == "" || result.Delivery != oauthceremony.DeliveryQuery {
		a.refuseByRedirect(ctx, w, target, "server_error", OutcomeAuthorizeUnavailable, clientID,
			"the ceremony assembled no query redirect")
		return
	}

	// Согласие первопартийного клиента не спрашивается (приёмка §4, 09): ответ
	// выдачи — сразу перенаправление с кодом. Адрес собрал движок; код
	// состояния — поверхности (302, приёмка 02).
	a.cfg.Census.count(OutcomeAuthorizeIssued)
	a.cfg.Logger.InfoContext(ctx, "authorization code issued",
		slog.String("outcome", string(OutcomeAuthorizeIssued)), slog.String("client", clientID),
		slog.String("subject", login.Subject), slog.String("acr", login.Level))
	w.Header().Set("Location", result.RedirectURI)
	w.WriteHeader(http.StatusFound)
}

// presentedSession — носитель нашей сессии из печенья полосы входа.
func presentedSession(r *http.Request) domain.SessionBearer {
	c, err := r.Cookie(loginlanehttp.CookieSession)
	if err != nil {
		return domain.SessionBearer{}
	}
	return domain.PresentedSessionBearer(c.Value)
}

// requiredLevel — наименьший уровень из `acr_values`: клиент перечисляет
// приемлемые уровни, и любой из них удовлетворяет запросу. ok=false — значение
// вне словаря платформы (ранжирование `acrlevel`).
func requiredLevel(acrValues string) (int, bool) {
	required := 0
	for _, v := range strings.Fields(acrValues) {
		rank := acrlevel.Rank(v)
		if rank == 0 {
			return 0, false
		}
		if required == 0 || rank < required {
			required = rank
		}
	}
	return required, true
}

// authorizeWire — код отказа точки авторизации из словаря RFC 6749 §4.1.2.1.
// Случай церемонии вне этого словаря уезжает ближайшим словом словаря, а не
// своим: чужая библиотека прочтёт только слово стандарта.
func authorizeWire(code oauthceremony.FailureCode) string {
	switch wire := code.WireCode(); wire {
	case "invalid_request", "unauthorized_client", "access_denied", "unsupported_response_type",
		"invalid_scope", "server_error", "temporarily_unavailable":
		return wire
	}
	if code.HTTPStatus() >= http.StatusInternalServerError {
		return "server_error"
	}
	return "invalid_request"
}

// refuseUntrusted — отказ без перенаправления (см. untrustedTargetRefusal).
func (a *Authorize) refuseUntrusted(ctx context.Context, w http.ResponseWriter, outcome Outcome, clientID string) {
	a.cfg.Census.count(outcome)
	a.cfg.Logger.WarnContext(ctx, "authorization request refused without redirect",
		slog.String("outcome", string(outcome)), slog.String("client", clientID))
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
