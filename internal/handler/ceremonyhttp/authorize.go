// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyhttp

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	ceremonyapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/oauth_ceremony"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/exchangepace"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/handler/methodrefusal"
)

// untrustedTargetRefusal — отказ, наступивший ДО того, как цель доверена:
// клиента нет, клиент снимается, адрес возврата не зарегистрирован, клиент или
// адрес не названы либо названы дважды. Один текст и одно состояние на все
// случаи (Р4, заказ разбора классов LAX-20): человеку не сообщается, какой из
// них, и перенаправлять некуда. Различимость — в счётчике и журнале.
const untrustedTargetRefusal = "The authorization request cannot be served: " +
	"the client or its return address is not recognised.\n"

// unavailableRefusal — справочник клиентов не ответил, пока цель не доверена;
// тем же текстом отвечает занятый потолок точки авторизации (П5): и там, и там
// занята НАША сторона.
const unavailableRefusal = "The authorization server is temporarily unavailable.\n"

// tooManyRefusal — источник исчерпал темп точки авторизации (П4).
const tooManyRefusal = "Too many authorization requests: retry later.\n"

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
	// Pace — запросов авторизации в секунду на источник (П4), ведро в одну
	// секунду темпа. Тратит его всякий запрос, прошедший проверку метода.
	Pace *exchangepace.Pace
	// InFlightCeiling — потолок одновременных запросов авторизации на процесс
	// (П5). Свой, отдельный от потолка токен-эндпоинта: поток обменов не
	// отнимает мест у навигаций людей, и наоборот.
	InFlightCeiling int
	// Source — адрес источника запроса по правилу Р7 (`issuingsource`).
	Source func(*http.Request) string
}

// Authorize — эндпоинт авторизации `GET /iam/v1/authorize`.
type Authorize struct {
	cfg AuthorizeConfig
	// slots — места одновременных запросов; занятое место — элемент канала.
	slots chan struct{}
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
	case cfg.Pace == nil:
		return nil, errors.New("ceremonyhttp: authorize endpoint needs its pace per source")
	case cfg.InFlightCeiling <= 0:
		return nil, errors.New("ceremonyhttp: authorize endpoint needs a positive in-flight ceiling")
	case cfg.Source == nil:
		return nil, errors.New("ceremonyhttp: authorize endpoint needs the source address rule")
	}
	return &Authorize{cfg: cfg, slots: make(chan struct{}, cfg.InFlightCeiling)}, nil
}

// ServeHTTP — см. порядок решений в шапке пакета.
func (a *Authorize) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if r.Method != http.MethodGet {
		a.cfg.Census.count(OutcomeAuthorizeMethodNotAllowed)
		// Форма решения R36 п. 3 — та же, что у полосы входа (Р12 приёмки темпа
		// церемонии, kaname#524): отказ метода решается до протокола, и словарь
		// ошибок OAuth к нему не применим.
		methodrefusal.Write(w, http.MethodGet)
		return
	}
	ctx := r.Context()

	// (1а) П4 — темп источника. Раньше потолка: источник, исчерпавший П4, места
	// под П5 не занимает. Обе оси — до справочника клиентов и хранилища сессий:
	// бережётся именно обращение к ним. Цель ещё не доверена, поэтому отказ —
	// прямо, без перенаправления.
	if _, after, ok := a.cfg.Pace.Reserve(a.cfg.Source(r)); !ok {
		a.cfg.Census.count(OutcomeAuthorizeSourcePaceExceeded)
		writeRetryText(w, http.StatusTooManyRequests, after, tooManyRefusal)
		return
	}
	// (1б) П5 — потолок одновременных запросов авторизации.
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	default:
		a.cfg.Census.count(OutcomeAuthorizeInFlightCeilingReached)
		writeRetryText(w, http.StatusServiceUnavailable, time.Second, unavailableRefusal)
		return
	}

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
		a.challenge(ctx, w, target.RedirectURI, "login_required", q.Get("state"),
			OutcomeAuthorizeLoginRequired, clientID, res.Subject)
	case ceremonyapp.VerdictStepUpRequired:
		a.challenge(ctx, w, target.RedirectURI, "insufficient_user_authentication", q.Get("state"),
			OutcomeAuthorizeStepUpRequired, clientID, res.Subject)
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

// challenge — вызов аутентификации (нет годной сессии либо уровень ниже
// запрошенного): кода нет, и отказ уходит ПРИЛОЖЕНИЮ — 302 на доверенную цель
// (приёмка ceremony-pace-is-named-by-number, Р11, задача kaname#525). Адрес
// авторизации открывает браузер; ответ без перенаправления остался бы у него,
// и приложение не узнало бы, что человека надо вести на вход либо на шаг
// вверх.
//
// Перенаправлять безопасно: сюда доходит только запрос, чья цель уже доверена
// — клиент известен, адрес возврата зарегистрирован, `state` не короче пола
// (ServeHTTP, шаги 2–3). Незарегистрированная цель и неизвестный клиент
// получают прежний отказ без перенаправления при любой сессии.
//
// В строке запроса — собственные параметры цели, `error` и `state` дословно, и
// ничего сверх: ни описания отказа, ни запрошенного уровня — строка уходит в
// историю браузера и в заголовок источника перехода, а уровень приложение
// назвало само. `state` здесь возвращается, в отличие от отказов протокола: он
// прошёл пол, и приложение по нему связывает ответ со своим запросом.
func (a *Authorize) challenge(ctx context.Context, w http.ResponseWriter, target, wire, state string,
	outcome Outcome, clientID, subject string,
) {
	a.cfg.Census.count(outcome)
	attrs := []any{slog.String("outcome", string(outcome)), slog.String("client", clientID)}
	if subject != "" {
		attrs = append(attrs, slog.String("subject", subject))
	}
	a.cfg.Logger.InfoContext(ctx, "authorization request needs authentication", attrs...)
	u, err := url.Parse(target)
	if err != nil {
		// Цель — зарегистрированный адрес, прошедший разбор домена ресурса;
		// неразбираемой она быть не может. Если всё же стала — отвечать ею
		// нельзя: отказ без перенаправления, как недоверенной цели.
		writeText(w, http.StatusBadRequest, untrustedTargetRefusal)
		return
	}
	params := u.Query()
	params.Set("error", wire)
	params.Set("state", state)
	u.RawQuery = params.Encode()
	w.Header().Set("Location", u.String())
	w.WriteHeader(http.StatusFound)
}

// writeRetryText — отказ по темпу точки авторизации: срок ожидания целыми
// секундами, округлённый вверх и не меньше одной. У П4 темп не меньше единицы в
// секунду, у П5 место освобождает любой завершившийся запрос, поэтому срок у
// обеих — секунда.
func writeRetryText(w http.ResponseWriter, status int, after time.Duration, body string) {
	secs := int64(math.Ceil(after.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
	writeText(w, status, body)
}

func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	noStore(w)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
