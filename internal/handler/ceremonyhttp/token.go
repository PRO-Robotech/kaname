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
	"time"

	"github.com/PRO-Robotech/corelib/oauthceremony"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
)

// TokenLane — полосы `authorization_code` и `refresh_token` токен-эндпоинта.
//
// Метод, потолок тела, разбор формы и перечень видов выдачи судит эндпоинт
// (`clienttokenhttp.Handler`) ДО полосы; полоса получает разобранную форму.
//
// # Единый тон после именования кода (приёмка Р10)
//
// Всякий отказ, наступивший после того, как назван код либо токен обновления,
// — неизвестен, истёк, уже использован, неверный `code_verifier`, клиент не
// тот, адрес возврата не тот — отдаёт побайтово `{"error":"invalid_grant"}`.
// Различимы только отказы, решённые ДО этого: форма запроса и аутентификация
// конфиденциального клиента (`invalid_client`, о клиенте, не о коде).
type TokenLane struct {
	engine Engine
	units  RequestUnits
	census *Census
	logger *slog.Logger
}

// RequestUnits — единица запроса обмена: погашение кода, запись выпуска и пара
// — одна транзакция хранилища, открываемая погашением (реализует
// `pg.CeremonyVaults`). settle урегулирует запрос: закрепляет погашение, если
// выдача не состоялась. Зовётся ровно один раз — после операции, до ответа.
type RequestUnits interface {
	OpenRequest(ctx context.Context) (context.Context, func(context.Context) error)
}

var _ clienttokenhttp.CeremonyLane = (*TokenLane)(nil)

// NewTokenLane строит полосы. Неполная провязка — отказ построения.
func NewTokenLane(engine Engine, units RequestUnits, census *Census, logger *slog.Logger) (*TokenLane, error) {
	switch {
	case engine == nil:
		return nil, errors.New("ceremonyhttp: token lane needs the ceremony")
	case units == nil:
		return nil, errors.New("ceremonyhttp: token lane needs the exchange request units")
	case census == nil:
		return nil, errors.New("ceremonyhttp: token lane needs the outcome census")
	case logger == nil:
		return nil, errors.New("ceremonyhttp: token lane needs a logger")
	}
	return &TokenLane{engine: engine, units: units, census: census, logger: logger}, nil
}

// Grants — виды выдачи полосы: словарь церемонии фундамента, а не выписанные
// слова.
func (l *TokenLane) Grants() []string {
	kinds := oauthceremony.GrantKinds()
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	return out
}

// settleTimeout — предел урегулирования запроса: одно закрепление транзакции.
const settleTimeout = 3 * time.Second

// laneSingleValued — параметры полосы, называемые не более одного раза.
var laneSingleValued = []string{
	"grant_type", "code", "redirect_uri", "code_verifier", "refresh_token", "client_id", "client_secret",
}

// ServeGrant обслуживает вид выдачи grant по разобранной форме запроса.
func (l *TokenLane) ServeGrant(w http.ResponseWriter, r *http.Request, grant string) {
	ctx := r.Context()
	form := r.PostForm
	for _, name := range laneSingleValued {
		if len(form[name]) > 1 {
			l.refuse(r, w, http.StatusBadRequest, "invalid_request", OutcomeTokenRequestRefused, form.Get("client_id"),
				"parameter "+name+" is named more than once")
			return
		}
	}

	// Доказательство клиента (RFC 6749 §2.3.1): заголовок Basic — его части
	// кодированы формой, — либо секрет в теле; двумя способами сразу нельзя.
	req := oauthceremony.TokenRequest{
		Grant:        oauthceremony.GrantKind(grant),
		ClientID:     form.Get("client_id"),
		Code:         form.Get("code"),
		RedirectURI:  form.Get("redirect_uri"),
		CodeVerifier: form.Get("code_verifier"),
		RefreshToken: form.Get("refresh_token"),
	}
	if user, pass, basic := r.BasicAuth(); basic {
		if form.Has("client_secret") {
			l.refuse(r, w, http.StatusBadRequest, "invalid_request", OutcomeTokenRequestRefused, req.ClientID,
				"the client authenticates by more than one method")
			return
		}
		id, idErr := url.QueryUnescape(user)
		secret, secretErr := url.QueryUnescape(pass)
		if idErr != nil || secretErr != nil || id == "" || (req.ClientID != "" && req.ClientID != id) {
			l.refuseClient(r, w, id, "the Basic credentials are malformed or name another client than the form")
			return
		}
		req.ClientID, req.ClientSecret, req.AuthMethod = id, secret, oauthceremony.ClientAuthBasic
	} else if form.Has("client_secret") {
		req.ClientSecret, req.AuthMethod = form.Get("client_secret"), oauthceremony.ClientAuthPost
	}

	// Назначаемое выдачей — субъект, уровень, момент, получатель — церемонии не
	// передаётся вовсе: читается из кода (Р5, сценарии 10, 27).
	unitCtx, settle := l.units.OpenRequest(ctx)
	res, err := l.engine.Exchange(unitCtx, req)
	// Урегулирование — ДО ответа и отвязано от отмены вызывающего: ответ
	// «отказ» после незакреплённого погашения оставил бы код живым для повтора.
	settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), settleTimeout)
	serr := settle(settleCtx)
	cancel()
	if serr != nil {
		l.logger.ErrorContext(ctx, "ceremony exchange request was not settled",
			slog.String("client", req.ClientID), slog.String("err", serr.Error()))
		if err == nil {
			err = serr
		}
	}
	if err != nil {
		l.refuseExchange(r, w, req.ClientID, err)
		return
	}

	outcome := OutcomeTokenCodeExchanged
	if req.Grant == oauthceremony.GrantRefreshToken {
		outcome = OutcomeTokenRefreshed
	}
	l.census.count(outcome)
	l.logger.InfoContext(ctx, "ceremony token issued",
		slog.String("outcome", string(outcome)), slog.String("client", req.ClientID))
	body := map[string]any{
		"access_token": res.AccessToken,
		"token_type":   "Bearer",
		"expires_in":   int64(res.ExpiresIn.Seconds()),
	}
	if res.RefreshToken != "" {
		body["refresh_token"] = res.RefreshToken
	}
	if len(res.Scopes) > 0 {
		body["scope"] = strings.Join(res.Scopes, " ")
	}
	writeJSON(w, http.StatusOK, body)
}

// refuseExchange переводит отказ церемонии в ответ полосы по словарю RFC 6749
// §5.2. Случай церемонии — в счётчик и журнал; наружу — только слово словаря.
func (l *TokenLane) refuseExchange(r *http.Request, w http.ResponseWriter, clientID string, err error) {
	code := oauthceremony.CodeOf(err)
	switch wire := code.WireCode(); {
	case errors.Is(err, domain.ErrVerifierAtCapacity):
		// Проверяющий секрета занят: отказ повторяемый и наш, а не клиента.
		w.Header().Set("Retry-After", "1")
		l.refuse(r, w, http.StatusServiceUnavailable, "temporarily_unavailable", OutcomeTokenUnavailable,
			clientID, "client secret checker at capacity")
	case errors.Is(err, domain.ErrAccessTokenFamilyNotLive):
		// Запись выпуска отвергнута: семейство гранта умерло ВО ВРЕМЯ операции
		// (одновременный повтор токена обновления отозвал его раньше, чем этот
		// оборот записал свой выпуск; К1). Грант, который назвал запрос, негоден —
		// это отказ гранта тем же тоном, а не отказ сервера.
		l.refuse(r, w, http.StatusBadRequest, "invalid_grant", OutcomeTokenGrantRefused, clientID,
			"the family of the grant was revoked during the operation")
	case wire == "invalid_client":
		l.refuseClient(r, w, clientID, code.String())
	case wire == "invalid_grant":
		l.refuse(r, w, http.StatusBadRequest, "invalid_grant", OutcomeTokenGrantRefused, clientID, code.String())
	case code.HTTPStatus() >= http.StatusInternalServerError || code == oauthceremony.CodeUnspecified:
		// Отказ операции: текст причины — только в журнал, наружу — слово.
		status, word := http.StatusInternalServerError, "server_error"
		if wire == "temporarily_unavailable" {
			status, word = http.StatusServiceUnavailable, wire
		}
		why := code.String() + ": " + err.Error()
		var pe *oauthceremony.ProtocolError
		if errors.As(err, &pe) && pe.Debug != "" {
			// Подробности — имя вызова порта и его отказ; предъявленных значений
			// в них нет (церемония вырезает их из текстов опознания, порты
			// службы их не пишут).
			why += " (" + pe.Debug + ")"
		}
		l.refuse(r, w, status, word, OutcomeTokenUnavailable, clientID, why)
	case wire == "unauthorized_client" || wire == "unsupported_grant_type" || wire == "invalid_scope":
		l.refuse(r, w, http.StatusBadRequest, wire, OutcomeTokenRequestRefused, clientID, code.String())
	default:
		l.refuse(r, w, http.StatusBadRequest, "invalid_request", OutcomeTokenRequestRefused, clientID, code.String())
	}
}

// refuseClient — `invalid_client`: 401 и вызов схемы, которой клиент
// доказывает себя (RFC 6749 §5.2).
func (l *TokenLane) refuseClient(r *http.Request, w http.ResponseWriter, clientID, why string) {
	w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	l.refuse(r, w, http.StatusUnauthorized, "invalid_client", OutcomeTokenClientRefused, clientID, why)
}

// refuse записывает отказ туда, где различимость законна, и отвечает словом.
// Ни код, ни токен обновления, ни секрет клиента в журнал не идут: у записи —
// исход, клиент и случай церемонии.
func (l *TokenLane) refuse(r *http.Request, w http.ResponseWriter, status int, wire string, outcome Outcome,
	clientID, why string,
) {
	l.census.count(outcome)
	l.logger.WarnContext(r.Context(), "ceremony token refused",
		slog.String("outcome", string(outcome)), slog.String("client", clientID),
		slog.String("error", wire), slog.String("why", why))
	writeJSON(w, status, errorBody(wire))
}
