// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ceremonyhttp — браузер-обращаемая половина церемонии OAuth 2.1
// `authorization_code` (под-фаза LINE-A-1, задача PRO-Robotech/kacho#2721):
// эндпоинт авторизации и метаданные обнаружения. Обмен кода и ротация живут
// на токен-эндпоинте (`clienttokenhttp`) — это одна поверхность выдачи.
//
// # Где монтируется — на внешней поверхности выдачи и НИГДЕ больше
//
// Оба пути монтирует композиционный корень на муксе поверхности выдачи, рядом
// с токен-эндпоинтом (ban #6, 23). Путь авторизации — ТОЧНАЯ пара «метод +
// путь»: поддеревом он не регистрируется, и соседняя координата с суффиксом
// действия (`…/authorize:<verb>` — REST-действия проверки доступа на крае) на
// этой поверхности не резолвится.
//
// # Обработчик тонкий
//
// Разбор запроса во вход варианта использования и печать его решения. Одно
// место строит `Location` и статус для всех перенаправлений (выдача кода и
// три перенаправляемых отказа, LAX-19): параметры добавляются к РАЗОБРАННОЙ
// цели, её собственная строка запроса сохраняется дословно. Ответы, несущие
// удостоверение либо отказ по нему, не кэшируются.
package ceremonyhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/ceremony"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

// AuthorizePath — путь эндпоинта авторизации.
const AuthorizePath = "/iam/v1/authorize"

// DiscoveryPath — путь метаданных обнаружения (RFC 8414 §3).
const DiscoveryPath = "/.well-known/oauth-authorization-server"

// authorizeParams — параметры запроса авторизации, чьё повторение судится.
var authorizeParams = []string{
	"client_id", "redirect_uri", "response_type", "scope", "state",
	"code_challenge", "code_challenge_method", "acr_values",
}

// Authorizer — порт варианта использования.
type Authorizer interface {
	Execute(ctx context.Context, p ceremony.AuthorizeParams) ceremony.AuthorizeDecision
}

// AuthorizeHandler — эндпоинт авторизации.
type AuthorizeHandler struct{ uc Authorizer }

// NewAuthorizeHandler — обработчик над вариантом использования.
func NewAuthorizeHandler(uc Authorizer) *AuthorizeHandler { return &AuthorizeHandler{uc: uc} }

func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": ceremony.ErrInvalidRequest})
		return
	}
	q := r.URL.Query()
	p := ceremony.AuthorizeParams{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		ResponseType:        q.Get("response_type"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		ACRValues:           q.Get("acr_values"),
	}
	for _, name := range authorizeParams {
		if len(q[name]) > 1 {
			p.Repeated = append(p.Repeated, name)
		}
	}
	if c, err := r.Cookie(loginlanehttp.CookieSession); err == nil {
		p.Session = domain.PresentedSessionBearer(c.Value)
	}

	d := h.uc.Execute(r.Context(), p)
	switch d.Kind {
	case ceremony.DecisionDeliverCode:
		redirect(w, d.Target, url.Values{"code": {d.Code.Deliver()}, "state": {d.State}})
	case ceremony.DecisionRedirectError:
		// Ровно `error`: ни `state`, ни описания отказа (Р13 п. 3).
		redirect(w, d.Target, url.Values{"error": {d.Error}})
	case ceremony.DecisionAuthenticate:
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "login_required"})
	case ceremony.DecisionStepUp:
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "insufficient_user_authentication", "acr_values": d.RequiredLevel,
		})
	case ceremony.DecisionUnavailable:
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": ceremony.ErrTemporarilyUnavailable})
	default:
		// Отказ до доверия цели: ОДИН ответ на все причины (04/05).
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": ceremony.ErrInvalidRequest})
	}
}

// redirect — единственный построитель перенаправления: статус 302, параметры
// добавлены к разобранной цели, её собственная строка запроса — дословно.
func redirect(w http.ResponseWriter, target string, extra url.Values) {
	u, err := url.Parse(target)
	if err != nil {
		// Цель — дословная запись списка клиента, прошедшая валидатор домена и
		// CHECK базы; неразбираемой она быть не может. Если всё же стала —
		// перенаправлять некуда.
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": ceremony.ErrInvalidRequest})
		return
	}
	if u.RawQuery == "" {
		u.RawQuery = extra.Encode()
	} else {
		u.RawQuery = u.RawQuery + "&" + extra.Encode()
	}
	w.Header().Set("Location", u.String())
	w.WriteHeader(http.StatusFound)
}

// DiscoveryHandler — метаданные обнаружения: публичное неаутентифицированное
// чтение, только публичный материал (Р11).
type DiscoveryHandler struct{ body []byte }

// NewDiscoveryHandler — документ собирается один раз из издателя; на проводе
// нет ни секретов, ни личных данных, ни инфра-данных.
//
// Перечень способов аутентификации клиента на токен-эндпоинте в документе не
// объявлен намеренно: его отсутствие по RFC 8414 §2 означает базовую
// аутентификацию секретом — ровно то, что принимают полосы этой церемонии.
// Виды выдачи названы те, что обслуживает церемония; машинные полосы
// токен-эндпоинта свои координаты этим документом не объявляют.
func NewDiscoveryHandler(issuer string) (*DiscoveryHandler, error) {
	body, err := json.Marshal(map[string]any{
		"issuer":                           issuer,
		"authorization_endpoint":           issuer + AuthorizePath,
		"token_endpoint":                   issuer + clienttokenhttp.TokenPath,
		"response_types_supported":         []string{"code"},
		"response_modes_supported":         []string{"query"},
		"grant_types_supported":            []string{ceremony.GrantTypeAuthorizationCode, ceremony.GrantTypeRefreshToken},
		"code_challenge_methods_supported": []string{domain.PKCEMethodS256},
	})
	if err != nil {
		return nil, err
	}
	return &DiscoveryHandler{body: body}, nil
}

func (h *DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": ceremony.ErrInvalidRequest})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.body)
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
