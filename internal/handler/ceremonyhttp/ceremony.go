// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ceremonyhttp — поверхность церемонии OAuth 2.1 `authorization_code`
// нашими силами (приёмка LINE-A-1, воркспейс, SHA-256 `b755886f…`; задача
// PRO-Robotech/kaname#423): эндпоинт авторизации, метаданные обнаружения и
// полосы `authorization_code` и `refresh_token` токен-эндпоинта.
//
// # Движок — фундамента, поверхность — наша
//
// Протокол исполняет церемония фундамента (`corelib/oauthceremony`): разбор
// запроса, PKCE, выдача и погашение кода, оборот токена обновления, отзыв
// семейства на повторе. Своего движка здесь нет. Этот пакет делает то, чего
// церемония не делает по построению: пишет в сеть, консультирует шов входа
// (LoginAuthority, приёмка Р2), решает, КУДА можно отвечать (Р4), держит пол
// `state` (Р13) и единый тон отказов (Р10), ведёт счёт исходов и журнал.
//
// # Порядок решений на эндпоинте авторизации — несущий
//
//  1. метод;
//  2. клиент и адрес возврата — ТОЧНЫМ равенством с регистрацией. До этого
//     шага цели нет: отказ показывается БЕЗ перенаправления и побайтово
//     одинаков для «клиента нет», «клиент снимается» и «адрес не тот» (Р4,
//     сценарии 04/05);
//  3. `state` не ниже пола — отказ ПЕРЕНАПРАВЛЯЕМ и несёт только `error`
//     (Р13, 29/30);
//  4. протокол (тип ответа, PKCE S256, область) — церемонией; отказ
//     перенаправляем, только `error` (06/07);
//  5. шов входа: нет сессии — вызов аутентификации (03); уровень ниже
//     запрошенного `acr_values` — вызов шага вверх (08);
//  6. выдача кода; согласие первопартийного клиента не спрашивается (09).
//
// Протокол судится раньше входа: человека не просят войти ради запроса, который
// кода не получит.
package ceremonyhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/oauthceremony"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
)

// AuthorizePath — путь эндпоинта авторизации (приёмка §5, группа A).
//
// #nosec G101 -- это АДРЕС поверхности, а не учётные данные.
const AuthorizePath = "/iam/v1/authorize"

// DiscoveryPath — путь метаданных обнаружения (RFC 8414 §3, приёмка группа H).
// Путь без суффикса издателя: издатель — начало координат (см. Endpoints).
const DiscoveryPath = "/.well-known/oauth-authorization-server"

// StateFloor — пол длины `state` в знаках (приёмка Р13 п. 2): длина записи
// BASE64URL от 16 случайных байтов, самая короткая форма 128-битного значения.
// НАША величина, а не умолчание движка; движку она передаётся тем же
// значением (`oauthceremony.Config.MinParameterEntropy`).
const StateFloor = 22

// Engine — церемония фундамента в той части, которой пользуется поверхность.
// Реализует `*oauthceremony.Ceremony`.
type Engine interface {
	Authorize(ctx context.Context, req oauthceremony.AuthorizationRequest) (oauthceremony.AuthorizationIntent, error)
	CompleteAuthorization(ctx context.Context, intent oauthceremony.AuthorizationIntent, grant oauthceremony.AuthorizationGrant) (oauthceremony.AuthorizationResult, error)
	Exchange(ctx context.Context, req oauthceremony.TokenRequest) (oauthceremony.TokenResult, error)
}

var _ Engine = (*oauthceremony.Ceremony)(nil)

// Clients — справочник клиентов церемонии: тот же порт, что у движка
// (`oauthceremony.ClientDirectory`), — сверка адреса возврата не заводит второго
// источника регистрации.
type Clients interface {
	LookupClient(ctx context.Context, clientID string) (oauthceremony.ClientRegistration, error)
}

// Login — ответ шва «авторитет входа» (приёмка Р2): кто вошёл, в какой сессии,
// когда и на каком уровне. Церемония знает ЧТО предъявлено, но не ЧЕМ получено.
type Login struct {
	Subject   string
	SessionID string
	AuthTime  time.Time
	Level     string
	// ExpiresAt — срок сессии: граница семейства, выданного в ней.
	ExpiresAt time.Time
}

// LoginAuthority — шов авторитета входа. Производитель — наш вход (Ф1):
// сессия человека по носителю. found=false — «не-аутентифицирован»; ошибка —
// авторитет не ответил.
type LoginAuthority interface {
	Resolve(ctx context.Context, bearer domain.SessionBearer) (login Login, found bool, err error)
}

// Endpoints выводит адреса точек церемонии из издателя.
//
// Издатель — начало координат сервера авторизации (RFC 8414 §2): метаданные
// публикуются под ним (DiscoveryPath), и точки, которые они называют, стоят на
// той же поверхности. Издатель с путём RFC 8414 допускает, но тогда адрес
// метаданных несёт путь издателя суффиксом (§3.1), а поверхность монтирует
// DiscoveryPath без суффикса — такой издатель отвергается, а не публикуется с
// адресом, по которому метаданных нет.
func Endpoints(issuer string) (authorize, token string, err error) {
	u, perr := url.Parse(issuer)
	switch {
	case perr != nil || !u.IsAbs() || u.Hostname() == "":
		return "", "", errors.New("ceremonyhttp: the issuer is not an absolute URL with a host")
	case u.Scheme != "https":
		return "", "", errors.New("ceremonyhttp: the issuer is not an https URL")
	case u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(issuer, "?#"):
		return "", "", errors.New("ceremonyhttp: the issuer carries user information, a query or a fragment")
	case u.Path != "" && u.Path != "/":
		return "", "", errors.New("ceremonyhttp: the issuer carries a path; the discovery document is mounted " +
			"at the origin, so its address would not be the one RFC 8414 §3.1 derives from the issuer")
	}
	origin := strings.TrimSuffix(issuer, "/")
	return origin + AuthorizePath, origin + clienttokenhttp.TokenPath, nil
}

// ── Ответы ──────────────────────────────────────────────────────────────────

// noStore — ответ несёт либо удостоверение, либо отказ по нему: не кэшируется
// (RFC 6749 §5.1).
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	noStore(w)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func errorBody(code string) map[string]string { return map[string]string{"error": code} }
