// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package oauth_ceremony

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/acrlevel"
	"github.com/PRO-Robotech/corelib/oauthceremony"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// AuthorizeDeps — зависимости выдачи кода. Все обязательны.
type AuthorizeDeps struct {
	Engine    AuthorizationEngine
	Clients   Clients
	Authority LoginAuthority
	// Clock — источник времени границы семейства. Вход, а не окружение.
	Clock func() time.Time
	// CallTimeout — срок ОДНОГО вызова справочника клиентов и шва входа: тот
	// же, что мост церемонии назначает каждому вызову порта.
	CallTimeout time.Duration
}

// AuthorizeUseCase — выдача кода авторизации в два шага: доверие цели (Trust),
// затем выдача по доверенной цели (Execute). Между шагами поверхность судит
// протокол своей стороны — однозначность параметров и пол `state`: их отказ
// уезжает перенаправлением, то есть требует уже доверенной цели.
type AuthorizeUseCase struct {
	d AuthorizeDeps
}

// NewAuthorizeUseCase строит выдачу. Неполная провязка — отказ построения.
func NewAuthorizeUseCase(d AuthorizeDeps) (*AuthorizeUseCase, error) {
	switch {
	case d.Engine == nil:
		return nil, errors.New("ceremony: authorize needs the ceremony")
	case d.Clients == nil:
		return nil, errors.New("ceremony: authorize needs the client directory")
	case d.Authority == nil:
		return nil, errors.New("ceremony: authorize needs the login authority")
	case d.Clock == nil:
		return nil, errors.New("ceremony: authorize needs a clock")
	case d.CallTimeout <= 0:
		return nil, errors.New("ceremony: authorize needs the per-call deadline of its store calls")
	}
	return &AuthorizeUseCase{d: d}, nil
}

// TrustVerdict — исход доверия цели. Словарь закрыт; нулевое значение — не
// исход.
type TrustVerdict int

// Исходы доверия цели.
const (
	_ TrustVerdict = iota // нулевое значение — не исход
	// TrustClientUnknown — клиента нет либо он снимается.
	TrustClientUnknown
	// TrustRedirectUnregistered — адрес возврата не зарегистрирован клиентом.
	TrustRedirectUnregistered
	// TrustDirectoryUnavailable — справочник клиентов не ответил.
	TrustDirectoryUnavailable
	// TrustGranted — цель доверена: отказ дальше уезжает перенаправлением.
	TrustGranted
)

// Target — доверенная цель: клиент, его адрес возврата и регистрация.
type Target struct {
	ClientID    string
	RedirectURI string
	audiences   []string
}

// Trust судит клиента и адрес возврата ДО всякого доверия: адрес сверяется с
// регистрацией ТОЧНЫМ равенством, без нормализации — хвостовой слэш, регистр,
// порядок параметров — другой адрес (приёмка Р4, LAX-4). Ошибка сопровождает
// только исход TrustDirectoryUnavailable.
func (uc *AuthorizeUseCase) Trust(ctx context.Context, clientID, redirect string) (Target, TrustVerdict, error) {
	callCtx, cancel := context.WithTimeout(ctx, uc.d.CallTimeout)
	defer cancel()
	reg, err := uc.d.Clients.LookupClient(callCtx, clientID)
	switch {
	case oauthceremony.CodeOf(err) == oauthceremony.CodeGrantNotFound:
		return Target{}, TrustClientUnknown, nil
	case err != nil:
		return Target{}, TrustDirectoryUnavailable, err
	case !slices.Contains(reg.RedirectURIs, redirect):
		return Target{}, TrustRedirectUnregistered, nil
	}
	return Target{ClientID: clientID, RedirectURI: redirect, audiences: append([]string(nil), reg.Audiences...)},
		TrustGranted, nil
}

// AuthorizeInput — разобранный запрос авторизации по доверенной цели.
// Назначаемое выдачей (субъект, уровень, момент, получатель) сюда не входит:
// из запроса оно не берётся вовсе (Р5).
type AuthorizeInput struct {
	Scopes              []string
	ResponseKinds       []string
	ResponseMode        string
	State               string
	AcrValues           string
	CodeChallenge       string
	CodeChallengeMethod string
	Session             domain.SessionBearer
}

// Verdict — исход выдачи по доверенной цели. Словарь закрыт; нулевое значение —
// не исход.
type Verdict int

// Исходы выдачи.
const (
	_ Verdict = iota // нулевое значение — не исход
	// VerdictRefusedByRedirect — отказ протокола перенаправлением на цель.
	VerdictRefusedByRedirect
	// VerdictRefusedUntrusted — церемония отказала, не назвав цели.
	VerdictRefusedUntrusted
	// VerdictLoginRequired — входа нет (либо он кончился до выдачи).
	VerdictLoginRequired
	// VerdictStepUpRequired — уровень входа ниже запрошенного.
	VerdictStepUpRequired
	// VerdictUnavailable — выдача не состоялась по нашей причине;
	// перенаправлением на цель.
	VerdictUnavailable
	// VerdictIssued — код выдан; RedirectURI собрал движок.
	VerdictIssued
)

// AuthorizeResult — исход выдачи. Wire — слово словаря точки авторизации для
// отказа перенаправлением; Why — причина для журнала, наружу не уходит.
type AuthorizeResult struct {
	Verdict     Verdict
	Wire        string
	Why         string
	Subject     string
	Level       string
	AcrValues   string
	RedirectURI string
}

// Execute — выдача по доверенной цели. Порядок решений несущий: протокол
// судится раньше входа — человека не просят войти ради запроса, который кода
// не получит.
func (uc *AuthorizeUseCase) Execute(ctx context.Context, target Target, in AuthorizeInput) AuthorizeResult {
	required, ok := requiredLevel(in.AcrValues)
	if !ok {
		return refusedByRedirect("invalid_request", "acr_values names a level outside the platform vocabulary")
	}
	if len(in.Scopes) == 0 {
		return refusedByRedirect("invalid_scope", "no scope requested")
	}
	if len(target.audiences) == 0 {
		// Получателя штампуем мы по регистрации клиента (Р6); клиент без
		// зарегистрированного получателя токена получить не может.
		return refusedByRedirect("unauthorized_client", "the client registers no audience")
	}

	// Протокол — церемонией фундамента.
	req := oauthceremony.AuthorizationRequest{
		ClientID:    target.ClientID,
		RedirectURI: target.RedirectURI,
		Scopes:      append([]string(nil), in.Scopes...),
		Audiences:   append([]string(nil), target.audiences...),
		State:       in.State,
		Delivery:    oauthceremony.ResponseDelivery(in.ResponseMode),
		Additional:  map[string][]string{},
	}
	for _, kind := range in.ResponseKinds {
		req.ResponseKinds = append(req.ResponseKinds, oauthceremony.ResponseKind(kind))
	}
	if in.CodeChallenge != "" {
		req.Additional["code_challenge"] = []string{in.CodeChallenge}
	}
	if in.CodeChallengeMethod != "" {
		req.Additional["code_challenge_method"] = []string{in.CodeChallengeMethod}
	}
	intent, err := uc.d.Engine.Authorize(ctx, req)
	if err != nil {
		code := oauthceremony.CodeOf(err)
		if intent.RedirectURI() == "" {
			return AuthorizeResult{Verdict: VerdictRefusedUntrusted, Why: code.String()}
		}
		return refusedByRedirect(authorizeWire(code), code.String())
	}

	// Шов входа — под своим сроком.
	login, found, err := uc.resolve(ctx, in.Session)
	switch {
	case err != nil:
		return AuthorizeResult{Verdict: VerdictUnavailable, Wire: "temporarily_unavailable",
			Why: "login authority did not answer: " + err.Error()}
	case !found:
		return AuthorizeResult{Verdict: VerdictLoginRequired}
	case required > 0 && acrlevel.Rank(login.Level) < required:
		return AuthorizeResult{Verdict: VerdictStepUpRequired, Subject: login.Subject,
			AcrValues: strings.TrimSpace(in.AcrValues)}
	}

	// Выдача. Граница семейства — правило домена: не позже сессии, в которой
	// оно выдано, и не позже потолка семейства от момента выдачи.
	bound := domain.CeremonyFamilyBound(uc.d.Clock(), login.ExpiresAt)
	result, err := uc.d.Engine.CompleteAuthorization(ctx, intent, oauthceremony.AuthorizationGrant{
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
	switch {
	case errors.Is(err, domain.ErrCeremonySessionNotLive), errors.Is(err, domain.ErrCeremonySessionUnknown):
		// Сессия кончилась между ответом шва и выдачей либо отрезана отсечкой
		// субъекта: входа, в котором идёт церемония, больше нет.
		return AuthorizeResult{Verdict: VerdictLoginRequired, Subject: login.Subject}
	case err != nil:
		code := oauthceremony.CodeOf(err)
		return AuthorizeResult{Verdict: VerdictUnavailable, Wire: authorizeWire(code),
			Why: code.String() + ": " + err.Error()}
	case result.RedirectURI == "" || result.Delivery != oauthceremony.DeliveryQuery:
		return AuthorizeResult{Verdict: VerdictUnavailable, Wire: "server_error",
			Why: "the ceremony assembled no query redirect"}
	}
	return AuthorizeResult{Verdict: VerdictIssued, Subject: login.Subject, Level: login.Level,
		RedirectURI: result.RedirectURI}
}

// resolve — шов входа под сроком одного вызова.
func (uc *AuthorizeUseCase) resolve(ctx context.Context, bearer domain.SessionBearer) (Login, bool, error) {
	callCtx, cancel := context.WithTimeout(ctx, uc.d.CallTimeout)
	defer cancel()
	return uc.d.Authority.Resolve(callCtx, bearer)
}

func refusedByRedirect(wire, why string) AuthorizeResult {
	return AuthorizeResult{Verdict: VerdictRefusedByRedirect, Wire: wire, Why: why}
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
	if code.HTTPStatus() >= 500 { // отказ сервера по классу статуса RFC 9110
		return "server_error"
	}
	return "invalid_request"
}
