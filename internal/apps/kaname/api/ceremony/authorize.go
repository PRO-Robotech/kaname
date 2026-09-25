// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremony

// authorize.go — эндпоинт авторизации: выдача кода (группа A приёмки: 02–09,
// 29, 30).
//
// # Порядок проверок НЕСУЩИЙ — он и есть граница «перенаправлять можно»
//
//	клиент и цель (точное равенство)  →  цель доверена
//	→ вид ответа → state → PKCE → область → уровень → шов входа → шаг вверх
//	→ условная вставка записи кода → код на цель
//
// Всё, что решается ДО того, как цель доверена, отвечает человеку без
// перенаправления и побайтово одним ответом (04/05, LAX-20): куда ещё не
// доверено, туда код не утекает. Всё после — перенаправляемый отказ, несущий
// ровно `error` (Р13 п. 3, паритет 06/07/29): ни `state`, ни описания.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// AuthorizeParams — параметры запроса авторизации, разобранные транспортом.
// Repeated — имена параметров, пришедших более одного раза (RFC 6749 §3.1).
type AuthorizeParams struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	ACRValues           string
	Repeated            []string
	Session             domain.SessionBearer
}

// DecisionKind — чем эндпоинт отвечает.
type DecisionKind int

const (
	// DecisionDeliverCode — 302 на цель с кодом и дословным `state`.
	DecisionDeliverCode DecisionKind = iota + 1
	// DecisionRedirectError — 302 на цель ровно с `error`.
	DecisionRedirectError
	// DecisionRefuseWithoutRedirect — отказ человеку без перенаправления.
	DecisionRefuseWithoutRedirect
	// DecisionAuthenticate — вызов аутентификации: сессии нашего входа нет.
	DecisionAuthenticate
	// DecisionStepUp — сессия ниже запрошенного уровня: нужна повторная
	// аутентификация нашим входом.
	DecisionStepUp
	// DecisionUnavailable — наш источник не ответил до того, как цель
	// доверена: перенаправлять некуда.
	DecisionUnavailable
)

// AuthorizeDecision — решение эндпоинта.
type AuthorizeDecision struct {
	Kind DecisionKind
	// Target — зарегистрированная цель, ДОСЛОВНО как в списке клиента.
	Target string
	Code   domain.CeremonySecret
	State  string
	// Error — код ошибки OAuth перенаправляемого отказа.
	Error string
	// RequiredLevel — уровень, которого требует запрос (шаг вверх).
	RequiredLevel string
	Outcome       Outcome
}

// OAuth-коды ошибок эндпоинта авторизации (RFC 6749 §4.1.2.1).
const (
	ErrInvalidRequest          = "invalid_request"
	ErrUnsupportedResponseType = "unsupported_response_type"
	ErrInvalidScope            = "invalid_scope"
	ErrTemporarilyUnavailable  = "temporarily_unavailable"
)

// interactiveClientIDForm — форма идентификатора интерактивного клиента, та
// же, что держит CHECK хранилища. Незаконная форма в хранилище не ходит: у неё
// нет строки by construction, и ответ у неё тот же, что у отсутствующего
// клиента.
var interactiveClientIDForm = regexp.MustCompile(`^ic-[0-9abcdefghjkmnpqrstvwxyz]{17}$`)

// AuthorizeUseCase — выдача кода.
type AuthorizeUseCase struct {
	clients ClientRegistry
	login   LoginAuthority
	store   Store
	census  *Census
	logger  *slog.Logger
}

// NewAuthorizeUseCase — построение; неполная провязка — отказ.
func NewAuthorizeUseCase(clients ClientRegistry, login LoginAuthority, store Store, census *Census, logger *slog.Logger) (*AuthorizeUseCase, error) {
	switch {
	case clients == nil:
		return nil, fmt.Errorf("ceremony authorize: client registry required")
	case login == nil:
		return nil, fmt.Errorf("ceremony authorize: login authority required")
	case store == nil:
		return nil, fmt.Errorf("ceremony authorize: store required")
	case census == nil:
		return nil, fmt.Errorf("ceremony authorize: outcome census required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &AuthorizeUseCase{clients: clients, login: login, store: store, census: census, logger: logger}, nil
}

// Execute — решение по запросу авторизации.
func (u *AuthorizeUseCase) Execute(ctx context.Context, p AuthorizeParams) AuthorizeDecision {
	// (1) Клиент и цель — до всего прочего. Повтор любого из двух —
	// неразбираемая цель: какое из двух значений доверять, запрос не говорит.
	if repeated(p.Repeated, "client_id") || repeated(p.Repeated, "redirect_uri") ||
		p.ClientID == "" || p.RedirectURI == "" || !interactiveClientIDForm.MatchString(p.ClientID) {
		return u.refuseUntrusted(AuthorizeTargetParamInvalid, "")
	}
	clientID := domain.InteractiveClientID(p.ClientID)
	client, found, err := u.clients.InteractiveClient(ctx, clientID)
	if err != nil {
		return u.unavailable(AuthorizeUnavailable, "", clientID, err)
	}
	if !found {
		return u.refuseUntrusted(AuthorizeClientUnknown, clientID)
	}
	if client.Status != domain.InteractiveClientActive {
		return u.refuseUntrusted(AuthorizeClientNotActive, clientID)
	}
	target, ok := exactTarget(client.RedirectURIs, p.RedirectURI)
	if !ok {
		return u.refuseUntrusted(AuthorizeRedirectUnregistered, clientID)
	}

	// Цель доверена: отказы ниже перенаправляемы и несут ровно `error`.
	if len(p.Repeated) > 0 {
		return u.redirectError(target, ErrInvalidRequest, AuthorizeParamRepeated, clientID)
	}
	switch {
	case p.ResponseType == "":
		return u.redirectError(target, ErrInvalidRequest, AuthorizeResponseTypeMissing, clientID)
	case p.ResponseType != "code":
		return u.redirectError(target, ErrUnsupportedResponseType, AuthorizeResponseTypeRefused, clientID)
	}
	// «Не прислан» и «короче пола» — ОДНА проверка (Р13 п. 1).
	if !domain.ValidOAuthState(p.State) {
		return u.redirectError(target, ErrInvalidRequest, AuthorizeStateRefused, clientID)
	}
	// PKCE обязателен вдобавок к аутентификации клиента на обмене (Р3):
	// отсутствующий метод по RFC 7636 означает `plain`, и отвергается так же.
	if p.CodeChallengeMethod != domain.PKCEMethodS256 || !domain.ValidPKCEChallengeS256(p.CodeChallenge) {
		return u.redirectError(target, ErrInvalidRequest, AuthorizePKCERefused, clientID)
	}
	if len(p.Scope) > domain.MaxOAuthScopeLen || !domain.ValidOAuthScope(p.Scope) {
		return u.redirectError(target, ErrInvalidScope, AuthorizeScopeRefused, clientID)
	}
	required, ok := requiredLevel(p.ACRValues)
	if !ok {
		return u.redirectError(target, ErrInvalidRequest, AuthorizeACRValuesRefused, clientID)
	}

	// (2) Шов входа. Три исхода, и ни один не сливается с другим.
	who, authenticated, err := u.login.Resolve(ctx, p.Session)
	if err != nil {
		return u.unavailable(AuthorizeUnavailable, target, clientID, err)
	}
	if !authenticated {
		return u.decide(AuthorizeDecision{Kind: DecisionAuthenticate, Outcome: AuthorizeUnauthenticated}, clientID, "")
	}

	// (3) Шаг вверх: ранжирование — единственная функция платформы, вердикт
	// о уровне здесь не переопределяется. Не поднят — кода нет.
	if required != "" && grpcsrv.EvaluateStepUp(grpcsrv.StepUpInput{
		PrincipalType: "user", PresentedACR: who.Level, RequiredACR: required,
	}) != grpcsrv.StepUpAllow {
		return u.decide(AuthorizeDecision{Kind: DecisionStepUp, RequiredLevel: required, Outcome: AuthorizeStepUpRequired},
			clientID, who.Subject)
	}

	// (4) Выдача. Запись ложится условной вставкой: клиент, цель и сессия
	// судятся ТЕМ ЖЕ оператором, и проигранная гонка с их снятием не даёт
	// кода на уже недоверенную цель.
	code, err := domain.NewCeremonySecret()
	if err != nil {
		return u.unavailable(AuthorizeUnavailable, target, clientID, err)
	}
	inserted, err := u.store.IssueCode(ctx, CodeIssue{
		Digest:        code.Digest(),
		Client:        clientID,
		Session:       who.Session,
		Subject:       who.Subject,
		RedirectURI:   target,
		Scope:         p.Scope,
		CodeChallenge: p.CodeChallenge,
		TTL:           domain.AuthorizationCodeTTL,
	})
	if err != nil {
		return u.unavailable(AuthorizeUnavailable, target, clientID, err)
	}
	if !inserted {
		return u.refuseUntrusted(AuthorizeIssueRaced, clientID)
	}
	return u.decide(AuthorizeDecision{
		Kind: DecisionDeliverCode, Target: target, Code: code, State: p.State, Outcome: AuthorizeIssued,
	}, clientID, who.Subject)
}

// refuseUntrusted — отказ до доверия цели: без перенаправления.
func (u *AuthorizeUseCase) refuseUntrusted(o Outcome, client domain.InteractiveClientID) AuthorizeDecision {
	return u.decide(AuthorizeDecision{Kind: DecisionRefuseWithoutRedirect, Outcome: o}, client, "")
}

// redirectError — перенаправляемый отказ на доверенную цель.
func (u *AuthorizeUseCase) redirectError(target, code string, o Outcome, client domain.InteractiveClientID) AuthorizeDecision {
	return u.decide(AuthorizeDecision{Kind: DecisionRedirectError, Target: target, Error: code, Outcome: o}, client, "")
}

// unavailable — наш источник не ответил. До доверия цели — без
// перенаправления; после — перенаправляемый `temporarily_unavailable`.
func (u *AuthorizeUseCase) unavailable(o Outcome, target string, client domain.InteractiveClientID, err error) AuthorizeDecision {
	u.census.Count(o)
	// Текст ошибки хранилища в журнал не идёт: он несёт координаты соединения.
	u.logger.Error("authorization ceremony: dependency did not answer",
		slog.String("outcome", string(o)), slog.String("client_id", string(client)),
		slog.Bool("dependency_error", err != nil), slog.String("error_class", errorClass(err)))
	if target == "" {
		return AuthorizeDecision{Kind: DecisionUnavailable, Outcome: o}
	}
	return AuthorizeDecision{Kind: DecisionRedirectError, Target: target, Error: ErrTemporarilyUnavailable, Outcome: o}
}

// decide — исход в перепись и журнал. Субъект — не-PII идентификатор.
func (u *AuthorizeUseCase) decide(d AuthorizeDecision, client domain.InteractiveClientID, subject domain.UserID) AuthorizeDecision {
	u.census.Count(d.Outcome)
	level := slog.LevelInfo
	if d.Kind != DecisionDeliverCode {
		level = slog.LevelWarn
	}
	u.logger.Log(context.Background(), level, "authorization request decided",
		slog.String("outcome", string(d.Outcome)),
		slog.String("client_id", string(client)),
		slog.String("user_id", string(subject)))
	return d
}

// exactTarget — точное равенство исходных строк, без нормализации
// (хвостовой слэш, регистр процентного кодирования, порт по умолчанию не
// приводятся, LAX-4). Возвращает запись списка клиента.
func exactTarget(registered []string, presented string) (string, bool) {
	for _, r := range registered {
		if r == presented {
			return r, true
		}
	}
	return "", false
}

// requiredLevel — уровень, которого требует `acr_values`: значения через
// пробел, каждое — из закрытой оси «1»…«3»; требуется наименьшее из
// перечисленных (любое из них запрос удовлетворяет). Пусто — требования нет.
func requiredLevel(acrValues string) (string, bool) {
	if acrValues == "" {
		return "", true
	}
	best := ""
	for _, v := range strings.Split(acrValues, " ") {
		if grpcsrv.ACRRank(v) == 0 {
			return "", false
		}
		if best == "" || grpcsrv.ACRRank(v) < grpcsrv.ACRRank(best) {
			best = v
		}
	}
	return best, true
}

func repeated(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

// errorClass — класс ошибки для журнала без её текста.
func errorClass(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "store"
	}
}

// sessionTTLBound — срок, которого не переживает выданное: остаток сессии.
func sessionTTLBound(ttl time.Duration, sessionExpiresAt, now time.Time) time.Duration {
	if rest := sessionExpiresAt.Sub(now); rest < ttl {
		return rest
	}
	return ttl
}
