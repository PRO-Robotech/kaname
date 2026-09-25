// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremony

// exchange.go — полосы `authorization_code` и `refresh_token` токен-эндпоинта
// (группы B, C, G, I приёмки: 10–21, 24, 26–28).
//
// # Порядок: форма → клиент → код
//
// Отказы, решаемые ДО того, как запрос назвал код, различимы и несут свои
// стандартные коды (Р10): форма — `invalid_request`, аутентификация
// конфиденциального клиента — `invalid_client`. Всё, что наступает после,
// отдаёт побайтово ОДНО `invalid_grant`, и различимость для нас живёт в
// переписи и журнале.
//
// # Повтор ОТЗЫВАЕТ, а не только отказывает (Р8)
//
// Потреблённый код, предъявленный вновь, и ротированное удостоверение,
// предъявленное вновь, отзывают семейство авторизации: авторизация помечается
// отозванной и её предъявителям ставится отсечка по ключу
// [domain.ClaimAuthorizationID] — той же транзакцией, что обнаружение повтора.
// Отсечку читают авторитет отзыва и читатель предъявленного на пути запроса;
// ширина отзыва — ровно семейство, живые удостоверения того же человека из
// других авторизаций не задеваются.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/audiencepolicy"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// Виды выдачи этих полос.
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
)

// Аудит-события полос. Полезная нагрузка — неизменяемые идентификаторы, без
// адресов и имён (гейт `audit_payload_pii`), без кода и удостоверений.
const (
	AuditAuthorizationGranted = "iam.authorization.granted"
	AuditAuthorizationRevoked = "iam.authorization.revoked"
)

// ClientPresentation — аутентификация клиента, как её прислал запрос.
type ClientPresentation struct {
	// Presented — прислан ли заголовок базовой аутентификации.
	Presented bool
	ID        string
	Secret    string
	// FormClientID — `client_id` тела; обязан совпадать с идентификатором
	// заголовка, когда прислан.
	FormClientID string
}

// CodeExchangeInput — обмен кода.
type CodeExchangeInput struct {
	Client      ClientPresentation
	Code        string
	RedirectURI string
	Verifier    string
	// Repeated — параметр полосы пришёл более одного раза.
	Repeated bool
}

// RefreshInput — предъявление обновляющего удостоверения.
type RefreshInput struct {
	Client  ClientPresentation
	Refresh string
	// Scope — `scope` запроса: пусто — область авторизации целиком; иначе —
	// её подмножество (RFC 6749 §6).
	Scope string
	// Repeated — параметр полосы пришёл более одного раза.
	Repeated bool
}

// TokenPair — выдача: предъявитель доступа и обновляющее удостоверение.
type TokenPair struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int
	Refresh     domain.CeremonySecret
	Scope       string
}

// Refusal — отказ полосы обмена. Code — стандартный код ошибки токен-эндпоинта
// (RFC 6749 §5.2) либо `temporarily_unavailable` для наших отказов.
type Refusal struct {
	Code    string
	Outcome Outcome
}

func (r *Refusal) Error() string { return "ceremony exchange refused: " + string(r.Outcome) }

// Коды ошибок токен-эндпоинта.
const (
	TokenErrInvalidRequest = "invalid_request"
	TokenErrInvalidClient  = "invalid_client"
	TokenErrInvalidGrant   = "invalid_grant"
	TokenErrInvalidScope   = "invalid_scope"
	TokenErrUnavailable    = "temporarily_unavailable"
)

// ExchangeConfig — настройка выдачи. Каждое поле обязательно.
type ExchangeConfig struct {
	AllowedAudiences []string
	DefaultAudience  string
	TokenTTL         time.Duration
	Clock            func() time.Time
}

// ExchangeUseCase — обмен кода и ротация.
type ExchangeUseCase struct {
	cfg     ExchangeConfig
	clients ClientRegistry
	secrets SecretVerifier
	store   Store
	signer  Signer
	users   Users
	claims  ClaimSource
	census  *Census
	logger  *slog.Logger
}

// ExchangeDeps — зависимости обмена.
type ExchangeDeps struct {
	Clients ClientRegistry
	Secrets SecretVerifier
	Store   Store
	Signer  Signer
	Users   Users
	Claims  ClaimSource
	Census  *Census
	Logger  *slog.Logger
}

// NewExchangeUseCase — построение; неполная настройка — отказ.
func NewExchangeUseCase(cfg ExchangeConfig, d ExchangeDeps) (*ExchangeUseCase, error) {
	switch {
	case len(cfg.AllowedAudiences) == 0:
		return nil, fmt.Errorf("ceremony exchange: allowed audiences must be declared (empty means 'any')")
	case strings.TrimSpace(cfg.DefaultAudience) == "":
		return nil, fmt.Errorf("ceremony exchange: default audience is required")
	case cfg.TokenTTL <= 0 || cfg.TokenTTL > tokenpolicy.MaxTokenTTL:
		return nil, fmt.Errorf("ceremony exchange: token lifetime must be positive and within %s", tokenpolicy.MaxTokenTTL)
	case cfg.Clock == nil:
		return nil, fmt.Errorf("ceremony exchange: clock is required")
	case d.Clients == nil || d.Secrets == nil || d.Store == nil || d.Signer == nil ||
		d.Users == nil || d.Claims == nil || d.Census == nil:
		return nil, fmt.Errorf("ceremony exchange: every dependency is required")
	}
	if !audiencepolicy.Contains(cfg.AllowedAudiences, cfg.DefaultAudience) {
		return nil, fmt.Errorf("ceremony exchange: default audience %q is not in the declared list", cfg.DefaultAudience)
	}
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &ExchangeUseCase{cfg: cfg, clients: d.Clients, secrets: d.Secrets, store: d.Store, signer: d.Signer,
		users: d.Users, claims: d.Claims, census: d.Census, logger: logger}, nil
}

// ExchangeCode — полоса `authorization_code`.
func (u *ExchangeUseCase) ExchangeCode(ctx context.Context, in CodeExchangeInput) (TokenPair, error) {
	if in.Repeated || in.Code == "" || in.RedirectURI == "" || in.Verifier == "" {
		return TokenPair{}, u.refuse(TokenErrInvalidRequest, ExchangeFormInvalid, "", "")
	}
	client, err := u.authenticateClient(ctx, in.Client)
	if err != nil {
		return TokenPair{}, err
	}

	// Вызов, вычисленный из присланного verifier. Незаконная форма verifier
	// даёт вызов, не равный никакому сохранённому: отказ тот же, что у
	// неверного verifier, и решается он тем же оператором.
	challenge := "!"
	if domain.ValidPKCEVerifier(in.Verifier) {
		challenge = domain.PKCEChallengeS256(in.Verifier)
	}
	redemption := CodeRedemption{
		Digest:      domain.PresentedCeremonySecret(in.Code).Digest(),
		Client:      client,
		RedirectURI: in.RedirectURI,
		Challenge:   challenge,
		Grant:       domain.AuthorizationGrantID(ids.NewID(domain.AuthorizationGrantIDPrefix)),
	}

	w, err := u.store.Writer(ctx)
	if err != nil {
		return TokenPair{}, u.unavailable(client, err)
	}
	defer func() { _ = w.Rollback(ctx) }()

	grant, redeemed, err := w.RedeemCode(ctx, redemption)
	if err != nil {
		return TokenPair{}, u.unavailable(client, err)
	}
	if !redeemed {
		return TokenPair{}, u.refuseCode(ctx, w, redemption)
	}

	refresh, err := domain.NewCeremonySecret()
	if err != nil {
		return TokenPair{}, u.unavailable(client, err)
	}
	if err := w.InsertRefresh(ctx, refresh.Digest(), grant.ID); err != nil {
		return TokenPair{}, u.unavailable(client, err)
	}
	pair, err := u.mint(ctx, grant, grant.Scope, refresh)
	if errors.Is(err, errSubjectIneligible) {
		return TokenPair{}, u.refuse(TokenErrInvalidGrant, ExchangeCodeSessionEnded, client, grant.Subject)
	}
	if err != nil {
		return TokenPair{}, u.unavailable(client, err)
	}
	if err := w.EmitAudit(ctx, outboxtypes.AuditEvent{
		EventType: AuditAuthorizationGranted,
		Payload: map[string]any{
			"user_id":    string(grant.Subject),
			"client_id":  string(grant.Client),
			"grant_id":   string(grant.ID),
			"session_id": string(grant.Session),
		},
	}); err != nil {
		return TokenPair{}, u.unavailable(client, err)
	}
	if err := w.Commit(ctx); err != nil {
		return TokenPair{}, u.unavailable(client, err)
	}
	u.accepted(ExchangeCodeAccepted, grant)
	return pair, nil
}

// Refresh — полоса `refresh_token`: ротация с обнаружением повтора.
func (u *ExchangeUseCase) Refresh(ctx context.Context, in RefreshInput) (TokenPair, error) {
	if in.Repeated || in.Refresh == "" {
		return TokenPair{}, u.refuse(TokenErrInvalidRequest, ExchangeFormInvalid, "", "")
	}
	if len(in.Scope) > domain.MaxOAuthScopeLen || !domain.ValidOAuthScope(in.Scope) {
		return TokenPair{}, u.refuse(TokenErrInvalidScope, ExchangeScopeRefused, "", "")
	}
	client, err := u.authenticateClient(ctx, in.Client)
	if err != nil {
		return TokenPair{}, err
	}
	presented := domain.PresentedCeremonySecret(in.Refresh).Digest()

	w, err := u.store.Writer(ctx)
	if err != nil {
		return TokenPair{}, u.unavailable(client, err)
	}
	defer func() { _ = w.Rollback(ctx) }()

	st, err := w.LockRefresh(ctx, presented)
	if err != nil {
		return TokenPair{}, u.unavailable(client, err)
	}
	switch {
	case !st.Found:
		return TokenPair{}, u.refuse(TokenErrInvalidGrant, ExchangeRefreshUnknown, client, "")
	case st.Grant.Client != client:
		// Удостоверение другого клиента: связка нарушена, но предъявивший
		// аутентифицировался собой — чужое семейство он не отзывает.
		return TokenPair{}, u.refuse(TokenErrInvalidGrant, ExchangeRefreshClientMismatch, client, st.Grant.Subject)
	case st.Revoked:
		return TokenPair{}, u.refuse(TokenErrInvalidGrant, ExchangeRefreshRevoked, client, st.Grant.Subject)
	case st.Rotated:
		return TokenPair{}, u.replayRevokes(ctx, w, st.Grant, RevokedRefreshReplay, ExchangeRefreshReplayed)
	case !st.SessionLive || st.CutOff:
		return TokenPair{}, u.refuse(TokenErrInvalidGrant, ExchangeRefreshSessionEnded, client, st.Grant.Subject)
	}

	scope, ok := narrowScope(st.Grant.Scope, in.Scope)
	if !ok {
		return TokenPair{}, u.refuse(TokenErrInvalidScope, ExchangeScopeRefused, client, st.Grant.Subject)
	}
	next, err := domain.NewCeremonySecret()
	if err != nil {
		return TokenPair{}, u.unavailable(client, err)
	}
	rotated, err := w.RotateRefresh(ctx, presented, next.Digest(), st.Grant.ID)
	if err != nil {
		return TokenPair{}, u.unavailable(client, err)
	}
	if !rotated {
		// Под замком семейства предшественник уже ротирован — это повтор, и
		// ответ у него тот же, что у повтора, прочитанного замком.
		return TokenPair{}, u.replayRevokes(ctx, w, st.Grant, RevokedRefreshReplay, ExchangeRefreshReplayed)
	}
	pair, err := u.mint(ctx, st.Grant, scope, next)
	if errors.Is(err, errSubjectIneligible) {
		return TokenPair{}, u.refuse(TokenErrInvalidGrant, ExchangeRefreshSessionEnded, client, st.Grant.Subject)
	}
	if err != nil {
		return TokenPair{}, u.unavailable(client, err)
	}
	if err := w.Commit(ctx); err != nil {
		return TokenPair{}, u.unavailable(client, err)
	}
	u.accepted(ExchangeRefreshRotated, st.Grant)
	return pair, nil
}

// authenticateClient — аутентификация конфиденциального клиента (Р3),
// ДО того, как назван код. Все отказы — `invalid_client`.
func (u *ExchangeUseCase) authenticateClient(ctx context.Context, p ClientPresentation) (domain.InteractiveClientID, error) {
	if !p.Presented || p.ID == "" {
		return "", u.refuse(TokenErrInvalidClient, ExchangeClientMissing, "", "")
	}
	if p.FormClientID != "" && p.FormClientID != p.ID {
		return "", u.refuse(TokenErrInvalidClient, ExchangeClientMissing, "", "")
	}
	if !interactiveClientIDForm.MatchString(p.ID) {
		return "", u.refuse(TokenErrInvalidClient, ExchangeClientUnknown, "", "")
	}
	id := domain.InteractiveClientID(p.ID)
	secret, found, err := u.clients.ClientSecret(ctx, id)
	if err != nil {
		return "", u.unavailable(id, err)
	}
	switch {
	case !found:
		return "", u.refuse(TokenErrInvalidClient, ExchangeClientUnknown, id, "")
	case !secret.Active:
		return "", u.refuse(TokenErrInvalidClient, ExchangeClientNotActive, id, "")
	}
	res := u.secrets.Verify(secret.Verifier, p.Secret)
	switch res.Outcome {
	case passwordverify.OutcomeMatched:
		return id, nil
	case passwordverify.OutcomeMismatched:
		return "", u.refuse(TokenErrInvalidClient, ExchangeClientSecretWrong, id, "")
	case passwordverify.OutcomeMaterialMissing:
		return "", u.refuse(TokenErrInvalidClient, ExchangeClientNoSecret, id, "")
	case passwordverify.OutcomeCapacityExhausted:
		return "", u.refuse(TokenErrUnavailable, ExchangeVerifierBusy, id, "")
	default:
		// Значение, которого проверяющий не читает, — наш дефект данных, а не
		// ошибка клиента; клиент при этом аутентифицироваться не может.
		return "", u.refuse(TokenErrInvalidClient, ExchangeClientSecretBroken, id, "")
	}
}

// refuseCode — код не потреблён: отзыв семейства, если это повтор, и ОДИН
// ответ на все причины.
func (u *ExchangeUseCase) refuseCode(ctx context.Context, w Writer, r CodeRedemption) error {
	grant, revoked, err := w.RevokeFamilyOfCode(ctx, r.Digest, u.familyCutoff())
	if err != nil {
		return u.unavailable(r.Client, err)
	}
	if revoked {
		if err := w.EmitAudit(ctx, revokedAudit(grant, RevokedCodeReplay)); err != nil {
			return u.unavailable(r.Client, err)
		}
		if err := w.Commit(ctx); err != nil {
			return u.unavailable(r.Client, err)
		}
		return u.refuse(TokenErrInvalidGrant, ExchangeCodeReplayed, r.Client, grant.Subject)
	}
	if err := w.Commit(ctx); err != nil {
		return u.unavailable(r.Client, err)
	}
	reason, err := u.store.ClassifyCode(ctx, r)
	if err != nil {
		// Отказ уже решён оператором потребления; журнал лишь теряет причину.
		reason = CodeUnknown
	}
	return u.refuse(TokenErrInvalidGrant, codeOutcome(reason), r.Client, "")
}

// replayRevokes — повтор: семейство отзывается той же транзакцией.
func (u *ExchangeUseCase) replayRevokes(ctx context.Context, w Writer, g Grant, reason RevocationReason, o Outcome) error {
	if _, err := w.RevokeFamily(ctx, FamilyRevocation{Grant: g.ID, Reason: reason, Before: u.familyCutoff()}); err != nil {
		return u.unavailable(g.Client, err)
	}
	if err := w.EmitAudit(ctx, revokedAudit(g, reason)); err != nil {
		return u.unavailable(g.Client, err)
	}
	if err := w.Commit(ctx); err != nil {
		return u.unavailable(g.Client, err)
	}
	return u.refuse(TokenErrInvalidGrant, o, g.Client, g.Subject)
}

// familyCutoff — отсечка предъявителей семейства. Предъявители семейства
// подписаны до отзыва (выдача и отзыв сериализованы замком строки), поэтому
// «сейчас» их покрывает; допуск расхождения часов прибавлен, потому что
// отметку выпуска ставит часами процесс, возможно — другой экземпляр.
// Уборка отсечки судит `revoke_before + MaxTokenTTL + ClockSkew + запас`, то
// есть строка живёт, пока жив хоть один предъявитель семейства.
func (u *ExchangeUseCase) familyCutoff() time.Time {
	return u.cfg.Clock().UTC().Add(tokenpolicy.ClockSkew)
}

// mint — наш подписанный предъявитель для авторизации. Субъект, уровень и
// момент — из авторизации (то есть из сессии), никогда из запроса.
func (u *ExchangeUseCase) mint(ctx context.Context, g Grant, scope string, refresh domain.CeremonySecret) (TokenPair, error) {
	user, err := u.users.GetByID(ctx, g.Subject)
	if err != nil {
		return TokenPair{}, fmt.Errorf("ceremony: read subject: %w", err)
	}
	if !user.InviteStatus.MayAuthenticate() {
		return TokenPair{}, errSubjectIneligible
	}
	client, found, err := u.clients.InteractiveClient(ctx, g.Client)
	if err != nil {
		return TokenPair{}, fmt.Errorf("ceremony: read client: %w", err)
	}
	if !found {
		return TokenPair{}, fmt.Errorf("ceremony: client of the authorization is gone")
	}
	audience, err := audiencepolicy.Resolve(audiencepolicy.Scope{
		Landing:  u.cfg.AllowedAudiences,
		Default:  u.cfg.DefaultAudience,
		Declared: client.Audiences,
		Subject:  string(client.ID),
	}, nil)
	if err != nil {
		return TokenPair{}, fmt.Errorf("ceremony: audience: %w", err)
	}
	now := u.cfg.Clock().UTC()
	ttl := sessionTTLBound(u.cfg.TokenTTL, g.SessionExpiresAt, now)
	if ttl < time.Second {
		return TokenPair{}, errSubjectIneligible
	}
	authTime := g.AuthenticatedAt.Unix()
	claims := u.claims.UserClaims(user, string(user.ExternalID), service.TokenHookContext{
		GrantedScopes: strings.Fields(scope),
		AuthTime:      authTime,
		ACR:           g.Level,
		OAuthClientID: string(g.Client),
		GrantType:     GrantTypeAuthorizationCode,
	})
	claims["acr"] = g.Level
	claims["auth_time"] = authTime
	claims["client_id"] = string(g.Client)
	claims[domain.ClaimAuthorizationID] = string(g.ID)
	if scope != "" {
		claims["scope"] = scope
	}
	tok, err := u.signer.Sign(ctx, tokensigner.Request{
		Subject:   string(g.Subject),
		Audience:  audience,
		TokenType: tokenpolicy.TokenTypeAccess,
		TTL:       ttl,
		Claims:    claims,
	})
	if err != nil {
		return TokenPair{}, fmt.Errorf("ceremony: sign: %w", err)
	}
	return TokenPair{
		AccessToken: tok.Token,
		TokenType:   "Bearer",
		ExpiresIn:   int(tok.ExpiresAt.Sub(tok.IssuedAt).Seconds()),
		Refresh:     refresh,
		Scope:       scope,
	}, nil
}

func (u *ExchangeUseCase) refuse(code string, o Outcome, client domain.InteractiveClientID, subject domain.UserID) error {
	u.census.Count(o)
	u.logger.Warn("token exchange refused",
		slog.String("outcome", string(o)),
		slog.String("client_id", string(client)),
		slog.String("user_id", string(subject)))
	return &Refusal{Code: code, Outcome: o}
}

func (u *ExchangeUseCase) unavailable(client domain.InteractiveClientID, err error) error {
	u.census.Count(ExchangeUnavailable)
	u.logger.Error("token exchange: dependency did not answer",
		slog.String("outcome", string(ExchangeUnavailable)),
		slog.String("client_id", string(client)),
		slog.String("error_class", errorClass(err)))
	return &Refusal{Code: TokenErrUnavailable, Outcome: ExchangeUnavailable}
}

func (u *ExchangeUseCase) accepted(o Outcome, g Grant) {
	u.census.Count(o)
	u.logger.Info("token exchange accepted",
		slog.String("outcome", string(o)),
		slog.String("client_id", string(g.Client)),
		slog.String("user_id", string(g.Subject)),
		slog.String("grant_id", string(g.ID)))
}

func revokedAudit(g Grant, reason RevocationReason) outboxtypes.AuditEvent {
	return outboxtypes.AuditEvent{
		EventType: AuditAuthorizationRevoked,
		Payload: map[string]any{
			"user_id":   string(g.Subject),
			"client_id": string(g.Client),
			"grant_id":  string(g.ID),
			"reason":    string(reason),
		},
	}
}

func codeOutcome(r CodeRefusal) Outcome {
	switch r {
	case CodeConsumed:
		return ExchangeCodeReplayed
	case CodeExpired:
		return ExchangeCodeExpired
	case CodeClientMismatch:
		return ExchangeCodeClientMismatch
	case CodeRedirectMismatch:
		return ExchangeCodeRedirectMismatch
	case CodeVerifierMismatch:
		return ExchangeCodeVerifierMismatch
	case CodeSessionEnded:
		return ExchangeCodeSessionEnded
	default:
		return ExchangeCodeUnknown
	}
}

// narrowScope — область выдачи ротации: пусто — область авторизации целиком;
// иначе каждый запрошенный токен обязан входить в неё (RFC 6749 §6).
func narrowScope(granted, requested string) (string, bool) {
	if requested == "" {
		return granted, true
	}
	have := map[string]bool{}
	for _, s := range strings.Fields(granted) {
		have[s] = true
	}
	for _, s := range strings.Fields(requested) {
		if !have[s] {
			return "", false
		}
	}
	return requested, true
}

// errSubjectIneligible — человек либо его сессия больше не вправе получать
// предъявитель: отказ предъявителю (`invalid_grant`), а не наш сбой.
var errSubjectIneligible = errors.New("ceremony: subject or its session may no longer be issued a bearer")

// IsRefusal — ошибка полосы обмена и её стандартный код.
func IsRefusal(err error) (*Refusal, bool) {
	var r *Refusal
	if errors.As(err, &r) {
		return r, true
	}
	return nil, false
}
