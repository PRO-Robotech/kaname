// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package loginlanehttp — HTTP-слушатель полосы формы: четыре глагола Р2 на
// адресе консоли, ретранслируемые краем (фаза Ф3, задача
// PRO-Robotech/kacho#1269; приёмка
// `docs/engineering/acceptance/login-lane-issues-our-session-and-logout-ends-it-server-side.md`,
// решения Р2, Р3, Р10, Р12, Р16).
//
// # Кто вправе звать — РОВНО край, и это судится здесь, до тела запроса
//
// Слушатель взаимный по TLS (режим `mutual` — транспорт), и множество
// допущенных равно краю: короткое имя службы, разобранное из SAN проверенного
// клиентского сертификата под доменом доверия установки, равно имени края —
// той же константе и тем же разбором, что у яруса gateway-only внутреннего
// слушателя (`authzguard.GatewayServiceName`, `authzguard.ServiceNameFromSAN`).
// Круг законных отправителей слушатель НЕ читает: он шире края by construction
// (§1.10). Пир с иным именем — `PERMISSION_DENIED` / 403 текстом `permission
// denied`, тело не читается, заголовки в счёт не попадают. Dev-послабления
// нет: слушатель наружный по построению.
//
// # Переданная личность НЕ читается
//
// На этой поверхности личность производит ОДИН механизм — носитель, судимый
// службой по записи (Р16, KAN-SOLE-01). Заголовков `x-kacho-*` слушатель не
// читает вовсе — ни в голой, ни в мостовой форме: пары извлечения переданной
// личности здесь нет, и субъект берётся из `kaname_session`.
//
// # Отказы — `google.rpc.Status` JSON, тексты фиксированы
//
// Форма — та, что отдаёт край через grpc-gateway (`{code, message, details}`),
// `details` — всегда массив (пустой либо с `ErrorInfo`): побайтовое равенство
// двух отказов (Ф3-02, Ф3-18) держится тем, что тело собирается одной
// функцией из закрытого набора полей.
package loginlanehttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Пути семейства — точное совпадение (Р2). «Кто я» — маршрут КРАЯ, здесь его
// нет намеренно.
const (
	PathLogin    = "/iam/v1/auth/login"
	PathLogout   = "/iam/v1/auth/logout"
	PathPassword = "/iam/v1/auth/password"
	PathCSRF     = "/iam/v1/auth/csrf"
)

// Paths — четыре глагола, ОДНИМ объявлением: край читает тот же перечень для
// ретрансляции (§8 инв. 7).
func Paths() []string { return []string{PathLogin, PathLogout, PathPassword, PathCSRF} }

// Имена печений (Р3). Имя носителя отлично от имени носителя поставщика
// (F4d-26) — перечень гасимых имён у края читает и это имя.
const (
	CookieSession = "kaname_session"
	CookieForm    = "kaname_form"
)

// HeaderForwardedFor — единственный заголовок, который слушатель читает у
// допущенного вызывающего: ОДИН адрес, выведенный краем (Р2, Р10).
const HeaderForwardedFor = "X-Forwarded-For"

// maxBody — потолок тела формы; форма из трёх строк в него помещается с
// запасом, а тело, которое в него не помещается, формой не является.
const maxBody = 16 << 10

// TextPermissionDenied — текст отказа пиру, который не край: дословно тот,
// которым отказывает ярус gateway-only.
const TextPermissionDenied = "permission denied"

// Lane — глаголы полосы (порт над вариантами использования).
type Lane interface {
	Login(ctx context.Context, in humansession.LoginInput) (humansession.LoginOutput, error)
	Logout(ctx context.Context, bearer domain.SessionBearer) (bool, error)
	ChangePassword(ctx context.Context, in humansession.ChangePasswordInput) (humansession.ChangePasswordOutput, error)
}

// Config — настройка слушателя. Срок и домен — величины профиля (Р3): срок без
// умолчания; домен — имя либо пусто на адресной посадке («нет» разбирает
// настройка, сюда приходит уже пустая строка).
type Config struct {
	SessionTTL    time.Duration
	CookieDomain  string
	TrustDomain   grpcsrv.TrustDomain
	RefusalDomain string
	Logger        *slog.Logger
	Observer      humansession.Observer
}

// Handler — слушатель полосы формы.
type Handler struct {
	cfg  Config
	lane Lane
	mux  *http.ServeMux
}

// New — слушатель; отказы построения — те же, что у стража старта, чтобы
// слушатель, собранный мимо него, не поднялся с пустой величиной.
func New(cfg Config, lane Lane) (*Handler, error) {
	switch {
	case cfg.SessionTTL <= 0:
		return nil, fmt.Errorf("login lane: session ttl must be positive")
	case !cfg.TrustDomain.IsDeclared():
		return nil, fmt.Errorf("login lane: trust domain must be declared — without it no caller is admitted")
	case lane == nil:
		return nil, fmt.Errorf("login lane: verbs required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Observer == nil {
		cfg.Observer = humansession.NopObserver{}
	}
	h := &Handler{cfg: cfg, lane: lane, mux: http.NewServeMux()}
	h.mux.HandleFunc(PathLogin, h.method(http.MethodPost, h.login))
	h.mux.HandleFunc(PathLogout, h.method(http.MethodPost, h.logout))
	h.mux.HandleFunc(PathPassword, h.method(http.MethodPost, h.changePassword))
	h.mux.HandleFunc(PathCSRF, h.method(http.MethodGet, h.csrf))
	return h, nil
}

// ServeHTTP — допуск ДО маршрута и до тела: пир, который не край, не доходит
// ни до одного глагола.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.callerIsGateway(r) {
		writeRefusal(w, http.StatusForbidden, codePermissionDenied, TextPermissionDenied, nil)
		return
	}
	h.mux.ServeHTTP(w, r)
}

// callerIsGateway — ярус допуска (Р16, форма Ф-т на HTTP-слушателе).
func (h *Handler) callerIsGateway(r *http.Request) bool {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return false
	}
	san := h.cfg.TrustDomain.CertIdentity(r.TLS.VerifiedChains[0][0])
	if san == "" {
		return false
	}
	svc, ok := authzguard.ServiceNameFromSAN(h.cfg.TrustDomain, san)
	return ok && svc == authzguard.GatewayServiceName()
}

func (h *Handler) method(want string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != want {
			w.Header().Set("Allow", want)
			writeRefusal(w, http.StatusMethodNotAllowed, codeInvalidArgument, "method not allowed", nil)
			return
		}
		next(w, r)
	}
}

// --- формы запросов: закрытый набор полей, лишнее отвергается ---

type loginForm struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	CSRFToken string `json:"csrfToken"`
}

type logoutForm struct {
	CSRFToken string `json:"csrfToken"`
}

type passwordForm struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
	CSRFToken       string `json:"csrfToken"`
}

// decodeForm — строгий разбор: неизвестное поле называется, а не глотается
// (`api-conventions.md` §«Принято-и-проигнорировано»).
func decodeForm(r *http.Request, into any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		msg := err.Error()
		if strings.HasPrefix(msg, "json: unknown field ") {
			field := strings.Trim(strings.TrimPrefix(msg, "json: unknown field "), `"`)
			return &humansession.FieldError{Field: field, Rule: "unknown field"}
		}
		return &humansession.FieldError{Field: "body", Rule: "malformed JSON"}
	}
	if dec.More() {
		return &humansession.FieldError{Field: "body", Rule: "trailing content"}
	}
	return nil
}

// requireFields — первое незаполненное поле в порядке формы называется отказом.
func requireFields(fields map[string]string) error {
	for _, name := range []string{"email", "password", "currentPassword", "newPassword"} {
		if v, present := fields[name]; present && v == "" {
			return humansession.FieldRequired(name)
		}
	}
	return nil
}

func (h *Handler) formContext(r *http.Request) string {
	if c, err := r.Cookie(CookieForm); err == nil {
		return c.Value
	}
	return ""
}

func (h *Handler) bearer(r *http.Request) domain.SessionBearer {
	if c, err := r.Cookie(CookieSession); err == nil {
		return domain.PresentedSessionBearer(c.Value)
	}
	return domain.SessionBearer{}
}

// judgeForm — признак формы (Р12): отсутствует → 400 с полем; не подошёл → 403.
func (h *Handler) judgeForm(w http.ResponseWriter, r *http.Request, kind domain.FormKind, token string) bool {
	err := humansession.JudgeFormToken(h.formContext(r), kind, token)
	switch {
	case err == nil:
		return true
	case errors.Is(err, humansession.ErrFormTokenRejected):
		h.cfg.Observer.FormRefusalObserved(humansession.FormRefusalRejected)
		writeRefusal(w, http.StatusForbidden, codePermissionDenied, humansession.TextFormTokenRejected,
			&errorInfo{Reason: humansession.ReasonFormTokenRejected, Domain: h.cfg.RefusalDomain})
	default:
		h.cfg.Observer.FormRefusalObserved(humansession.FormRefusalMissing)
		h.writeError(w, err, humansession.TextRequestNotPerformed)
	}
	return false
}

// --- глаголы ---

func (h *Handler) csrf(w http.ResponseWriter, r *http.Request) {
	kind, err := domain.ParseFormKind(r.URL.Query().Get("form"))
	if err != nil {
		writeRefusal(w, http.StatusBadRequest, codeInvalidArgument, err.Error(), nil)
		return
	}
	ctx := h.formContext(r)
	if ctx == "" {
		fresh, ferr := humansession.NewFormContext()
		if ferr != nil {
			writeRefusal(w, http.StatusServiceUnavailable, codeUnavailable, humansession.TextRequestNotPerformed, nil)
			return
		}
		ctx = fresh
		http.SetCookie(w, h.formCookie(ctx))
	}
	writeJSON(w, http.StatusOK, map[string]string{"csrfToken": humansession.FormToken(ctx, kind)})
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var form loginForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormLogin, form.CSRFToken) {
		return
	}
	// Отсутствующее поле называется ДО глагола (Ф3-05): такой отказ в счёт
	// частоты не идёт, потому что до счёта не доходит.
	if err := requireFields(map[string]string{"email": form.Email, "password": form.Password}); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	out, err := h.lane.Login(r.Context(), humansession.LoginInput{
		Email: form.Email, Password: form.Password, Source: h.source(r),
	})
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	// Контекст формы СМЕНЯЕТСЯ выдачей сессии (Р12, Ф3-37).
	fresh, ferr := humansession.NewFormContext()
	if ferr != nil {
		writeRefusal(w, http.StatusServiceUnavailable, codeUnavailable, humansession.TextRequestNotPerformed, nil)
		return
	}
	http.SetCookie(w, h.sessionCookie(out.Bearer))
	http.SetCookie(w, h.formCookie(fresh))
	writeJSON(w, http.StatusOK, map[string]any{
		"user":    userJSON(out.View),
		"session": sessionJSON(out.View),
	})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	var form logoutForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextLogoutNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormLogout, form.CSRFToken) {
		return
	}
	if _, err := h.lane.Logout(r.Context(), h.bearer(r)); err != nil {
		// Носитель цел: `Set-Cookie` не пишется (Ф1-58).
		h.writeError(w, err, humansession.TextLogoutNotPerformed)
		return
	}
	http.SetCookie(w, h.endedSessionCookie())
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (h *Handler) changePassword(w http.ResponseWriter, r *http.Request) {
	var form passwordForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormPassword, form.CSRFToken) {
		return
	}
	if err := requireFields(map[string]string{"currentPassword": form.CurrentPassword, "newPassword": form.NewPassword}); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	out, err := h.lane.ChangePassword(r.Context(), humansession.ChangePasswordInput{
		Bearer: h.bearer(r), CurrentPassword: form.CurrentPassword, NewPassword: form.NewPassword, Source: h.source(r),
	})
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	http.SetCookie(w, h.sessionCookie(out.Bearer))
	writeJSON(w, http.StatusOK, map[string]any{"session": sessionJSON(out.View)})
}

// source — адрес источника: значение заголовка допущенного вызывающего как
// есть, цепочка не разбирается (Р10).
func (h *Handler) source(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get(HeaderForwardedFor))
}

// --- печенья (Р3) ---

func (h *Handler) sessionCookie(b domain.SessionBearer) *http.Cookie {
	return &http.Cookie{
		Name: CookieSession, Value: b.CookieValue(), Path: "/", Domain: h.cfg.CookieDomain,
		MaxAge: int(h.cfg.SessionTTL / time.Second), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	}
}

func (h *Handler) endedSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name: CookieSession, Value: "", Path: "/", Domain: h.cfg.CookieDomain,
		MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	}
}

func (h *Handler) formCookie(ctx string) *http.Cookie {
	return &http.Cookie{
		Name: CookieForm, Value: ctx, Path: "/", Domain: h.cfg.CookieDomain,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	}
}

// --- тела ответов ---

func userJSON(v humansession.SessionView) map[string]any {
	return map[string]any{
		"id":          string(v.User.ID),
		"email":       string(v.User.Email),
		"displayName": string(v.User.DisplayName),
	}
}

func sessionJSON(v humansession.SessionView) map[string]any {
	return map[string]any{
		// Срок — до секунды (конвенция); сравнивает его служба, не клиент.
		"expiresAt":              v.Session.ExpiresAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		"assuranceLevel":         v.Session.AssuranceLevel,
		"emailVerified":          v.EmailVerified,
		"passwordChangeRequired": v.Session.PasswordChangeRequired,
	}
}

// writeError — отказ по типу ошибки глагола; unavailableText — текст 503 этого
// глагола (у выхода свой — Ф1-58).
func (h *Handler) writeError(w http.ResponseWriter, err error, unavailableText string) {
	var (
		fe  *humansession.FieldError
		tma *humansession.TooManyAttemptsError
	)
	switch {
	case errors.As(err, &fe):
		writeRefusal(w, http.StatusBadRequest, codeInvalidArgument, fe.Error(), nil)
	case errors.As(err, &tma):
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfterSeconds(tma.RetryAfter))))
		writeRefusal(w, http.StatusTooManyRequests, codeResourceExhausted, humansession.TextTooManyAttempts,
			&errorInfo{Reason: humansession.ReasonTooManyAttempts, Domain: h.cfg.RefusalDomain})
	case errors.Is(err, humansession.ErrAuthenticationFailed):
		writeRefusal(w, http.StatusUnauthorized, codeUnauthenticated, humansession.TextAuthenticationFailed, nil)
	case errors.Is(err, humansession.ErrFormTokenRejected):
		writeRefusal(w, http.StatusForbidden, codePermissionDenied, humansession.TextFormTokenRejected,
			&errorInfo{Reason: humansession.ReasonFormTokenRejected, Domain: h.cfg.RefusalDomain})
	case errors.Is(err, humansession.ErrStoreUnavailable), errors.Is(err, humansession.ErrBreachAuthorityMisconfigured):
		writeRefusal(w, http.StatusServiceUnavailable, codeUnavailable, unavailableText, nil)
	default:
		// Неклассифицированный отказ — тоже 503 фиксированным текстом, а не
		// эхо ошибки: причина уходит в журнал, не в тело.
		h.cfg.Logger.Error("login lane: unclassified refusal", "err", err.Error())
		writeRefusal(w, http.StatusServiceUnavailable, codeUnavailable, unavailableText, nil)
	}
}

func retryAfterSeconds(d time.Duration) int64 {
	s := int64(d / time.Second)
	if d%time.Second != 0 {
		s++
	}
	if s < 1 {
		s = 1
	}
	return s
}

// Коды `google.rpc.Code`, которые отдаёт полоса.
const (
	codeInvalidArgument   = 3
	codePermissionDenied  = 7
	codeResourceExhausted = 8
	codeUnavailable       = 14
	codeUnauthenticated   = 16
)

// errorInfo — `google.rpc.ErrorInfo` в форме, какой её печатает protojson.
type errorInfo struct {
	Type   string `json:"@type"`
	Reason string `json:"reason"`
	Domain string `json:"domain"`
}

type refusalBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Details []any  `json:"details"`
}

func writeRefusal(w http.ResponseWriter, status, code int, message string, info *errorInfo) {
	body := refusalBody{Code: code, Message: message, Details: []any{}}
	if info != nil {
		info.Type = "type.googleapis.com/google.rpc.ErrorInfo"
		body.Details = append(body.Details, info)
	}
	writeJSON(w, status, body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, `{"code":13,"message":"internal error","details":[]}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
