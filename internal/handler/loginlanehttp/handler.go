// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package loginlanehttp — HTTP-слушатель полосы формы: четыре глагола Р2 на
// адресе консоли, ретранслируемые краем (фаза Ф3, задача
// PRO-Robotech/kacho#1269; приёмка
// `docs/engineering/acceptance/login-lane-issues-our-session-and-logout-ends-it-server-side.md`,
// решения Р2, Р3, Р10, Р12, Р16), пятый — регистрация (фаза Ф4,
// PRO-Robotech/kacho#1270): та же форма ответа, то же печенье, свой вид
// признака формы и ОДИН отказ на занятость и потолок темпа (Ф4 Р3), — и два
// глагола восстановления доступа на той же полосе (фаза Ф5, задача
// PRO-Robotech/kacho#1271; приёмка `docs/engineering/acceptance/recovery-of-access.md`):
// запрос кода и его предъявление с новым паролем, — и шесть глаголов второго
// фактора (фаза Ф12, задача PRO-Robotech/kacho#1281; приёмка
// `docs/engineering/acceptance/second-factor-totp-and-recovery-codes.md`, Р4):
// заведение, подтверждение, снятие, перечеканка запасных кодов, чтение
// состояния и церемония повышения внутри сессии; форма входа при этом несёт
// необязательное поле `secondFactor`. Три глагола своих сессий (задача
// PRO-Robotech/kaname#634; приёмка
// `docs/engineering/acceptance/own-sessions-are-listed-and-ended-by-their-owner.md`,
// Р1…Р10): перечень своих живых сессий, выход из выбранной и из всех, кроме
// текущей, — субъект из носителя, ответ синхронный.
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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Пути семейства — точное совпадение (Р2). «Кто я» — маршрут КРАЯ, здесь его
// нет намеренно.
const (
	PathLogin  = "/iam/v1/auth/login"
	PathLogout = "/iam/v1/auth/logout"
	// #nosec G101 -- это ПУТЬ глагола смены пароля, а не значение пароля.
	PathPassword = "/iam/v1/auth/password"
	PathCSRF     = "/iam/v1/auth/csrf"
	// PathRegister — регистрация паролем (Ф4): подпутём, как остальные.
	PathRegister = "/iam/v1/auth/register"
	// Восстановление доступа (Ф5): запрос кода и его предъявление с новым
	// паролем — два глагола, две формы, два вида признака.
	PathRecovery         = "/iam/v1/auth/recovery"
	PathRecoveryComplete = "/iam/v1/auth/recovery/complete"
	// Второй фактор (Ф12 Р4): четыре глагола семейства подпутями, чтение
	// состояния на корне семейства, церемония повышения — своим подпутём.
	PathSecondFactor            = "/iam/v1/auth/second-factor"
	PathSecondFactorEnroll      = "/iam/v1/auth/second-factor/enroll"
	PathSecondFactorConfirm     = "/iam/v1/auth/second-factor/confirm"
	PathSecondFactorRemove      = "/iam/v1/auth/second-factor/remove"
	PathSecondFactorBackupCodes = "/iam/v1/auth/second-factor/backup-codes"
	PathStepUp                  = "/iam/v1/auth/step-up"
	// Подтверждение адреса (kaname#456, Р6; имена ратифицированы — Ф6 Р15):
	// запрос письма и предъявление кода — два глагола под сессией человека.
	PathVerifyEmail        = "/iam/v1/auth/verify-email"
	PathVerifyEmailConfirm = "/iam/v1/auth/verify-email/confirm"
	// Вход ключом доступа (Ф13 Р1, kaname#613): выдача испытания и
	// предъявление утверждения — два глагола, два вида признака формы.
	PathAccessKeyBegin = "/iam/v1/auth/access-key/begin"
	PathAccessKeyLogin = "/iam/v1/auth/access-key/login"
	// PathPasswordEnroll — заведение первого пароля из живой сессии
	// (kaname#213, приёмка A7 Р1): подпуть семейства пароля.
	// #nosec G101 -- это ПУТЬ глагола, а не значение пароля.
	PathPasswordEnroll = "/iam/v1/auth/password/enroll"
	// Свои сессии (kaname#634, Р1): перечень на корне семейства, два снимающих
	// глагола подпутями.
	PathSessions          = "/iam/v1/auth/sessions"
	PathSessionsEnd       = "/iam/v1/auth/sessions/end"
	PathSessionsEndOthers = "/iam/v1/auth/sessions/end-others"
)

// Paths — двадцать один глагол, ОДНИМ объявлением: край читает тот же перечень
// для ретрансляции (§8 инв. 7).
func Paths() []string {
	return []string{
		PathLogin, PathLogout, PathPassword, PathCSRF, PathRegister, PathRecovery, PathRecoveryComplete,
		PathSecondFactor, PathSecondFactorEnroll, PathSecondFactorConfirm, PathSecondFactorRemove,
		PathSecondFactorBackupCodes, PathStepUp, PathVerifyEmail, PathVerifyEmailConfirm,
		PathAccessKeyBegin, PathAccessKeyLogin, PathPasswordEnroll,
		PathSessions, PathSessionsEnd, PathSessionsEndOthers,
	}
}

// PathPosition — что путь полосы делает в ПОЛОЖЕНИИ ПОДТВЕРЖДЕНИЯ (kaname#456,
// Р2). Перечень строк закрыт; нулевое значение — «не объявлено», и путь без
// объявления есть находка гейта, а не умолчание в любую сторону.
type PathPosition int

const (
	// PathAvailableInVerification — доступно в положении подтверждения.
	PathAvailableInVerification PathPosition = iota + 1
	// PathRefusedInVerification — отказ положения (Р3).
	PathRefusedInVerification
)

// pathPositions — объявление Р2 для каждого пути полосы. Путь, заводимый
// позже, объявляет себя здесь той же правкой, что заводит путь.
var pathPositions = map[string]PathPosition{
	PathRegister:           PathAvailableInVerification,
	PathLogin:              PathAvailableInVerification,
	PathCSRF:               PathAvailableInVerification,
	PathLogout:             PathAvailableInVerification,
	PathVerifyEmail:        PathAvailableInVerification,
	PathVerifyEmailConfirm: PathAvailableInVerification,
	PathRecovery:           PathAvailableInVerification,
	PathRecoveryComplete:   PathAvailableInVerification,
	// Вход ключом выдаёт сессию так же, как вход паролем: положения
	// подтверждения у вызывающего до выдачи нет.
	PathAccessKeyBegin:          PathAvailableInVerification,
	PathAccessKeyLogin:          PathAvailableInVerification,
	PathPassword:                PathRefusedInVerification,
	PathSecondFactor:            PathRefusedInVerification,
	PathSecondFactorEnroll:      PathRefusedInVerification,
	PathSecondFactorConfirm:     PathRefusedInVerification,
	PathSecondFactorRemove:      PathRefusedInVerification,
	PathSecondFactorBackupCodes: PathRefusedInVerification,
	PathStepUp:                  PathRefusedInVerification,
	// Заведение пароля — правка своих данных: в положении подтверждения адреса
	// отказ (A7 Р2, F6b Р2).
	PathPasswordEnroll: PathRefusedInVerification,
	// Свои сессии (kaname#634, Р8): сессия без отметки подтверждения перечня не
	// видит и снимать не может — отказ положения.
	PathSessions:          PathRefusedInVerification,
	PathSessionsEnd:       PathRefusedInVerification,
	PathSessionsEndOthers: PathRefusedInVerification,
}

// PathPositions — объявление Р2 копией.
func PathPositions() map[string]PathPosition {
	out := make(map[string]PathPosition, len(pathPositions))
	for k, v := range pathPositions {
		out[k] = v
	}
	return out
}

// Имена печений (Р3). Имя носителя отлично от имени носителя поставщика
// (F4d-26) — перечень гасимых имён у края читает и это имя.
const (
	CookieSession = "kaname_session"
	CookieForm    = "kaname_form"
)

// HeaderForwardedFor — заголовок адреса источника у допущенного вызывающего:
// ОДИН адрес, выведенный краем (Р2, Р10).
const HeaderForwardedFor = "X-Forwarded-For"

// HeaderUserAgent — описание клиента, как его доставил край (kaname#634, Р3).
// Читается ровно выдающими глаголами — его значение идёт только в запись
// выдаваемой сессии, — и служба его не разбирает и не толкует.
const HeaderUserAgent = "User-Agent"

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
	// Register — регистрация паролем (Ф4): три следствия одним исходом.
	Register(ctx context.Context, in registration.Input) (registration.Output, error)
	// RequestRecovery — запрос кода (Ф5-01/02): исход наружу не выходит.
	RequestRecovery(ctx context.Context, in humansession.RequestRecoveryInput) error
	// CompleteRecovery — предъявление кода с новым паролем (Ф5-03): выдаёт
	// сессию, как вход.
	CompleteRecovery(ctx context.Context, in humansession.CompleteRecoveryInput) (humansession.CompleteRecoveryOutput, error)
	// Второй фактор (Ф12 Р4): шесть глаголов под сессией носителя.
	EnrollSecondFactor(ctx context.Context, in humansession.EnrollInput) (humansession.EnrollOutput, error)
	ConfirmSecondFactor(ctx context.Context, in humansession.ConfirmInput) (humansession.ConfirmOutput, error)
	SecondFactorStatus(ctx context.Context, in humansession.StatusInput) (humansession.StatusOutput, error)
	RemoveSecondFactor(ctx context.Context, in humansession.RemoveSecondFactorInput) (humansession.RemoveSecondFactorOutput, error)
	RegenerateBackupCodes(ctx context.Context, in humansession.RegenerateBackupCodesInput) (humansession.RegenerateBackupCodesOutput, error)
	StepUp(ctx context.Context, in humansession.StepUpInput) (humansession.StepUpOutput, error)
	// Подтверждение адреса (kaname#456, Р6): запрос письма и предъявление кода.
	RequestEmailVerification(ctx context.Context, bearer domain.SessionBearer) (humansession.RequestVerificationOutput, error)
	ConfirmEmailVerification(ctx context.Context, in humansession.ConfirmVerificationInput) (humansession.ConfirmVerificationOutput, error)
	// AddressPosition — положение сессии носителя по ТЕКУЩЕЙ отметке (Р1):
	// его спрашивает отказ положения на путях, объявленных отказом Р2.
	AddressPosition(ctx context.Context, bearer domain.SessionBearer) (humansession.Position, error)
	// Вход ключом доступа (Ф13 Р1): испытание выдаётся, не назвав человека;
	// предъявление утверждения выдаёт сессию той же формой ответа, что вход
	// паролем.
	BeginAccessKeyLogin(ctx context.Context, in humansession.BeginAccessKeyLoginInput) (humansession.BeginAccessKeyLoginOutput, error)
	AccessKeyLogin(ctx context.Context, in humansession.AccessKeyLoginInput) (humansession.LoginOutput, error)
	// EnrollPassword — заведение первого пароля из живой сессии (kaname#213).
	EnrollPassword(ctx context.Context, in humansession.EnrollPasswordInput) (humansession.EnrollPasswordOutput, error)
	// Свои сессии (kaname#634): перечень, выход из выбранной и из всех, кроме
	// текущей.
	ListOwnSessions(ctx context.Context, in humansession.ListOwnSessionsInput) (humansession.ListOwnSessionsOutput, error)
	EndOwnSession(ctx context.Context, in humansession.EndOwnSessionInput) (humansession.EndOwnSessionOutput, error)
	EndOtherOwnSessions(ctx context.Context, in humansession.EndOtherOwnSessionsInput) (humansession.EndOtherOwnSessionsOutput, error)
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
	// Verification — клетки отказов положения на путях полосы (kaname#456,
	// П13); nil — не считаются.
	Verification humansession.AddressVerificationObserver
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
	if cfg.Verification == nil {
		cfg.Verification = humansession.NopObserver{}
	}
	h := &Handler{cfg: cfg, lane: lane, mux: http.NewServeMux()}
	h.mux.HandleFunc(PathLogin, h.method(http.MethodPost, h.login))
	h.mux.HandleFunc(PathLogout, h.method(http.MethodPost, h.logout))
	h.mux.HandleFunc(PathPassword, h.method(http.MethodPost, h.changePassword))
	h.mux.HandleFunc(PathCSRF, h.method(http.MethodGet, h.csrf))
	h.mux.HandleFunc(PathRegister, h.method(http.MethodPost, h.register))
	h.mux.HandleFunc(PathRecovery, h.method(http.MethodPost, h.requestRecovery))
	h.mux.HandleFunc(PathRecoveryComplete, h.method(http.MethodPost, h.completeRecovery))
	h.mux.HandleFunc(PathSecondFactor, h.method(http.MethodGet, h.secondFactorStatus))
	h.mux.HandleFunc(PathSecondFactorEnroll, h.method(http.MethodPost, h.enrollSecondFactor))
	h.mux.HandleFunc(PathSecondFactorConfirm, h.method(http.MethodPost, h.confirmSecondFactor))
	h.mux.HandleFunc(PathSecondFactorRemove, h.method(http.MethodPost, h.removeSecondFactor))
	h.mux.HandleFunc(PathSecondFactorBackupCodes, h.method(http.MethodPost, h.regenerateBackupCodes))
	h.mux.HandleFunc(PathStepUp, h.method(http.MethodPost, h.stepUp))
	h.mux.HandleFunc(PathVerifyEmail, h.method(http.MethodPost, h.requestEmailVerification))
	h.mux.HandleFunc(PathVerifyEmailConfirm, h.method(http.MethodPost, h.confirmEmailVerification))
	h.mux.HandleFunc(PathAccessKeyBegin, h.method(http.MethodPost, h.accessKeyBegin))
	h.mux.HandleFunc(PathAccessKeyLogin, h.method(http.MethodPost, h.accessKeyLogin))
	h.mux.HandleFunc(PathPasswordEnroll, h.method(http.MethodPost, h.enrollPassword))
	h.mux.HandleFunc(PathSessions, h.method(http.MethodGet, h.ownSessions))
	h.mux.HandleFunc(PathSessionsEnd, h.method(http.MethodPost, h.endOwnSession))
	h.mux.HandleFunc(PathSessionsEndOthers, h.method(http.MethodPost, h.endOtherOwnSessions))
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
	return authzguard.PeerIsGateway(h.cfg.TrustDomain, r.TLS)
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
	// SecondFactor — необязательное предъявление кода (Ф12 Р4, Р5): способ
	// называет клиент; отсутствие поля — сессия «1». Разбирается отдельно,
	// чтобы отказ формы называл вложенное поле полным именем.
	SecondFactor json.RawMessage `json:"secondFactor"`
}

// secondFactorField — `{"method", "code"}`: и во входе, и как подтверждение у
// снятия и перечеканки. Лишнее вложенное поле отвергается тем же разбором.
type secondFactorField struct {
	Method string `json:"method"`
	Code   string `json:"code"`
}

// enrollForm — заведение: только признак.
type enrollForm struct {
	CSRFToken string `json:"csrfToken"`
}

// confirmForm — подтверждение первым кодом; способ здесь один (`totp`) и не
// называется.
type confirmForm struct {
	Code      string `json:"code"`
	CSRFToken string `json:"csrfToken"`
}

// confirmedForm — снятие и перечеканка: подтверждение кодом, как у смены пароля
// `currentPassword` (Р4).
type confirmedForm struct {
	Method    string `json:"method"`
	Code      string `json:"code"`
	CSRFToken string `json:"csrfToken"`
}

// stepUpForm — церемония: один способ; `password` — у ветви пароля, `code` — у
// кода; поле, не относящееся к названному способу, отвергается глаголом.
type stepUpForm struct {
	Method    string `json:"method"`
	Password  string `json:"password"`
	Code      string `json:"code"`
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

// registerForm — форма регистрации: адрес, пароль, признак. Отображаемое имя
// сюда не принимается: у человека, заводящего себя, оно выводится из адреса и
// правится отдельным глаголом; поле без читателя принимать нельзя.
type registerForm struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	CSRFToken string `json:"csrfToken"`
}

// recoveryRequestForm — запрос кода: только адрес.
type recoveryRequestForm struct {
	Email     string `json:"email"`
	CSRFToken string `json:"csrfToken"`
}

// verifyEmailForm — запрос письма подтверждения: только признак. Адреса в теле
// НЕТ by construction (Р6): поле `email` — отказ разбора.
type verifyEmailForm struct {
	CSRFToken string `json:"csrfToken"`
}

// verifyEmailConfirmForm — предъявление кода подтверждения.
type verifyEmailConfirmForm struct {
	Code      string `json:"code"`
	CSRFToken string `json:"csrfToken"`
}

// recoveryCompleteForm — предъявление: адрес, код и новый пароль. Текущего
// пароля здесь НЕТ by construction — код и есть доказательство (Ф5 Р1).
type recoveryCompleteForm struct {
	Email       string `json:"email"`
	Code        string `json:"code"`
	NewPassword string `json:"newPassword"`
	CSRFToken   string `json:"csrfToken"`
}

// endOwnSessionForm — выход из выбранной (Р1): запись и признак.
type endOwnSessionForm struct {
	SessionID string `json:"sessionId"`
	CSRFToken string `json:"csrfToken"`
}

// endOtherOwnSessionsForm — выход из всех, кроме текущей (Р1): только признак.
type endOtherOwnSessionsForm struct {
	CSRFToken string `json:"csrfToken"`
}

// decodeForm — строгий разбор: неизвестное поле называется, а не глотается
// (конвенция платформы «принято-и-проигнорировано — запрещено»: поле запроса без читателя не принимается молча).
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

// decodeNested — строгий разбор вложенного объекта формы: неизвестное поле
// называется полным именем `<prefix>.<поле>`.
func decodeNested(prefix string, raw json.RawMessage, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		msg := err.Error()
		if strings.HasPrefix(msg, "json: unknown field ") {
			field := strings.Trim(strings.TrimPrefix(msg, "json: unknown field "), `"`)
			return &humansession.FieldError{Field: prefix + "." + field, Rule: "unknown field"}
		}
		return &humansession.FieldError{Field: prefix, Rule: "must be an object"}
	}
	return nil
}

// requireFields — первое незаполненное поле в порядке формы называется отказом.
func requireFields(fields map[string]string) error {
	for _, name := range []string{"email", "password", "code", "currentPassword", "newPassword"} {
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

// admitted — отказ положения подтверждения (Р2, Р3) на пути, объявленном
// отказом: положение читается из ТЕКУЩЕЙ отметки на каждом запросе (Р1).
// Сессии нет — судить нечего: отказ сессии выносит глагол. Отказ положения
// Set-Cookie не пишет, сессию и контекст формы не трогает. Путь, объявленный
// доступным, этой ступени не проходит — её зов с таким путём есть дефект
// провязки, и он отвечает отказом, а не проходом.
func (h *Handler) admitted(w http.ResponseWriter, r *http.Request, path string, unavailableText string) bool {
	if pathPositions[path] != PathRefusedInVerification {
		h.cfg.Logger.Error("login lane: position step on a path not declared refused", "path", path)
		writeRefusal(w, http.StatusServiceUnavailable, codeUnavailable, unavailableText, nil)
		return false
	}
	pos, err := h.lane.AddressPosition(r.Context(), h.bearer(r))
	if err != nil {
		writeRefusal(w, http.StatusServiceUnavailable, codeUnavailable, unavailableText, nil)
		return false
	}
	if pos == humansession.PositionVerification {
		h.cfg.Verification.AddressVerificationObserved(humansession.VerificationPositionRefusedLane)
		writeRefusal(w, http.StatusForbidden, codePermissionDenied, humansession.TextEmailNotVerified,
			&errorInfo{Reason: humansession.ReasonEmailNotVerified, Domain: h.cfg.RefusalDomain})
		return false
	}
	return true
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
	in := humansession.LoginInput{Email: form.Email, Password: form.Password, Source: h.source(r), Client: h.client(r)}
	if len(form.SecondFactor) > 0 && string(form.SecondFactor) != "null" {
		var nested secondFactorField
		if err := decodeNested("secondFactor", form.SecondFactor, &nested); err != nil {
			h.writeError(w, err, humansession.TextRequestNotPerformed)
			return
		}
		factor, err := parseSecondFactorField("secondFactor", nested)
		if err != nil {
			h.writeError(w, err, humansession.TextRequestNotPerformed)
			return
		}
		in.SecondFactor = &factor
	}
	out, err := h.lane.Login(r.Context(), in)
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

// register — регистрация паролем (Ф4-01): три следствия одним исходом глагола,
// ответ и печенья — как у входа; отказ — один (Ф4-11/12).
func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var form registerForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormRegister, form.CSRFToken) {
		return
	}
	if err := requireFields(map[string]string{"email": form.Email, "password": form.Password}); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	out, err := h.lane.Register(r.Context(), registration.Input{
		Email: form.Email, Password: form.Password, Source: h.source(r), Client: h.client(r),
	})
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	// Контекст формы СМЕНЯЕТСЯ выдачей сессии (Р12) — как у входа.
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
	if !h.admitted(w, r, PathPassword, humansession.TextRequestNotPerformed) {
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

// passwordEnrollForm — форма заведения первого пароля (A7 Р1): закрытый набор.
type passwordEnrollForm struct {
	NewPassword string `json:"newPassword"`
	CSRFToken   string `json:"csrfToken"`
}

// enrollPassword — заведение первого пароля из живой сессии (kaname#213):
// форма → признак своего вида → положение подтверждения → поле → глагол.
// Ответ — сессия как есть, БЕЗ Set-Cookie: глагол носитель не перевыпускает
// (A7 Р5, Р6).
func (h *Handler) enrollPassword(w http.ResponseWriter, r *http.Request) {
	var form passwordEnrollForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormPasswordEnroll, form.CSRFToken) {
		return
	}
	if !h.admitted(w, r, PathPasswordEnroll, humansession.TextRequestNotPerformed) {
		return
	}
	if err := requireFields(map[string]string{"newPassword": form.NewPassword}); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	out, err := h.lane.EnrollPassword(r.Context(), humansession.EnrollPasswordInput{
		Bearer: h.bearer(r), NewPassword: form.NewPassword,
	})
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": sessionJSON(out.View)})
}

// requestRecovery — запрос кода восстановления (Ф5-01, Ф5-02). Ответ ОДИН при
// любом исходе — `200 {}` без печений: сессии нет, контекст формы прежний;
// исход глагол не сообщает и постановки письма не ждёт (Р2).
func (h *Handler) requestRecovery(w http.ResponseWriter, r *http.Request) {
	var form recoveryRequestForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormRecovery, form.CSRFToken) {
		return
	}
	if err := requireFields(map[string]string{"email": form.Email}); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if err := h.lane.RequestRecovery(r.Context(), humansession.RequestRecoveryInput{
		Email: form.Email, Source: h.source(r),
	}); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{})
}

// completeRecovery — предъявление кода с новым паролем (Ф5-03…08, Ф5-17):
// успех отвечает как вход — тело Ф3-01, носитель сессии и НОВЫЙ контекст формы
// (Р12); отказ — фиксированным текстом без Set-Cookie.
func (h *Handler) completeRecovery(w http.ResponseWriter, r *http.Request) {
	var form recoveryCompleteForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormRecoveryComplete, form.CSRFToken) {
		return
	}
	if err := requireFields(map[string]string{"email": form.Email, "code": form.Code, "newPassword": form.NewPassword}); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	out, err := h.lane.CompleteRecovery(r.Context(), humansession.CompleteRecoveryInput{
		Email: form.Email, Code: form.Code, NewPassword: form.NewPassword, Source: h.source(r),
		Client: h.client(r),
	})
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
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

// --- второй фактор (Ф12 Р4) ---

// parseSecondFactorField — способ и форма кода (Н12) судятся ДО глагола, с
// именем поля: у вложенного объекта — `<prefix>.method` / `<prefix>.code`, у
// плоской формы (пустой prefix) — `method` / `code`.
func parseSecondFactorField(prefix string, f secondFactorField) (humansession.SecondFactorPresentation, error) {
	field := func(name string) string {
		if prefix == "" {
			return name
		}
		return prefix + "." + name
	}
	method, err := humansession.ParseSecondFactorMethod(field("method"), f.Method)
	if err != nil {
		return humansession.SecondFactorPresentation{}, err
	}
	p := humansession.SecondFactorPresentation{Method: method, Code: f.Code}
	if err := humansession.JudgeCodeForm(field("code"), p); err != nil {
		return humansession.SecondFactorPresentation{}, err
	}
	return p, nil
}

// enrollSecondFactor — Ф12-01: секрет и адрес показываются один раз, печений
// нет — сессия и контекст прежние.
func (h *Handler) enrollSecondFactor(w http.ResponseWriter, r *http.Request) {
	var form enrollForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormSecondFactor, form.CSRFToken) {
		return
	}
	if !h.admitted(w, r, PathSecondFactorEnroll, humansession.TextRequestNotPerformed) {
		return
	}
	out, err := h.lane.EnrollSecondFactor(r.Context(), humansession.EnrollInput{Bearer: h.bearer(r)})
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":     out.Secret.Base32(),
		"otpauthUri": out.OtpauthURI,
		"expiresAt":  out.ExpiresAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	})
}

// confirmSecondFactor — Ф12-02: коды один раз; предъявление — новый носитель.
func (h *Handler) confirmSecondFactor(w http.ResponseWriter, r *http.Request) {
	var form confirmForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormSecondFactor, form.CSRFToken) {
		return
	}
	if !h.admitted(w, r, PathSecondFactorConfirm, humansession.TextRequestNotPerformed) {
		return
	}
	if err := requireFields(map[string]string{"code": form.Code}); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	out, err := h.lane.ConfirmSecondFactor(r.Context(), humansession.ConfirmInput{
		Bearer: h.bearer(r), Code: form.Code, Source: h.source(r),
	})
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	http.SetCookie(w, h.sessionCookie(out.Bearer))
	writeJSON(w, http.StatusOK, map[string]any{
		"backupCodes": out.BackupCodes,
		"session":     sessionJSON(out.View),
		"assurance":   assuranceJSON(out.Assurance),
	})
}

// secondFactorStatus — чтение состояния (Р4): без признака; две формы тела —
// `pending` и `active`; ключ `backupCodes` — только у заведённого.
func (h *Handler) secondFactorStatus(w http.ResponseWriter, r *http.Request) {
	if !h.admitted(w, r, PathSecondFactor, humansession.TextRequestNotPerformed) {
		return
	}
	out, err := h.lane.SecondFactorStatus(r.Context(), humansession.StatusInput{Bearer: h.bearer(r)})
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	totp := map[string]any{"enrolled": out.TOTPEnrolled}
	switch {
	case out.TOTPEnrolled:
		totp["confirmedAt"] = out.ConfirmedAt.UTC().Truncate(time.Second).Format(time.RFC3339)
	case !out.PendingUntil.IsZero():
		totp["pendingUntil"] = out.PendingUntil.UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	body := map[string]any{"totp": totp}
	if out.BackupCodes != nil {
		body["backupCodes"] = map[string]any{"remaining": out.BackupCodes.Remaining, "total": out.BackupCodes.Total}
	}
	writeJSON(w, http.StatusOK, body)
}

// removeSecondFactor — Ф12-28: подтверждение кодом, ответ как у церемонии.
func (h *Handler) removeSecondFactor(w http.ResponseWriter, r *http.Request) {
	var form confirmedForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormSecondFactor, form.CSRFToken) {
		return
	}
	if !h.admitted(w, r, PathSecondFactorRemove, humansession.TextRequestNotPerformed) {
		return
	}
	factor, err := parseSecondFactorField("", secondFactorField{Method: form.Method, Code: form.Code})
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	out, err := h.lane.RemoveSecondFactor(r.Context(), humansession.RemoveSecondFactorInput{
		Bearer: h.bearer(r), Factor: factor, Source: h.source(r),
	})
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	http.SetCookie(w, h.sessionCookie(out.Bearer))
	body := map[string]any{"session": sessionJSON(out.View), "assurance": assuranceJSON(out.Assurance)}
	if out.BackupCodesRemaining != nil {
		body["backupCodesRemaining"] = *out.BackupCodesRemaining
	}
	writeJSON(w, http.StatusOK, body)
}

// regenerateBackupCodes — Ф12-25: новый набор один раз, ответ как у церемонии.
func (h *Handler) regenerateBackupCodes(w http.ResponseWriter, r *http.Request) {
	var form confirmedForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormSecondFactor, form.CSRFToken) {
		return
	}
	if !h.admitted(w, r, PathSecondFactorBackupCodes, humansession.TextRequestNotPerformed) {
		return
	}
	factor, err := parseSecondFactorField("", secondFactorField{Method: form.Method, Code: form.Code})
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	out, err := h.lane.RegenerateBackupCodes(r.Context(), humansession.RegenerateBackupCodesInput{
		Bearer: h.bearer(r), Factor: factor, Source: h.source(r),
	})
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	http.SetCookie(w, h.sessionCookie(out.Bearer))
	writeJSON(w, http.StatusOK, map[string]any{
		"backupCodes": out.BackupCodes,
		"session":     sessionJSON(out.View),
		"assurance":   assuranceJSON(out.Assurance),
	})
}

// stepUp — церемония повышения (Ф11-08, Ф12-15…19): способ называет клиент из
// словаря Ф11 Р8; поля, не относящиеся к способу, судит глагол.
func (h *Handler) stepUp(w http.ResponseWriter, r *http.Request) {
	var form stepUpForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormStepUp, form.CSRFToken) {
		return
	}
	if !h.admitted(w, r, PathStepUp, humansession.TextRequestNotPerformed) {
		return
	}
	method, err := humansession.ParseStepUpMethod("method", form.Method)
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	in := humansession.StepUpInput{Bearer: h.bearer(r), Method: method, Password: form.Password, Code: form.Code, Source: h.source(r)}
	if err := humansession.JudgeStepUpForm(in); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	out, err := h.lane.StepUp(r.Context(), in)
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	http.SetCookie(w, h.sessionCookie(out.Bearer))
	body := map[string]any{"session": sessionJSON(out.View), "assurance": assuranceJSON(out.Assurance)}
	if out.BackupCodesRemaining != nil {
		body["backupCodesRemaining"] = *out.BackupCodesRemaining
	}
	writeJSON(w, http.StatusOK, body)
}

// --- подтверждение адреса (kaname#456, Р6) ---

// requestEmailVerification — запрос письма подтверждения: `200 {}` без печений;
// `Retry-After` называет промежуток до следующего разрешённого письма (по нему
// экран ведёт отсчёт, своих правил у него нет).
func (h *Handler) requestEmailVerification(w http.ResponseWriter, r *http.Request) {
	var form verifyEmailForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormVerifyEmail, form.CSRFToken) {
		return
	}
	out, err := h.lane.RequestEmailVerification(r.Context(), h.bearer(r))
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(retryAfterSeconds(out.NextAllowedIn))))
	writeJSON(w, http.StatusOK, map[string]any{})
}

// confirmEmailVerification — предъявление кода: успех — тело `session` с
// `emailVerified: true` и НОВЫЙ носитель той же сессии; контекст формы прежний.
func (h *Handler) confirmEmailVerification(w http.ResponseWriter, r *http.Request) {
	var form verifyEmailConfirmForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormVerifyEmailConfirm, form.CSRFToken) {
		return
	}
	out, err := h.lane.ConfirmEmailVerification(r.Context(), humansession.ConfirmVerificationInput{
		Bearer: h.bearer(r), Code: form.Code,
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

// client — описание клиента выдающего запроса (kaname#634, Р3): значение
// заголовка, как его доставил край, приведённое типом домена (замена байтов вне
// UTF-8, предел 512 рун). Нет заголовка либо он пуст — описания нет. Приведение
// не отказывает и исхода глагола не меняет.
func (h *Handler) client(r *http.Request) domain.ClientDescription {
	return domain.NewClientDescription(r.Header.Get(HeaderUserAgent))
}

// --- свои сессии (kaname#634) ---

// ownSessionsQuery — параметры перечня из строки запроса (Р1, Р4): набор
// закрыт — лишний параметр называется отказом; повтор параметра — отказ, а не
// выбор одного из значений. Судится ДО любого чтения хранилища.
func ownSessionsQuery(r *http.Request) (humansession.OwnSessionsPage, error) {
	q := r.URL.Query()
	names := make([]string, 0, len(q))
	for name := range q {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		switch name {
		case humansession.OwnSessionsPageSizeParam, humansession.OwnSessionsPageTokenParam:
			if len(q[name]) != 1 {
				return humansession.OwnSessionsPage{}, &humansession.FieldError{Field: name, Rule: "must be given once"}
			}
		default:
			return humansession.OwnSessionsPage{}, &humansession.FieldError{Field: name, Rule: "unknown field"}
		}
	}
	_, sizeGiven := q[humansession.OwnSessionsPageSizeParam]
	return humansession.ParseOwnSessionsPage(q.Get(humansession.OwnSessionsPageSizeParam), sizeGiven,
		q.Get(humansession.OwnSessionsPageTokenParam))
}

// ownSessions — перечень своих живых сессий (Р4): параметры → положение →
// глагол. Признака не требует (чтение, как состояние второго фактора).
func (h *Handler) ownSessions(w http.ResponseWriter, r *http.Request) {
	page, err := ownSessionsQuery(r)
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.admitted(w, r, PathSessions, humansession.TextRequestNotPerformed) {
		return
	}
	out, err := h.lane.ListOwnSessions(r.Context(), humansession.ListOwnSessionsInput{Bearer: h.bearer(r), Page: page})
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	items := make([]map[string]any, 0, len(out.Sessions))
	for _, s := range out.Sessions {
		items = append(items, ownSessionJSON(s))
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": items, "nextPageToken": out.NextPageToken})
}

// endOwnSession — выход из выбранной (Р5): форма → признак `session-end` →
// поле `sessionId` и его форма → положение → глагол. Ответ без Set-Cookie:
// носитель текущей записи не перевыпускается (Р6).
func (h *Handler) endOwnSession(w http.ResponseWriter, r *http.Request) {
	var form endOwnSessionForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormSessionEnd, form.CSRFToken) {
		return
	}
	if form.SessionID == "" {
		h.writeError(w, humansession.FieldRequired("sessionId"), humansession.TextRequestNotPerformed)
		return
	}
	id, ok := domain.ParseHumanSessionID(form.SessionID)
	if !ok {
		h.writeError(w, &humansession.FieldError{Field: "sessionId", Rule: domain.TextHumanSessionIDRule},
			humansession.TextRequestNotPerformed)
		return
	}
	if !h.admitted(w, r, PathSessionsEnd, humansession.TextRequestNotPerformed) {
		return
	}
	if _, err := h.lane.EndOwnSession(r.Context(), humansession.EndOwnSessionInput{Bearer: h.bearer(r), SessionID: id}); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ended": true})
}

// endOtherOwnSessions — выход из всех, кроме текущей (Р7): форма → признак →
// положение → глагол; ответ — число снятых, без Set-Cookie.
func (h *Handler) endOtherOwnSessions(w http.ResponseWriter, r *http.Request) {
	var form endOtherOwnSessionsForm
	if err := decodeForm(r, &form); err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	if !h.judgeForm(w, r, domain.FormSessionEnd, form.CSRFToken) {
		return
	}
	if !h.admitted(w, r, PathSessionsEndOthers, humansession.TextRequestNotPerformed) {
		return
	}
	out, err := h.lane.EndOtherOwnSessions(r.Context(), humansession.EndOtherOwnSessionsInput{Bearer: h.bearer(r)})
	if err != nil {
		h.writeError(w, err, humansession.TextRequestNotPerformed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ended": out.Ended})
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

// assuranceJSON — объект `assurance` ответа церемонии (Р4): два поля, два
// факта; `missingForLevel2` — всегда массив.
func assuranceJSON(a humansession.AssuranceView) map[string]any {
	missing := a.MissingForLevel2
	if missing == nil {
		missing = []string{}
	}
	return map[string]any{"level": a.Level, "level2Reachable": a.Level2Reachable, "missingForLevel2": missing}
}

// ownSessionJSON — элемент перечня своих сессий (Р4): набор ключей закрыт;
// `userAgent` — только у записи, чей выдающий запрос назвал клиента (Р3):
// отсутствие — отсутствие ключа, а не пустая строка. Моменты — до секунды.
func ownSessionJSON(s humansession.OwnSession) map[string]any {
	out := map[string]any{
		"id":              string(s.Session.ID),
		"current":         s.Current,
		"authenticatedAt": s.Session.AuthenticatedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		"lastPresentedAt": s.Session.LastPresentedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		"expiresAt":       s.Session.ExpiresAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	if !s.Session.Client.IsZero() {
		out["userAgent"] = s.Session.Client.Value()
	}
	return out
}

func sessionJSON(v humansession.SessionView) map[string]any {
	return map[string]any{
		// Срок — до секунды (конвенция); сравнивает его служба, не клиент.
		"expiresAt":      v.Session.ExpiresAt.UTC().Truncate(time.Second).Format(time.RFC3339),
		"assuranceLevel": v.Session.AssuranceLevel,
		"emailVerified":  v.EmailVerified,
	}
}

// ResponseObjectKeys — ключи объектов тела ответа полосы по имени объекта,
// снятые с САМИХ производителей тел, а не выписанные: клиентская страница
// сверяет с ними ключи своих примеров (kaname#247), и второй перечень разошёлся
// бы с производителем молча — ровно так пример пережил снятое поле.
func ResponseObjectKeys() map[string][]string {
	keysOf := func(m map[string]any) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return map[string][]string{
		"user":      keysOf(userJSON(humansession.SessionView{})),
		"session":   keysOf(sessionJSON(humansession.SessionView{})),
		"assurance": keysOf(assuranceJSON(humansession.AssuranceView{})),
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
	case errors.Is(err, registration.ErrRefused):
		// ОДИН отказ на занятость адреса и потолок темпа (Ф4 Р3): состояние не
		// позволяет, а какое — не говорится. Ни Retry-After, ни 409: и то и
		// другое было бы оракулом.
		writeRefusal(w, http.StatusBadRequest, codeFailedPrecondition, registration.TextRegistrationRefused,
			&errorInfo{Reason: registration.ReasonRegistrationRefused, Domain: h.cfg.RefusalDomain})
	case errors.Is(err, humansession.ErrFormTokenRejected):
		writeRefusal(w, http.StatusForbidden, codePermissionDenied, humansession.TextFormTokenRejected,
			&errorInfo{Reason: humansession.ReasonFormTokenRejected, Domain: h.cfg.RefusalDomain})
	// Второй фактор (Ф12 Р4): состояние — 400 с токеном; «уже заведён» —
	// 409; свежесть — 403 с токеном; материал не открылся — 503 своим текстом.
	case errors.Is(err, humansession.ErrSecondFactorNotEnrolled):
		writeRefusal(w, http.StatusBadRequest, codeFailedPrecondition, humansession.TextSecondFactorNotEnrolled,
			&errorInfo{Reason: humansession.ReasonSecondFactorNotEnrolled, Domain: h.cfg.RefusalDomain})
	case errors.Is(err, humansession.ErrEnrollmentNotPending):
		writeRefusal(w, http.StatusBadRequest, codeFailedPrecondition, humansession.TextEnrollmentNotPending,
			&errorInfo{Reason: humansession.ReasonEnrollmentNotPending, Domain: h.cfg.RefusalDomain})
	case errors.Is(err, humansession.ErrPasswordAlreadySet):
		writeRefusal(w, http.StatusConflict, codeAlreadyExists, humansession.TextPasswordAlreadySet,
			&errorInfo{Reason: humansession.ReasonPasswordAlreadySet, Domain: h.cfg.RefusalDomain})
	case errors.Is(err, humansession.ErrSecondFactorAlreadyEnrolled):
		writeRefusal(w, http.StatusConflict, codeAlreadyExists, humansession.TextSecondFactorAlreadyEnrolled,
			&errorInfo{Reason: humansession.ReasonSecondFactorAlreadyEnrolled, Domain: h.cfg.RefusalDomain})
	case errors.Is(err, humansession.ErrSessionNotFresh):
		writeRefusal(w, http.StatusForbidden, codePermissionDenied, humansession.TextSessionNotFresh,
			&errorInfo{Reason: humansession.ReasonSessionNotFresh, Domain: h.cfg.RefusalDomain})
	// Подтверждение адреса (kaname#456, Р6, Р11, Р15): состояние — 400 с
	// признаком; отказ положения — значение Р3.
	case errors.Is(err, humansession.ErrEmailAlreadyVerified):
		writeRefusal(w, http.StatusBadRequest, codeFailedPrecondition, humansession.TextEmailAlreadyVerified,
			&errorInfo{Reason: humansession.ReasonEmailAlreadyVerified, Domain: h.cfg.RefusalDomain})
	case errors.Is(err, humansession.ErrInviteNotValid):
		writeRefusal(w, http.StatusBadRequest, codeFailedPrecondition, humansession.TextInviteNotValid,
			&errorInfo{Reason: humansession.ReasonInviteNotValid, Domain: h.cfg.RefusalDomain})
	case errors.Is(err, humansession.ErrEmailNotVerified):
		writeRefusal(w, http.StatusForbidden, codePermissionDenied, humansession.TextEmailNotVerified,
			&errorInfo{Reason: humansession.ReasonEmailNotVerified, Domain: h.cfg.RefusalDomain})
	// Свои сессии (kaname#634, Р5): названная запись — не живая своя — 404
	// одним текстом, без идентификатора; названа текущая — 400 состояния.
	case errors.Is(err, humansession.ErrSessionNotFound):
		writeRefusal(w, http.StatusNotFound, codeNotFound, humansession.TextSessionNotFound,
			&errorInfo{Reason: humansession.ReasonSessionNotFound, Domain: h.cfg.RefusalDomain})
	case errors.Is(err, humansession.ErrSessionIsCurrent):
		writeRefusal(w, http.StatusBadRequest, codeFailedPrecondition, humansession.TextSessionIsCurrent,
			&errorInfo{Reason: humansession.ReasonSessionIsCurrent, Domain: h.cfg.RefusalDomain})
	case errors.Is(err, humansession.ErrSecondFactorUnavailable):
		writeRefusal(w, http.StatusServiceUnavailable, codeUnavailable, humansession.TextSecondFactorUnavailable, nil)
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
	codeInvalidArgument    = 3
	codeNotFound           = 5
	codeAlreadyExists      = 6
	codePermissionDenied   = 7
	codeResourceExhausted  = 8
	codeFailedPrecondition = 9
	codeUnavailable        = 14
	codeUnauthenticated    = 16
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
