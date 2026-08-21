// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package clienttokenhttp — токен-эндпоинт платформы (задача #898, приёмка F2
// §9.1 п. 1).
//
// Клиент предъявляет подписанное утверждение, мы сверяем подпись его открытым
// ключом из своей же таблицы и выдаём токен доступа по виду выдачи «учётные
// данные клиента». Форма запроса и форма ответа — стандартные (RFC 6749 §4.4,
// RFC 7523 §2.2): предъявитель — чужая библиотека, и ответ обязан быть тем,
// который она умеет прочитать, иначе отказ выглядит для неё сбоем сети.
//
// # Единый тон наружу и различимость внутрь
//
// Всякий отказ, наступивший ПОСЛЕ того, как в запросе назван клиент — включая
// «такого клиента нет», — отдаёт побайтово ОДНО И ТО ЖЕ. Различимый отказ есть
// оракул: по нему устанавливают, существует ли клиент, жив ли он, какой у него
// алгоритм и какие идентификаторы однократности уже заняты. Каждый ответ сам по
// себе безобиден, а вместе они дают карту.
//
// Различимыми остаются ровно ПЯТЬ отказов, и все пять решаются ДО того, как
// запрос назвал хоть какого-нибудь клиента: метод, потолок тела, неразбираемая
// форма, вид выдачи вне перечня и повторённый параметр утверждения. Они не
// сообщают о клиенте ничего, потому что клиента на этом шаге ещё нет, и
// стандартные коды у них обязаны быть свои — иначе чужая библиотека прочтёт
// «слишком большое тело» как «неверный клиент» и будет чинить не то.
//
// Различимость для НАС живёт с другой стороны провода: у каждого исхода свой
// счётчик и своя запись в журнале. Без счётчика мёртвый контроль невидим —
// проверка, не отказавшая ни разу за всё время жизни, неотличима от проверки,
// которая работает и просто не встречала нарушителя.
package clienttokenhttp

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/PRO-Robotech/kacho/pkg/httpbody"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/client_token"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clientassertion"
	"github.com/PRO-Robotech/kacho/services/iam/internal/tokensigner"
)

// TokenPath — объявленный путь эндпоинта.
const TokenPath = "/iam/v1/token"


// Verifier — порт проверяющего утверждение.
type Verifier interface {
	Verify(ctx context.Context, assertionType, raw string) (clientassertion.Result, error)
}

// Issuer — порт выдачи.
type Issuer interface {
	Issue(ctx context.Context, in client_token.Input) (client_token.Output, clientassertion.Outcome, error)
}

// Config — настройка эндпоинта.
type Config struct {
	// BodyCeiling — потолок тела запроса в байтах. ОБЯЗАТЕЛЕН.
	//
	// Умолчания здесь нет намеренно. Величина, которую построение подставляет
	// молча, не может быть предметом стража старта: страж, требующий её
	// задания, зелен при любом входе, потому что незаданной она не бывает. Тело
	// этого запроса — форма с одним подписанным утверждением, и его потолок
	// объявляет тот, кто поднимает сервис.
	BodyCeiling int64
	Logger      *slog.Logger
}

// Handler — токен-эндпоинт.
type Handler struct {
	cfg      Config
	verifier Verifier
	issuer   Issuer

	// mu защищает перепись исходов. Счётчики читаются сборщиком метрик, и
	// карта под конкурентной записью без него разъехалась бы молча.
	mu       sync.Mutex
	outcomes map[clientassertion.Outcome]uint64
}

// NewHandler строит эндпоинт. Неполная провязка — отказ построения: эндпоинт
// без проверяющего принимал бы кого угодно, без выдачи — не выдавал бы никому,
// и оба состояния обнаружились бы на первом запросе, а не на старте.
func NewHandler(cfg Config, verifier Verifier, issuer Issuer) (*Handler, error) {
	if verifier == nil {
		return nil, errRequired("verifier")
	}
	if issuer == nil {
		return nil, errRequired("issuer")
	}
	if cfg.BodyCeiling <= 0 {
		return nil, errRequired("body ceiling")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	h := &Handler{cfg: cfg, verifier: verifier, issuer: issuer,
		outcomes: make(map[clientassertion.Outcome]uint64, len(clientassertion.Outcomes()))}
	// Перепись заводится ЦЕЛИКОМ по закрытому словарю, а не по мере
	// встречаемости: счётчик, появляющийся при первом отказе, не отличает
	// «ноль отказов» от «исход без счётчика».
	for _, o := range clientassertion.Outcomes() {
		h.outcomes[o] = 0
	}
	return h, nil
}

type requiredError string

func (e requiredError) Error() string { return "clienttokenhttp: " + string(e) + " is required" }
func errRequired(what string) error   { return requiredError(what) }

// NewMux монтирует эндпоинт на объявленный путь и НИ НА КАКОЙ другой.
//
// Перечень путей выводится из этой функции, а не выписывается: утверждение о
// единственном маршруте оставалось бы зелёным, уедь второй не туда.
func NewMux(h http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	if h != nil {
		mux.Handle(TokenPath, h)
	}
	return mux
}

// Outcomes — перепись исходов. Читается сборщиком метрик.
func (h *Handler) Outcomes() map[clientassertion.Outcome]uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[clientassertion.Outcome]uint64, len(h.outcomes))
	for k, v := range h.outcomes {
		out[k] = v
	}
	return out
}

func (h *Handler) count(o clientassertion.Outcome) {
	h.mu.Lock()
	h.outcomes[o]++
	h.mu.Unlock()
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// (1) Метод. Ответ несёт перечень допустимых — иначе клиент не узнает, чем
	// именно он ошибся, и будет считать эндпоинт сломанным.
	if r.Method != http.MethodPost {
		h.count(clientassertion.OutcomeMethodNotAllowed)
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("invalid_request"))
		return
	}

	// (2) Потолок тела — ДО чтения. Объявленная длина сверх потолка отвергается
	// так, что ни одного байта тела не прочитано: отказ, выданный после
	// разбора, память уже не экономит.
	if httpbody.Cap(w, r, h.cfg.BodyCeiling) {
		h.count(clientassertion.OutcomeBodyAboveCeiling)
		writeJSON(w, http.StatusRequestEntityTooLarge, errorBody("invalid_request"))
		return
	}

	if err := r.ParseForm(); err != nil {
		h.count(clientassertion.OutcomeMalformedRequest)
		writeJSON(w, http.StatusBadRequest, errorBody("invalid_request"))
		return
	}

	// (3) Вид выдачи — из ЗАКРЫТОГО перечня. «Прочее» не является корзиной
	// приёма.
	if r.PostForm.Get("grant_type") != tokenpolicy.GrantTypeClientCredentials {
		h.count(clientassertion.OutcomeUnsupportedGrantType)
		writeJSON(w, http.StatusBadRequest, errorBody("unsupported_grant_type"))
		return
	}

	// (4) Ровно ОДНО утверждение и ровно ОДИН объявленный вид предъявления.
	// Это требование к НАШЕМУ разбору, а не описание намерения клиента: форма
	// позволяет прислать параметр дважды, и разбор, берущий первое значение,
	// проверил бы не то, что подписал предъявитель.
	assertionValues := r.PostForm["client_assertion"]
	typeValues := r.PostForm["client_assertion_type"]
	if len(assertionValues) != 1 || len(typeValues) != 1 {
		// Отказ наступает ДО проверки подписи любого из значений.
		h.count(clientassertion.OutcomeMultipleAssertions)
		writeJSON(w, http.StatusBadRequest, errorBody("invalid_request"))
		return
	}

	// (5) Аутентификация. Всё, что ниже, отдаёт наружу ОДНО И ТО ЖЕ.
	res, err := h.verifier.Verify(r.Context(), typeValues[0], assertionValues[0])
	if err != nil {
		h.refuse(r, res.Outcome, err)
		writeJSON(w, http.StatusUnauthorized, errorBody(res.PresenterResponse()))
		return
	}

	// (6) Выдача.
	out, outcome, err := h.issuer.Issue(r.Context(), client_token.Input{
		Client:            res.Client,
		RequestedAudience: r.PostForm["audience"],
		Scope:             strings.TrimSpace(r.PostForm.Get("scope")),
		Confirmation:      confirmationFrom(r),
	})
	if err != nil {
		h.refuse(r, outcome, err)
		writeJSON(w, http.StatusUnauthorized, errorBody(clientassertion.PresenterResponseFor(outcome)))
		return
	}

	h.count(clientassertion.OutcomeAccepted)
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": out.AccessToken,
		"token_type":   out.TokenType,
		"expires_in":   out.ExpiresIn,
		"scope":        out.Scope,
	})
}

// refuse записывает отказ туда, где различимость ЗАКОННА.
//
// Ни предъявленное утверждение целиком, ни ключевой материал сюда не попадают:
// утверждение — подписанный материал, из которого восстанавливается
// предъявление, и запись его в журнал делает журнал носителем предъявительского
// документа.
func (h *Handler) refuse(r *http.Request, outcome clientassertion.Outcome, err error) {
	h.count(outcome)
	h.cfg.Logger.Warn("client authentication refused",
		slog.String("outcome", string(outcome)),
		slog.String("path", r.URL.Path),
		slog.String("err", err.Error()))
}

// confirmationFrom читает привязку из ПРЕДЪЯВЛЕННОГО при выдаче материала.
//
// Сегодня доказательство владения на этот путь не приезжает: его предъявляют на
// транспорте, а не полем формы. Функция существует одним местом, чтобы
// привязка, когда она появится, бралась ОТСЮДА, а не выдумывалась подписантом,
// — и чтобы «привязки не запрашивали» было выражено, а не подразумевалось.
func confirmationFrom(*http.Request) *tokensigner.Confirmation { return nil }

func errorBody(code string) map[string]any { return map[string]any{"error": code} }

func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	// Токен-эндпоинт не кэшируется: ответ несёт предъявительский документ.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
