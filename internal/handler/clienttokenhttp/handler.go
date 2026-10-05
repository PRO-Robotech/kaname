// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
// Различимыми остаются ровно ПЯТЬ отказов формы, и все пять решаются ДО того,
// как запрос назвал хоть какого-нибудь клиента: метод, потолок тела,
// неразбираемая форма, вид выдачи вне перечня и повторённый параметр
// утверждения. Они не сообщают о клиенте ничего, потому что клиента на этом шаге
// ещё нет, и стандартные коды у них обязаны быть свои — иначе чужая библиотека
// прочтёт «слишком большое тело» как «неверный клиент» и будет чинить не то.
//
// # Три отказа по темпу — тоже свои (kaname#315)
//
// Приёмка `docs/engineering/acceptance/ceremony-pace-is-named-by-number.md`
// называет на этом эндпоинте три оси:
//
//   - П3 — неудавшихся доказательств клиента за окно на источник: источник
//     прислал слишком много, 429 со сроком до момента, когда в окне останется
//     предел минус один отказ;
//   - П1 — потолок одновременных обменов, все четыре вида выдачи: занята НАША
//     ёмкость, и занял её не обязательно этот вызывающий, — 503 и
//     `Retry-After: 1`, та же форма, что у занятого проверяющего секрета
//     церемонии;
//   - П2 — темп обменов на идентификатор клиента, только машинные полосы: судит
//     проверяющий по ЗАЯВЛЕННОМУ идентификатору до реестра, 429.
//
// Ни одна не сливается с отказом аутентификации: слитая, она заставила бы
// клиента чинить учётные данные, которые исправны. Все три решаются ДО
// обращения к реестру и потому о записи реестра не сообщают ничего.
//
// # Порядок решений — несущий (Р3)
//
// Метод → потолок тела → разбор формы → вид выдачи из закрытого перечня → П3 →
// П1 → полоса. Отказы формы решаются до всех осей и остаются различимыми: ось
// темпа не прячет «неверный метод» под «повторите позже». Источник, исчерпавший
// П3, места под потолком не занимает. П3 решается при входе по счёту, набранному
// к этому моменту, а растёт по исходу — отказом доказательства клиента (Р5):
// на машинных полосах это отказ проверяющего, кроме двух исходов нашей стороны
// (`registry-unavailable`, `replay-store-unavailable`) и отказов формы и темпа;
// на полосах церемонии — `invalid_client`, о котором сообщает полоса
// ([LaneVerdict]).
//
// Различимость для НАС живёт с другой стороны провода: у каждого исхода свой
// счётчик и своя запись в журнале. Без счётчика мёртвый контроль невидим —
// проверка, не отказавшая ни разу за всё время жизни, неотличима от проверки,
// которая работает и просто не встречала нарушителя.
package clienttokenhttp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PRO-Robotech/corelib/httpbody"
	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/client_token"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/failurewindow"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// TokenPath — объявленный путь эндпоинта.
//
// #nosec G101 -- это АДРЕС поверхности, а не учётные данные: строка попадает в
// маршрут и в документацию клиента, её знает всякий, кто обращается к сервису.
// Слово в адресе называет предмет выдачи, а не хранимый секрет.
const TokenPath = "/iam/v1/token"

// Verifier — порт проверяющего утверждение, ОБЕ полосы.
//
// Один порт на две полосы, а не два: эндпоинт обязан выбирать полосу сам, по
// объявленному виду выдачи. Разнеси их по двум портам — и появилась бы посадка,
// где провязана одна, а вторая молча отвергает всё.
type Verifier interface {
	// Verify — полоса аутентификации клиента (RFC 7523 §2.2): утверждение
	// доказывает личность клиента, ключ берётся из строки реестра.
	Verify(ctx context.Context, assertionType, raw string) (clientassertion.Result, error)
	// VerifyFederated — федеративная полоса (RFC 7523 §2.1): утверждение
	// подписал внешний издатель, ключ берётся из нашего перечня доверенных
	// издателей.
	VerifyFederated(ctx context.Context, raw string) (clientassertion.Result, error)
}

// Issuer — порт выдачи.
type Issuer interface {
	Issue(ctx context.Context, in client_token.Input) (client_token.Output, clientassertion.Outcome, error)
}

// CeremonyLane — полосы церемонии OAuth на этом же эндпоинте:
// `authorization_code` и `refresh_token` (приёмка LINE-A-1, группы B и G).
//
// Эндпоинт судит метод, потолок тела и разбор формы для ВСЕХ полос, а вид
// выдачи — по закрытому перечню: машинные полосы названы поимённо ниже, полосы
// церемонии — словом церемонии (Grants). Полоса получает разобранную форму.
// Реализует `ceremonyhttp.TokenLane`.
type CeremonyLane interface {
	// Grants — виды выдачи, которые обслуживает полоса.
	Grants() []string
	// ServeGrant отвечает на запрос вида grant.
	ServeGrant(w http.ResponseWriter, r *http.Request, grant string) LaneVerdict
}

// LaneVerdict — что полоса церемонии сообщает эндпоинту о доказательстве
// клиента. Судит по нему ось П3: засчитывается отказ доказательства клиента, а
// не всякий отказ обмена (приёмка Р5).
type LaneVerdict uint8

const (
	// LaneProofNotRefused — доказательство клиента не отвергнуто: принято либо
	// до него не дошло (отказ формы). `invalid_grant` сюда же: его производит
	// клиент, уже доказавший себя.
	LaneProofNotRefused LaneVerdict = iota
	// LaneProofRefused — отвергнуто доказательство клиента: `invalid_client`.
	LaneProofRefused
)

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
	// InFlightCeiling — потолок одновременных обменов на этом процессе (П1),
	// все четыре вида выдачи. ОБЯЗАТЕЛЕН по тому же доводу, что потолок тела:
	// ноль означал бы «без потолка», а величина, подставленная построением,
	// стражу старта не видна.
	//
	// Обмен сверх потолка отвергается сразу, а не ждёт места: ожидание держало
	// бы соединение и горутину ровно тогда, когда их и так слишком много.
	InFlightCeiling int
	Logger          *slog.Logger
	// Ceremony — полосы церемонии. nil — церемония не собрана (сборка мимо
	// корня либо выключенный вне боевого режима эндпоинт), и её виды выдачи —
	// вне перечня.
	Ceremony CeremonyLane
	// FailedProofs — окно отказов доказательства клиента на источник (П3).
	// ОБЯЗАТЕЛЬНО: эндпоинт без него не решал бы П3 ни разу.
	FailedProofs *failurewindow.Window
	// Source — адрес источника запроса по правилу Р7 (`issuingsource`).
	// ОБЯЗАТЕЛЕН: ключ П3.
	Source func(*http.Request) string
}

// Handler — токен-эндпоинт.
type Handler struct {
	cfg      Config
	verifier Verifier
	issuer   Issuer

	// slots — места одновременных обменов; занятое место — элемент канала.
	slots chan struct{}

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
	if cfg.InFlightCeiling <= 0 {
		return nil, errRequired("in-flight ceiling")
	}
	if cfg.FailedProofs == nil {
		return nil, errRequired("failed-proof window per source")
	}
	if cfg.Source == nil {
		return nil, errRequired("source address rule")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	h := &Handler{cfg: cfg, verifier: verifier, issuer: issuer,
		slots:    make(chan struct{}, cfg.InFlightCeiling),
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

// ВТОРОГО МОНТИРОВЩИКА ЗДЕСЬ НЕТ — снят вместе со своим утверждением
// (kacho#2480, kacho#2504).
//
// Стояла `NewMux`, чей godoc утверждал: «перечень путей выводится из этой
// функции, а не выписывается». Производство её не звало ни разу — композиционный
// корень монтирует маршрут руками, а единственность монтажа держит гейт по
// дереву `TestCeremonySurfaceIsSingularAcrossTheCompositionRoot`
// (`internal/check`): путь резолвится ровно на одной поверхности процесса, и она
// внешняя. То есть перечень выводился не отсюда, а утверждение об обратном
// переживало свой предмет и прикрывало второй монтировщик с единственным
// вызывающим — собственной пробой.
//
// Единственный источник пути остался один: [TokenPath].

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

// DeclaredOutcomes — закрытый словарь исходов этой полосы строками.
//
// Отдаётся наружу ради читателя величин: набор рядов витрины обязан совпадать с
// набором клеток переписи by construction. Выведен из того же [clientassertion.Outcomes],
// которым засеяна перепись, поэтому второй копией словаря не является.
func DeclaredOutcomes() []string {
	declared := clientassertion.Outcomes()
	out := make([]string, 0, len(declared))
	for _, o := range declared {
		out = append(out, string(o))
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
	// приёма: машинные виды названы поимённо, виды церемонии — словом полосы, а
	// всё остальное отвергается здесь.
	grantType := r.PostForm.Get("grant_type")
	ceremonyGrant := h.cfg.Ceremony != nil && slices.Contains(h.cfg.Ceremony.Grants(), grantType)
	if !ceremonyGrant && grantType != tokenpolicy.GrantTypeClientCredentials &&
		grantType != tokenpolicy.GrantTypeJWTBearer {
		h.count(clientassertion.OutcomeUnsupportedGrantType)
		writeJSON(w, http.StatusBadRequest, errorBody("unsupported_grant_type"))
		return
	}

	// (3а) П3 — отказы доказательства клиента с этого источника. Раньше
	// потолка: источник, исчерпавший П3, места под потолком не занимает.
	source := h.cfg.Source(r)
	if after, ok := h.cfg.FailedProofs.Admit(source); !ok {
		h.count(clientassertion.OutcomeSourceFailuresExceeded)
		writeRetryLater(w, after)
		return
	}

	// (3б) П1 — потолок одновременных обменов, все четыре вида выдачи, ДО
	// проверки: всё, что ниже, обращается к хранилищам и сверяет подпись либо
	// секрет, и обмен сверх потолка до этого не доходит.
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		h.count(clientassertion.OutcomeInFlightCeilingReached)
		writeCapacityTaken(w)
		return
	}

	if ceremonyGrant {
		// Полосы церемонии: доказательство клиента, обмен и счёт исходов — у
		// полосы; об отказе доказательства она сообщает, и П3 его засчитывает.
		if h.cfg.Ceremony.ServeGrant(w, r, grantType) == LaneProofRefused {
			h.cfg.FailedProofs.Record(source)
		}
		return
	}

	// (4) Полоса выбирается ВИДОМ ВЫДАЧИ, и формы двух полос не смешиваются.
	//
	// У каждого вида свои параметры: пара `client_assertion` +
	// `client_assertion_type` у аутентификации клиента, одиночный `assertion` у
	// федеративной выдачи. Приняв чужой параметр, эндпоинт позволил бы
	// предъявителю ВЫБИРАТЬ, какой проверкой его проверят, — а проверки эти
	// берут ключ из разных источников: одна из строки реестра, другая из
	// перечня доверенных издателей.
	res, err := h.authenticate(r, grantType)
	if err != nil {
		if res.Outcome == outcomeMalformedGrantForm {
			// Форма запроса, а не отказ аутентификации: подписи здесь ещё
			// никто не проверял, и различимость этого исхода оракулом не
			// является — он говорит о запросе, не о состоянии перечня.
			h.count(clientassertion.OutcomeMultipleAssertions)
			writeJSON(w, http.StatusBadRequest, errorBody("invalid_request"))
			return
		}
		if res.Outcome == clientassertion.OutcomeClientPaceExceeded {
			// (5) Темп заявленного идентификатора: решён проверяющим ДО
			// реестра, поэтому отвечает своим кодом, а не единым тоном отказов
			// аутентификации.
			h.count(clientassertion.OutcomeClientPaceExceeded)
			writeRetryLater(w, res.RetryAfter)
			return
		}
		h.refuse(r, res.Outcome, err)
		if countsAgainstSource(res.Outcome) {
			h.cfg.FailedProofs.Record(source)
		}
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

// outcomeMalformedGrantForm — внутренний признак «форма запроса не та».
//
// Не значение закрытого словаря исходов: у того словаря каждое значение несёт
// СВОЙ счётчик, а этот случай считается уже заведённым счётчиком формы запроса.
// Заведи мы здесь новое значение — оно осталось бы без счётчика, и мёртвый
// контроль снова стал бы невидимым.
const outcomeMalformedGrantForm clientassertion.Outcome = "\x00malformed-grant-form"

// authenticate выбирает полосу по виду выдачи и проверяет утверждение.
//
// Возвращает outcomeMalformedGrantForm, когда форма запроса не соответствует
// объявленному виду выдачи: до проверки подписи дело в этом случае не доходит.
func (h *Handler) authenticate(r *http.Request, grantType string) (clientassertion.Result, error) {
	switch grantType {
	case tokenpolicy.GrantTypeJWTBearer:
		// Параметры полосы клиента здесь не принимаются вовсе.
		if len(r.PostForm["client_assertion"]) != 0 || len(r.PostForm["client_assertion_type"]) != 0 {
			return clientassertion.Result{Outcome: outcomeMalformedGrantForm},
				errFormMismatch
		}
		// Ровно ОДНО утверждение: форма позволяет прислать параметр дважды, и
		// разбор, берущий первое значение, проверил бы не то, что подписал
		// предъявитель.
		values := r.PostForm["assertion"]
		if len(values) != 1 {
			return clientassertion.Result{Outcome: outcomeMalformedGrantForm}, errFormMismatch
		}
		return h.verifier.VerifyFederated(r.Context(), values[0])

	default: // tokenpolicy.GrantTypeClientCredentials — проверен вызывающим.
		// Зеркально: одиночный параметр федеративной полосы здесь не
		// принимается. Запрет симметричен, потому что и предмет его
		// симметричен: выбирать проверку не вправе ни один вид выдачи.
		if len(r.PostForm["assertion"]) != 0 {
			return clientassertion.Result{Outcome: outcomeMalformedGrantForm}, errFormMismatch
		}
		assertionValues := r.PostForm["client_assertion"]
		typeValues := r.PostForm["client_assertion_type"]
		if len(assertionValues) != 1 || len(typeValues) != 1 {
			return clientassertion.Result{Outcome: outcomeMalformedGrantForm}, errFormMismatch
		}
		return h.verifier.Verify(r.Context(), typeValues[0], assertionValues[0])
	}
}

// countsAgainstSource — засчитывается ли отказ проверяющего в П3 (приёмка Р5).
//
// Отказ доказательства клиента засчитывается; не засчитываются два исхода
// НАШЕЙ стороны — их отвечают тем же `invalid_client`, но причина у нас, и счёт
// наших сбоев против источника заблокировал бы исправных вызывающих после
// восстановления хранилища. Отказы формы и темпа решены до этого места и сюда
// не приходят.
func countsAgainstSource(o clientassertion.Outcome) bool {
	return !clientassertion.OurSide(o)
}

// errFormMismatch — форма запроса не соответствует объявленному виду выдачи.
var errFormMismatch = errors.New("clienttokenhttp: request form does not match the declared grant type")

// refuse записывает отказ туда, где различимость ЗАКОННА.
//
// Ни предъявленное утверждение целиком, ни ключевой материал сюда не попадают:
// утверждение — подписанный материал, из которого восстанавливается
// предъявление, и запись его в журнал делает журнал носителем предъявительского
// документа.
//
// Запись ОДНА на отказ, уровень — по таблице службы
// (`docs/engineering/components/32-observability.md`, «Уровни», kaname#390):
// отклонённое предъявление — WARN; отказ НАШЕЙ стороны
// ([clientassertion.OurSide]: реестр или хранилище однократности не ответили,
// отсечку спросить не удалось, выпуск не состоялся) — ERROR. В одном ряду с
// неверной подписью предъявителя наш сбой терялся бы среди штатных отказов.
func (h *Handler) refuse(r *http.Request, outcome clientassertion.Outcome, err error) {
	h.count(outcome)
	level := slog.LevelWarn
	if clientassertion.OurSide(outcome) {
		level = slog.LevelError
	}
	h.cfg.Logger.LogAttrs(r.Context(), level, "client authentication refused",
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

// writeRetryLater — вызывающий прислал слишком много (П2, П3): 429 и срок
// ожидания целыми секундами, округлённый ВВЕРХ. Повтор, названный раньше, чем
// темп или окно освободится, снова получил бы отказ; ноль секунд значил бы
// «повторите сразу».
func writeRetryLater(w http.ResponseWriter, after time.Duration) {
	secs := int64(math.Ceil(after.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.FormatInt(secs, 10))
	writeJSON(w, http.StatusTooManyRequests, errorBody("temporarily_unavailable"))
}

// writeCapacityTaken — занята наша ёмкость (П1): 503 и `Retry-After: 1` — место
// освобождает любой завершившийся обмен. Та же форма, что у занятого
// проверяющего секрета церемонии на этом эндпоинте: второй формы для «наша
// ёмкость занята» не заводится (приёмка Р2).
func writeCapacityTaken(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeJSON(w, http.StatusServiceUnavailable, errorBody("temporarily_unavailable"))
}

func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	// Токен-эндпоинт не кэшируется: ответ несёт предъявительский документ.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
