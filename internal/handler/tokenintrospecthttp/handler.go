// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tokenintrospecthttp — авторитет отзыва НАШИХ токенов на
// cluster-внутреннем слушателе (задача #897).
//
// # Зачем он существует
//
// Контроль, действующий на ВЫДАЧЕ и не действующий на ПРЕДЪЯВЛЕНИИ, отзывом не
// является: он лишь не выдаёт нового, а предъявленное продолжает проходить до
// истечения срока. Это состояние не сходится само — в отличие от задержки
// распространения, — и потому окно отзыва равнялось бы сроку токена, а не
// сроку, который мы выбрали.
//
// Отсюда: у поверхности, принимающей наш токен, есть читатель отзыва НА ПУТИ
// ЗАПРОСА, и спрашивает он нас. Мы — единственные, кто знает про наши токены:
// прежний провайдер о них не знает by construction, поэтому вопрос ему был бы
// вопросом не про тот предмет.
//
// # Форма ответа выбрана стандартной намеренно
//
// Ответ — тот же документ, которого ждёт всякий, кто умеет спрашивать про
// действительность токена (RFC 7662): `{"active": true|false}`. Своя форма
// заставила бы переписывать каждого спрашивающего и сделала бы будущее решение
// о поверхности решением о переписывании.
//
// # Что этот авторитет НЕ делает
//
// Он не рассказывает, ЧЕМ токен негоден. Наружу уходит суждение, подробность —
// в журнал: различение подсказывало бы предъявителю, какая половина неверна.
package tokenintrospecthttp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/PRO-Robotech/kacho/pkg/httpbody"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/tokenrevocation"
)

// IntrospectPath — путь авторитета на cluster-внутреннем слушателе.
//
// Внутренний по решению, а не по привычке: он принимает предъявленный токен, а
// значит доступен всякому, кто такой токен добыл. Наружу его не выставляем.
const IntrospectPath = "/internal/tokens/introspect"

// maxTokenBytes — потолок принимаемого тела. Компактная подпись нашего токена
// на порядок меньше; потолок стоит, чтобы неограниченное чтение не было
// способом занять процесс.
const maxTokenBytes = 16 << 10

// KeySetSource — источник публикуемого набора: тем же набором, что отдаётся
// потребителям, проверяется и подпись здесь. Один источник, а не второй, —
// иначе авторитет судил бы по другим ключам, чем проверяющий.
type KeySetSource interface {
	PublishedSet(ctx context.Context) ([]domain.PublishedKey, error)
}

// RevocationReader — хранилище отзывов субъектов.
//
// Отвечает «с какого момента токены субъекта недействительны». Отсутствие
// записи — законный ответ «отзыва нет», а НЕ ошибка: пустое обязано означать
// пусто.
type RevocationReader interface {
	RevokedBefore(ctx context.Context, subject string) (time.Time, bool, error)
}

// Config — настройка авторитета.
type Config struct {
	// Issuer — наш издатель. Токен, объявляющий другого, этому авторитету не
	// принадлежит, и он про него не судит.
	Issuer      string
	Keys        KeySetSource
	Revocations RevocationReader
	Clock       func() time.Time
	Logger      *slog.Logger
	// RequireClientCert — принимать вопрос ТОЛЬКО от пира, предъявившего
	// проверенный сертификат.
	//
	// Обязательно на всяком поднятом стенде, и вот почему это не педантизм.
	// Соседняя поверхность того же слушателя — набор проверочных ключей —
	// намеренно не требует ничего: на проводе только публичный материал, и
	// потребитель обязан оставаться origin-agnostic. У ЭТОЙ поверхности
	// предмет другой: ей ПРИСЫЛАЮТ предъявленный токен. Обоснование снятия
	// authN, выданное набору ключей, сюда не распространяется, и молчаливое
	// пользование им было бы тем самым запрещённым допущением «внутреннее —
	// значит доверенное».
	//
	// Транспорт при этом сертификат лишь ЗАПРАШИВАЕТ (иначе набор ключей стал
	// бы недоступен потребителю без сертификата), поэтому отказывать обязан
	// сам обработчик — считать, что за него это сделал транспорт, нельзя.
	RequireClientCert bool
}

// Stats — величины по каждому исходу. «Ноль отказов за всё время жизни»
// обязано быть отличимо от «контроль не исполнялся».
type Stats struct {
	Active      uint64
	Inactive    uint64
	Unavailable uint64
}

// Handler — авторитет отзыва.
type Handler struct {
	cfg    Config
	logger *slog.Logger

	active      atomic.Uint64
	inactive    atomic.Uint64
	unavailable atomic.Uint64
}

// NewHandler — построитель.
func NewHandler(cfg Config) *Handler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Handler{cfg: cfg, logger: logger}
}

// Stats возвращает величины.
func (h *Handler) Stats() Stats {
	return Stats{Active: h.active.Load(), Inactive: h.inactive.Load(), Unavailable: h.unavailable.Load()}
}

// NewMux монтирует авторитет на его путь.
func NewMux(h http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	if h != nil {
		mux.Handle(IntrospectPath, h)
	}
	return mux
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.cfg.RequireClientCert && !clientCertVerified(r) {
		// Наружу — опознавательное слово и ничего сверх: спрашивающий без
		// сертификата не обязан узнать, существует ли токен, о котором он
		// собирался спросить.
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "client_certificate_required"})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	// Потолок — в pkg/httpbody, единственной в дереве реализации; вместе с ней
	// приезжает слой «объявленная длина сверх потолка», которого здесь не было.
	if httpbody.Cap(w, r, maxTokenBytes) {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "payload_too_large"})
		return
	}
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	raw := strings.TrimSpace(r.PostFormValue("token"))
	if raw == "" {
		// Отсутствующий обязательный параметр — отказ ФОРМЫ, а не суждение о
		// токене: суждения о токене, которого не прислали, не бывает.
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}

	verdict, err := h.judge(r.Context(), raw)
	if err != nil {
		// Недоступность источника НЕ ЕСТЬ «да» и не есть «нет»: авторитет
		// отвечает отказом, по которому спрашивающий закрывается сам.
		h.unavailable.Add(1)
		h.logger.Error("token introspection could not be answered (fail-closed)",
			slog.Uint64("unavailable_total", h.unavailable.Load()),
			slog.String("err", err.Error()))
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "introspection_unavailable"})
		return
	}
	if verdict {
		h.active.Add(1)
	} else {
		h.inactive.Add(1)
	}
	writeJSON(w, http.StatusOK, map[string]any{"active": verdict})
}

// judge отвечает, действителен ли предъявленный токен.
//
// Возвращаемая ошибка означает «ответить не смогли», и это ТРЕТИЙ исход,
// отличный от обоих суждений: смешать его с «недействителен» значило бы
// сделать сбой базы неотличимым от отзыва.
func (h *Handler) judge(ctx context.Context, raw string) (bool, error) {
	keys, err := h.cfg.Keys.PublishedSet(ctx)
	if err != nil {
		return false, fmt.Errorf("key set: %w", err)
	}
	byKID := make(map[string]domain.PublishedKey, len(keys))
	for _, k := range keys {
		byKID[string(k.KID)] = k
	}

	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		// Алгоритм берётся из ЗАКРЫТОГО словаря; «без подписи» отвергается
		// разбором, а не отдельной веткой, которую можно забыть.
		jwt.WithValidMethods(tokenpolicy.Algorithms()),
		// Обязательность срока включается ЯВНО: разбор, не встретив срока, не
		// возразит сам ни в одной известной библиотеке.
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(h.cfg.Issuer),
		jwt.WithLeeway(tokenpolicy.ClockSkew),
		jwt.WithTimeFunc(h.cfg.Clock),
	)
	tok, err := parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if !domain.ValidKeyIDForm(kid) {
			return nil, fmt.Errorf("key id has illegal form")
		}
		pub, ok := byKID[kid]
		if !ok {
			return nil, fmt.Errorf("key id does not resolve")
		}
		// Алгоритм заголовка СВЕРЯЕТСЯ с закреплённым за найденным ключом;
		// заголовок алгоритм не выбирает.
		if t.Method.Alg() != string(pub.Algorithm) {
			return nil, fmt.Errorf("header algorithm does not match the key")
		}
		// Параметр, помеченный отправителем обязательным к пониманию, мы обязаны
		// либо исполнить, либо отвергнуть токен целиком (RFC 7515 §4.1.11).
		// Обратная сторона того же требования — НЕ помеченное неизвестное
		// игнорируется (RFC 7519, EID 8060); на этом держится совместимость,
		// поэтому прочие неизвестные поля разбор молча пропускает.
		if ok, name := tokenpolicy.CriticalHeadersUnderstood(critHeaders(t.Header)); !ok {
			return nil, fmt.Errorf("critical header %q is not understood", name)
		}
		return parsePublicKey(pub.PublicKeyPEM)
	})
	if err != nil || !tok.Valid {
		// Токен, за который поручиться нельзя, недействителен. Это СУЖДЕНИЕ,
		// а не сбой: спрашивающий получил ответ.
		return false, nil
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return false, nil
	}

	// Правило отзыва — ОДНО на обе поверхности, объявленное в своём пакете.
	//
	// Ключей отсечки несколько, и это не несколько механизмов, а несколько ключей
	// у одного: отзыв КЛИЕНТА — снятие ключа, которым клиент себя
	// аутентифицирует, — обязан снимать и уже выданные ИМ токены. Вторая копия
	// правила разошлась бы молча и разошлась бы там, где расхождение не видно.
	//
	// Токен без отметки выпуска правило считает отозванным: он не сопоставим ни с
	// какой отсечкой, и принять его значило бы завести материал, который отозвать
	// нечем.
	revoked, err := tokenrevocation.Revoked(ctx, h.cfg.Revocations, claims)
	if err != nil {
		// Недоступность источника отсечек НЕ ЕСТЬ «не отозван»: это третий
		// исход, и спрашивающий закрывается сам.
		return false, fmt.Errorf("revocations: %w", err)
	}
	if revoked {
		return false, nil
	}
	return true, nil
}

func parsePublicKey(pemStr string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("public half is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("public half does not parse")
	}
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported public key type")
	}
}

// clientCertVerified отвечает, предъявил ли пир сертификат, ПРОВЕРЕННЫЙ
// транспортом. Читается именно проверенная цепочка, а не сырой список
// предъявленного: непроверенный сертификат — это заявление пира о себе, и
// принимать его за личность значило бы завести контроль, который не отказывает.
func clientCertVerified(r *http.Request) bool {
	return r.TLS != nil && len(r.TLS.VerifiedChains) > 0
}

func writeJSON(w http.ResponseWriter, code int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// critHeaders приводит `crit` к перечню имён.
//
// Разбор отдаёт заголовок как произвольный JSON, поэтому годятся ровно два вида:
// список строк и его отсутствие. Всё прочее — не перечень имён, и принимать по
// нему решение нельзя; такой вход даёт одно ЗАВЕДОМО неизвестное имя, то есть
// отказ. Молчаливый пропуск здесь означал бы «параметр помечен обязательным, а
// мы не разобрали его форму и приняли токен».
func critHeaders(h map[string]any) []string {
	raw, ok := h["crit"]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return []string{"<crit is not a list>"}
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		name, ok := v.(string)
		if !ok {
			return []string{"<crit entry is not a string>"}
		}
		out = append(out, name)
	}
	return out
}

// DeclaredDeviations — обязательные проверки, которых интроспекция НЕ исполняет,
// вместе с причиной. Пустая причина не засчитывается: отступление без неё
// неотличимо от пропуска.
//
// Обе причины — про РАЗНИЦУ ВОПРОСА, а не про очередь работ. Интроспекция
// отвечает о состоянии токена У ЕГО ИЗДАТЕЛЯ («выпущен нами, подписан, не
// истёк, не отозван»), а не о пригодности токена ДЛЯ ЗАДАЮЩЕГО ВОПРОС. Адресат
// и тип — свойства поверхности предъявления, и проверяет их та поверхность, где
// токен предъявлен: край и проверяющий реестра исполняют обе.
func (h *Handler) DeclaredDeviations() []tokenpolicy.Deviation {
	return []tokenpolicy.Deviation{
		{
			Check: tokenpolicy.CheckAudience,
			Reason: "интроспекция сообщает состояние токена у издателя, а не его " +
				"пригодность для спрашивающего: адресата проверяет поверхность " +
				"предъявления, у которой он свой",
		},
		{
			Check: tokenpolicy.CheckTokenType,
			Reason: "по той же причине: тип объявляет, для какой поверхности токен " +
				"выпущен, и сверяет его та поверхность, а не издатель",
		},
	}
}

// DeclaredChecks возвращает состав проверок ЭТОГО проверяющего.
//
// Объявление существует затем, чтобы его можно было СВЕРИТЬ с единым перечнем
// (`tokenpolicy.MandatoryChecks`), а не читать три реализации глазами. Запись,
// которой проверяющий не исполняет, отсюда нельзя: тогда объявление станет
// вторым местом об одном предмете, и разойдётся оно молча.
func (h *Handler) DeclaredChecks() []tokenpolicy.Check {
	return []tokenpolicy.Check{
		tokenpolicy.CheckAlgorithmAllowed,
		tokenpolicy.CheckKeyID,
		tokenpolicy.CheckSignature,
		tokenpolicy.CheckKeyBoundAlgorithm,
		tokenpolicy.CheckIssuer,
		tokenpolicy.CheckExpiry,
		tokenpolicy.CheckNotBefore,
		tokenpolicy.CheckCriticalHeaders,
		tokenpolicy.CheckRevocation,
	}
}
