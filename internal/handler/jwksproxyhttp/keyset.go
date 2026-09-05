// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package jwksproxyhttp

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// KeySetSource — источник НАШЕЙ записи публикуемого набора.
//
// Реализуется ключницей. Порт назван здесь, у вызывающего: публикатор не знает
// ни про базу, ни про обёртку приватной половины — да и не может знать, потому
// что тип, которым ключ сюда приезжает, поля приватной половины не имеет вовсе.
type KeySetSource interface {
	PublishedSet(ctx context.Context) ([]domain.PublishedKey, error)
}

// KeySetConfig — настройка обработчика нашей записи.
type KeySetConfig struct {
	Source KeySetSource
	Logger *slog.Logger
}

// KeySetStats — величины по каждому исходу.
//
// «Ноль отказов за всё время жизни» обязано быть отличимо от «контроль не
// исполнялся», поэтому величины читаются всегда, включая нулевые.
type KeySetStats struct {
	Served      uint64
	Unavailable uint64
	Empty       uint64
}

// KeySetHandler — НАША запись публикуемого набора: ПРОЕКЦИЯ ключницы.
//
// # Почему проекция, а не собственный кэш
//
// Порядок «ключ в наборе раньше, чем им подписан первый токен» становится
// верен ПО ПОСТРОЕНИЮ: опубликованный и подписывающий читаются из одних и тех
// же строк, и состояния, в котором ключ подписывает, а в ответе его нет, не
// существует — его не допускает схема.
//
// Собственный кэш вернул бы состояние «строка есть, в ответе нет», и тогда
// вступление ключа в подпись пришлось бы гейтить на видимость
// eventually-consistent проекции — запрещённый подтверждающий барьер. С
// несколькими репликами публикатора «ответ эндпоинта» перестал бы быть одной
// величиной.
//
// # Цена решения названа
//
// Каждый запрос публикации становится чтением своей базы. Величина ограничена
// сверху числом потребителей, помноженным на частоту их перезапроса, — то есть
// единицами запросов в минуту, а не функцией от пользовательской нагрузки.
type KeySetHandler struct {
	source KeySetSource
	logger *slog.Logger

	served      atomic.Uint64
	unavailable atomic.Uint64
	empty       atomic.Uint64
}

// NewKeySetHandler — построитель.
func NewKeySetHandler(cfg KeySetConfig) *KeySetHandler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &KeySetHandler{source: cfg.Source, logger: logger}
}

// Stats возвращает величины по каждому исходу.
func (h *KeySetHandler) Stats() KeySetStats {
	return KeySetStats{
		Served:      h.served.Load(),
		Unavailable: h.unavailable.Load(),
		Empty:       h.empty.Load(),
	}
}

func (h *KeySetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Маршрут только на чтение; отказ несёт перечень допустимых.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeFailClosed(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}

	// Свой предел времени на чтение источника: клиент по умолчанию не
	// используется ни на одном пути, и предел запроса не заменяет собственного.
	ctx, cancel := context.WithTimeout(r.Context(), keySetReadTimeout)
	defer cancel()

	keys, err := h.source.PublishedSet(ctx)
	if err != nil {
		h.unavailable.Add(1)
		// Наружу уходит опознавательное слово; подробность — в журнал.
		h.logger.Error("jwks: our key-set record could not be served (fail-closed)",
			slog.String("classification", reasonKeySetUnavailable),
			slog.Uint64("unavailable_total", h.unavailable.Load()),
			slog.String("err", err.Error()))
		writeFailClosed(w, failClosedStatus, reasonKeySetUnavailable)
		return
	}
	if len(keys) == 0 {
		// Пустой успешный ответ ЗАПРЕЩЁН. Отсутствие ключей — это отказ, а не
		// «набор из нуля ключей»: пустой массив читается потребителем как факт
		// о нас, и здесь этот факт был бы ложью.
		h.empty.Add(1)
		h.logger.Error("jwks: our key set is empty — refusing rather than publishing an empty set",
			slog.String("classification", reasonKeySetEmpty),
			slog.Uint64("empty_total", h.empty.Load()))
		writeFailClosed(w, failClosedStatus, reasonKeySetEmpty)
		return
	}

	doc, err := encodeJWKS(keys)
	if err != nil {
		h.unavailable.Add(1)
		h.logger.Error("jwks: our key set could not be encoded (fail-closed)",
			slog.String("classification", reasonKeySetUnavailable),
			slog.String("err", err.Error()))
		writeFailClosed(w, failClosedStatus, reasonKeySetUnavailable)
		return
	}

	h.served.Add(1)
	w.Header().Set("Content-Type", "application/json")
	// Срок годности ответа ВЫБРАН, а не унаследован: это то же слагаемое
	// арифметики отсрочки, только со стороны публикатора, и оно объявлено
	// числом.
	w.Header().Set("Cache-Control", keySetCacheControl)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc)
}

// jwk — публикуемая форма одного ключа.
//
// Поля приватной половины у этого типа НЕТ и быть не может: положить её сюда
// не выражается, а не «запрещено правилом».
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// encodeJWKS переводит публикуемые ключи в СТАНДАРТНЫЙ по форме документ.
//
// Стандартность — требование, а не вкус: будущее решение вынести набор наружу
// обязано остаться решением о ПОВЕРХНОСТИ, а не переписыванием публикатора и
// каждого его потребителя.
func encodeJWKS(keys []domain.PublishedKey) ([]byte, error) {
	set := jwkSet{Keys: make([]jwk, 0, len(keys))}
	for _, k := range keys {
		entry, err := toJWK(k)
		if err != nil {
			// Неотдаваемый ключ закрывает ЗАПИСЬ целиком: частичный набор
			// неотличим от полного, и потребитель примет его за истину.
			return nil, fmt.Errorf("key %s: %w", k.KID, err)
		}
		set.Keys = append(set.Keys, entry)
	}
	return json.Marshal(set)
}

func toJWK(k domain.PublishedKey) (jwk, error) {
	block, _ := pem.Decode([]byte(k.PublicKeyPEM))
	if block == nil {
		return jwk{}, fmt.Errorf("public half is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return jwk{}, fmt.Errorf("public half does not parse")
	}
	out := jwk{Kid: string(k.KID), Alg: string(k.Algorithm), Use: "sig"}
	switch key := pub.(type) {
	case *rsa.PublicKey:
		out.Kty = "RSA"
		out.N = b64(key.N.Bytes())
		out.E = b64(bigEndianExponent(key.E))
	case *ecdsa.PublicKey:
		out.Kty = "EC"
		out.Crv = key.Curve.Params().Name
		// Сырые координаты X/Y объявлены устаревшими в Go 1.26: как *big.Int они
		// теряют ведущие нули и не годятся для криптографических значений.
		// Bytes() отдаёт несжатую форму точки 0x04 || X || Y, где ОБЕ координаты
		// уже дополнены слева до размера кривой, — ровно то, чего требует JWK,
		// и без ручного дополнения. Отдаваемые байты те же, что и прежде.
		raw, err := key.Bytes()
		if err != nil {
			return jwk{}, fmt.Errorf("public half is not a valid curve point")
		}
		size := (key.Curve.Params().BitSize + 7) / 8
		if len(raw) != 1+2*size {
			// Форма точки — часть контракта записи. Неожиданная длина закрывает
			// запись целиком: усечённая координата неотличима от полной.
			return jwk{}, fmt.Errorf("uncompressed point is %d bytes, want %d", len(raw), 1+2*size)
		}
		out.X = b64(raw[1 : 1+size])
		out.Y = b64(raw[1+size:])
	case ed25519.PublicKey:
		out.Kty = "OKP"
		out.Crv = "Ed25519"
		out.X = b64(key)
	default:
		return jwk{}, fmt.Errorf("unsupported public key type %T", pub)
	}
	return out, nil
}

func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func bigEndianExponent(e int) []byte {
	var buf []byte
	for v := e; v > 0; v >>= 8 {
		buf = append([]byte{byte(v & 0xff)}, buf...)
	}
	if len(buf) == 0 {
		buf = []byte{0}
	}
	return buf
}
