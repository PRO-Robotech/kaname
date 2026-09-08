// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package jwksproxyhttp — cluster-ВНУТРЕННИЙ публикатор наборов проверочных
// ключей.
//
// # Записей ДВЕ, и у каждой свой объявленный путь
//
// Платформа чеканит свои токены сама (задача #897), поэтому публикуются две
// записи, а не одна:
//
//   - НАША (keyset.go) — ПРОЕКЦИЯ ключницы: только наши ключи, только публичный
//     материал, собственного кэша нет by construction;
//   - ЗЕРКАЛО прежнего издателя (этот файл) — тонкий кэширующий обратный
//     посредник его публичного набора, побайтовое равенство источнику. Оно
//     сохраняется до последней фазы отказа от внешнего OAuth-сервера и уходит
//     вместе с ним: запись, которой больше нечего зеркалить, — находка, а не
//     «оставим на всякий случай».
//
// Объединять наборы в один документ было бы дешевле и уничтожило бы ровно ту
// защиту, ради которой развязка заводится: ключ одного издателя проверял бы
// токен, объявляющий другого. Привязка «издатель → путь» — в binding.go.
//
// # Что верно ИМЕННО для зеркала
//
// Оно отдаёт чужие идентификаторы ключей и НИКОГДА наши: наши живут в своей
// записи. Наш идентификатор здесь был бы гарантированным промахом проверки —
// потребитель этой записи ищет ключи прежнего издателя.
//
// Fail-closed. A cold cache + an unavailable Hydra (network error / non-200 / empty
// keyset / timeout) yields 502 — never an empty 200, never a substitute keyset. A
// warm cache within TTL survives a brief Hydra blip (bounded-stale); once the TTL
// elapses with Hydra still down the endpoint degrades to fail-closed, never
// indefinitely-stale.
//
// Per-call timeout. The upstream fetch uses a dedicated http.Client WITH a Timeout
// plus a per-request context deadline — never http.DefaultClient (architecture.md:
// DefaultClient has no Timeout, so a hung/half-open Hydra would wedge the goroutine
// forever).
//
// # Снятие authN — задокументированное исключение, и его обоснование СМЕНИЛОСЬ
//
// Маршруты НАБОРА КЛЮЧЕЙ не требуют аутентификации осознанно. Прежде это
// обосновывалось тем, что публикуется ЧУЖОЕ зеркало; после того как платформа
// стала чеканить сама, обоснование другое и записано здесь, чтобы двух мест об
// одном предмете не завелось: на проводе — ТОЛЬКО ПУБЛИЧНЫЙ МАТЕРИАЛ проверки
// подписи (наш в одной записи, прежнего издателя в другой), в форме
// стандартного документа, на cluster-ВНУТРЕННЕМ слушателе (:9097, никогда
// внешнем — ban #6), под односторонней TLS с сертификатом внутреннего
// удостоверяющего центра.
//
// Требовать сертификат у ПОТРЕБИТЕЛЯ набора нельзя: он обязан оставаться
// origin-agnostic, и взаимная TLS сломала бы ровно это свойство.
//
// # Но соседняя поверхность того же слушателя обоснованием НЕ пользуется
//
// Авторитет отзыва (internal/handler/tokenintrospecthttp) стоит на этом же
// слушателе и принимает ПРЕДЪЯВЛЕННЫЙ ТОКЕН, а не отдаёт публичный материал.
// Обоснование выше на него не распространяется, поэтому он требует
// проверенного клиентского сертификата САМ, а слушатель переводится в режим
// «сертификат запрашивается и верифицируется, если предъявлен» — набор ключей
// при этом остаётся доступен без сертификата.
//
// Не добавляйте здесь authN-гейт, не пересмотрев это решение (и TLS-клиента
// потребителя набора).
package jwksproxyhttp

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
	"sync"
	"sync/atomic"
	"time"
)

// WellKnownJWKSPath — the standard OIDC JWKS well-known path this proxy serves.
const WellKnownJWKSPath = "/.well-known/jwks.json"

const (
	defaultTTL       = 5 * time.Minute
	defaultTimeout   = 5 * time.Second
	maxJWKSBytes     = 1 << 20 // 1 MiB upstream-body cap (defensive)
	failClosedStatus = http.StatusBadGateway
)

// The two reasons a fetch can fail, kept apart because only one of them can be
// fixed by waiting.
//
//   - reasonUnavailable — the provider did not answer, timed out, or answered
//     with a server error / a keyless-but-well-formed keyset. Retrying is the
//     right response.
//   - reasonMisconfigured — whatever answered is not a JWKS endpoint: the path
//     serves nothing (404/405/410/501), or the body is a web page, or JSON with
//     no `keys` member at all. No retry ever fixes this, and the address it names
//     is the data-plane's verification anchor, so it must not be filed under the
//     same word as an outage. A permanently wrong address that reads as a
//     transient outage is a control that is present, wired, executed on every
//     request, and has never once been able to succeed.
const (
	reasonUnavailable   = "jwks_upstream_unavailable"
	reasonMisconfigured = "jwks_upstream_misconfigured"
)

// Config — inputs for the JWKS-proxy handler.
type Config struct {
	// UpstreamURL — the Hydra PUBLIC JWKS URL to mirror (config.ResolveHydraJWKSURL).
	UpstreamURL string
	// Client — optional injectable http.Client. nil → an internal client WITH a
	// per-call Timeout (never http.DefaultClient).
	Client *http.Client
	// TTL — cache lifetime when the upstream advertises no Cache-Control max-age.
	// <=0 → defaultTTL (5m).
	TTL time.Duration
	// Timeout — per-call upstream-fetch timeout. <=0 → defaultTimeout (5s).
	Timeout time.Duration
	// Clock — injectable time source (tests). nil → time.Now.
	Clock func() time.Time
	// Logger — nil → slog.Default().
	Logger *slog.Logger
}

// cachedDoc — a verbatim upstream JWKS document + its serving metadata.
type cachedDoc struct {
	body         []byte
	contentType  string
	cacheControl string
	expiresAt    time.Time
}

// Handler — the caching reverse-proxy handler.
type Handler struct {
	upstreamURL string
	client      *http.Client
	ttl         time.Duration
	timeout     time.Duration
	clock       func() time.Time
	logger      *slog.Logger

	mu     sync.Mutex
	cached *cachedDoc

	served        atomic.Uint64
	unavailable   atomic.Uint64
	misconfigured atomic.Uint64
}

// NewHandler builds the JWKS-proxy handler. The default http.Client carries a
// per-call Timeout (never http.DefaultClient).
func NewHandler(cfg Config) *Handler {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = defaultTTL
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	client := cfg.Client
	if client == nil {
		// Dedicated client with a Timeout — NEVER http.DefaultClient (which has
		// no Timeout and would wedge on a hung Hydra).
		client = &http.Client{Timeout: timeout}
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{
		upstreamURL: cfg.UpstreamURL,
		client:      client,
		ttl:         ttl,
		timeout:     timeout,
		clock:       clock,
		logger:      logger,
	}
}

// MirrorStats — what this mirror has actually done since the process started.
//
// It exists to answer "has this control ever refused anything, and for which
// reason?". Without the counts, a mirror that has fail-closed on every fetch since
// the stand came up is indistinguishable from one that never had to — and the
// difference is "every docker pull is 401" versus "everything is fine".
//
// WHO READS THIS. The composition root registers a scrape collector over these
// counters (kaname_jwks_mirror_outcomes_total), so Served is published beside
// the two refusal reasons and "never refused" stays distinguishable from "never
// reached". Здесь стояло «процесс сообщает их в журнале жизненного цикла» — такого
// читателя в дереве не было НИ ОДНОГО, то есть комментарий описывал наблюдаемость,
// которой не существовало, и именно поэтому её отсутствие никого не смутило.
// Свойство «читатель есть» держит гейт по дереву
// TestDeclaredAccumulatorsHaveANonTestReader.
type MirrorStats struct {
	// Served — fetches that produced a keyset (a cache hit serves without a fetch
	// and is not counted here; this counts what came off the hop).
	Served uint64
	// Unavailable — fetches refused because the provider did not answer usefully.
	Unavailable uint64
	// Misconfigured — fetches refused because the address does not serve a JWKS.
	Misconfigured uint64
}

// Stats returns a snapshot of the counters.
func (h *Handler) Stats() MirrorStats {
	return MirrorStats{
		Served:        h.served.Load(),
		Unavailable:   h.unavailable.Load(),
		Misconfigured: h.misconfigured.Load(),
	}
}

// upstreamError — a fetch failure together with its class.
type upstreamError struct {
	reason string
	err    error
}

func (e *upstreamError) Error() string { return e.err.Error() }

// unavailable / misconfigured — the two constructors, so no call site has to
// remember which token goes with which situation.
func unavailable(format string, a ...any) error {
	return &upstreamError{reason: reasonUnavailable, err: fmt.Errorf(format, a...)}
}

func misconfigured(format string, a ...any) error {
	return &upstreamError{reason: reasonMisconfigured, err: fmt.Errorf(format, a...)}
}

// classify reports the reason token of a fetch error. An unclassified error is
// treated as an outage: the classes exist to make a WRONG ADDRESS loud, and
// claiming misconfiguration on an error nobody classified would be the same defect
// mirrored.
func classify(err error) string {
	var ue *upstreamError
	if errors.As(err, &ue) {
		return ue.reason
	}
	return reasonUnavailable
}

// Маршруты публикации монтирует NewMux(Binding) в binding.go: записей больше
// одной, и перечень их путей ВЫВОДИТСЯ из объявленной привязки, а не
// выписывается здесь. Прежний NewMux(http.Handler) знал ровно один путь, и
// утверждение о единственном маршруте осталось бы зелёным, уедь второй на
// внешнюю поверхность.

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Read-only well-known endpoint.
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeFailClosed(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}

	now := h.clock()

	// Fresh cache → serve verbatim without hitting the upstream (this is also what
	// makes a within-TTL Hydra blip a no-op: we do not even try the upstream).
	h.mu.Lock()
	c := h.cached
	h.mu.Unlock()
	if c != nil && now.Before(c.expiresAt) {
		h.serve(w, c)
		return
	}

	// Cold OR expired → refetch. Success caches + serves; failure is fail-closed
	// (never empty-200, never a substitute keyset).
	doc, err := h.fetch(r.Context())
	if err != nil {
		reason := classify(err)
		if reason == reasonMisconfigured {
			h.misconfigured.Add(1)
			// Louder than an outage, and worded so it cannot be read as one: this
			// address will never serve a keyset, so the data-plane will reject every
			// token for as long as the address stands.
			h.logger.Error("jwks-proxy: upstream address does NOT serve a JWKS document — "+
				"this is a MISCONFIGURED address, not an outage; no retry fixes it, and every "+
				"token verification downstream fails until it is corrected",
				slog.String("upstream", h.upstreamURL),
				slog.String("classification", reasonMisconfigured),
				slog.String("setting", "authn.hydra-jwks-url (env KANAME_HYDRA_JWKS_URL)"),
				slog.Uint64("misconfigured_total", h.misconfigured.Load()),
				slog.String("err", err.Error()))
		} else {
			h.unavailable.Add(1)
			h.logger.Error("jwks-proxy: upstream Hydra JWKS fetch failed (fail-closed)",
				slog.String("upstream", h.upstreamURL),
				slog.String("classification", reasonUnavailable),
				slog.Uint64("unavailable_total", h.unavailable.Load()),
				slog.String("err", err.Error()))
		}
		writeFailClosed(w, failClosedStatus, reason)
		return
	}

	h.served.Add(1)
	h.mu.Lock()
	h.cached = doc
	h.mu.Unlock()
	h.serve(w, doc)
}

// serve writes a cached document verbatim with its Content-Type + Cache-Control.
func (h *Handler) serve(w http.ResponseWriter, c *cachedDoc) {
	w.Header().Set("Content-Type", c.contentType)
	w.Header().Set("Cache-Control", c.cacheControl)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(c.body)
}

// fetch GETs the upstream Hydra JWKS under a per-call deadline, validates it is a
// non-empty keyset, and returns a verbatim cached document. Any transport error,
// non-200 status, oversized/unparseable body, or empty keyset → error (fail-closed).
func (h *Handler) fetch(parent context.Context) (*cachedDoc, error) {
	ctx, cancel := context.WithTimeout(parent, h.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.upstreamURL, nil)
	if err != nil {
		// An address the http package will not even build a request for is an
		// operator error, not a provider one.
		return nil, misconfigured("build upstream request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := h.client.Do(req)
	if err != nil {
		// Transport failures are NOT split further on purpose. A refused
		// handshake reads the same whether the peer is down or presented a
		// certificate this process will not accept, and guessing between them
		// here would put a wrong word in the log. The pinned anchor is asserted
		// where it belongs — on the hop's own tests.
		return nil, unavailable("upstream request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if isWrongEndpointStatus(resp.StatusCode) {
			return nil, misconfigured("upstream status %d — the address serves no JWKS", resp.StatusCode)
		}
		return nil, unavailable("upstream status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, unavailable("read upstream body: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return nil, misconfigured("upstream body exceeds %d bytes — a JWKS document does not", maxJWKSBytes)
	}
	if err := validateNonEmptyKeyset(body); err != nil {
		return nil, err
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}

	cacheControl := strings.TrimSpace(resp.Header.Get("Cache-Control"))
	ttl := h.ttl
	if maxAge, ok := parseMaxAge(cacheControl); ok && maxAge > 0 && maxAge < ttl {
		// Honor the upstream's freshness signal ONLY when it SHORTENS our TTL.
		// h.ttl is a HARD CEILING: a large upstream max-age (e.g. a CDN/Ory
		// advertising 24h) must never let iam serve a rotated/revoked keyset past
		// the short bounded-stale window — the data-plane trusts these kids as its
		// token-verification anchor, so freshness cannot be delegated to an
		// unvalidated upstream header (security freshness invariant).
		ttl = maxAge
	}
	if cacheControl == "" {
		cacheControl = "public, max-age=" + strconv.Itoa(int(ttl.Seconds()))
	}

	return &cachedDoc{
		body:         body,
		contentType:  contentType,
		cacheControl: cacheControl,
		expiresAt:    h.clock().Add(ttl),
	}, nil
}

// isWrongEndpointStatus reports whether a status proves the address does not serve
// this resource at all, as opposed to serving it badly right now. 404/410 — no such
// resource; 405 — the resource exists but not for GET, which a well-known JWKS
// always answers; 501 — the peer does not implement it. Everything else (403, 429,
// 5xx) can legitimately be transient and stays an outage.
func isWrongEndpointStatus(code int) bool {
	switch code {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusGone, http.StatusNotImplemented:
		return true
	default:
		return false
	}
}

// validateNonEmptyKeyset ensures the upstream document is a JWKS with >=1 key,
// and separates the two ways it can fail to be one:
//
//   - not JSON at all, or JSON WITHOUT a `keys` member — whatever is at that
//     address is not a JWKS endpoint (a login page, a health handler, the wrong
//     port). Permanent: MISCONFIGURED.
//   - a `keys` member that is present and empty — this IS a JWKS endpoint, and the
//     provider currently has no signing keys. Fail-closed, and an outage: it can
//     resolve on its own.
//
// Neither is ever served as a success — a keyless JWKS verifies nothing.
func validateNonEmptyKeyset(body []byte) error {
	var doc struct {
		Keys *[]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return misconfigured("upstream body is not a JWKS document: %w", err)
	}
	if doc.Keys == nil {
		return misconfigured("upstream body has no \"keys\" member — the address does not serve a JWKS")
	}
	if len(*doc.Keys) == 0 {
		return unavailable("upstream JWKS has no keys")
	}
	return nil
}

// parseMaxAge extracts the `max-age=<seconds>` directive from a Cache-Control
// header. Returns (0, false) when absent/unparseable.
func parseMaxAge(cc string) (time.Duration, bool) {
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "max-age="); ok {
			secs, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || secs < 0 {
				return 0, false
			}
			return time.Duration(secs) * time.Second, true
		}
	}
	return 0, false
}

// writeFailClosed emits a fixed opaque JSON error (no upstream/pgx text leak, no
// keys, never a kacho-* kid).
func writeFailClosed(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":%q}`, reason)
}
