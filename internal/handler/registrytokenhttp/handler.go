// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package registrytokenhttp — thin HTTP transport for the IAM Docker Registry v2
// auth-server: the `/iam/token` endpoint (Basic-auth → Hydra-brokered token).
//
// Transport only: parse the Docker token-auth request, delegate to the
// registry_token use-case (which verifies the presented BASIC ACCESS TOKEN —
// the only credential kind this lane accepts, задача #1143 — and issues the
// registry token), format the Docker-compatible JSON. No business logic.
//
// Hydra remains the token issuer/signer; kacho-iam mints NOTHING. The data-plane
// verifies the returned token against HYDRA's JWKS — which it now fetches from a
// cluster-INTERNAL Hydra-JWKS mirror served by kacho-iam (a short-TTL caching
// reverse-proxy of Hydra's public JWKS at GET /.well-known/jwks.json on the :9097
// jwks-proxy listener, package internal/handler/jwksproxyhttp), NOT from this
// external `/iam/token` listener. The mirror keeps the served kids equal to Hydra's
// real signing kids; iam has no keyset of its own to serve (it mints nothing). This
// `/iam/token` mux therefore carries no JWKS endpoint of its own.
//
// Endpoint:
//
//	GET|POST /iam/token — Docker Registry v2 token endpoint (Basic → Hydra token).
package registrytokenhttp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	registrytokenuc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho/pkg/credsecret"
)

// unauthorizedBody — ЕДИНСТВЕННОЕ тело отказа этой полосы, одно на ВСЯКУЮ
// причину: отсутствие удостоверения, чужое имя, неверный секрет, негодный вид,
// отвергнутый адресат. Различимость снаружи сказала бы предъявителю, как именно
// разобран его вход, — то есть была бы оракулом.
//
// Годный вид оно называет СТАТИЧЕСКИ — так же, как называет его страница
// документации, — а не по разбору предъявленного. Из тела нельзя узнать ничего
// о том, что прислали; можно узнать только, что прислать следовало. Без этого
// арендатор, настроенный на снятый вход по ключевому материалу (#1143), видит
// отказ и не знает, чем его заменить.
//
// Марка берётся из `credsecret` — ЕДИНСТВЕННОГО объявленного места, где живёт
// форма базового удостоверения. Второй её копии здесь не заводится: копия
// разошлась бы молча, и разошлась бы именно в подсказке, которую читают вместо
// документации.
// Формулировка НЕ утверждает, отвергнут ли прежний вид НА ЭТОМ контуре: пока
// открыто окно перехода #1143, он принимается, и текст, объявивший обратное,
// был бы ложью для одной посадки и оракулом ручки для другой (по нему
// перебором узнают, объявлено ли окно). Поэтому тело говорит о ГОДНОМ виде и
// только о нём — то же, что говорит страница документации.
var unauthorizedBody = `{"error":"unauthorized","error_description":` +
	`"this lane issues registry tokens for the Kacho basic access token: docker login -u <credential id> -p ` +
	credsecret.Mark + `<credential id>_<secret>"}`

// TokenPath — the token endpoint path. MUST equal the data-plane's Bearer realm
// path (the WWW-Authenticate realm), so verifiers and docker clients resolve the
// same URL.
const TokenPath = "/iam/token"

// NewMux mounts the token handler on its canonical path. The caller exposes the
// returned mux on an EXTERNAL-reachable HTTP listener (docker clients hit
// /iam/token through the edge) — unlike the cluster-internal hooks mux.
func NewMux(token http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	if token != nil {
		mux.Handle(TokenPath, token)
	}
	return mux
}

// TokenIssuer — the registry_token use-case port the handler delegates to.
// Execute serves the presented-credential (Basic) path; ExecuteAnonymous brokers the
// public `user:*` anonymous-pull path (no Basic creds); AnonymousEnabled reports
// whether that path is configured (else the handler fails closed to a challenge).
type TokenIssuer interface {
	Execute(ctx context.Context, in registrytokenuc.IssueInput) (registrytokenuc.IssueOutput, error)
	ExecuteAnonymous(ctx context.Context, service string) (registrytokenuc.IssueOutput, error)
	AnonymousEnabled() bool
}

// Config — handler config (the WWW-Authenticate realm + default service name).
type Config struct {
	// Realm — the token-endpoint URL advertised in WWW-Authenticate (must match
	// the data-plane's Bearer realm, e.g. https://api.kacho.local/iam/token).
	Realm string
	// DefaultService — the service name used in WWW-Authenticate when the request
	// omits ?service= (e.g. registry.kacho.local).
	DefaultService string
}

// TokenHandler — the `/iam/token` endpoint.
type TokenHandler struct {
	cfg    Config
	issuer TokenIssuer
	// logger — единственное место, где причина отказа вообще попадает в трейл.
	// Наружу тело фиксировано, и это правильно; но до этой строки причина не
	// уходила НИКУДА, и «провайдер лежит», «стучимся не туда», «имя не
	// резолвится» выглядели одинаково — при том что чинятся противоположно.
	// nil допустим (пробы), тогда журналирования нет.
	logger *slog.Logger
}

// NewTokenHandler — builder.
func NewTokenHandler(cfg Config, issuer TokenIssuer) *TokenHandler {
	return &TokenHandler{cfg: cfg, issuer: issuer}
}

// WithLogger провязывает журнал причин отказа. Отдельным методом, а не полем
// Config: Config описывает то, что видит КЛИЕНТ (realm, имя службы), а журнал —
// то, что видим мы.
func (h *TokenHandler) WithLogger(l *slog.Logger) *TokenHandler {
	h.logger = l
	return h
}

// tokenResponse — the Docker Registry v2 token-endpoint body. `access_token`
// mirrors `token` for OAuth2-flow client compatibility. `issued_at` is an RFC3339
// UTC *string* per the Docker Registry v2 token spec: the docker client parses it
// via `time.Time.UnmarshalJSON`, which accepts ONLY a JSON string — serializing it
// as a bare Unix-epoch number breaks `docker login` with «Time.UnmarshalJSON:
// input is not a JSON string», so no bearer is minted and all pull/push 401.
type tokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	IssuedAt    string `json:"issued_at,omitempty"`
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	// Два РАЗНЫХ значения, и смешивать их нельзя.
	//
	// `requested` — то, что назвал ЗАПРОС; пустое означает «не назвал», и решает
	// это выдача: ключ, объявивший при выдаче своё назначение, обязан получить
	// адресат из СВОЕГО объявления, а не умолчание посадки. Подставив умолчание
	// здесь, транспорт принял бы за выдачу решение, которого не знает, — и такой
	// ключ отвергался бы собственной проверкой (задача #1184).
	//
	// `service` — то, что показывают КЛИЕНТУ в вызове на аутентификацию. Здесь
	// умолчание уместно: вызов обязан назвать службу, даже когда запрос её не
	// назвал.
	requested := r.URL.Query().Get("service")
	service := requested
	if service == "" {
		service = h.cfg.DefaultService
	}

	user, pass, ok := r.BasicAuth()
	if !ok {
		// No Basic creds → the docker anonymous-pull flow. When anonymous pull is
		// enabled, issue the read-only public `user:*` bearer; otherwise fail
		// closed to the 401 Bearer challenge (secure-by-default, anon is opt-in).
		if !h.issuer.AnonymousEnabled() {
			h.challenge(w, service)
			return
		}
		out, err := h.issuer.ExecuteAnonymous(r.Context(), requested)
		if err != nil {
			h.writeError(w, service, err)
			return
		}
		h.writeToken(w, out)
		return
	}

	out, err := h.issuer.Execute(r.Context(), registrytokenuc.IssueInput{
		Username: user,
		Password: pass,
		Service:  requested,
		// Материал привязки токена к ключу владельца (Ф1б #926) — из
		// ПРОВЕРЕННОЙ цепочки, а не из того, что пир прислал.
		ConfirmationX5TS256: verifiedClientCertThumbprint(r),
	})
	if err != nil {
		h.writeError(w, service, err)
		return
	}
	h.writeToken(w, out)
}

// writeError maps a use-case failure to the fail-closed HTTP response: an
// unreachable issuer (Hydra) → 503 (no token); any auth failure → 401 challenge;
// anything else → 500. No raw Hydra/network error ever leaks (fixed text).
func (h *TokenHandler) writeError(w http.ResponseWriter, service string, err error) {
	switch {
	case errors.Is(err, registrytokenuc.ErrIssuerUnavailable):
		// Причина — в журнал, тело — фиксированное. Разные адресаты, разные
		// требования: клиенту различать нечего (оракул), нам различать
		// обязательно.
		if h.logger != nil {
			h.logger.Error("docker token: issuer unavailable", "err", err, "service", service)
		}
		http.Error(w, `{"error":"unavailable"}`, http.StatusServiceUnavailable)
	case errors.Is(err, registrytokenuc.ErrAudienceNotAllowed):
		// Наружу — тот же 401-вызов, что на всяком отказе аутентификации:
		// различимость снаружи сказала бы предъявителю, ЧТО именно объявлено
		// посадкой и подо что выдан ключ, — то есть была бы оракулом.
		//
		// В журнал — причина: «посадка такого адресата не объявляла» и «ключ
		// выдавался не под этот адресат» чинятся в разных местах и разными
		// людьми, а без этой строки они выглядят одинаково. Отдельная ветка от
		// ErrUnauthenticated ровно за этим и заведена: слив их, мы отдали бы
		// оператору отказ учётных данных на исправных учётных данных.
		if h.logger != nil {
			h.logger.Warn("docker token: requested audience refused", "err", err, "service", service)
		}
		h.challenge(w, service)
	case errors.Is(err, registrytokenuc.ErrUnauthenticated):
		if errors.Is(err, registrytokenuc.ErrCredentialKindNotAccepted) && h.logger != nil {
			// Наружу — тот же отказ, что и на всяком другом; в журнал —
			// причина: «клиент настроен на снятый вход» и «секрет неверен»
			// чинятся в разных местах и разными людьми, а без этой строки
			// они выглядят одинаково. Ни имени, ни предъявленного здесь нет
			// — в журнал не уходит то, чего клиенту не отдают.
			h.logger.Warn("docker token: presented credential kind is no longer accepted "+
				"(the lane takes the Kacho basic access token)", "service", service)
		}
		h.challenge(w, service)
	default:
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
	}
}

// writeToken writes the 200 Docker Registry v2 token body.
func (h *TokenHandler) writeToken(w http.ResponseWriter, out registrytokenuc.IssueOutput) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	issuedAt := ""
	if out.IssuedAt > 0 {
		issuedAt = time.Unix(out.IssuedAt, 0).UTC().Format(time.RFC3339)
	}
	// #nosec G117 -- registry token endpoint intentionally returns the minted bearer token to the client (Docker registry v2 auth flow); serializing it is the contract, not a leak
	_ = json.NewEncoder(w).Encode(tokenResponse{
		Token:       out.Token,
		AccessToken: out.Token,
		ExpiresIn:   out.ExpiresIn,
		IssuedAt:    issuedAt,
	})
}

// challenge writes the 401 Bearer WWW-Authenticate challenge (realm + service).
func (h *TokenHandler) challenge(w http.ResponseWriter, service string) {
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Bearer realm=%q,service=%q`, h.cfg.Realm, service))
	http.Error(w, unauthorizedBody, http.StatusUnauthorized)
}

// verifiedClientCertThumbprint — отпечаток клиентского сертификата хопа выдачи
// по RFC 8705 §3.1: base64url от SHA-256 над DER целиком.
//
// # Почему ПРОВЕРЕННАЯ цепочка, а не присланный сертификат
//
// `PeerCertificates` содержит то, что пир ПРИСЛАЛ; `VerifiedChains` — то, что
// принято против доверенных корней. Считать отпечаток по первому значило бы
// разрешить предъявителю назначить себе привязку самому: он присылает любой
// сертификат, получает токен, привязанный к нему, и предъявляет их вместе.
// Привязка, которую выбирает предъявитель, не привязывает ни к чему.
//
// # Почему пусто — законный исход, а не отказ
//
// Слушатель выдачи докер-токена односторонний ПО РЕШЕНИЮ: по нему едет HTTP
// Basic, и клиентского сертификата на нём не спрашивают. Значит на сегодняшней
// посадке материал не предъявляется, токен выходит предъявительским, и это
// ровно то, чего требует приёмка: привязка не появляется там, где её не
// просили. Начнёт ли хоп её предъявлять — свойство ПОСАДКИ слушателя, а не
// этого кода; код обязан лишь не выдумывать того, чего не предъявили.
func verifiedClientCertThumbprint(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return ""
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if leaf == nil || len(leaf.Raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(leaf.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
