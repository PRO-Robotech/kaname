// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// hydra_admin_client.go — client for the Ory Hydra Admin API.
//
// Carries the shared connection config (base URL, bearer, HTTP client) for the
// Hydra admin surfaces iam actually drives, and the OAuth2 client lifecycle
// itself (/admin/clients: CreateOAuthClient, DeleteOAuthClient — below). The
// wire types that lifecycle carries live under the port's role name, in
// provider_oauth_clients.go.
//
// It no longer publishes or deletes JWKs, и причина — НЕ в том, что своих
// ключей у платформы нет.
//
// Здесь стояло «iam owns no signing keyset: it mints nothing, Hydra is the
// issuer and signer». Утверждение пережило свой предмет: ключница у платформы
// есть (`kaname.token_signing_keys`, package internal/signingkeygen), свои
// токены она подписывает сама (internal/tokensigner), а публикатор :9097
// отдаёт её набор своей записью. Зеркало набора провайдера, стоявшее рядом,
// снято вместе с ним (kaname#361).
//
// Настоящая причина снятия: пара PublishKey/DeleteKey писала ключи В ЧУЖОЕ
// хранилище — она существовала исключительно ради ночной JWKSRotationService,
// снятой (713f7e1) вместе с хранилищем, которое ротировала (миграция 0065).
// Наша ротация живёт ВНУТРИ службы и админ-API провайдера не касается вовсе,
// поэтому интерфейс service.JWKSPublisher не имеет здесь предмета.
//
// Authentication: if HYDRA_ADMIN_TOKEN env is set — Bearer; otherwise
// anonymous (default Hydra config in the kind dev-stand exposes an
// anonymous admin port).
package clients

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HydraAdminClient — HTTP-клиент к Hydra admin API.
type HydraAdminClient struct {
	BaseURL     string
	BearerToken string
	HTTPClient  *http.Client

	// roadObserver — счётчик исходов ЭТОЙ дороги. nil законен: счёта нет,
	// решения дороги это не меняет (разбор клеток — provider_road.go).
	roadObserver ProviderRoadObserver
}

// WithRoadObserver подключает счётчик исходов административной дороги.
// Composition-root only; возвращает того же клиента, чтобы провязка читалась
// одной строкой у места сборки.
func (c *HydraAdminClient) WithRoadObserver(obs ProviderRoadObserver) *HydraAdminClient {
	c.roadObserver = obs
	return c
}

// observeStatus — учёт исхода по коду ответа поставщика. Единая точка, чтобы ни
// одна ветка возврата не осталась непосчитанной.
func (c *HydraAdminClient) observeStatus(status int) {
	observeProviderRoad(c.roadObserver, ProviderRoadAdmin, classifyProviderRoadStatus(status))
}

// observeTransportFailure — учёт исхода, когда ответа не было вовсе. Сеть и срок
// лечатся временем, поэтому клетка отдельная от настройки.
func (c *HydraAdminClient) observeTransportFailure() {
	observeProviderRoad(c.roadObserver, ProviderRoadAdmin, ProviderRoadOutcomeUnavailable)
}

// ProviderAdminHopTimeout — per-call ceiling on one admin conversation with the
// provider. Named, not inlined, for the same reason tokenHopTimeout is: a value
// nobody can reference is a value every consumer re-guesses.
//
// Здесь имя покупает ещё одно, и оно несущее. Терпение дренажа компенсаций
// ВЫВОДИТСЯ из этой величины (`cmd/kaname/provider_compensation_wiring.go`):
// при обратном соотношении разговор обрывал бы всегда дренаж, и предел клиента
// не фигурировал бы ни в одном исходе — величина была бы объявлена и не
// исполнялась бы никогда (kacho#2490). Вывести её можно только из имени;
// литерал потребитель обязан был бы угадать, а угаданные числа расходятся молча.
const ProviderAdminHopTimeout = 10 * time.Second

// NewHydraAdminClientWithCA — ЕДИНСТВЕННЫЙ конструктор клиента: им собирает
// клиента композиционный корень, и им же — пробы. Здесь стоял второй,
// без якоря, «для мест, адресующих открытый админ-API стенда разработчика»;
// таких мест в не-тестовом коде не было — корень всегда звал этот, а пустой
// caFile даёт ровно то, что давал второй. Второй конструктор собирал клиента
// иначе, чем корень, и пробы, звавшие его, судили не ту сборку.
//
// It builds the client and, when an anchor is configured, verifies the provider
// against THAT bundle and nothing else.
//
// caFile empty ⇒ the default transport, unchanged. That is not an oversight: an
// in-cluster admin API served over plaintext http needs no anchor, and inventing
// one would refuse a stand deliberately configured that way. The production boot
// guard is what forbids that combination in production (config.Validate).
//
// caFile set ⇒ the returned client trusts that bundle ALONE. Not "in addition to
// the system roots": an internal-CA hop has no business accepting a publicly
// issued certificate for the same name, and narrowing the anchor is the whole
// point of pinning it.
//
// An anchor that cannot be read, or that holds no certificate, is an ERROR rather
// than a fallback. Continuing on the system roots would produce the one state
// nobody can see — the operator has configured verification against the internal
// CA, the process is not doing it, and everything works until a certificate
// rotates.
func NewHydraAdminClientWithCA(baseURL, bearerToken, caFile string) (*HydraAdminClient, error) {
	httpClient, err := ProviderHopHTTPClient(ProviderAdminHopTimeout, caFile, adminHopCASetting)
	if err != nil {
		return nil, err
	}
	return &HydraAdminClient{
		BaseURL:     strings.TrimRight(baseURL, "/"),
		BearerToken: bearerToken,
		HTTPClient:  httpClient,
	}, nil
}

// CreateOAuthClient registers a new client_credentials OAuth2 client with
// Hydra.
//
// When `req.TokenEndpointAuthMethod == "private_key_jwt"` the
// caller supplies `req.JWKS` with the public half of the keypair; Hydra
// validates `client_assertion` (RFC 7521/7523) signatures against it and
// returns NO `client_secret`. Otherwise (legacy `client_secret_basic`)
// Hydra mints + returns the plaintext `client_secret` exactly once.
func (c *HydraAdminClient) CreateOAuthClient(ctx context.Context, req CreateOAuthClientRequest) (ProviderOAuthClient, error) {
	// ДОРОГА, КОТОРОЙ НЕТ, ОТКАЗЫВАЕТ ПЕРВОЙ (kaname#21). На посадке без
	// внешнего поставщика адрес не собран вовсе, и разбирать вход некуда:
	// отказ здесь терминальный и опознаётся `errors.Is`.
	if !c.roadIsBuilt() {
		return ProviderOAuthClient{}, c.refuseAbsentRoad("create-client")
	}
	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = defaultStr(req.AuthMethod, "client_secret_basic")
	}
	grants := req.GrantTypes
	if len(grants) == 0 {
		grants = []string{"client_credentials"}
	}
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"token"}
	}
	payload := ProviderOAuthClient{
		ClientID:                    req.ClientID,
		ClientName:                  req.ClientName,
		GrantTypes:                  grants,
		ResponseTypes:               responseTypes,
		RedirectURIs:                req.RedirectURIs,
		PostLogoutRedirectURIs:      req.PostLogoutRedirectURIs,
		Scope:                       req.Scope,
		Audience:                    req.Audience,
		Owner:                       req.Owner,
		TokenEndpointAuthMethod:     authMethod,
		TokenEndpointAuthSigningAlg: req.TokenEndpointAuthSigningAlg,
		JWKS:                        req.JWKS,
		AccessTokenLifespan:         req.AccessTokenLifespan,

		DPoPBoundAccessTokens:                 req.DPoPBoundAccessTokens,
		TLSClientCertificateBoundAccessTokens: req.TLSClientCertificateBoundAccessTokens,
	}
	// #nosec G117 -- client_secret is a legitimate field of the Hydra OAuth2 client-registration payload, not a leaked credential.
	body, err := json.Marshal(payload)
	if err != nil {
		return ProviderOAuthClient{}, fmt.Errorf("marshal create-client: %w", err)
	}
	url := c.BaseURL + "/admin/clients"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return ProviderOAuthClient{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.BearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		c.observeTransportFailure()
		return ProviderOAuthClient{}, fmt.Errorf("provider admin create-client: %w", err)
	}
	defer resp.Body.Close()
	c.observeStatus(resp.StatusCode)
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode/100 != 2 {
		return ProviderOAuthClient{}, providerAPIError(resp.StatusCode, respBody)
	}
	var out ProviderOAuthClient
	if err := json.Unmarshal(respBody, &out); err != nil {
		return ProviderOAuthClient{}, fmt.Errorf("provider admin create-client: unmarshal response: %w", err)
	}
	if out.ClientID == "" {
		return ProviderOAuthClient{}, errors.New("provider admin create-client: response carries no client_id")
	}
	return out, nil
}

// DeleteOAuthClient revokes an OAuth2 client. Returns nil on success or if
// Hydra returns 404 (idempotent).
func (c *HydraAdminClient) DeleteOAuthClient(ctx context.Context, clientID string) error {
	// ДОРОГА, КОТОРОЙ НЕТ, ОТКАЗЫВАЕТ ПЕРВОЙ (kaname#21). На посадке без
	// внешнего поставщика адрес не собран вовсе, и разбирать вход некуда:
	// отказ здесь терминальный и опознаётся `errors.Is`.
	if !c.roadIsBuilt() {
		return c.refuseAbsentRoad("delete-client")
	}
	url := c.BaseURL + "/admin/clients/" + clientID
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	if c.BearerToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		c.observeTransportFailure()
		return fmt.Errorf("provider admin delete-client: %w", err)
	}
	defer resp.Body.Close()
	// Учёт стоит ДО развилки: 404 здесь остаётся успехом вызова (см. разбор
	// размена в provider_road.go), и без учёта он был бы НЕВИДИМ — а именно он
	// отличает идемпотентное снятие от адреса, по которому наших клиентов нет.
	c.observeStatus(resp.StatusCode)
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return providerAPIError(resp.StatusCode, body)
	}
	return nil
}

func defaultStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
