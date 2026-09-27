// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/PRO-Robotech/corelib/oauthceremony"
)

// DiscoveryConfig — что публикуют метаданные. Все поля — публичный материал
// (приёмка Р11): координаты и словари, ни секретов, ни данных арендатора, ни
// инфраструктуры.
type DiscoveryConfig struct {
	// Issuer — наш издатель, ДОСЛОВНО тот, что стоит в `iss` выпускаемых
	// токенов (RFC 8414 §3.3).
	Issuer string
	// AuthorizationEndpoint, TokenEndpoint — адреса точек (см. Endpoints).
	AuthorizationEndpoint string
	TokenEndpoint         string
	// GrantTypes — виды выдачи токен-эндпоинта: церемонии и машинные полосы.
	GrantTypes []string
	// Scopes — области, которые интерактивный клиент вправе запросить.
	Scopes []string
}

// metadata — документ RFC 8414 §2. Способы аутентификации клиента на
// токен-эндпоинте НЕ публикуются: умолчание стандарта — секрет в заголовке
// Basic, и оно верно для конфиденциального клиента церемонии.
type metadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	ResponseModesSupported        []string `json:"response_modes_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	ScopesSupported               []string `json:"scopes_supported"`
}

// Discovery — метаданные обнаружения `GET /.well-known/oauth-authorization-server`:
// публичное неаутентифицированное чтение (паритет с набором ключей).
type Discovery struct {
	body []byte
}

// NewDiscovery собирает документ ОДИН раз: у него нет состояния, и каждый ответ
// побайтово один и тот же.
func NewDiscovery(cfg DiscoveryConfig) (*Discovery, error) {
	switch {
	case strings.TrimSpace(cfg.Issuer) == "":
		return nil, errors.New("ceremonyhttp: discovery needs the issuer")
	case cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "":
		return nil, errors.New("ceremonyhttp: discovery needs both endpoints")
	case len(cfg.GrantTypes) == 0 || len(cfg.Scopes) == 0:
		return nil, errors.New("ceremonyhttp: discovery needs the grant types and the scopes")
	}
	methods := make([]string, 0, len(oauthceremony.ProofKeyMethods()))
	for _, m := range oauthceremony.ProofKeyMethods() {
		methods = append(methods, string(m))
	}
	body, err := json.Marshal(metadata{
		Issuer:                        cfg.Issuer,
		AuthorizationEndpoint:         cfg.AuthorizationEndpoint,
		TokenEndpoint:                 cfg.TokenEndpoint,
		ResponseTypesSupported:        []string{string(oauthceremony.ResponseKindCode)},
		ResponseModesSupported:        []string{string(oauthceremony.DeliveryQuery)},
		GrantTypesSupported:           append([]string(nil), cfg.GrantTypes...),
		CodeChallengeMethodsSupported: methods,
		ScopesSupported:               append([]string(nil), cfg.Scopes...),
	})
	if err != nil {
		return nil, fmt.Errorf("ceremonyhttp: discovery document: %w", err)
	}
	return &Discovery{body: append(body, '\n')}, nil
}

// ServeHTTP — только GET.
func (d *Discovery) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, errorBody("invalid_request"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(d.body)
}
