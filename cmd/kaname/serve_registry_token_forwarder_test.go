// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// serve_registry_token_forwarder_test.go — ТЕМП АНОНИМНОЙ ВЫДАЧИ ЗА ПРОКСИ
// РЕЕСТРА (kaname#930).
//
// Единственный вход анонимной выдачи — прокси реестра: все клиенты приходят к
// службе с ОДНОГО пира. Ключ темпа — адрес клиента, который передаёт
// доверенный пересыльщик, опознанный проверенным клиентским сертификатом;
// пересылка от любого другого пира ключа не меняет.
//
// Полоса собирается из НАСТРОЙКИ службы (env → Load → страж старта →
// переложение корня → сборка), как у соседних проб анонимного потока: ручка,
// не доехавшая до сборки, видна здесь исходом, а не чтением кода.

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/handler/registrytokenhttp"
	"github.com/PRO-Robotech/kaname/internal/issuingsource"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// registryProxyPeer — адрес пода прокси реестра: пир соединения у всех
// клиентов за ним.
const registryProxyPeer = "10.0.0.5:44100"

// pullVia — анонимный вход клиента client через пира с сертификатом san
// (пусто — без сертификата; verified=false — цепочка не проверена слушателем).
func pullVia(t *testing.T, h http.Handler, san string, verified bool, client string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, registrytokenhttp.TokenPath+
		"?service="+anonLaneService+"&scope=repository:pub/app:pull", nil)
	req.RemoteAddr = registryProxyPeer
	req.Header.Set("X-Forwarded-For", client)
	req.TLS = &tls.ConnectionState{}
	if san != "" {
		u, err := url.Parse(san)
		if err != nil {
			t.Fatalf("разбор SAN %q: %v", san, err)
		}
		leaf := &x509.Certificate{URIs: []*url.URL{u}}
		req.TLS.PeerCertificates = []*x509.Certificate{leaf}
		if verified {
			req.TLS.VerifiedChains = [][]*x509.Certificate{{leaf}}
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// Два клиента за одним доверенным пересыльщиком получают НЕЗАВИСИМЫЕ темпы:
// исчерпание темпа первым не отказывает второму.
func TestAnonymousRegistryToken_TwoClientsBehindTheTrustedForwarderHaveTheirOwnPace(t *testing.T) {
	h := anonymousLaneFromSettings(t, anonLanePrincipal, "1", nil)
	if code := pullVia(t, h, anonLaneForwarderSAN, true, "203.0.113.1"); code != http.StatusOK {
		t.Fatalf("первый вход клиента A: статус %d", code)
	}
	if code := pullVia(t, h, anonLaneForwarderSAN, true, "203.0.113.1"); code != http.StatusTooManyRequests {
		t.Fatalf("второй вход клиента A при темпе 1 в секунду: статус %d, ждали 429", code)
	}
	if code := pullVia(t, h, anonLaneForwarderSAN, true, "203.0.113.2"); code != http.StatusOK {
		t.Fatalf("клиент B за тем же пересыльщиком получил отказ темпа клиента A: статус %d, ждали 200", code)
	}
}

// Близнец: пересылка от пира, который НЕ доверенный пересыльщик, ключа не
// меняет — разные адреса в заголовке делят один темп пира. Отличие от пробы
// выше — ровно личность пира.
func TestAnonymousRegistryToken_ForwardingFromAnUntrustedPeerDoesNotChangeTheKey(t *testing.T) {
	for name, peer := range map[string]struct {
		san      string
		verified bool
	}{
		"без сертификата":      {"", false},
		"сертификат соседа":    {"spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc", true},
		"цепочка не проверена": {anonLaneForwarderSAN, false},
	} {
		t.Run(name, func(t *testing.T) {
			h := anonymousLaneFromSettings(t, anonLanePrincipal, "1", nil)
			if code := pullVia(t, h, peer.san, peer.verified, "203.0.113.1"); code != http.StatusOK {
				t.Fatalf("первый вход: статус %d", code)
			}
			if code := pullVia(t, h, peer.san, peer.verified, "203.0.113.2"); code != http.StatusTooManyRequests {
				t.Fatalf("заголовок недоверенного пира сменил ключ темпа: статус %d, ждали 429", code)
			}
		})
	}
}

// registryTokenFallbackRow — строка ряда переписи точки анонимной выдачи по
// причине reason на витрине реестра reg.
func registryTokenFallbackRow(t *testing.T, reg *metrics.Registry, reason string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	prefix := metrics.RegistryTokenSourceFallbacksMetric + `{reason="` + reason + `"} `
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	t.Fatalf("на витрине нет ряда %q", prefix)
	return ""
}

// Пересылка от пира, который не доверенный пересыльщик, ВИДНА оператору: ряд
// переписи точки на витрине растёт на каждый такой вход. Без него неверно
// названный пересыльщик (все клиенты за прокси реестра делят один темп)
// неотличим от залпа одного клиента: оба дают только рост
// `anonymous_pace_exceeded`. Близнец — те же входы от доверенного
// пересыльщика: ряд остаётся нулём. Полоса и витрина собраны переходниками
// корня, теми же, что провязывает serve.go.
func TestAnonymousRegistryToken_ForwardingFromAnUntrustedPeerIsCountedOnTheShowcase(t *testing.T) {
	for name, tc := range map[string]struct {
		san      string
		verified bool
		want     string
	}{
		"сосед с заголовком":              {"spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc", true, "2"},
		"другое пространство имён":        {"spiffe://kacho.cloud/ns/other/sa/kacho-registry", true, "2"},
		"близнец: доверенный пересыльщик": {anonLaneForwarderSAN, true, "0"},
	} {
		t.Run(name, func(t *testing.T) {
			rule := issuingsource.New(grpcsrv.NewTrustDomain(anonLaneTrustDomain), moduleidentity.Roster{})
			reg := metrics.NewRegistry()
			reg.NewRegistryTokenSourceFallbackCollector(registryTokenSourceFallbackReasons(), registryTokenSourceFallbackReader(rule))
			h := anonymousLaneWithSourceRule(t, anonLanePrincipal, "5", nil, rule)
			if row := registryTokenFallbackRow(t, reg, unrecognizedPeerReason); !strings.HasSuffix(row, " 0") {
				t.Fatalf("до первого входа ряд не ноль: %q", row)
			}
			for _, client := range []string{"203.0.113.1", "203.0.113.2"} {
				if code := pullVia(t, h, tc.san, tc.verified, client); code != http.StatusOK {
					t.Fatalf("вход клиента %s: статус %d", client, code)
				}
			}
			if row := registryTokenFallbackRow(t, reg, unrecognizedPeerReason); !strings.HasSuffix(row, " "+tc.want) {
				t.Fatalf("ряд после двух входов: %q, ждали значение %s", row, tc.want)
			}
		})
	}
}

// Метки рядов переписи точки анонимной выдачи — строками витрины: проба держит
// то, что читает оператор, а не константу правила.
const (
	unrecognizedPeerReason   = "forwarded-from-unrecognized-peer"
	edgeWithoutAddressReason = "edge-without-address"
)

// Объявленный пересыльщик без годного адреса ВИДЕН оператору (kaname#935): ряд
// edge-without-address растёт на +1 за каждый такой вход. Прокси реестра, не
// передающий адрес клиента или передающий список, сводит всех клиентов за
// собой к одному ключу темпа — без ряда это неотличимо от залпа одного
// клиента. Близнец — тот же пересыльщик с одним адресом: ряд остаётся нулём;
// строки отличаются ровно значением заголовка. Соседний ряд точки не
// двигается ни в одной строке. Полоса и витрина собраны переходниками корня,
// теми же, что провязывает serve.go.
func TestAnonymousRegistryToken_TrustedForwarderWithoutUsableAddressIsCountedOnTheShowcase(t *testing.T) {
	for name, tc := range map[string]struct {
		clients []string
		want    string
	}{
		"список адресов":      {[]string{"203.0.113.1, 198.51.100.1", "203.0.113.2, 198.51.100.1"}, "2"},
		"не адрес":            {[]string{"not-an-address"}, "1"},
		"пустое значение":     {[]string{""}, "1"},
		"близнец: один адрес": {[]string{"203.0.113.1", "203.0.113.2"}, "0"},
	} {
		t.Run(name, func(t *testing.T) {
			rule := issuingsource.New(grpcsrv.NewTrustDomain(anonLaneTrustDomain), moduleidentity.Roster{})
			reg := metrics.NewRegistry()
			reg.NewRegistryTokenSourceFallbackCollector(registryTokenSourceFallbackReasons(), registryTokenSourceFallbackReader(rule))
			h := anonymousLaneWithSourceRule(t, anonLanePrincipal, "5", nil, rule)
			if row := registryTokenFallbackRow(t, reg, edgeWithoutAddressReason); !strings.HasSuffix(row, " 0") {
				t.Fatalf("до первого входа ряд не ноль: %q", row)
			}
			for _, client := range tc.clients {
				if code := pullVia(t, h, anonLaneForwarderSAN, true, client); code != http.StatusOK {
					t.Fatalf("вход с заголовком %q: статус %d", client, code)
				}
			}
			if row := registryTokenFallbackRow(t, reg, edgeWithoutAddressReason); !strings.HasSuffix(row, " "+tc.want) {
				t.Fatalf("ряд после %d входов: %q, ждали значение %s", len(tc.clients), row, tc.want)
			}
			if row := registryTokenFallbackRow(t, reg, unrecognizedPeerReason); !strings.HasSuffix(row, " 0") {
				t.Fatalf("соседний ряд точки сдвинулся: %q", row)
			}
		})
	}
}

// anonymousLaneConfig — настройка с поднятым слушателем и объявленным
// анонимным потоком, без церемонии.
func anonymousLaneConfig() config.Config {
	var cfg config.Config
	cfg.APIServer.RegistryToken = config.RegistryTokenConfig{
		Endpoint: "tcp://0.0.0.0:9096", Service: anonLaneService, Issuer: anonLaneIssuer,
		AnonymousClientID: anonLanePrincipal, AnonymousPerSourcePerSec: 5,
		AnonymousForwarderSAN: anonLaneForwarderSAN,
	}
	return cfg
}

// Анонимный поток на слушателе, который сертификата не запрашивает: личность
// пересыльщика не проверялась бы ни разу, и ключом темпа молча остался бы адрес
// прокси реестра. Отказ старта называет ручку и требуемое значение; близнецы —
// запрашивающий режим и посадка без анонимного потока.
func TestKN930_AnonymousLaneRefusesAListenerThatDoesNotAskForACertificate(t *testing.T) {
	const knob = "KANAME_REGISTRYTOKEN_SERVER_MTLS_CLIENTAUTHMODE"
	listener := func(mode string) config.MTLSConfig {
		var m config.MTLSConfig
		m.RegistryTokenServerMTLS = grpcsrv.TLSServer{Enable: true, CertFile: "/tls/tls.crt", KeyFile: "/tls/tls.key",
			ClientCAFiles: []string{"/tls/ca.crt"}}
		m.RegistryTokenClientAuthMode = mode
		return m
	}
	for _, mode := range []string{"server-tls-only", "mutual", ""} {
		t.Run("режим "+mode, func(t *testing.T) {
			err := requireIssuingListenerAsksForACertificate(anonymousLaneConfig(), listener(mode))
			if err == nil {
				t.Fatal("анонимный поток на слушателе без запроса сертификата стартовал")
			}
			for _, want := range []string{knob, "optional-mutual", "anonymous"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("отказ не называет %q: %v", want, err)
				}
			}
		})
	}
	t.Run("близнец: optional-mutual", func(t *testing.T) {
		if err := requireIssuingListenerAsksForACertificate(anonymousLaneConfig(), listener("optional-mutual")); err != nil {
			t.Errorf("законный режим отвергнут: %v", err)
		}
	})
	t.Run("близнец: анонимного потока нет", func(t *testing.T) {
		cfg := anonymousLaneConfig()
		cfg.APIServer.RegistryToken.AnonymousClientID = ""
		if err := requireIssuingListenerAsksForACertificate(cfg, listener("server-tls-only")); err != nil {
			t.Errorf("без анонимного потока режим слушателя не судится: %v", err)
		}
	})
}
