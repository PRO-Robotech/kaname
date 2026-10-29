// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// source_test.go — правило адреса источника поверхности выдачи (Р7 приёмки
// ceremony-pace-is-named-by-number.md, kaname#315).
//
// Здесь правило судится на разобранном запросе: состояние рукопожатия задаётся
// проверенной цепочкой, как её оставляет слушатель. Настоящий слушатель в режиме
// optional-mutual с тестовым УЦ — в пробах точек (группа F).
package issuingsource_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/issuingsource"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/servicesan"
)

const (
	trustDomain = "kacho.cloud"
	edgeSAN     = "spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"
	neighborSAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc"
	peer        = "192.0.2.10"
)

func newRule(t *testing.T) *issuingsource.Rule {
	t.Helper()
	roster, err := moduleidentity.Parse(servicesan.NewForm("kacho-{service}"), []string{"kacho/kacho-api-gateway=edge", "kacho/kacho-vpc=module-writer"})
	require.NoError(t, err)
	return issuingsource.New(grpcsrv.NewTrustDomain(trustDomain), roster)
}

// request — запрос от пира с адреса peer; san пуст — сертификата нет.
func request(t *testing.T, san string, header http.Header) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/iam/v1/authorize", nil)
	r.RemoteAddr = peer + ":40000"
	for k, vs := range header {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	if san != "" {
		u, err := url.Parse(san)
		require.NoError(t, err)
		leaf := &x509.Certificate{URIs: []*url.URL{u}}
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf},
			VerifiedChains: [][]*x509.Certificate{{leaf}}}
	} else {
		r.TLS = &tls.ConnectionState{}
	}
	return r
}

func xff(values ...string) http.Header {
	h := http.Header{}
	for _, v := range values {
		h.Add("X-Forwarded-For", v)
	}
	return h
}

// requireCells — клетки переписи равны ожидаемым; не названные — нулю.
func requireCells(t *testing.T, r *issuingsource.Rule, want map[issuingsource.Cell]uint64) {
	t.Helper()
	got := r.Read()
	require.Len(t, got, 4, "перепись несёт четыре клетки — (authorize, token) × (две причины)")
	for _, c := range issuingsource.Cells() {
		require.Equalf(t, want[c], got[c], "клетка %s/%s", c.Point, c.Reason)
	}
}

// KN-PACE-32 на правиле: край с одним адресом — ключ есть этот адрес, клетки
// не двигаются.
func TestEdgeWithOneAddressKeysByTheClient(t *testing.T) {
	r := newRule(t)
	require.Equal(t, "203.0.113.7", r.Of(request(t, edgeSAN, xff("203.0.113.7")), issuingsource.PointAuthorize))
	require.Equal(t, "2001:db8::7", r.Of(request(t, edgeSAN, xff("2001:db8::7")), issuingsource.PointToken),
		"IPv6 одним значением — тоже адрес")
	requireCells(t, r, nil)
}

// KN-PACE-33 на правиле: пир без сертификата с заголовком — ключ есть пир,
// заголовок не прочитан и посчитан.
func TestHeaderWithoutEdgeCertificateDoesNotChangeTheKey(t *testing.T) {
	r := newRule(t)
	for _, h := range []http.Header{
		xff("203.0.113.1"),
		{"Forwarded": {"for=203.0.113.1"}},
		{"X-Real-Ip": {"203.0.113.1"}},
	} {
		require.Equal(t, peer, r.Of(request(t, "", h), issuingsource.PointAuthorize))
	}
	requireCells(t, r, map[issuingsource.Cell]uint64{
		{Point: issuingsource.PointAuthorize, Reason: issuingsource.ReasonForwardedFromNonEdge}: 3,
	})
}

// Законный близнец 33: пир без сертификата и без заголовка — ключ пир, счёта нет.
func TestDirectCallerWithoutHeaderIsNotAFallback(t *testing.T) {
	r := newRule(t)
	require.Equal(t, peer, r.Of(request(t, "", nil), issuingsource.PointToken))
	requireCells(t, r, nil)
}

// KN-PACE-34 на правиле: сертификат соседа — не сертификат края.
func TestNeighborCertificateIsNotTheEdge(t *testing.T) {
	r := newRule(t)
	require.Equal(t, peer, r.Of(request(t, neighborSAN, xff("203.0.113.1")), issuingsource.PointToken))
	requireCells(t, r, map[issuingsource.Cell]uint64{
		{Point: issuingsource.PointToken, Reason: issuingsource.ReasonForwardedFromNonEdge}: 1,
	})
}

// kaname#984 на правиле: лист с учёткой края из НЕОБЪЯВЛЕННОГО пространства —
// не край. Ключ — адрес пира, заголовок не читается; близнец — тот же
// заголовок от объявленной пары края — читается.
func TestEdgeAccountFromAnUndeclaredNamespaceIsNotTheEdge(t *testing.T) {
	r := newRule(t)
	intruder := "spiffe://kacho.cloud/ns/intruder/sa/kacho-api-gateway"
	require.Equal(t, peer, r.Of(request(t, intruder, xff("203.0.113.1")), issuingsource.PointToken))
	requireCells(t, r, map[issuingsource.Cell]uint64{
		{Point: issuingsource.PointToken, Reason: issuingsource.ReasonForwardedFromNonEdge}: 1,
	})
	require.Equal(t, "203.0.113.1", r.Of(request(t, edgeSAN, xff("203.0.113.1")), issuingsource.PointToken),
		"близнец: объявленная пара края — край")
}

// KN-PACE-35 на правиле: край без годного адреса делит ключ своего пира.
func TestEdgeWithoutUsableAddressSharesItsPeerKey(t *testing.T) {
	r := newRule(t)
	for name, h := range map[string]http.Header{
		"заголовка нет":    nil,
		"два значения":     xff("203.0.113.7", "198.51.100.2"),
		"список":           xff("203.0.113.7, 198.51.100.2"),
		"не адрес":         xff("not-an-address"),
		"адрес с зоной":    xff("fe80::1%eth0"),
		"пустое значение":  xff(""),
		"адрес с портом":   xff("203.0.113.7:443"),
		"адрес в скобках":  xff("[2001:db8::7]"),
		"адрес и пробелы2": xff("203.0.113.7 198.51.100.2"),
	} {
		require.Equalf(t, peer, r.Of(request(t, edgeSAN, h), issuingsource.PointAuthorize), "строка %q", name)
	}
	requireCells(t, r, map[issuingsource.Cell]uint64{
		{Point: issuingsource.PointAuthorize, Reason: issuingsource.ReasonEdgeWithoutAddress}: 9,
	})
}

// Цепочка без проверки — не край: сертификат, который слушатель не проверил,
// личности не доказывает.
func TestUnverifiedCertificateIsNotTheEdge(t *testing.T) {
	r := newRule(t)
	req := request(t, edgeSAN, xff("203.0.113.7"))
	req.TLS.VerifiedChains = nil
	require.Equal(t, peer, r.Of(req, issuingsource.PointAuthorize))
	requireCells(t, r, map[issuingsource.Cell]uint64{
		{Point: issuingsource.PointAuthorize, Reason: issuingsource.ReasonForwardedFromNonEdge}: 1,
	})
}

// KN-PACE-37 на правиле: четыре клетки засеяны нулями до первого запроса.
func TestCensusIsSeededWithZeroes(t *testing.T) {
	r := newRule(t)
	require.Len(t, issuingsource.Cells(), 4)
	requireCells(t, r, nil)
	names := map[string]bool{}
	for _, c := range issuingsource.Cells() {
		names[string(c.Point)+"/"+string(c.Reason)] = true
	}
	require.Equal(t, map[string]bool{
		"authorize/forwarded-from-non-edge": true, "authorize/edge-without-address": true,
		"token/forwarded-from-non-edge": true, "token/edge-without-address": true,
	}, names)
}

// TestRegistryTokenPointFollowsTheRuleAndLeavesTheCensusClosed — источник
// анонимного входа докерной полосы (kaname#928) выводится тем же правилом
// (пп. 1–3): адрес от края только при проверенном сертификате края, иначе адрес
// пира. Словарь переписи п. 4 закрыт двумя точками приёмки, и третья точка его
// не двигает.
func TestRegistryTokenPointFollowsTheRuleAndLeavesTheCensusClosed(t *testing.T) {
	r := newRule(t)
	require.Equal(t, "203.0.113.7", r.RegistryTokenPoint("")(request(t, edgeSAN, xff("203.0.113.7"))),
		"край с одним адресом — источник из заголовка")
	require.Equal(t, peer, r.RegistryTokenPoint("")(request(t, "", xff("203.0.113.7"))),
		"заголовок пересылки без сертификата края не меняет ключа")
	require.Equal(t, peer, r.RegistryTokenPoint("")(request(t, neighborSAN, xff("203.0.113.7"))),
		"чужой проверенный сертификат краем не считается")
	require.Equal(t, peer, r.RegistryTokenPoint("")(request(t, edgeSAN, xff("203.0.113.7, 198.51.100.1"))),
		"край без годного адреса делит ключ своего пира")
	requireCells(t, r, nil)
	require.Len(t, issuingsource.Cells(), 4)
}

// registryForwarderSAN — прокси реестра, объявленный доверенным пересыльщиком
// точки анонимной выдачи (kaname#930).
const registryForwarderSAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-registry"

// TestRegistryTokenPointTwoClientsBehindTheTrustedForwarderKeyApart — два
// клиента за одним доверенным пересыльщиком получают РАЗНЫЕ ключи темпа: адрес
// клиента из одного значения X-Forwarded-For, а не адрес пересыльщика
// (kaname#930). Пир у обоих один — под прокси реестра.
func TestRegistryTokenPointTwoClientsBehindTheTrustedForwarderKeyApart(t *testing.T) {
	r := newRule(t)
	source := r.RegistryTokenPoint(registryForwarderSAN)
	require.Equal(t, "203.0.113.1", source(request(t, registryForwarderSAN, xff("203.0.113.1"))))
	require.Equal(t, "203.0.113.2", source(request(t, registryForwarderSAN, xff("203.0.113.2"))))
	require.Equal(t, "2001:db8::7", source(request(t, registryForwarderSAN, xff("2001:db8::7"))),
		"IPv6 одним значением — тоже адрес")
	requireCells(t, r, nil)
}

// Близнец: пересылка от пира, который НЕ объявленный пересыльщик, ключа не
// меняет — ключ остаётся адресом пира. Строки различаются от положительной
// пробы выше ровно личностью пира.
func TestRegistryTokenPointIgnoresForwardingFromAnUntrustedPeer(t *testing.T) {
	r := newRule(t)
	source := r.RegistryTokenPoint(registryForwarderSAN)
	unverified := request(t, registryForwarderSAN, xff("203.0.113.1"))
	unverified.TLS.VerifiedChains = nil
	for name, req := range map[string]*http.Request{
		"без сертификата":          request(t, "", xff("203.0.113.1")),
		"сертификат соседа":        request(t, neighborSAN, xff("203.0.113.1")),
		"цепочка не проверена":     unverified,
		"чужой домен доверия":      request(t, "spiffe://other.example/ns/kacho/sa/kacho-registry", xff("203.0.113.1")),
		"другое пространство имён": request(t, "spiffe://kacho.cloud/ns/other/sa/kacho-registry", xff("203.0.113.1")),
	} {
		require.Equalf(t, peer, source(req), "строка %q", name)
	}
	requireCells(t, r, nil)
}

// Близнец: тот же сертификат прокси реестра при НЕобъявленном пересыльщике
// личности пересыльщика не даёт — доверие задаёт ручка, а не сертификат.
func TestRegistryTokenPointWithoutDeclaredForwarderKeysByThePeer(t *testing.T) {
	r := newRule(t)
	require.Equal(t, peer, r.RegistryTokenPoint("")(request(t, registryForwarderSAN, xff("203.0.113.1"))))
}

// Пересыльщик без годного адреса делит ключ своего пира — как край (п. 3):
// нового ключа он не получает.
func TestRegistryTokenPointForwarderWithoutUsableAddressSharesItsPeerKey(t *testing.T) {
	r := newRule(t)
	source := r.RegistryTokenPoint(registryForwarderSAN)
	for name, h := range map[string]http.Header{
		"заголовка нет":  nil,
		"два значения":   xff("203.0.113.7", "198.51.100.2"),
		"список":         xff("203.0.113.7, 198.51.100.2"),
		"не адрес":       xff("not-an-address"),
		"адрес с портом": xff("203.0.113.7:443"),
	} {
		require.Equalf(t, peer, source(request(t, registryForwarderSAN, h)), "строка %q", name)
	}
}

// Доверие пересыльщику ограничено ТОЧКОЙ анонимной выдачи: на точках приёмки
// (авторизация, токен-эндпоинт) его заголовок не читается и считается.
func TestForwarderIsNotTrustedOnTheAcceptancePoints(t *testing.T) {
	r := newRule(t)
	_ = r.RegistryTokenPoint(registryForwarderSAN)
	require.Equal(t, peer, r.Of(request(t, registryForwarderSAN, xff("203.0.113.1")), issuingsource.PointAuthorize))
	require.Equal(t, peer, r.TokenPoint(request(t, registryForwarderSAN, xff("203.0.113.1"))))
	requireCells(t, r, map[issuingsource.Cell]uint64{
		{Point: issuingsource.PointAuthorize, Reason: issuingsource.ReasonForwardedFromNonEdge}: 1,
		{Point: issuingsource.PointToken, Reason: issuingsource.ReasonForwardedFromNonEdge}:     1,
	})
}

// requireRegistryTokenCensus — перепись точки анонимной выдачи равна
// ожидаемой; не названные причины — нулю.
func requireRegistryTokenCensus(t *testing.T, r *issuingsource.Rule, want map[issuingsource.RegistryTokenReason]uint64) {
	t.Helper()
	got := r.ReadRegistryTokenPoint()
	require.Len(t, got, len(issuingsource.RegistryTokenReasons()),
		"перепись точки несёт ровно клетки своего словаря")
	for _, reason := range issuingsource.RegistryTokenReasons() {
		require.Equalf(t, want[reason], got[reason], "причина %s", reason)
	}
}

// Перепись точки анонимной выдачи засеяна нулём до первого запроса: клетка,
// появляющаяся при первом попадании, не отличает «ноль случаев» от «счёта
// нет». Словарь закрыт и отделён от словаря п. 4 приёмки.
func TestRegistryTokenPointCensusIsSeededWithZeros(t *testing.T) {
	r := newRule(t)
	require.Equal(t, []issuingsource.RegistryTokenReason{
		issuingsource.RegistryTokenReasonForwardedFromUnrecognizedPeer,
		registryEdgeWithoutAddress,
	}, issuingsource.RegistryTokenReasons())
	require.Equal(t, "forwarded-from-unrecognized-peer",
		string(issuingsource.RegistryTokenReasonForwardedFromUnrecognizedPeer))
	require.Equal(t, registryEdgeWithoutAddress, issuingsource.RegistryTokenReasonEdgeWithoutAddress,
		"метка клетки — та же, что у клетки п. 4 точек приёмки")
	requireRegistryTokenCensus(t, r, nil)
	requireCells(t, r, nil)
}

// Заголовок пересылки от проверенного или непроверенного пира, который ни
// край, ни объявленный пересыльщик точки, на точке анонимной выдачи СЧИТАЕТСЯ:
// при неверно названном пересыльщике все клиенты за прокси реестра делят один
// ключ темпа, и без этого счёта такая посадка неотличима от залпа одного
// клиента (kaname#930). Каждая строка — один запрос и ровно +1; словарь п. 4
// приёмки при этом не двигается.
func TestRegistryTokenPointCountsForwardingFromAnUnrecognizedPeer(t *testing.T) {
	unverified := func(t *testing.T) *http.Request {
		req := request(t, registryForwarderSAN, xff("203.0.113.1"))
		req.TLS.VerifiedChains = nil
		return req
	}
	for name, build := range map[string]func(*testing.T) *http.Request{
		"без сертификата":      func(t *testing.T) *http.Request { return request(t, "", xff("203.0.113.1")) },
		"сертификат соседа":    func(t *testing.T) *http.Request { return request(t, neighborSAN, xff("203.0.113.1")) },
		"цепочка не проверена": unverified,
		"чужой домен доверия": func(t *testing.T) *http.Request {
			return request(t, "spiffe://other.example/ns/kacho/sa/kacho-registry", xff("203.0.113.1"))
		},
		"другое пространство имён": func(t *testing.T) *http.Request {
			return request(t, "spiffe://kacho.cloud/ns/other/sa/kacho-registry", xff("203.0.113.1"))
		},
		"заголовок Forwarded": func(t *testing.T) *http.Request {
			return request(t, neighborSAN, http.Header{"Forwarded": []string{"for=203.0.113.1"}})
		},
		"заголовок X-Real-Ip": func(t *testing.T) *http.Request {
			return request(t, neighborSAN, http.Header{"X-Real-Ip": []string{"203.0.113.1"}})
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRule(t)
			source := r.RegistryTokenPoint(registryForwarderSAN)
			require.Equal(t, peer, source(build(t)))
			requireRegistryTokenCensus(t, r, map[issuingsource.RegistryTokenReason]uint64{
				issuingsource.RegistryTokenReasonForwardedFromUnrecognizedPeer: 1,
			})
			requireCells(t, r, nil)
		})
	}
}

// Близнец: тот же запрос от ОБЪЯВЛЕННОГО пересыльщика и от края счёта не
// двигает — строки отличаются от отрицательных выше ровно личностью пира.
// Запрос без заголовка пересылки не считается тоже: заголовка не было.
func TestRegistryTokenPointLeavesTheCensusForRecognizedPeers(t *testing.T) {
	r := newRule(t)
	source := r.RegistryTokenPoint(registryForwarderSAN)
	require.Equal(t, "203.0.113.1", source(request(t, registryForwarderSAN, xff("203.0.113.1"))))
	require.Equal(t, "203.0.113.2", source(request(t, edgeSAN, xff("203.0.113.2"))))
	require.Equal(t, peer, source(request(t, neighborSAN, nil)))
	requireRegistryTokenCensus(t, r, nil)
	requireCells(t, r, nil)
}

// Перепись точки анонимной выдачи не смешивается с переписью точек приёмки:
// тот же пир-сосед с заголовком двигает клетку своей точки, и только её.
func TestRegistryTokenPointCensusIsSeparateFromTheAcceptancePoints(t *testing.T) {
	r := newRule(t)
	_ = r.RegistryTokenPoint(registryForwarderSAN)(request(t, neighborSAN, xff("203.0.113.1")))
	_ = r.TokenPoint(request(t, neighborSAN, xff("203.0.113.1")))
	requireRegistryTokenCensus(t, r, map[issuingsource.RegistryTokenReason]uint64{
		issuingsource.RegistryTokenReasonForwardedFromUnrecognizedPeer: 1,
	})
	requireCells(t, r, map[issuingsource.Cell]uint64{
		{Point: issuingsource.PointToken, Reason: issuingsource.ReasonForwardedFromNonEdge}: 1,
	})
}

// registryEdgeWithoutAddress — клетка точки анонимной выдачи «край или
// объявленный пересыльщик без годного адреса» (kaname#935). Записана строкой
// метки витрины, а не константой правила: метка — то, что читает оператор, и
// проба держит именно её.
const registryEdgeWithoutAddress = issuingsource.RegistryTokenReason("edge-without-address")

// Край или объявленный пересыльщик без годного адреса на точке анонимной
// выдачи СЧИТАЕТСЯ (kaname#935): ключом темпа стал адрес пира, и все клиенты
// за прокси реестра делят один предел. Без счёта такая посадка (прокси не
// передаёт адрес клиента либо передаёт список) неотличима от залпа одного
// клиента — оба видны только отказами по темпу. Каждая строка — один запрос и
// ровно +1 в клетке edge-without-address; соседняя клетка точки и словарь п. 4
// приёмки при этом не двигаются. Законный близнец — тот же пир с одним
// адресом — в TestRegistryTokenPointLeavesTheCensusForRecognizedPeers: строки
// отличаются от него ровно значением заголовка.
func TestRegistryTokenPointCountsARecognizedPeerWithoutUsableAddress(t *testing.T) {
	for name, tc := range map[string]struct {
		san    string
		header http.Header
	}{
		"пересыльщик: заголовка нет":  {registryForwarderSAN, nil},
		"пересыльщик: два значения":   {registryForwarderSAN, xff("203.0.113.7", "198.51.100.2")},
		"пересыльщик: список":         {registryForwarderSAN, xff("203.0.113.7, 198.51.100.2")},
		"пересыльщик: не адрес":       {registryForwarderSAN, xff("not-an-address")},
		"пересыльщик: адрес с портом": {registryForwarderSAN, xff("203.0.113.7:443")},
		"пересыльщик: адрес с зоной":  {registryForwarderSAN, xff("fe80::1%eth0")},
		"край: заголовка нет":         {edgeSAN, nil},
		"край: список":                {edgeSAN, xff("203.0.113.7, 198.51.100.2")},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRule(t)
			source := r.RegistryTokenPoint(registryForwarderSAN)
			require.Equal(t, peer, source(request(t, tc.san, tc.header)),
				"пир без годного адреса делит ключ своего пира")
			got := r.ReadRegistryTokenPoint()
			require.Equalf(t, uint64(1), got[registryEdgeWithoutAddress],
				"клетка %s точки анонимной выдачи после одного запроса без годного адреса; перепись %v",
				registryEdgeWithoutAddress, got)
			require.Contains(t, issuingsource.RegistryTokenReasons(), registryEdgeWithoutAddress,
				"клетка объявлена в закрытом словаре точки — иначе витрина её не печатает")
			requireRegistryTokenCensus(t, r, map[issuingsource.RegistryTokenReason]uint64{
				registryEdgeWithoutAddress: 1,
			})
			requireCells(t, r, nil)
		})
	}
}
