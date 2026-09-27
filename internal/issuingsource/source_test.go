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
)

const (
	trustDomain = "kacho.cloud"
	edgeSAN     = "spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"
	neighborSAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc"
	peer        = "192.0.2.10"
)

func newRule(t *testing.T) *issuingsource.Rule {
	t.Helper()
	return issuingsource.New(grpcsrv.NewTrustDomain(trustDomain))
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
