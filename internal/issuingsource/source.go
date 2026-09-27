// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package issuingsource — правило адреса источника поверхности выдачи: одно на
// точку авторизации и на токен-эндпоинт (приёмка
// ceremony-pace-is-named-by-number.md, Р7; kaname#315).
//
// # Правило
//
//  1. Слушатель выдачи ЗАПРАШИВАЕТ клиентский сертификат и проверяет
//     предъявленный (`optional-mutual`); вызывающий без сертификата допускается.
//  2. Пир предъявил ПРОВЕРЕННЫЙ сертификат края — источник есть значение
//     `X-Forwarded-For`, когда это ровно один адрес IPv4 или IPv6 одним
//     значением заголовка.
//  3. Во всех остальных случаях источник есть адрес пира соединения, а
//     `X-Forwarded-For`, `Forwarded` и `X-Real-IP` не читаются.
//  4. Каждый случай п.3, где заголовок был и не прочитан или край адреса не
//     дал, считается в закрытом словаре клеток ([Cells]), засеянном нулями.
//
// Край узнаётся тем же признаком, что у полосы входа и яруса gateway-only:
// короткое имя службы из SAN проверенного сертификата
// ([authzguard.PeerIsGateway]). Сертификат, который слушатель не проверил,
// личности не доказывает и краем не считается.
//
// Правило закрывает оба направления подмены: заголовок без сертификата края
// ключа не меняет, а край без годного адреса нового ключа не получает — он
// делит ключ своего пира. Необъявленный домен доверия не узнаёт края вовсе:
// тогда источник — всегда адрес пира, и всякий заголовок пересылки посчитан.
package issuingsource

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
)

// HeaderForwardedFor — единственный заголовок, который правило читает, и
// только у края.
const HeaderForwardedFor = "X-Forwarded-For"

// forwardingHeaders — заголовки пересылки, чьё присутствие у пира, который не
// край, считается (п.4): ни один из них не читается.
var forwardingHeaders = []string{HeaderForwardedFor, "Forwarded", "X-Real-Ip"}

// Point — точка поверхности выдачи.
type Point string

// Точки поверхности выдачи.
const (
	PointAuthorize Point = "authorize"
	PointToken     Point = "token"
)

// Reason — почему источником стал адрес пира, хотя заголовок был или ждался.
type Reason string

// Причины. Словарь ЗАКРЫТ.
const (
	// ReasonForwardedFromNonEdge — заголовок пересылки у пира, который не край.
	ReasonForwardedFromNonEdge Reason = "forwarded-from-non-edge"
	// ReasonEdgeWithoutAddress — край без годного адреса: заголовка нет, два
	// значения, список через запятую или не адрес.
	ReasonEdgeWithoutAddress Reason = "edge-without-address"
)

// Cell — клетка переписи.
type Cell struct {
	Point  Point
	Reason Reason
}

// Cells — закрытый словарь клеток, КОПИЕЙ: (точка) × (причина).
func Cells() []Cell {
	var out []Cell
	for _, p := range []Point{PointAuthorize, PointToken} {
		for _, r := range []Reason{ReasonForwardedFromNonEdge, ReasonEdgeWithoutAddress} {
			out = append(out, Cell{Point: p, Reason: r})
		}
	}
	return out
}

// Rule — правило и его перепись.
type Rule struct {
	trust grpcsrv.TrustDomain

	mu     sync.Mutex
	counts map[Cell]uint64
}

// New собирает правило над доменом доверия процесса. Перепись засеяна нулём по
// каждой клетке: клетка, появляющаяся при первом попадании, не отличает «ноль
// случаев» от «счёта нет».
func New(trust grpcsrv.TrustDomain) *Rule {
	r := &Rule{trust: trust, counts: make(map[Cell]uint64, 4)}
	for _, c := range Cells() {
		r.counts[c] = 0
	}
	return r
}

// Of — источник запроса на точке p.
func (r *Rule) Of(req *http.Request, p Point) string {
	peer := peerAddress(req)
	if authzguard.PeerIsGateway(r.trust, req.TLS) {
		if addr, ok := oneAddress(req.Header.Values(HeaderForwardedFor)); ok {
			return addr
		}
		r.count(Cell{Point: p, Reason: ReasonEdgeWithoutAddress})
		return peer
	}
	for _, h := range forwardingHeaders {
		if len(req.Header.Values(h)) > 0 {
			r.count(Cell{Point: p, Reason: ReasonForwardedFromNonEdge})
			break
		}
	}
	return peer
}

// AuthorizePoint — источник запроса точки авторизации: форма, которую
// принимает сборка точки.
func (r *Rule) AuthorizePoint(req *http.Request) string { return r.Of(req, PointAuthorize) }

// TokenPoint — источник запроса токен-эндпоинта.
func (r *Rule) TokenPoint(req *http.Request) string { return r.Of(req, PointToken) }

// Read — снимок переписи. Читается сборщиком метрик.
func (r *Rule) Read() map[Cell]uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[Cell]uint64, len(r.counts))
	for k, v := range r.counts {
		out[k] = v
	}
	return out
}

func (r *Rule) count(c Cell) {
	r.mu.Lock()
	r.counts[c]++
	r.mu.Unlock()
}

// oneAddress — ровно одно значение заголовка, и оно — адрес IPv4 или IPv6 без
// зоны. Адрес приводится к одной записи: две записи одного адреса — один ключ.
func oneAddress(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(values[0]))
	if err != nil || addr.Zone() != "" {
		return "", false
	}
	return addr.Unmap().String(), true
}

// peerAddress — адрес пира соединения, приведённый к одной записи.
func peerAddress(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	if addr, perr := netip.ParseAddr(host); perr == nil {
		return addr.Unmap().String()
	}
	return host
}
