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
//     значением заголовка. На точке анонимной выдачи докерной полосы тем же
//     признаком узнаётся и ОБЪЯВЛЕННЫЙ доверенный пересыльщик — прокси реестра
//     (kaname#930, [Rule.RegistryTokenPoint]).
//  3. Во всех остальных случаях источник есть адрес пира соединения, а
//     `X-Forwarded-For`, `Forwarded` и `X-Real-IP` не читаются.
//  4. Каждый случай п.3, где заголовок был и не прочитан или край адреса не
//     дал, считается в закрытом словаре клеток ([Cells]), засеянном нулями.
//     Точка анонимной выдачи считается в СВОЁМ закрытом словаре
//     ([RegistryTokenReasons]): заголовок пересылки у пира, который ни край, ни
//     объявленный пересыльщик (kaname#930), и край или объявленный
//     пересыльщик без годного адреса (kaname#935).
//
// Край узнаётся тем же признаком, что у полосы входа и яруса gateway-only:
// короткое имя службы из SAN проверенного сертификата
// ([authzguard.PeerIsGateway]). Сертификат, который слушатель не проверил,
// личности не доказывает и краем не считается.
//
// Правило закрывает оба направления подмены: заголовок без сертификата края
// (или объявленного пересыльщика) ключа не меняет, а край без годного адреса
// нового ключа не получает — он делит ключ своего пира. Необъявленный домен
// доверия не узнаёт края вовсе: тогда источник — всегда адрес пира, и всякий
// заголовок пересылки посчитан.
package issuingsource

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/servicesan"
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

// RegistryTokenReason — почему на точке анонимной выдачи докерной полосы
// источником стал адрес пира, хотя заголовок пересылки был или ждался
// (kaname#930, kaname#935).
type RegistryTokenReason string

// Причины точки анонимной выдачи. Словарь ЗАКРЫТ и отделён от словаря п. 4
// точек приёмки ([Cells]).
const (
	// RegistryTokenReasonForwardedFromUnrecognizedPeer — заголовок пересылки у
	// пира, который ни край, ни объявленный пересыльщик точки: сертификата нет,
	// цепочка не проверена либо идентификатор не равен объявленному. Рост
	// клетки значит одно из двух: вызывающий пришёл к слушателю мимо прокси
	// реестра, либо пересыльщик назван не тем идентификатором и все клиенты за
	// прокси делят один ключ темпа.
	RegistryTokenReasonForwardedFromUnrecognizedPeer RegistryTokenReason = "forwarded-from-unrecognized-peer"
	// RegistryTokenReasonEdgeWithoutAddress — край или объявленный пересыльщик
	// точки без годного адреса: заголовка нет, два значения, список через
	// запятую или не адрес (kaname#935). Метка та же, что у клетки п. 4 точек
	// приёмки, и значит то же: признанный пир адреса не дал. Рост клетки при
	// пересыльщике значит, что прокси реестра не передаёт адрес клиента одним
	// значением, и все клиенты за ним делят один ключ темпа.
	RegistryTokenReasonEdgeWithoutAddress RegistryTokenReason = RegistryTokenReason(ReasonEdgeWithoutAddress)
)

// RegistryTokenReasons — закрытый словарь переписи точки анонимной выдачи,
// КОПИЕЙ.
func RegistryTokenReasons() []RegistryTokenReason {
	return []RegistryTokenReason{
		RegistryTokenReasonForwardedFromUnrecognizedPeer,
		RegistryTokenReasonEdgeWithoutAddress,
	}
}

// Rule — правило и его перепись.
type Rule struct {
	trust grpcsrv.TrustDomain
	// form — форма имени службы, объявленная установкой: ею узнаётся край.
	form servicesan.Form

	mu       sync.Mutex
	counts   map[Cell]uint64
	registry map[RegistryTokenReason]uint64
}

// New собирает правило над доменом доверия и формой имени службы процесса:
// по ним узнаётся край. Перепись засеяна нулём по
// каждой клетке: клетка, появляющаяся при первом попадании, не отличает «ноль
// случаев» от «счёта нет».
func New(trust grpcsrv.TrustDomain, form servicesan.Form) *Rule {
	r := &Rule{trust: trust, form: form, counts: make(map[Cell]uint64, 4),
		registry: make(map[RegistryTokenReason]uint64, len(RegistryTokenReasons()))}
	for _, c := range Cells() {
		r.counts[c] = 0
	}
	for _, reason := range RegistryTokenReasons() {
		r.registry[reason] = 0
	}
	return r
}

// Of — источник запроса на точке p.
func (r *Rule) Of(req *http.Request, p Point) string {
	source, reason, counted := r.resolve(req, "")
	if counted {
		r.count(Cell{Point: p, Reason: reason})
	}
	return source
}

// resolve — пп. 1–3 правила: источник и, если источником стал адрес пира при
// случае п. 4, причина этого. forwarderSAN — доверенный пересыльщик точки
// сверх края; пусто — доверен только край.
func (r *Rule) resolve(req *http.Request, forwarderSAN string) (source string, reason Reason, counted bool) {
	peer := peerAddress(req)
	if r.forwards(req, forwarderSAN) {
		if addr, ok := oneAddress(req.Header.Values(HeaderForwardedFor)); ok {
			return addr, "", false
		}
		return peer, ReasonEdgeWithoutAddress, true
	}
	for _, h := range forwardingHeaders {
		if len(req.Header.Values(h)) > 0 {
			return peer, ReasonForwardedFromNonEdge, true
		}
	}
	return peer, "", false
}

// forwards — пир вправе назвать источник заголовком: проверенный сертификат
// края либо проверенный сертификат, чей идентификатор РАВЕН объявленному
// пересыльщику точки. Сравнение точное: пересыльщик назван ручкой целиком,
// а не узнан по форме имени.
func (r *Rule) forwards(req *http.Request, forwarderSAN string) bool {
	if authzguard.PeerIsGateway(r.trust, r.form, req.TLS) {
		return true
	}
	return forwarderSAN != "" && authzguard.VerifiedPeerIdentity(r.trust, req.TLS) == forwarderSAN
}

// AuthorizePoint — источник запроса точки авторизации: форма, которую
// принимает сборка точки.
func (r *Rule) AuthorizePoint(req *http.Request) string { return r.Of(req, PointAuthorize) }

// TokenPoint — источник запроса токен-эндпоинта.
func (r *Rule) TokenPoint(req *http.Request) string { return r.Of(req, PointToken) }

// RegistryTokenPoint — источник анонимного входа докерной полосы `/iam/token`
// (kaname#928): ключ её темпа на источник. Выводится пп. 1–3 правила — тем же
// кодом, что у двух точек приёмки, — с одним отличием: адрес из заголовка
// берётся и у ДОВЕРЕННОГО ПЕРЕСЫЛЬЩИКА forwarderSAN (kaname#930).
//
// Единственный вход анонимной выдачи — прокси реестра, и к службе все его
// клиенты приходят с одного пира. Без признанного пересыльщика ключ темпа был
// бы адресом этого прокси, и предел стал бы общим на всех. Пересыльщик
// узнаётся тем же признаком, что край: проверенный слушателем сертификат нашего
// домена доверия, чей идентификатор равен объявленному. Пересылка от любого
// другого пира ключа не меняет; пересыльщик без годного адреса делит ключ
// своего пира, как край. Доверие ограничено ЭТОЙ точкой: на точках приёмки
// заголовок пересыльщика не читается (п. 3) и считается (п. 4).
//
// Пустой forwarderSAN — доверен только край. Анонимный поток без пересыльщика
// не стартует (страж `RegistryTokenConfig.Validate`).
//
// Словарь п. 4 к этой точке НЕ применяется: он закрыт приёмкой
// (ceremony-pace-is-named-by-number.md, Р7 п. 4, KN-PACE-37) двумя точками, и
// счёт третьей в клетку `token` смешал бы две разные точки. Заголовок
// пересылки от пира, который ни край, ни объявленный пересыльщик, считается в
// своём словаре точки ([RegistryTokenReasons]): без счёта пересыльщик,
// названный не тем идентификатором, неотличим от залпа одного клиента — оба
// видны только отказами по темпу. Там же считаются пересыльщик и край без
// годного адреса (kaname#935): прокси реестра, не передающий адрес клиента
// одним значением, сводит всех за собой к одному ключу темпа так же молча.
func (r *Rule) RegistryTokenPoint(forwarderSAN string) func(*http.Request) string {
	return func(req *http.Request) string {
		source, reason, counted := r.resolve(req, forwarderSAN)
		if !counted {
			return source
		}
		// Обе причины, которые даёт resolve, — по своей клетке словаря точки.
		switch reason {
		case ReasonForwardedFromNonEdge:
			r.countRegistryToken(RegistryTokenReasonForwardedFromUnrecognizedPeer)
		case ReasonEdgeWithoutAddress:
			r.countRegistryToken(RegistryTokenReasonEdgeWithoutAddress)
		}
		return source
	}
}

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

// ReadRegistryTokenPoint — снимок переписи точки анонимной выдачи. Читается
// сборщиком метрик.
func (r *Rule) ReadRegistryTokenPoint() map[RegistryTokenReason]uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[RegistryTokenReason]uint64, len(r.registry))
	for k, v := range r.registry {
		out[k] = v
	}
	return out
}

func (r *Rule) count(c Cell) {
	r.mu.Lock()
	r.counts[c]++
	r.mu.Unlock()
}

func (r *Rule) countRegistryToken(reason RegistryTokenReason) {
	r.mu.Lock()
	r.registry[reason]++
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
