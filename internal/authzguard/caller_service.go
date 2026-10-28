// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// caller_service.go — признание края и пира на HTTP-слушателях.
//
// Модулем, в том числе краем, признаётся только пара (пространство, учётка),
// объявленная установкой (`moduleidentity.Roster`, kaname#984). Разбор
// идентификатора один на все пути признания вызывающего —
// `moduleidentity.ParseSAN`; здесь стояла своя обёртка над разбором стража
// записи отношений, и вместе с ним она снята.
package authzguard

import (
	"crypto/tls"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
)

// PeerIsGateway — пир HTTP-слушателя предъявил ПРОВЕРЕННЫЙ сертификат края:
// объявленная установкой личность, чья служба — api-gateway.
//
// Один признак края на все HTTP-слушатели, читающие заголовок, который ставит
// край: полосу входа (допуск ровно края) и поверхность выдачи (адрес источника,
// приёмка ceremony-pace-is-named-by-number.md Р7). Сертификат, которого слушатель
// не проверил (нет проверенной цепочки), личности не доказывает. Необъявленный
// домен доверия и необъявленная пара не узнают никого.
//
// Привязка к выпустившему центру (kaname#988) судится ТЕМ ЖЕ перечнем, что на
// gRPC-слушателях: лист края, выпущенный не центром края, краем не признаётся.
func PeerIsGateway(modules moduleidentity.Roster, d grpcsrv.TrustDomain, st *tls.ConnectionState) bool {
	id, ok := modules.FromTLSState(d, st)
	return ok && id.Service == GatewayServiceName()
}

// VerifiedPeerIdentity — идентификатор пира HTTP-слушателя: URI SAN нашего
// домена доверия с ПРОВЕРЕННОГО слушателем листа. Пусто — сертификата нет,
// цепочка не проверена либо лист не несёт идентификатора нашего домена.
//
// Одно место, где решается «чей это пир» по сертификату: признак края выше и
// доверенный пересыльщик поверхности выдачи (`issuingsource`, kaname#930)
// спрашивают его, а не разбирают состояние рукопожатия каждый сам.
func VerifiedPeerIdentity(d grpcsrv.TrustDomain, st *tls.ConnectionState) string {
	if st == nil || len(st.VerifiedChains) == 0 || len(st.VerifiedChains[0]) == 0 {
		return ""
	}
	return d.CertIdentity(st.VerifiedChains[0][0])
}
