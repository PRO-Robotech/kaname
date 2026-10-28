// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// caller_service.go — короткое имя службы из SAN для политики вызывающего.
//
// ServiceNameFromSAN разбирает проверенный SPIFFE-идентификатор модуля в
// короткое имя службы (например, "api-gateway"). Пер-RPC политика вызывающего
// (caller_policy.go) спрашивает его и для пола (любой идентификатор модульной
// формы), и для круга края (svc == "api-gateway"). Прежний страж с выписанным
// перечнем допущенных (CallerServiceGate) вытеснен пер-RPC политикой и снят.
package authzguard

import (
	"crypto/tls"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/servicesan"
)

// ServiceNameFromSAN — короткое имя службы модуля из проверенного SAN: домен d,
// учётка формы f. Иначе ("", false).
//
// # Одна реализация, а не две
//
// Здесь стояла ПОБАЙТОВАЯ КОПИЯ тела [SANToServiceDomain] — двадцать строк,
// повторяющих тот же разбор. Расходятся такие копии молча: правка одной не
// доезжает до другой, и вторая продолжает принимать то, что первая уже
// отвергает. Свели их вместе с переводом домена доверия в величину; форма имени
// службы переведена в величину тем же порядком (kaname#308), и разбор её — один,
// `servicesan.Form.Parse`.
func ServiceNameFromSAN(d grpcsrv.TrustDomain, f servicesan.Form, san string) (string, bool) {
	return SANToServiceDomain(d, f, san)
}

// PeerIsGateway — пир HTTP-слушателя предъявил ПРОВЕРЕННЫЙ сертификат края:
// короткое имя службы из SAN проверенного листа — api-gateway.
//
// Один признак края на все HTTP-слушатели, читающие заголовок, который ставит
// край: полосу входа (допуск ровно края) и поверхность выдачи (адрес источника,
// приёмка ceremony-pace-is-named-by-number.md Р7). Сертификат, которого слушатель
// не проверил (нет проверенной цепочки), личности не доказывает. Необъявленный
// домен доверия и необъявленная форма имени службы не узнают никого.
func PeerIsGateway(d grpcsrv.TrustDomain, f servicesan.Form, st *tls.ConnectionState) bool {
	san := VerifiedPeerIdentity(d, st)
	if san == "" {
		return false
	}
	svc, ok := ServiceNameFromSAN(d, f, san)
	return ok && svc == GatewayServiceName()
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
