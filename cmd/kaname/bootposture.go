// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"github.com/PRO-Robotech/kacho/pkg/observability"
	"github.com/PRO-Robotech/kacho/pkg/servicecontract"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// bootPosture — самоотчёт kaname о posture, с которой процесс реально
// стартовал (см. observability.BootPosture).
//
// Откуда значения:
//
//   - auth_mode     — cfg.AuthN.Mode (уже провалидирован cfg.Validate() в main).
//
//   - db_sslmode    — из ТОЙ строки, что уходит в pgxpool (cfg.DSN()): sslmode
//     может прийти как из repository.postgres.ssl-mode, так и из самого raw-URL
//     (composeDSN не перетирает уже заданный), пустое поле деривится в `disable`.
//
//   - public/internal mtls — у iam листенеров больше двух (hooks :9092, metrics
//     :9095, jwks-proxy :9097), но в контракт попадают РОВНО два gRPC-листенера:
//     public :9090 и cluster-internal :9091. Именно их server-creds строятся из
//     mtlsCfg.{Public,Internal}ServerMTLS и именно их гейтит production-guard.
//
//   - authz_check   — iam сам себе PDP: он не дозванивается до чужого
//     InternalIAMService.Check, а гейтит свои RPC внутренними floor'ами
//     (caller-policy / system_viewer / acr), опирающимися на дверь решения.
//     Поэтому здесь — факт проводки ИСТОЧНИКА ВЕРДИКТА, не адрес.
//
//     Со снятием внешнего движка прав (стадия S6 эпика #747) источник — это
//     реляционная форма в собственной базе службы, и «провязан» означает: двери
//     решения есть чем отвечать. Дверь без формы отвечала бы ОШИБКОЙ на каждый
//     вопрос, а не отказом, — то есть служба была бы Ready, не решая ничего;
//     старт в этом состоянии запрещён отдельно (ownGateWiringComplaint).
//
//   - identity_provider — ПОСАДКА ЛИЧНОСТИ, принятая процессом (задача #1125):
//     `external` — человека проверяет внешний поставщик, `own` — наша
//     собственная чеканка. Берётся из уже провалидированной настройки:
//     незаданное и негодное значения до этой строки не доживают, потому что
//     процесс на них не стартует, — значит поле отчитывается об ИСХОДЕ, а не о
//     намерении профиля.
//
//     Почему это отдельное измерение, а не следствие auth_mode: посадка
//     разводит ТРЕБОВАНИЯ старта, и стенд в боевом режиме законно бывает и той,
//     и другой. Гейт посадки обязан читать её у живого процесса — карта
//     настроек отвечает намерением, потому что читается один раз при старте, и
//     её правка меняет карту, а не процесс.
//
//   - trusted_forwarders — сужен ли круг отправителей, которым разрешено
//     передавать личность конечного пользователя. Берётся из
//     cfg.AuthN.TrustedForwarders() — ровно того значения, что уходит в
//     grpcsrv.WithTrustedForwarders на ОБОИХ листенерах, — а не из сырого поля:
//     corelib отбрасывает пустые записи, поэтому список из одних пустых записей
//     вырождается там в «доверяем любому», и рапортовать его как сужение значило
//     бы отчитываться о намерении вместо исхода.
//
//   - own_rest_public_tls / own_rest_internal_tls — СОБСТВЕННЫЕ REST-фронты
//     службы (публичный :9098 и внутренний :9099, internal/restfront). Под
//     определение производителя они подпадают буквально: мультиплексор
//     grpc-gateway поднят НАД СОБСТВЕННЫМИ gRPC-слушателями и дозванивается до
//     них через сокет, поэтому запрос по HTTP проходит ровно ту цепочку звеньев,
//     что и тот же запрос по gRPC.
//
//     Прочие HTTP-поверхности службы (вебхуки провайдера, выдача docker-токена,
//     зеркало ключей проверки, скрейп) в эти оси НЕ входят и входить не должны:
//     они обслуживают собственные обработчики, а не свои же gRPC-службы, — то
//     есть под определение не подпадают. Ось, назвавшая бы их, отчитывалась бы
//     о другом предмете.
//
//     Величина ВЫВОДИТСЯ из объявления фронта (ownRESTFront), а не вписывается:
//     по тому же объявлению фронт поднимается, поэтому самоотчёт и профиль
//     поверхности разойтись не могут. Ось спрашивает про ПРОВОД — «под
//     транспортом или открытым текстом», — а не про то, требует ли фронт
//     клиентского сертификата: это отдельное измерение, и в этой оси его нет.
func bootPosture(posture servicecontract.Descriptor, cfg config.Config,
	mtlsCfg config.MTLSConfig, authzCheckWired bool,
	restFront, internalRESTFront observability.OwnRESTFront) observability.BootPosture {
	// Режим и шифрование до базы берутся из ПРИНЯТОГО дескриптора, а не из
	// настройки рядом. Разница не косметическая: настройка отвечает намерением,
	// дескриптор — тем, что прошло отказы старта. Пока их было два места,
	// самоотчёт мог рапортовать посадку, которой процесс не принимал.
	accepted := posture.Spec()
	dbSSLMode, _ := accepted.DBSSLMode.Get()
	return observability.BootPosture{
		Service:            "iam",
		AuthMode:           accepted.Mode.String(),
		DBSSLMode:          dbSSLMode,
		PublicMTLS:         mtlsCfg.PublicServerMTLS.Enable,
		InternalMTLS:       observability.InternalMTLSFrom(mtlsCfg.InternalServerMTLS.Enable),
		AuthZCheck:         authzCheckWired,
		TrustedForwarders:  cfg.AuthN.TrustedForwarders().IsNarrowed(),
		IdentityProvider:   cfg.AuthN.IdentityProvider.String(),
		OwnRESTPublicTLS:   observability.OwnRESTFrontFrom(restFront),
		OwnRESTInternalTLS: observability.OwnRESTFrontFrom(internalRESTFront),
	}
}
