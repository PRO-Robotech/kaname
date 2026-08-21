// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/observability"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// bootPosture — самоотчёт kacho-iam о posture, с которой процесс реально
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
//   - trusted_forwarders — сужен ли круг отправителей, которым разрешено
//     передавать личность конечного пользователя. Берётся из
//     cfg.AuthN.TrustedForwarders() — ровно того значения, что уходит в
//     grpcsrv.WithTrustedForwarders на ОБОИХ листенерах, — а не из сырого поля:
//     corelib отбрасывает пустые записи, поэтому список из одних пустых записей
//     вырождается там в «доверяем любому», и рапортовать его как сужение значило
//     бы отчитываться о намерении вместо исхода.
func bootPosture(cfg config.Config, mtlsCfg config.MTLSConfig, authzCheckWired bool) observability.BootPosture {
	return observability.BootPosture{
		Service:           "iam",
		AuthMode:          cfg.AuthN.Mode.String(),
		DBSSLMode:         coredb.SSLModeFromDSN(cfg.DSN()),
		PublicMTLS:        mtlsCfg.PublicServerMTLS.Enable,
		InternalMTLS:      mtlsCfg.InternalServerMTLS.Enable,
		AuthZCheck:        authzCheckWired,
		TrustedForwarders: cfg.AuthN.TrustedForwarders().IsNarrowed(),
	}
}
