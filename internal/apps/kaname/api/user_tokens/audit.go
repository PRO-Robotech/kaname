// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user_tokens

// audit.go — audit-trail slice для User-токенов.
// Durable audit_outbox taxonomy + payload builder + emit-порт для UserTokenService
// Issue / Revoke.
//
// Токен несёт долгоживущий OAuth2 credential-материал (private-key PEM). Audit
// payload несёт ТОЛЬКО не-секретные compliance-измерения — actor / userId / tokenId /
// keyAlgorithm — и НИКОГДА секрет (нет private_key_pem, нет token).
//
// EventType значения удовлетворяют audit_outbox_event_type_check
// (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`) — включая underscore-сегмент в
// `user_token`.

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/service"
)

const (
	// auditEventUserGrantRevoked — UserTokenService.Revoke.
	auditEventUserGrantRevoked = "iam.user_token.revoked"
)

// auditEmitter — порт для эмита одной durable audit_outbox compliance-строки
// внутри worker-tx. Атомарно с user_oauth_clients-мутацией (запрет #10).
// Реализуется *kanamepg.AuditOutboxEmitter. nil → emit пропускается.
type auditEmitter interface {
	EmitTx(ctx context.Context, tx service.Tx, ev service.AuditEvent) error
}

func userTokenAuditPayload(actor, userID, tokenID, keyAlgorithm string) map[string]any {
	return shared.UserTokenAuditPayload(actor, userID, tokenID, keyAlgorithm)
}
