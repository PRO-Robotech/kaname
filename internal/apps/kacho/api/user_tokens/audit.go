// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

const (
	// auditEventUserTokenIssued — UserTokenService.Issue.
	auditEventUserTokenIssued = "iam.user_token.issued"
	// auditEventUserTokenRevoked — UserTokenService.Revoke.
	auditEventUserTokenRevoked = "iam.user_token.revoked" // #nosec G101 -- audit event-type constant, not a credential
)

// auditEmitter — порт для эмита одной durable audit_outbox compliance-строки
// внутри worker-tx. Атомарно с user_oauth_clients-мутацией (запрет #10).
// Реализуется *kachopg.AuditOutboxEmitter. nil → emit пропускается.
type auditEmitter interface {
	EmitTx(ctx context.Context, tx service.Tx, ev service.AuditEvent) error
}

// userTokenAuditPayload — тело event_payload для issue/revoke-события токена.
// Snake_case ключи (паритет с прочими audit-строками).
//
//   - actor         — ВЕРИФИЦИРОВАННЫЙ принципал вызывающего (из
//     PrincipalFromContext), никогда из тела запроса (anti-spoofing).
//   - user_id       — User, которому принадлежит токен.
//   - token_id      — kacho-iam UserOAuthClient id (uoc_…), НЕ секрет.
//   - key_algorithm — JOSE alg зарегистрированного публичного ключа ("ES256").
//
// НИКОГДА не несёт private_key_pem / любой токен — credential-материал не попадает
// в audit-trail.
func userTokenAuditPayload(actor, userID, tokenID, keyAlgorithm string) map[string]any {
	return map[string]any{
		"actor":         actor,
		"resource_type": "user_token",
		"resource_id":   tokenID,
		"user_id":       userID,
		"token_id":      tokenID,
		"key_algorithm": keyAlgorithm,
	}
}
