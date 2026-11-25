// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

import (
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// UserTokenIssuedAuditEvent строит один и тот же payload для обычной и заранее
// зарезервированной строки журнала. Удостоверение передаётся только по ID.
func UserTokenIssuedAuditEvent(actor string, owner domain.UserID, credential domain.UserOAuthClientID, algorithm string) outboxtypes.AuditEvent {
	return outboxtypes.AuditEvent{EventType: "iam.user_token.issued", Payload: UserTokenAuditPayload(actor, string(owner), string(credential), algorithm)}
}

// UserTokenAuditPayload — тело event_payload для issue/revoke-события токена.
// Snake_case ключи (паритет с прочими audit-строками).
//
//   - actor         — ВЕРИФИЦИРОВАННЫЙ принципал вызывающего (из
//     PrincipalFromContext), никогда из тела запроса (anti-spoofing).
//   - user_id       — User, которому принадлежит токен.
//   - token_id      — kaname UserOAuthClient id (uoc_…), НЕ секрет.
//   - key_algorithm — JOSE alg зарегистрированного публичного ключа ("ES256").
//
// НИКОГДА не несёт private_key_pem / любой токен — credential-материал не попадает
// в audit-trail.
func UserTokenAuditPayload(actor, userID, tokenID, keyAlgorithm string) map[string]any {
	return map[string]any{
		"actor":         actor,
		"resource_type": "user_token",
		"resource_id":   tokenID,
		"user_id":       userID,
		"token_id":      tokenID,
		"key_algorithm": keyAlgorithm,
	}
}
