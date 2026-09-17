// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys

// audit.go — три вида события аудита ключа (§4.1 п. 11): заведение церемонией,
// перенос, снятие — по числу действий, которыми строка появляется или
// исчезает. Событие пишется ТОЙ ЖЕ транзакцией, что строка ключа, — тогда и
// только тогда, когда действие состоялось: отказ до записи события не
// порождает, откат уносит его вместе со строкой.
//
// Форма вида взята у удостоверения служебной учётки (`iam.sa_key.issued` /
// `iam.sa_key.revoked` / `iam.sa_key.expired_reclaimed`): системное действие
// несёт свой вид, и перенос повторяет эту форму (Р3).

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

const (
	AuditAccessKeyRegistered  = "iam.access_key.registered"
	AuditAccessKeyTransferred = "iam.access_key.transferred"
	AuditAccessKeyRevoked     = "iam.access_key.revoked"
)

// emitKeyAudit — событие ключа той же транзакцией: субъект, ключ, актор,
// алгоритм; ни адреса, ни имени, ни материала (гейт `audit_payload_pii`).
func emitKeyAudit(ctx context.Context, w Writer, eventType string, k domain.AccessKey, accountID domain.AccountID, actor string) error {
	return w.EmitAudit(ctx, outboxtypes.AuditEvent{
		EventType:       eventType,
		TenantAccountID: string(accountID),
		Payload: map[string]any{
			"user_id":       string(k.UserID),
			"access_key_id": string(k.ID),
			"actor":         actor,
			"algorithm":     k.Algorithm,
		},
	})
}
