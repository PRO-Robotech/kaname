// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package sa_keys

// audit.go — audit-trail slice for SAKey.
// Durable audit_outbox taxonomy + payload builder + emit-port for SAKey
// Issue / Revoke.
//
// SAKey deals with long-lived OAuth2 client credential material (private-key
// PEM, JWKS, audience). The audit payload carries ONLY non-secret compliance
// dimensions — actor / serviceAccountId / keyId / keyAlgorithm — and NEVER any
// secret (no private_key_pem, no client_secret, no token).
//
// EventType values satisfy audit_outbox_event_type_check
// (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`) — including the underscore segment
// in `sa_key`.

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

const (
	// auditEventSAKeyIssued — SAKeyService.IssueSAKey (Class A static SA-key
	// minted via Hydra OAuth2 client).
	auditEventSAKeyIssued = "iam.sa_key.issued"
	// auditEventSAKeyRevoked — SAKeyService.RevokeSAKey.
	auditEventSAKeyRevoked = "iam.sa_key.revoked"
)

// auditEmitter — port for emitting one durable audit_outbox compliance row
// inside the SAKey worker-tx. Atomic with the
// service_account_oauth_clients mutation (запрет #10). Implemented by
// *kachopg.AuditOutboxEmitter. nil → emit is skipped (degraded/legacy wiring);
// the mutation contract is unchanged either way (purely-additive audit).
type auditEmitter interface {
	EmitTx(ctx context.Context, tx service.Tx, ev service.AuditEvent) error
}

// saKeyAuditPayload — builds the event_payload body for a SAKey issue/revoke
// event. Snake_case keys (parity with the other audit rows).
//
//   - actor             — the VERIFIED caller principal, sourced from
//     PrincipalFromContext upstream, never from the request body (anti-spoofing).
//   - service_account_id — the SA the key belongs to.
//   - key_id            — the kacho-iam SA-OAuth-client id (soc_…), NOT a secret.
//   - key_algorithm     — JOSE alg of the registered public key ("ES256", or ""
//     for a federated key that carries no kacho-held material).
//
// NEVER carries private_key_pem / client_secret / any token — SAKey credential
// material stays out of the audit trail (acceptance 5.2-36).
func saKeyAuditPayload(actor, serviceAccountID, keyID, keyAlgorithm string) map[string]any {
	return map[string]any{
		"actor":              actor,
		"resource_type":      "sa_key",
		"resource_id":        keyID,
		"service_account_id": serviceAccountID,
		"key_id":             keyID,
		"key_algorithm":      keyAlgorithm,
	}
}
