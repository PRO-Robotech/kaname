// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

// audit.go — durable audit_outbox event-type taxonomy for Account mutations.
// Values are the canonical `iam.<resource>.<action>`
// strings from the taxonomy; they satisfy audit_outbox_event_type_check.
const (
	auditEventAccountCreated = "iam.account.created"
	auditEventAccountUpdated = "iam.account.updated"
	auditEventAccountDeleted = "iam.account.deleted"
)
