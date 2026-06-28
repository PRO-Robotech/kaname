// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package account

// audit.go — durable audit_outbox event-type taxonomy for Account mutations.
// Values are the canonical `iam.<resource>.<action>`
// strings from the taxonomy; they satisfy audit_outbox_event_type_check.
const (
	auditEventAccountCreated = "iam.account.created"
	auditEventAccountUpdated = "iam.account.updated"
	auditEventAccountDeleted = "iam.account.deleted"
)
