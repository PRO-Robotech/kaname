// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service_account

// audit.go — durable audit_outbox event-type taxonomy for ServiceAccount
// mutations.
const (
	auditEventServiceAccountCreated = "iam.service_account.created"
	auditEventServiceAccountUpdated = "iam.service_account.updated"
	auditEventServiceAccountDeleted = "iam.service_account.deleted"

	// Taking a machine identity out of service, and putting it back, are events
	// of their own — not an `updated` row with a field inside. «Who disabled the
	// CI bot» has to be answerable by looking for the event, which is the only
	// way it stays answerable once the payload shape has moved on.
	auditEventServiceAccountDisabled = "iam.service_account.disabled"
	auditEventServiceAccountEnabled  = "iam.service_account.enabled"
)
