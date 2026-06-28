// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package role

// audit.go — durable audit_outbox event-type taxonomy for Role mutations.
// Update payload records changed_fields only — the
// full permissions matrix is NOT exploded into the audit payload.
const (
	auditEventRoleCreated = "iam.role.created"
	auditEventRoleUpdated = "iam.role.updated"
	auditEventRoleDeleted = "iam.role.deleted"
)
