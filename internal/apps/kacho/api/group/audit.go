// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package group

// audit.go — durable audit_outbox event-type taxonomy for Group mutations.
// Group member± (member_added/removed) is out of the CRUD scope here (separate
// event-type slice).
const (
	auditEventGroupCreated = "iam.group.created"
	auditEventGroupUpdated = "iam.group.updated"
	auditEventGroupDeleted = "iam.group.deleted"
)
