// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

// audit.go — durable audit_outbox event-type taxonomy for User mutations.
// created = UpsertFromIdentity bootstrap (insert branch); updated =
// activate-invite (update branch); deleted = UserService.Delete.
const (
	auditEventUserCreated = "iam.user.created"
	auditEventUserUpdated = "iam.user.updated"
	auditEventUserDeleted = "iam.user.deleted"

	// Suspending a person's participation in an Account, and restoring it, are
	// events of their own — not an `updated` row with a field inside. «Who blocked
	// this person» has to be answerable by looking for the event, which is the
	// only way it stays answerable once the payload shape has moved on.
	auditEventUserBlocked   = "iam.user.blocked"
	auditEventUserUnblocked = "iam.user.unblocked"
)
