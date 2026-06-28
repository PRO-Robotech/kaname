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
)
