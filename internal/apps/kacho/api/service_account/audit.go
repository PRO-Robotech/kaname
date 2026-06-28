// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service_account

// audit.go — durable audit_outbox event-type taxonomy for ServiceAccount
// mutations.
const (
	auditEventServiceAccountCreated = "iam.service_account.created"
	auditEventServiceAccountUpdated = "iam.service_account.updated"
	auditEventServiceAccountDeleted = "iam.service_account.deleted"
)
