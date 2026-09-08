// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package project

// audit.go — durable audit_outbox event-type taxonomy for Project mutations.
// ProjectService.Move is N/A — no Move RPC exists in the current surface, so
// iam.project.moved is not emitted here.
const (
	auditEventProjectCreated = "iam.project.created"
	auditEventProjectUpdated = "iam.project.updated"
	auditEventProjectDeleted = "iam.project.deleted"
)
