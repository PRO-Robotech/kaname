// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster

// audit.go — audit_outbox taxonomy + payload builder for the
// highest-sensitivity cluster-admin mutations.
//
// EventType values satisfy audit_outbox_event_type_check
// (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`) — including the underscore segment
// in `cluster_admin`. The payload carries only non-secret compliance dimensions
// (actor / subject / resource id); cluster-admin grants carry no secret
// material, so there is nothing to redact here.

import "github.com/PRO-Robotech/kaname/internal/domain"

const (
	// auditEventClusterAdminGranted — GrantAdmin (fresh or reactivate). The
	// reactivate path emits the SAME type as a fresh grant (compliance:
	// "cluster admin granted again"); no separate reactivated type.
	auditEventClusterAdminGranted = "iam.cluster_admin.granted"
	// auditEventClusterAdminRevoked — RevokeAdmin.
	auditEventClusterAdminRevoked = "iam.cluster_admin.revoked"
)

// clusterAdminAuditPayload — builds the event_payload body for a cluster-admin
// grant/revoke event.
//
//   - actor      — the VERIFIED caller principal (grantor/revoker), sourced from
//     PrincipalFromContext upstream, never from the request body (anti-spoofing).
//   - subjectType / subjectId — the subject the admin authority is granted to /
//     revoked from, named by its OWN kind (`user` / `service_account`).
//     It used to be the literal `user` for every kind, so a machine grant was
//     recorded as a human one (finding Н2, acceptance ADM-CA).
//   - resourceType / resourceId — the cluster_admin_grant row affected.
func clusterAdminAuditPayload(actor string, subjectType domain.GrantSubjectType, subjectID, grantID string) map[string]any {
	return map[string]any{
		"actor":         actor,
		"subject_type":  string(subjectType),
		"subject_id":    subjectID,
		"resource_type": "cluster_admin_grant",
		"resource_id":   grantID,
	}
}
