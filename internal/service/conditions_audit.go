// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service

// conditions_audit.go — durable audit_outbox
// taxonomy + payload builder for ConditionsService CRUD (Create / Update /
// Delete).
//
// ConditionsService is the CEL conditional-authz overlay — its mutations widen
// or narrow access grants, so they are security-relevant and MUST leave a
// durable compliance trail, exactly like the other audited mutations. The audit
// row is emitted inside the SAME worker-tx as the condition mutation (atomic,
// ban #10).
//
// EventType values satisfy audit_outbox_event_type_check
// (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`): `iam` + `.condition` + `.created`
// / `.updated` / `.deleted` — three dot-separated lower-case segments.
//
// Payload carries ONLY non-secret compliance dimensions — actor / condition_id
// / binding_id / expression_name / (for update) changed_fields. It NEVER
// carries the opaque condition params blob or any secret material (security.md).

const (
	// auditEventConditionCreated — ConditionsService.Create commit.
	auditEventConditionCreated = "iam.condition.created"
	// auditEventConditionUpdated — ConditionsService.Update commit.
	auditEventConditionUpdated = "iam.condition.updated"
	// auditEventConditionDeleted — ConditionsService.Delete (hard-delete) commit.
	auditEventConditionDeleted = "iam.condition.deleted"
)

// conditionAuditPayload — builds the event_payload body for a condition
// create/update/delete event. Snake_case keys (parity with the other audit
// rows).
//
//   - actor           — the VERIFIED caller principal, captured synchronously
//     from PrincipalFromContext upstream, never from a request-body field
//     (anti-spoofing).
//   - condition_id    — the cnd_… resource id.
//   - binding_id      — the AccessBinding the condition is bound to ("" when the
//     condition is standalone / folder-scoped, not yet bound).
//   - expression_name — the CEL/builtin expression NAME (e.g. "non_expired"),
//     NOT the opaque params blob — no secret material.
//   - changed_fields  — for Update only: the mask paths actually applied
//     (description / labels / expression / parameters_schema). nil → omitted.
//
// NEVER carries the opaque condition params / secret material — only compliance
// dimensions (security.md).
func conditionAuditPayload(actor, conditionID, bindingID, expressionName string, changedFields []string) map[string]any {
	p := map[string]any{
		"actor":           actor,
		"resource_type":   "condition",
		"resource_id":     conditionID,
		"condition_id":    conditionID,
		"binding_id":      bindingID,
		"expression_name": expressionName,
	}
	if len(changedFields) > 0 {
		p["changed_fields"] = changedFields
	}
	return p
}
