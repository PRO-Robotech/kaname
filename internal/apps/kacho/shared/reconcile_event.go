// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package shared

// reconcile_event.go — app-layer reconcile-event type literals.
//
// The γ reconciler-worker drains kacho_iam.resource_reconcile_outbox and re-evaluates
// the bindings that reference the changed object (ReconcileObject keys on
// object_type/object_id — it does NOT branch on the event type). So an IAM-OWN
// resource CHANGE (label-update OR a brand-new resource that must forward-materialize
// under an owner `*.*` binding, rbac-contract-a-fix) re-uses the SAME "mirror.upsert"
// literal the β mirror-change path uses — there is no separate "created" type.
//
// These literals are kept in lockstep with repo/kacho/pg/reconcile_outbox.Event*
// (the drainer reads the same strings) but declared HERE so the use-case layer does
// not import the pg adapter package (Clean Architecture dependency rule — the same
// reason internal_iam.register_resource.go inlines them).
const (
	// ReconcileEventUpsert — an object appeared or changed (mirror upsert / iam-native
	// Create / label update). Drives a forward re-evaluation of matching bindings.
	ReconcileEventUpsert = "mirror.upsert"
	// ReconcileEventDelete — an object was removed (mirror delete). Drives eager-revoke
	// of any materialized member referencing it.
	ReconcileEventDelete = "mirror.delete"
)
