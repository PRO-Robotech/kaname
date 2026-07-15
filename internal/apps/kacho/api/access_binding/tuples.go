// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// tuples.go — FGA tuple-builder for AccessBinding emit-in-tx flow.
//
// Permission-based mapping collapses the previous name-based mappers
// (`roleNameToRelation`, `resolveBindingRelation`, `resolveRelationFromRepo`)
// into a single permission-based mapper `authzmap.PermissionsToRelations` and
// a single tuple-builder `tuplesForBinding(b, []Relation)`.
//
// Emit path:
//
//  1. Read role (via Writer-tx reader-side or pre-loaded role).
//  2. relations := authzmap.PermissionsToRelations(role.Permissions)
//  3. tuples := tuplesForBinding(binding, relations)
//  4. w.AccessBindingsW().EmitRelationWrite(ctx, tuples)         // grant
//     -- OR --
//     w.AccessBindingsW().EmitRelationDelete(ctx, tuples)        // revoke (symmetric)
//  5. w.Commit(ctx)
//
// Drainer (clients/fga_applier.go) asynchronously applies to OpenFGA.

import (
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	abrepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

// buildBindingTuples builds the FULL FGA tuple set a (thin) binding emits for a
// given role — the SINGLE source of truth shared by Create (the grant emit +
// emitted-set persist) and the Role.Update reconcile fan-out. The per-binding
// target arms were dropped, so the projection is role-driven only. Binding-time
// scope_grant emission was also removed wholesale — the unified reconciler is
// the SINGLE materialization path for ALL selector arms:
//
//   - RULES role → ONLY the binding-lifecycle hierarchy parent-pointer; the
//     per-object access tuples (ARM_ANCHOR/ARM_NAMES/ARM_LABELS) are materialized
//     post-commit by the reconciler, NOT here. No per-rule scope_grant tuple.
//   - legacy permissions-only role → whole-role tier relations on the scope
//     anchor (PermissionsToRelations) + the hierarchy parent-pointer (via
//     tuplesForBinding).
//
// Returns the deterministic tuple set so a diff against the stored emitted-set is
// stable (idempotent reconcile: an unchanged tier yields an empty delta).
// dedupeTuples removes duplicate tuples while preserving first-seen order:
// the per-subject emission loop appends the
// subject-independent scope→binding hierarchy parent-pointer once per subject, so
// the combined set must be deduped before the fga_outbox emit + ledger persist
// (the ledger PK + ON CONFLICT DO NOTHING would also dedupe, but a stable deduped
// slice keeps the emitted-set ↔ ledger round-trip byte-symmetric for revoke).
func dedupeTuples(tuples []abrepo.RelationTuple) []abrepo.RelationTuple {
	if len(tuples) < 2 {
		return tuples
	}
	seen := make(map[abrepo.RelationTuple]struct{}, len(tuples))
	out := tuples[:0:0]
	for _, t := range tuples {
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

func buildBindingTuples(b domain.AccessBinding, role domain.Role) ([]abrepo.RelationTuple, error) {
	// RBAC explicit-model 2026 P4 (D-4 / КФ-3): the binding-time scope_grant emission
	// path is REMOVED WHOLESALE. A RULES-role no longer emits per-rule scope_grant
	// tuples at Create — the UNIFIED reconciler is the SINGLE materialization path
	// for ALL selector arms (ARM_ANCHOR(all)+ARM_NAMES+ARM_LABELS), emitting DIRECT
	// per-object v_*/tier tuples. At Create a rules-role binding therefore emits ONLY
	// the binding-lifecycle hierarchy parent-pointer (so the scope owner keeps a
	// viewer path to the binding OBJECT itself — #166, membership-write-authz cascade,
	// D-7); the per-object access tuples are materialized post-commit by the
	// reconciler (create.go ReconcileBinding) + forward on each resource's Create.
	if len(role.Rules) > 0 {
		var tuples []abrepo.RelationTuple
		if hp, ok := hierarchyParentTuple(b); ok {
			tuples = append(tuples, hp)
		}
		return tuples, nil
	}
	// Legacy permissions-only role (no rules): emit the whole-role tier relations
	// on the scope anchor + the hierarchy parent-pointer (via tuplesForBinding).
	permissions := make([]string, len(role.Permissions))
	for i, p := range role.Permissions {
		permissions[i] = string(p)
	}
	relations := authzmap.PermissionsToRelations(permissions)
	return tuplesForBinding(b, relations), nil
}

// tuplesForBinding builds the FGA tuple set for an AccessBinding given the
// pre-resolved relation list (output of authzmap.PermissionsToRelations).
//
// Per relation, one role-relation tuple is emitted:
//
//	subject_type:subject_id  →  <relation>  →  resource_type:resource_id
//
// Subjects use the canonical FGA prefix mapping (group→#member sigil).
//
// For EVERY scope ONE hierarchy (parent-pointer) tuple is appended (independent of
// relation count) wiring the binding-OBJECT into the scope hierarchy. The
// parent-pointer relation on iam_access_binding is named after the scope:
//
//	project:<resourceID>  →  project  →  iam_access_binding:<bindingID>
//	account:<resourceID>  →  account  →  iam_access_binding:<bindingID>
//	cluster:<resourceID>  →  cluster  →  iam_access_binding:<bindingID>
//
// rbac-contract-a-fix: under the FLAT OpenFGA model the `<rel> from <scope>` ACCESS
// computed relations on iam_access_binding were removed, so this parent-pointer is
// the hierarchy/lineage edge only — it no longer by itself grants the scope owner a
// viewer path to the binding object. The owner's/grantor's access on the binding
// OBJECT is MATERIALIZED per-object by the reconciler (the owner `*.*` ARM_ANCHOR over
// iam.accessBinding, triggered by the create.go reconcile-event emit).
//
// Returns nil when the binding cannot be represented (empty resource_type).
func tuplesForBinding(b domain.AccessBinding, relations []authzmap.Relation) []abrepo.RelationTuple {
	resType := strings.ToLower(string(b.ResourceType))
	if resType == "" || len(relations) == 0 {
		return nil
	}

	subject := domain.FGASubjectRef(string(b.SubjectType), string(b.SubjectID))
	object := fmt.Sprintf("%s:%s", resType, b.ResourceID)

	// Cluster is the only scope where the *direct* relations on the FGA
	// type are `system_admin` / `system_viewer` (the canonical names that
	// existing tuples — including the BG approve-B path and the
	// bootstrap-admin seed — use). The generic tier mapping resolves
	// `admin`/`editor` → "admin"/"editor" relations, but on cluster those
	// are computed-only aliases derived from system_admin. Emitting the
	// computed-relation names would create dangling tuples on the
	// computed-relation side (FGA rejects writing tuples on computed
	// relations) — so map them to the direct relation here.
	if resType == "cluster" {
		relations = mapClusterRelations(relations)
	}

	out := make([]abrepo.RelationTuple, 0, len(relations)+1)
	for _, rel := range relations {
		out = append(out, abrepo.RelationTuple{
			User:     subject,
			Relation: string(rel),
			Object:   object,
		})
	}

	// Emit one hierarchy (parent-pointer) tuple so the FGA model's
	// `<rel> from <scope>` computed-relations resolve cascade Get/List/Delete
	// on the binding object.
	if hp, ok := hierarchyParentTuple(b); ok {
		out = append(out, hp)
	}
	return out
}

// hierarchyParentTuple builds the scope→binding parent-pointer tuple wiring the
// BINDING object into the scope hierarchy:
//
//	project:<resourceID>  →  project  →  iam_access_binding:<bindingID>
//	account:<resourceID>  →  account  →  iam_access_binding:<bindingID>
//	cluster:<resourceID>  →  cluster  →  iam_access_binding:<bindingID>
//
// rbac-contract-a-fix: the flat OpenFGA model dropped the `<rel> from <scope>` ACCESS
// computed-relations on iam_access_binding, so this is the lineage edge only — the
// scope owner's Get/List/Delete authz on the binding OBJECT is materialized
// per-object by the reconciler (owner `*.*` ARM_ANCHOR over iam.accessBinding), not
// derived from this pointer.
//
// The relation is named after the scope; the closed set is the bindable
// resource scopes (project/account/cluster). It is INDEPENDENT of the target
// arm — both the all_in_scope arm (tuplesForBinding) and the resources[] arm
// (tuplesForTarget) MUST emit it, otherwise the scope owner holds no viewer
// path to the binding object itself and Get/Delete 403 (issue #166: the
// resources[] arm previously emitted only per-object tuples and skipped this).
//
// ok=false when the scope is not a hierarchy parent or the binding has no id.
func hierarchyParentTuple(b domain.AccessBinding) (abrepo.RelationTuple, bool) {
	resType := strings.ToLower(string(b.ResourceType))
	switch resType {
	case "project", "account", "cluster":
		if b.ID == "" {
			return abrepo.RelationTuple{}, false
		}
		return abrepo.RelationTuple{
			User:     fmt.Sprintf("%s:%s", resType, b.ResourceID),
			Relation: resType,
			Object:   fmt.Sprintf("iam_access_binding:%s", b.ID),
		}, true
	default:
		return abrepo.RelationTuple{}, false
	}
}

// mapClusterRelations rewrites tier-derived relations to the canonical
// direct relations on the FGA `cluster` type (Item #5 unification):
//
//	admin   → system_admin   (full CRUD; computed `admin`/`editor`/`viewer` on
//	                          cluster all derive from system_admin)
//	editor  → system_admin   (cluster has no separate "editor" tier; treat
//	                          write-tier on the cluster as system_admin)
//	viewer  → system_viewer  (read-only; covers the `viewer` computed
//	                          relation via cascade)
//
// Unknown relations pass through unchanged.
//
// Output is deduplicated (a binding granting both editor + viewer collapses
// to a single system_admin + system_viewer pair).
func mapClusterRelations(rels []authzmap.Relation) []authzmap.Relation {
	if len(rels) == 0 {
		return rels
	}
	seen := make(map[authzmap.Relation]struct{}, len(rels))
	out := make([]authzmap.Relation, 0, len(rels))
	for _, r := range rels {
		mapped := r
		switch r {
		case "admin", "editor":
			mapped = "system_admin"
		case "viewer":
			mapped = "system_viewer"
		}
		if _, dup := seen[mapped]; dup {
			continue
		}
		seen[mapped] = struct{}{}
		out = append(out, mapped)
	}
	return out
}
