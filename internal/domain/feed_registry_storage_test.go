// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// feed_registry_storage_test.go — regression lock for #71 (materialization side).
//
// Adding the storage FGA types to the model + authzmap tables (commit c01c2b9) was
// NOT sufficient for a project-scoped owner to Get/Update/Delete their own volume:
// the reconciler materializes per-object v_* ONLY for object types in the wildcard-
// expansion set AllMaterializableTypes() (labelSelectableTypes ∪ registry.repositories).
// That set is projected into the system-role (edit/view/admin/owner) role_rule_selectors
// by the boot-backfill SyncAllSystemRoleSelectors; a type absent here is INVISIBLE to
// binding discovery, so the editor's project binding materializes nothing on the
// storage object → the owner gets 403 on their OWN just-created volume (verified live:
// storage_volume:<id> carried only the `#project` structural tuple, no v_get for the
// creator SA). Storage volumes/snapshots/images carry own-table labels (mirror-fed via
// storage→iam RegisterResource, `Labels` payload) exactly like vpc/compute, so they are
// label-selectable AND materializable — they belong in labelSelectableTypes.
func TestMaterializableTypes_IncludesStorage(t *testing.T) {
	storage := []string{"storage.volumes", "storage.snapshots", "storage.images"}

	// (1) label-selectable (own-table labels, ARM_LABELS-eligible like vpc/compute).
	for _, ty := range storage {
		assert.Truef(t, IsLabelSelectableType(ty),
			"%s must be label-selectable (mirror-fed with own-table labels, parity vpc/compute) — #71", ty)
	}

	// (2) in the wildcard-expansion / materializable set → projected into every
	//     system-role's role_rule_selectors by SyncAllSystemRoleSelectors, so a
	//     project-editor binding materializes the owner's per-object v_* on the
	//     storage object (else 403 on own resource).
	seen := map[string]struct{}{}
	for _, ty := range AllMaterializableTypes() {
		seen[ty] = struct{}{}
	}
	for _, ty := range storage {
		_, ok := seen[ty]
		assert.Truef(t, ok, "AllMaterializableTypes must include %s (reconciler owner-materialization) — #71", ty)
	}
}
